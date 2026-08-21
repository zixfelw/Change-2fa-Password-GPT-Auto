"""DatabaseEngine — SQLite engine với WAL mode, transaction management, schema migration.

Quản lý single connection, WAL mode, BEGIN IMMEDIATE cho write transactions.
Hỗ trợ reentrant transactions: nested get_connection() reuse transaction hiện có.
Schema migration tự động chạy khi khởi tạo engine.
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
import threading
from pathlib import Path
from typing import Generator

from .schema import ALL_DDL, CURRENT_VERSION, MIGRATIONS


# --- Exception hierarchy ---


class DatabaseError(Exception):
    """Base error cho database layer."""


class SchemaError(DatabaseError):
    """Schema migration failure."""


class DatabaseEngine:
    """SQLite engine với WAL mode và reentrant transaction management.

    Attributes:
        db_path: Path tới SQLite database file.
        is_closed: True nếu engine đã được close.
    """

    def __init__(self, db_path: Path | str = "runtime/data.db") -> None:
        """Khởi tạo engine. Tạo directories + file nếu chưa có.

        Args:
            db_path: Đường dẫn tới SQLite file.

        Raises:
            PermissionError: Nếu path không writable.
        """
        self._db_path = Path(db_path)
        self._closed = False
        self._shutdown_requested = threading.Event()
        self._tx_lock = threading.RLock()  # Reentrant lock cho nested transactions
        self._tx_depth = 0  # Track nesting depth
        # Thread-local read connections — mỗi thread tự open. WAL mode cho phép
        # multi-reader concurrent + 1 writer (writer dùng self._conn shared).
        # Tránh block frontend GET request khi runner đang write transaction.
        self._read_locals = threading.local()
        # Track tất cả read connections để close trong shutdown.
        self._read_conns: list[sqlite3.Connection] = []
        self._read_conns_lock = threading.Lock()

        # Tạo directories nếu thiếu
        self._db_path.parent.mkdir(parents=True, exist_ok=True)

        # Kiểm tra writable trước khi tạo connection
        self._check_writable()

        # Tạo connection và configure pragmas
        self._conn = self._create_connection()

        # Chạy schema migration
        self._migrate()

    def _check_writable(self) -> None:
        """Kiểm tra path có writable không.

        Raises:
            PermissionError: Nếu directory hoặc file không writable.
        """
        parent = self._db_path.parent

        # Nếu file đã tồn tại, kiểm tra file writable
        if self._db_path.exists():
            if not os.access(self._db_path, os.W_OK):
                raise PermissionError(
                    f"Database file is not writable: {self._db_path}"
                )
        else:
            # File chưa tồn tại — kiểm tra directory writable
            if not os.access(parent, os.W_OK):
                raise PermissionError(
                    f"Directory is not writable, cannot create database: {parent}"
                )

    def _create_connection(self) -> sqlite3.Connection:
        """Tạo và configure SQLite connection."""
        conn = sqlite3.connect(
            str(self._db_path),
            check_same_thread=False,
            isolation_level=None,  # Manual transaction control
        )
        conn.row_factory = sqlite3.Row

        # Configure pragmas
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        conn.execute("PRAGMA foreign_keys=ON")

        return conn

    def _migrate(self) -> None:
        """Chạy schema migration nếu cần.

        Phân biệt 2 path để tránh xung đột giữa DDL latest và incremental migration:

        - **Fresh DB** (``_schema_version`` chưa có row, hay version=0): chạy
          ``ALL_DDL`` — đã ở phiên bản ``CURRENT_VERSION`` cuối cùng.
        - **Existing DB** (version >= 1): KHÔNG đụng ``ALL_DDL`` (DDL latest có
          thể chứa cột/index chưa tồn tại ở schema cũ). Chỉ chạy
          ``MIGRATIONS[v+1..CURRENT_VERSION]`` tuần tự. Mỗi MIGRATIONS[v] PHẢI
          self-contained (CREATE / ALTER / rebuild đầy đủ cho version đó).

        Cuối cùng INSERT ``_schema_version (version, description)`` = CURRENT.

        Raises:
            SchemaError: Nếu migration fail (DDL error).
        """
        current_db_version = self._get_schema_version()

        if current_db_version >= CURRENT_VERSION:
            return

        is_fresh = current_db_version == 0

        try:
            # Tạm tắt FK check — cần thiết cho migration rebuild table
            # (DROP parent table khi child FK còn reference). SQLite yêu cầu
            # PRAGMA foreign_keys phải chạy NGOÀI transaction.
            self._conn.execute("PRAGMA foreign_keys=OFF")
            self._conn.execute("BEGIN IMMEDIATE")

            if is_fresh:
                # Fresh DB: chạy DDL latest, đã ở version cuối.
                for ddl_block in ALL_DDL:
                    for statement in self._split_statements(ddl_block):
                        self._conn.execute(statement)
            else:
                # Existing DB: chỉ chạy incremental migrations từng step.
                # MIGRATIONS[v] PHẢI self-contained — KHÔNG dựa vào ALL_DDL chạy trước.
                for version in range(current_db_version + 1, CURRENT_VERSION + 1):
                    stmts = MIGRATIONS.get(version, [])
                    for stmt in stmts:
                        self._conn.execute(stmt)

            # Ghi version mới
            self._conn.execute(
                "INSERT OR REPLACE INTO _schema_version (version, description) VALUES (?, ?)",
                (CURRENT_VERSION, f"Migration to version {CURRENT_VERSION}"),
            )
            self._conn.execute("COMMIT")
            # Bật lại FK check sau migration thành công.
            self._conn.execute("PRAGMA foreign_keys=ON")
        except Exception as exc:
            self._conn.execute("ROLLBACK")
            self._conn.execute("PRAGMA foreign_keys=ON")
            raise SchemaError(
                f"Schema migration to version {CURRENT_VERSION} failed: {exc}"
            ) from exc

    @staticmethod
    def _split_statements(ddl_block: str) -> list[str]:
        """Split DDL block thành individual SQL statements.

        Loại bỏ empty strings và whitespace-only.
        """
        statements = []
        for stmt in ddl_block.split(";"):
            stripped = stmt.strip()
            if stripped:
                statements.append(stripped + ";")
        return statements

    def _get_schema_version(self) -> int:
        """Đọc schema version hiện tại từ database.

        Returns:
            Version number, hoặc 0 nếu table chưa tồn tại.
        """
        try:
            row = self._conn.execute(
                "SELECT MAX(version) FROM _schema_version"
            ).fetchone()
            return row[0] if row and row[0] is not None else 0
        except sqlite3.OperationalError:
            # Table _schema_version chưa tồn tại
            return 0

    @staticmethod
    def _begin_command(immediate: bool) -> str:
        """Trả về SQL BEGIN command tương ứng với mode.

        Args:
            immediate: True → ``BEGIN IMMEDIATE`` (write-lock SQLite ngay từ đầu);
                False → ``BEGIN DEFERRED`` (deferred mode, lock chỉ acquire khi gặp write thật).

        Returns:
            ``"BEGIN IMMEDIATE"`` hoặc ``"BEGIN DEFERRED"``.
        """
        return "BEGIN IMMEDIATE" if immediate else "BEGIN DEFERRED"

    @contextlib.contextmanager
    def transaction(
        self, immediate: bool = True
    ) -> Generator[sqlite3.Connection, None, None]:
        """Public API cho write transactions (sync, reentrant). Default IMMEDIATE.

        Default ``immediate=True`` để giữ backward compat tuyệt đối với mọi caller hiện
        có (mọi repository write hiện ngầm dựa trên IMMEDIATE — write-lock sớm tránh
        ``database is locked`` ở COMMIT). Caller chủ động opt-in DEFERRED bằng
        ``transaction(immediate=False)`` khi cần giảm contention và biết rõ block không
        chạm write nhiều.

        R2.15: ``transaction(immediate=True)`` ép ``BEGIN IMMEDIATE TRANSACTION`` để
        ``Pool_Manager.pick_active_profile()`` write-lock SQLite ngay từ đầu, đảm bảo
        nhiều process song song serialize qua write-lock.

        Reentrant: nested call reuse transaction hiện có; flag ``immediate`` trên nested
        call bị ignore (không re-emit BEGIN), behavior do outer scope quyết định —
        khớp R6.3 (rollback inner = rollback outer).

        Args:
            immediate: True → ``BEGIN IMMEDIATE``. False → ``BEGIN DEFERRED``.

        Yields:
            sqlite3.Connection đã bắt đầu transaction.

        Raises:
            DatabaseError: Nếu engine đã closed hoặc đang shutdown.
            Bất kỳ exception nào xảy ra trong block — được re-raise sau rollback.
        """
        with self._scoped_transaction(immediate=immediate) as conn:
            yield conn

    @contextlib.contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Low-level alias hardcode IMMEDIATE — giữ signature cũ cho backward compat.

        Mọi caller cũ (`db/migrate.py`, `db/repositories.py`, hotmail flow) đang dùng
        ``with engine.get_connection()`` SHALL nhận đúng behavior IMMEDIATE như trước.
        Caller mới cần opt-in DEFERRED PHẢI dùng ``transaction(immediate=False)``.

        Yields:
            sqlite3.Connection đã bắt đầu transaction.

        Raises:
            DatabaseError: Nếu engine đã closed hoặc đang shutdown.
        """
        with self._scoped_transaction(immediate=True) as conn:
            yield conn

    @contextlib.contextmanager
    def _scoped_transaction(
        self, *, immediate: bool
    ) -> Generator[sqlite3.Connection, None, None]:
        """Internal helper — implement reentrant transaction lifecycle (sync).

        Nested call (``self._tx_depth > 0``) chỉ yield lại connection, không emit
        BEGIN/COMMIT/ROLLBACK. Outer scope quản lý lifecycle: BEGIN <mode>, COMMIT
        on success, ROLLBACK on exception. RLock acquire/release để cùng thread reentrant.

        Args:
            immediate: True → ``BEGIN IMMEDIATE``; False → ``BEGIN DEFERRED``.
                Chỉ ảnh hưởng outer scope (nested call ignore flag này).
        """
        if self._closed or self._shutdown_requested.is_set():
            raise DatabaseError("Engine is closed")

        self._tx_lock.acquire()
        is_outer = self._tx_depth == 0
        self._tx_depth += 1
        try:
            if is_outer:
                self._conn.execute(self._begin_command(immediate))
            try:
                yield self._conn
                if is_outer:
                    try:
                        self._conn.execute("COMMIT")
                    except Exception:
                        if self._shutdown_requested.is_set():
                            # Connection closed during shutdown — implicit rollback đã xảy ra
                            return
                        raise
            except BaseException:
                if is_outer:
                    try:
                        self._conn.execute("ROLLBACK")
                    except Exception:
                        pass  # Connection closed during shutdown — implicit rollback
                raise
        finally:
            self._tx_depth -= 1
            self._tx_lock.release()

    @contextlib.asynccontextmanager
    async def transaction_async(self, immediate: bool = True):
        """Public API cho write transactions (async, reentrant). Default IMMEDIATE.

        Đối ứng async của ``transaction(immediate)``. Cùng nguyên tắc backward compat:
        default IMMEDIATE; opt-in DEFERRED qua ``transaction_async(immediate=False)``.

        Args:
            immediate: True → ``BEGIN IMMEDIATE``; False → ``BEGIN DEFERRED``.

        Yields:
            sqlite3.Connection đã bắt đầu transaction.
        """
        async with self._scoped_transaction_async(immediate=immediate) as conn:
            yield conn

    @contextlib.asynccontextmanager
    async def get_connection_async(self):
        """Async wrapper cho get_connection() — chạy toàn bộ lock/tx trên cùng một thread.

        Hardcode IMMEDIATE (giữ signature cũ). Caller async cần DEFERRED PHẢI dùng
        ``transaction_async(immediate=False)``.

        Thay vì dùng threading.RLock qua nhiều asyncio.to_thread (có thể dispatch
        acquire/release sang thread khác nhau), chạy BEGIN/COMMIT/ROLLBACK đồng bộ
        trên main thread (SQLite connection đã check_same_thread=False).
        Async safety đảm bảo bởi threading.RLock acquire/release trên cùng thread gọi.

        Reentrant: nếu đã trong transaction → reuse.

        Yields:
            sqlite3.Connection đã bắt đầu transaction.

        Raises:
            DatabaseError: Nếu engine đã closed hoặc đang shutdown.
        """
        async with self._scoped_transaction_async(immediate=True) as conn:
            yield conn

    @contextlib.asynccontextmanager
    async def _scoped_transaction_async(self, *, immediate: bool):
        """Internal async helper — implement reentrant transaction lifecycle.

        Mirror logic của ``_scoped_transaction`` cho async path. Single shared
        connection (``check_same_thread=False``); RLock acquire/release đảm bảo
        nested call cùng thread reentrant.

        Args:
            immediate: True → ``BEGIN IMMEDIATE``; False → ``BEGIN DEFERRED``.
                Chỉ ảnh hưởng outer scope (nested call ignore flag này).
        """
        if self._closed or self._shutdown_requested.is_set():
            raise DatabaseError("Engine is closed")

        self._tx_lock.acquire()
        is_outer = self._tx_depth == 0
        self._tx_depth += 1
        try:
            if is_outer:
                self._conn.execute(self._begin_command(immediate))
            try:
                yield self._conn
                if is_outer:
                    try:
                        self._conn.execute("COMMIT")
                    except Exception:
                        if self._shutdown_requested.is_set():
                            return
                        raise
            except BaseException:
                if is_outer:
                    try:
                        self._conn.execute("ROLLBACK")
                    except Exception:
                        pass
                raise
        finally:
            self._tx_depth -= 1
            self._tx_lock.release()

    def raw_connection(self) -> sqlite3.Connection:
        """Trả về thread-local read connection cho read-only operations.

        Mỗi thread tự open connection riêng (lazy). Trong WAL mode, multi-reader
        có thể chạy song song KHÔNG bị block bởi writer (writer dùng self._conn
        shared cho transaction). Nhờ đó frontend GET /profiles, /emails không
        bị stuck "Loading..." khi HmeRunner / AutoRegRunner đang write.

        Caller KHÔNG được dùng để write — dùng get_connection() / transaction()
        cho writes (vẫn share self._conn để giữ tx_lock semantics).

        Returns:
            sqlite3.Connection thread-local, read-only mode (PRAGMA query_only=ON).
        """
        if self._closed or self._shutdown_requested.is_set():
            raise DatabaseError("Engine is closed")

        conn = getattr(self._read_locals, "conn", None)
        if conn is not None:
            return conn

        conn = sqlite3.connect(
            str(self._db_path),
            check_same_thread=False,
            isolation_level=None,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        # KHÔNG set query_only=ON vì 1 số test legacy dùng raw_connection() để
        # UPDATE. Read-only contract enforce qua convention (caller chỉ SELECT).
        self._read_locals.conn = conn
        with self._read_conns_lock:
            self._read_conns.append(conn)
        return conn

    @property
    def in_transaction(self) -> bool:
        """True nếu đang trong write transaction (tx_depth > 0)."""
        return self._tx_depth > 0

    @property
    def is_closed(self) -> bool:
        """True nếu engine đã được close."""
        return self._closed

    @property
    def db_path(self) -> Path:
        """Path tới database file."""
        return self._db_path

    async def run_sync(self, fn):
        """Execute sync function trong thread pool — không block event loop.

        Dùng cho async callers cần gọi repository methods (sync) mà không block.
        Toàn bộ fn() (bao gồm lock acquire, BEGIN, execute, COMMIT, release)
        chạy trên 1 worker thread.

        Args:
            fn: Callable không nhận argument, trả về kết quả.

        Returns:
            Kết quả của fn().

        Raises:
            Bất kỳ exception nào fn() raise.
        """
        import asyncio
        return await asyncio.to_thread(fn)

    def close(self, timeout: float = 5.0) -> None:
        """Graceful shutdown: đợi in-flight transactions hoàn tất, rồi close connection.

        1. Set _shutdown_requested event để ngăn transactions mới.
        2. Set _closed = True.
        3. Acquire lock (đợi in-flight transaction commit/rollback) với timeout.
        4. Nếu timeout: close connection trực tiếp (sqlite3 implicit rollback on close).
        5. Close connection.

        Args:
            timeout: Max seconds đợi in-flight transactions hoàn tất.
                     Sau timeout → close connection (triggers implicit rollback).
        """
        self._shutdown_requested.set()
        self._closed = True

        # Đợi in-flight transaction hoàn tất bằng cách acquire lock
        acquired = self._tx_lock.acquire(timeout=timeout)

        # Close connection — nếu transaction đang pending, sqlite3 implicit rollback.
        # Không force ROLLBACK qua execute() từ thread ngoài (gây race condition).
        try:
            self._conn.close()
        except Exception:
            pass
        # Close all thread-local read connections
        with self._read_conns_lock:
            for rc in self._read_conns:
                try:
                    rc.close()
                except Exception:
                    pass
            self._read_conns.clear()
        if acquired:
            self._tx_lock.release()
