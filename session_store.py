"""Session cache file-based, cô lập theo instance (db stem).

LEAF module: chỉ stdlib + ``config.runtime_dir`` (lazy). KHÔNG import web/*, db/*,
session_phase → import được từ mọi nơi (manager, server, upi_runner, probe
scripts) mà không tạo circular import.

Mỗi account 1 file ``<runtime_dir>/session_cache/<instance_id>/<slug>-<hash>.json``:
- ``instance_id`` = stem của DB path (GSH_DB_PATH / engine.db_path) → nhiều web
  chạy song song (--db khác nhau) không đè cache của nhau.
- ``<slug>-<hash>``: slug để người đọc nhận diện + hash sha256(email) để chống
  đụng tên (1355/1370 email chứa '+' → slug map '+'→'_' dễ trùng).
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any


# Tên cookie NextAuth session-token (split .0/.1 khi quá dài). Nguồn chân lý
# DUY NHẤT cho "cookie này reuse-được" — dùng bởi seed + reuse-gate.
SESSION_TOKEN_COOKIE_NAMES: tuple[str, ...] = (
    "__Secure-next-auth.session-token",
    "__Secure-next-auth.session-token.0",
)


def safe_email_slug(email: str) -> str:
    """Email → tên file an toàn (giữ chữ/số/._-@, ký tự khác → _)."""
    return "".join(c if (c.isalnum() or c in "._-@") else "_" for c in email) or "unknown"


def has_session_token(cookies: Any) -> bool:
    """True nếu list cookie có chứa NextAuth session-token (⇒ reuse-được)."""
    if not isinstance(cookies, list):
        return False
    for c in cookies:
        if isinstance(c, dict) and c.get("name") in SESSION_TOKEN_COOKIE_NAMES and c.get("value"):
            return True
    return False


def session_token_from_cookies(cookies: Any) -> str | None:
    """Trích value của cookie session-token (R4.6) — `/api/auth/session` JSON
    không có field này, phải lấy từ cookie."""
    if not isinstance(cookies, list):
        return None
    for c in cookies:
        if isinstance(c, dict) and c.get("name") in SESSION_TOKEN_COOKIE_NAMES and c.get("value"):
            return c.get("value")
    return None


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def resolve_instance_id(db_path: str | os.PathLike[str] | None = None) -> str:
    """Instance_Id = stem của db path. Ưu tiên ``db_path`` tường minh (engine),
    else env ``GSH_DB_PATH``, else ``"data"``."""
    raw = str(db_path) if db_path else (os.environ.get("GSH_DB_PATH") or "data")
    return Path(raw).stem or "data"


def _default_runtime_dir() -> Path:
    from config import load_settings  # lazy: giữ session_store là leaf
    return load_settings().runtime_dir


class SessionStore:
    """File cache session/cookie 1 account, cô lập theo instance.

    DI: ``instance_id`` + ``runtime_dir`` inject lúc khởi tạo (testable). Default
    factory resolve từ engine db path / env ``GSH_DB_PATH``.
    """

    def __init__(
        self,
        *,
        instance_id: str | None = None,
        runtime_dir: Path | None = None,
    ) -> None:
        self._instance_id = instance_id or resolve_instance_id()
        self._runtime_dir = Path(runtime_dir) if runtime_dir else _default_runtime_dir()
        self._cache_dir = self._runtime_dir / "session_cache" / self._instance_id
        self._locks: dict[str, asyncio.Lock] = {}

    @property
    def instance_id(self) -> str:
        return self._instance_id

    @property
    def cache_dir(self) -> Path:
        return self._cache_dir

    def _path_for(self, email: str) -> Path:
        h = hashlib.sha256(email.encode("utf-8")).hexdigest()[:12]
        return self._cache_dir / f"{safe_email_slug(email)}-{h}.json"

    def lock_for(self, email: str) -> asyncio.Lock:
        """asyncio.Lock per-(instance,email) — tuần tự hoá read-modify-write +
        chống 2 job cùng email login song song trong 1 instance."""
        key = self._path_for(email).name
        lock = self._locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[key] = lock
        return lock

    def load(self, email: str) -> dict | None:
        """Đọc record. Fail-soft: file thiếu/hỏng → None. Guard email-mismatch
        (R12.3): record.email != email → None (không trả nhầm account)."""
        path = self._path_for(email)
        try:
            raw = path.read_text(encoding="utf-8")
        except (FileNotFoundError, OSError):
            return None
        try:
            rec = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return None
        if not isinstance(rec, dict) or rec.get("email") != email:
            return None
        return rec

    def save(self, email: str, record: dict) -> Path:
        """Atomic write (tmp + replace), chmod 0600. Ép ``email`` khớp file để
        guard load luôn đúng. Latest-wins (1 file/email/instance)."""
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        path = self._path_for(email)
        payload = {**record, "email": email}
        tmp = path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass  # FS không hỗ trợ chmod (vd Windows) → best-effort
        tmp.replace(path)
        return path

    def delete(self, email: str) -> bool:
        """Xoá record. True nếu xoá được, False nếu không tồn tại / lỗi FS."""
        try:
            self._path_for(email).unlink()
            return True
        except (FileNotFoundError, OSError):
            return False
