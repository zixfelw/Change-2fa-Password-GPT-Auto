"""Database package — SQLite persistence layer.

Exports:
    get_engine: Factory function trả về DatabaseEngine singleton.
    get_repos: Factory function trả về tuple repositories.
    get_settings_repo: Factory function trả về SettingsRepository instance.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .engine import DatabaseEngine
    from .repositories import (
        ComboRepository,
        JobRepository,
        SessionResultRepository,
        SettingsRepository,
    )


_engine_singleton: "DatabaseEngine | None" = None


def get_engine(db_path: str | None = None) -> "DatabaseEngine":
    """Trả về DatabaseEngine singleton.

    Tạo instance lần đầu, lần gọi sau trả cùng instance (share connection/lock).
    Nếu db_path khác với instance hiện tại → raise (tránh mở 2 connection cùng file).

    Resolution order:
        1. Tham số ``db_path`` (caller chỉ định).
        2. Env ``GSH_DB_PATH`` (override cho test/dev/CI).
        3. Default ``runtime/data.db``.

    Args:
        db_path: Đường dẫn tới SQLite file. None = đọc env hoặc default.
    """
    global _engine_singleton  # noqa: PLW0603
    import os
    from pathlib import Path

    from .engine import DatabaseEngine

    resolved_path = db_path or os.environ.get("GSH_DB_PATH") or "runtime/data.db"
    if _engine_singleton is not None:
        if not _engine_singleton.is_closed:
            # So sánh resolved path — tránh ghi nhầm DB khác trong cùng process
            existing_resolved = _engine_singleton.db_path.resolve()
            new_resolved = Path(resolved_path).resolve()
            if existing_resolved != new_resolved:
                raise RuntimeError(
                    f"DatabaseEngine singleton đã mở cho '{existing_resolved}', "
                    f"không thể mở thêm '{new_resolved}' trong cùng process. "
                    f"Gọi engine.close() trước hoặc dùng cùng db_path."
                )
            return _engine_singleton
        # Engine đã close → tạo mới
        _engine_singleton = None
    _engine_singleton = DatabaseEngine(db_path=resolved_path)
    return _engine_singleton


def get_repos(
    engine: "DatabaseEngine",
) -> tuple["ComboRepository", "JobRepository", "SessionResultRepository"]:
    """Tạo và trả về tuple (ComboRepository, JobRepository, SessionResultRepository).

    Args:
        engine: DatabaseEngine instance đã khởi tạo.
    """
    from .repositories import (
        ComboRepository,
        JobRepository,
        SessionResultRepository,
    )

    return (
        ComboRepository(engine),
        JobRepository(engine),
        SessionResultRepository(engine),
    )


def get_settings_repo(engine: "DatabaseEngine") -> "SettingsRepository":
    """Tạo và trả về SettingsRepository instance.

    Args:
        engine: DatabaseEngine instance đã khởi tạo.
    """
    from .repositories import SettingsRepository

    return SettingsRepository(engine)
