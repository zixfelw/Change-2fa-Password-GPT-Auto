"""Cô lập cache Camoufox của ứng dụng để dự án khác không đổi active build."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


_CACHE_HOME_MARKER = "GSH_CAMOUFOX_CACHE_HOME"


def _cache_home(root_dir: Path) -> Path:
    return root_dir.resolve() / "runtime" / "camoufox-cache"


def _platform_cache_override() -> str:
    # platformdirs trên Windows ưu tiên Known Folder API, nên LOCALAPPDATA không
    # đủ để override. WIN_PD_OVERRIDE_* là override chính thức của platformdirs.
    if sys.platform.startswith("win"):
        return "WIN_PD_OVERRIDE_LOCAL_APPDATA"
    return "XDG_CACHE_HOME"


def _camoufox_cache_dir() -> Path:
    from platformdirs import user_cache_dir

    return Path(user_cache_dir("camoufox"))


def _pinned_spec(root_dir: Path) -> str | None:
    spec_files = [root_dir / "camoufox-browser-spec.txt"]
    bundled_root = getattr(sys, "_MEIPASS", None)
    if bundled_root:
        spec_files.append(Path(bundled_root) / "camoufox-browser-spec.txt")
    for spec_file in spec_files:
        if not spec_file.is_file():
            continue
        entries = [
            line.strip().lower()
            for line in spec_file.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        if len(entries) == 1:
            return entries[0]
    return None


def _restore_pinned_active_version(root_dir: Path) -> bool:
    """Chọn lại build đã ghim nếu cache cũ chứa config bị dự án khác đổi."""
    expected_spec = _pinned_spec(root_dir)
    if expected_spec is None:
        return False
    try:
        from camoufox.multiversion import list_installed, set_active
    except ImportError:
        return False

    for installed in list_installed():
        if installed.channel_path.lower() == expected_spec:
            if not installed.is_active:
                set_active(installed.relative_path)
            return True
    return False


def _install_pinned_browser(root_dir: Path) -> None:
    expected_spec = _pinned_spec(root_dir)
    if expected_spec is None:
        return
    print(f"[camoufox] Pinned browser {expected_spec} is missing; restoring once...")
    subprocess.run(
        [sys.executable, "-m", "camoufox", "fetch", expected_spec],
        check=False,
    )
    if not _restore_pinned_active_version(root_dir):
        raise RuntimeError(
            "Camoufox auto-restore failed. Check the Internet connection and restart the application."
        )


def configure_camoufox_cache(root_dir: Path) -> Path:
    """Dùng cache Camoufox riêng trong ``runtime/``.

    Camoufox lưu active browser trong user cache toàn máy. Cache dự án cô lập
    build ghim khỏi các project khác. Trên Windows không copy/rename cache cũ:
    antivirus hoặc indexer có thể lock directory khi rename. Một cache sạch sẽ
    được khôi phục bằng browser version ghim ở lần khởi động đầu tiên.
    """
    cache_home = _cache_home(root_dir)
    if os.environ.get(_CACHE_HOME_MARKER):
        return _camoufox_cache_dir()

    override_name = _platform_cache_override()
    os.environ[override_name] = str(cache_home)
    os.environ[_CACHE_HOME_MARKER] = str(cache_home)
    project_cache = _camoufox_cache_dir()
    project_cache.mkdir(parents=True, exist_ok=True)

    resolved_root = root_dir.resolve()
    if not _restore_pinned_active_version(resolved_root):
        _install_pinned_browser(resolved_root)
    return project_cache
