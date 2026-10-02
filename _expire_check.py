"""Expire enforcement với chống tua giờ — chạy ngay khi exe khởi động.

Hằng số ``BUILD_TIME`` và ``EXPIRES_AT`` được module ``_expire_const`` cung cấp,
generate tại build time (xem ``scripts/build_exe.py``). Khi chạy từ source (dev
mode), ``_expire_const`` không tồn tại → bypass check (return ngay).

Strategy chống tua giờ (defense-in-depth, không yêu cầu internet):

1. Sanity check: ``time.time() < BUILD_TIME`` → user đã tua máy về quá khứ →
   exit. Không có cách hợp lệ nào để machine clock < build time của exe.

2. Local hard-cap: ``time.time() > EXPIRES_AT`` → hết hạn → exit.

3. Last-seen ratchet: lưu max(``time.time()``, online_time) qua mỗi lần app
   start vào file ẩn ``%LOCALAPPDATA%/GSH/.state`` (Windows) hoặc
   ``~/.gsh_state`` (mac/linux). Lần start kế nếu ``time.time() < last_seen
   - GRACE`` → user đã tua lùi sau khi đã chạy app trước đó → exit. GRACE để
   tolerance NTP drift / DST.

4. Online time best-effort: thử HTTP HEAD ``https://www.google.com`` (timeout
   3s), parse ``Date`` header. Nếu fetch thành công và lệch local > 5 phút →
   trust online → re-check expiry với online time. Offline → fail-open (chỉ
   dựa vào local + ratchet).

UX khi block: in thông báo rõ + sys.exit(2). Không silent.
"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

# Tolerance cho NTP drift / DST shift / quick reboot khi so sánh ratchet.
# 1 giờ — đủ tolerance UX + đủ chặt chống tua giờ thẳng tay.
_RATCHET_GRACE_SECONDS = 3600

# Lệch local vs online nếu vượt → coi local đã bị tampered.
_ONLINE_VS_LOCAL_MAX_DRIFT = 300  # 5 phút

# Online check — timeout ngắn để không block startup.
_ONLINE_TIMEOUT = 3.0

_HEADER_DATE_HOSTS = (
    "https://www.google.com",
    "https://www.cloudflare.com",
    "https://www.microsoft.com",
)


def _state_file_path() -> Path:
    """File lưu last-seen timestamp. Đặt cùng vị trí app data, không phải cwd
    (cwd có thể là USB / read-only / khác mỗi lần chạy).
    """
    if sys.platform.startswith("win"):
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or str(Path.home())
        return Path(base) / "GSH" / ".state"
    return Path.home() / ".gsh_state"


def _read_last_seen() -> int:
    """Đọc last-seen unix timestamp. 0 nếu thiếu/lỗi (= first run, không enforce
    ratchet)."""
    try:
        path = _state_file_path()
        if not path.exists():
            return 0
        raw = path.read_text(encoding="ascii", errors="ignore").strip()
        if not raw.isdigit():
            return 0
        return int(raw)
    except (OSError, ValueError):
        return 0


def _write_last_seen(ts: int) -> None:
    """Ghi last-seen, best-effort. Lỗi IO KHÔNG crash app — chỉ làm yếu ratchet
    cho lần kế."""
    try:
        path = _state_file_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(int(ts)), encoding="ascii")
        # Hide trên Windows (best-effort, không fail nếu thiếu attrib)
        if sys.platform.startswith("win"):
            try:
                import ctypes
                FILE_ATTRIBUTE_HIDDEN = 0x02
                ctypes.windll.kernel32.SetFileAttributesW(str(path), FILE_ATTRIBUTE_HIDDEN)
            except Exception:  # noqa: BLE001
                pass
    except OSError:
        pass


def _fetch_online_time() -> int | None:
    """Best-effort fetch unix time từ HTTP ``Date`` header. Trả None nếu offline/
    fail. KHÔNG raise. Dùng stdlib urllib để không thêm dependency vào exe.
    """
    from email.utils import parsedate_to_datetime
    from urllib.request import Request, urlopen

    for url in _HEADER_DATE_HOSTS:
        try:
            req = Request(url, method="HEAD")
            with urlopen(req, timeout=_ONLINE_TIMEOUT) as resp:  # noqa: S310
                date_hdr = resp.headers.get("Date")
                if not date_hdr:
                    continue
                dt = parsedate_to_datetime(date_hdr)
                return int(dt.timestamp())
        except Exception:  # noqa: BLE001 — best-effort
            continue
    return None


def _block(reason: str) -> None:
    """In thông báo block + exit ngay. Code 2 để phân biệt với generic error
    (1) hoặc CTRL+C (130). Caller (build_exe orchestrator + GitHub Actions
    workflow) có thể bắt code này để retry / re-build với expire mới."""
    msg = (
        "\n"
        "════════════════════════════════════════════════════════════════\n"
        f"  Phiên bản hết hạn hoặc đồng hồ hệ thống không hợp lệ.\n"
        f"  Lý do: {reason}\n"
        "  Vui lòng liên hệ tác giả để nhận bản cập nhật.\n"
        "════════════════════════════════════════════════════════════════\n"
    )
    try:
        sys.stderr.write(msg)
    except Exception:  # noqa: BLE001
        pass
    # Cho user kịp đọc nếu app chạy qua double-click trên Windows.
    try:
        if sys.platform.startswith("win") and sys.stdin.isatty():
            input("Nhấn Enter để đóng...")
    except Exception:  # noqa: BLE001
        pass
    sys.exit(2)


def enforce_expiry() -> None:
    """Public entrypoint — gọi tại đầu app startup.

    Dev mode (chạy từ source): ``_expire_const`` không tồn tại → return ngay,
    không có overhead.

    Build mode (chạy từ exe): module được generate vào exe → enforce strict.
    """
    try:
        import _expire_const  # type: ignore[attr-defined]
    except ImportError:
        try:
            import _expire_const  # type: ignore[import-not-found]
        except ImportError:
            return  # dev mode — bypass

    build_time = int(getattr(_expire_const, "BUILD_TIME", 0))
    expires_at = int(getattr(_expire_const, "EXPIRES_AT", 0))
    if build_time <= 0 or expires_at <= 0:
        return  # const malformed → fail-open dev safety

    now = int(time.time())

    # 1. Sanity: now < BUILD_TIME (60s grace cho clock skew giữa CI và máy
    # khách). Lỗi rõ ràng = user tua quá xa quá khứ.
    if now < build_time - 60:
        _block(
            f"đồng hồ máy ({_fmt(now)}) sớm hơn thời điểm build ({_fmt(build_time)}). "
            "Có thể đồng hồ hệ thống bị chỉnh sai."
        )

    # 2. Hard-cap local
    if now > expires_at:
        _block(f"đã quá hạn sử dụng ({_fmt(expires_at)}).")

    # 3. Ratchet: nếu now < last_seen - GRACE → tua lùi sau khi đã chạy
    last_seen = _read_last_seen()
    if last_seen > 0 and now < last_seen - _RATCHET_GRACE_SECONDS:
        _block(
            f"đồng hồ máy ({_fmt(now)}) lùi quá xa so với phiên trước "
            f"({_fmt(last_seen)})."
        )

    # 4. Online time best-effort
    online_now = _fetch_online_time()
    if online_now is not None:
        # Lệch lớn → trust online (user có thể tua local nhưng online không
        # tua được).
        if abs(online_now - now) > _ONLINE_VS_LOCAL_MAX_DRIFT:
            if online_now > expires_at:
                _block(
                    f"đã quá hạn theo giờ chuẩn online ({_fmt(online_now)})."
                )
            if online_now < build_time - 60:
                _block(
                    f"giờ online ({_fmt(online_now)}) bất thường (sớm hơn build). "
                    "Network có thể bị MITM."
                )
        # Cập nhật ratchet với giá trị đáng tin nhất (max).
        _write_last_seen(max(now, online_now))
    else:
        # Offline → fail-open, vẫn ratchet với now.
        _write_last_seen(now)


def _fmt(ts: int) -> str:
    """Format unix → ISO local time."""
    try:
        from datetime import datetime
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:  # noqa: BLE001
        return str(ts)


__all__ = ["enforce_expiry"]
