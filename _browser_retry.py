"""Shared utilities cho browser launch retry — dùng bởi browser_phase + session_phase.

Lý do tách module: lỗi `Page.goto: Connection closed while reading from the driver`
xảy ra ở cả 2 phase (signup + get_session), pattern xử lý giống nhau:
  - Detect lỗi driver pipe đóng sớm (transient)
  - Retry launch với profile sạch
  - Fail-fast nếu lỗi non-transient hoặc đã pass mốc check-point quan trọng

Không phụ thuộc playwright/camoufox — chỉ phân tích error message.
"""
from __future__ import annotations

from urllib.parse import urlparse


# Số lần thử lại launch khi driver pipe đóng sớm.
LAUNCH_RETRY_MAX = 2

# Backoff giữa các retry (seconds).
LAUNCH_RETRY_BACKOFF = 2.0

BROWSER_ENGINE_ORDER: tuple[str, ...] = ("camoufox", "chromium", "chrome")


def browser_launch_order(preferred: str | None) -> tuple[str, ...]:
    """Return a deterministic browser fallback order."""
    normalized = (preferred or BROWSER_ENGINE_ORDER[0]).strip().casefold()
    normalized = {
        "playwright": "chromium",
        "chrome-stable": "chrome",
    }.get(normalized, normalized)
    if normalized not in BROWSER_ENGINE_ORDER:
        allowed = ", ".join(BROWSER_ENGINE_ORDER)
        raise ValueError(
            f"Unsupported browser engine {preferred!r}; expected one of: {allowed}"
        )
    return (
        normalized,
        *(engine for engine in BROWSER_ENGINE_ORDER if engine != normalized),
    )


LAUNCH_FAILURE_MARKERS: tuple[str, ...] = (
    "executable doesn't exist",
    "executable does not exist",
    "browser distribution",
    "chromium distribution",
    "could not find browser",
    "failed to launch",
    "browser version",
    "browser_type.launch",
    "browsertype.launch",
    "playwright install",
    "camoufox is not installed",
    "camoufoxnotinstalled",
    "no module named 'camoufox",
    "no module named 'playwright",
)


def is_browser_launch_error(exc: BaseException | None) -> bool:
    """Return True for a missing/failed browser binary or driver package."""
    if exc is None:
        return False
    message = str(exc).casefold()
    return any(marker in message for marker in LAUNCH_FAILURE_MARKERS)

# Patterns nhận biết lỗi driver pipe / browser process chết.
# Đây là lỗi transient — retry launch sạch lại profile thường thoát.
DRIVER_DEAD_MARKERS: tuple[str, ...] = (
    "Connection closed while reading from the driver",
    "Target page, context or browser has been closed",
    "Browser closed",
    "Browser has been closed",
    "Target closed",
    "Transport closed",
    "Page closed",
    "BrowserContext has been closed",
    "has been closed",
)


NETWORK_ERROR_MARKERS: tuple[str, ...] = (
    # Playwright / Chromium / Firefox markers
    "NS_ERROR_PROXY_CONNECTION_REFUSED",
    "NS_ERROR_CONNECTION_REFUSED",
    "NS_ERROR_NET_TIMEOUT",
    "NS_ERROR_NET_RESET",
    "NS_ERROR_NET_INTERRUPT",
    "NS_ERROR_UNKNOWN_PROXY_HOST",
    "ERR_PROXY_CONNECTION_FAILED",
    "ERR_CONNECTION_REFUSED",
    "ERR_CONNECTION_RESET",
    "ERR_CONNECTION_TIMED_OUT",
    "ERR_TUNNEL_CONNECTION_FAILED",
    "net::ERR_PROXY",
    # curl_cffi / libcurl markers (luồng HTTP API qua proxy — Stripe/GoPay/session)
    # Các curl error code mang nghĩa network/proxy không kết nối được:
    #   (7) couldn't connect, (28) timeout, (35) TLS connect error qua proxy chết,
    #   (56) recv failure, (97) proxy CONNECT aborted.
    "curl: (7)",
    "curl: (28)",
    "curl: (35)",
    "curl: (56)",
    "curl: (97)",
    "TLS connect error",
    "Connection refused",
    "Could not connect to proxy",
    "Failed to connect to",
    # httpx markers (proxy probe + fallback path)
    "ConnectError",
    "ConnectTimeout",
    "ProxyError",
)


def is_navigation_abort_error(exc: BaseException | None) -> bool:
    """Return True for a narrowly-scoped Firefox/Playwright navigation abort.

    Firefox may report a redirect or a detached navigation as
    ``NS_BINDING_ABORTED``.  Treat it as retryable only when the message also
    identifies a navigation/``Page.goto`` operation; the same marker from an
    unrelated request must not trigger a browser relaunch.
    """
    if exc is None:
        return False
    message = str(exc).casefold()
    if "page.goto" not in message and "navigation" not in message:
        return False
    return (
        "ns_binding_aborted" in message
        or "frame was detached" in message
        or "maybe frame was detached" in message
    )


def is_execution_context_destroyed_error(exc: BaseException | None) -> bool:
    """Nhận diện race ``Page.evaluate`` bị navigation thay document.

    Browser/context vẫn có thể còn sống; đây không phải driver-dead. Chỉ coi là
    retryable khi error đồng thời nói rõ execution context bị hủy và liên quan
    tới ``Page.evaluate``/navigation để không che các lỗi JavaScript nghiệp vụ.
    """
    if exc is None:
        return False
    message = str(exc).casefold()
    return (
        "execution context was destroyed" in message
        and ("page.evaluate" in message or "navigation" in message)
    )


def is_driver_dead_error(exc: BaseException | None) -> bool:
    """Return True nếu exc là lỗi driver/browser pipe chết (transient)."""
    if exc is None:
        return False
    msg = str(exc)
    return any(marker in msg for marker in DRIVER_DEAD_MARKERS)


def is_network_error(exc: BaseException | None) -> bool:
    """Return True nếu exc là lỗi proxy/network transient (retry-worthy)."""
    if exc is None:
        return False
    msg = str(exc)
    return any(marker in msg for marker in NETWORK_ERROR_MARKERS)


def is_navigation_timeout(exc: BaseException | None) -> bool:
    """Return True nếu exc là Playwright navigation timeout (retry-worthy trước OTP).

    Pattern: 'TimeoutError: Page.goto: Timeout 60000ms exceeded'
    Đây là lỗi transient — server chậm respond, proxy lag, hoặc redirect chain dài.
    Safe để retry nếu flow chưa trigger OTP.
    """
    if exc is None:
        return False
    cls_name = type(exc).__name__
    if cls_name != "TimeoutError":
        return False
    msg = str(exc)
    return "Page.goto" in msg and "Timeout" in msg


def parse_proxy_for_playwright(proxy_url: str) -> dict[str, str]:
    """Parse proxy URL → Playwright proxy dict với credentials tách riêng.

    Playwright/Camoufox KHÔNG parse inline credentials từ URL.
    http://user:pass@host:port → {"server": "http://host:port", "username": ..., "password": ...}
    """
    parsed = urlparse(proxy_url)
    if parsed.scheme in {"socks5", "socks5h"} and (parsed.username or parsed.password):
        raise ValueError(
            "Authenticated SOCKS proxies are not supported by the browser path. "
            "Run test/socks5h_http_bridge.py and pass the local http://127.0.0.1:<port> proxy instead."
        )
    server = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port:
        server += f":{parsed.port}"
    result: dict[str, str] = {"server": server}
    if parsed.username:
        result["username"] = parsed.username
    if parsed.password:
        result["password"] = parsed.password
    return result
