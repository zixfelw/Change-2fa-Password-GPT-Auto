"""Windows Chrome browser persona — single source of truth cho mọi flow reg/request.

Mục đích:
    Đồng bộ User-Agent + sec-ch-ua family + TLS fingerprint + browser persona
    giữa Phase 1 (browser_phase.py — Camoufox), Phase 2 (request_phase.py /
    session_phase.py — curl_cffi) và Sentinel (PoW + QuickJS).

    Trước refactor mỗi module hardcode UA khác nhau (Mac Chrome 136 / Windows
    Chrome 145 / Mac Firefox 135) → fingerprint mismatch giữa các tầng cùng 1
    reg, anti-bot OpenAI có thể flag (biểu hiện: 200 OK nhưng OTP không gửi).

Quy tắc khi nâng version:
    1. Sửa CHROME_MAJOR (string).
    2. Đảm bảo curl_cffi hiện hành có ``chrome{MAJOR}`` impersonate token
       (kiểm tra: ``BrowserType`` enum trong curl_cffi.requests.impersonate).
       Nếu không có → giữ MAJOR mới nhất mà curl_cffi support, fallback về
       version cũ hơn cùng family.
    3. KHÔNG hardcode ngoài file này. Tất cả module khác phải import.

Tham khảo:
    - sec-ch-ua format: https://wicg.github.io/ua-client-hints/
    - curl_cffi browser impersonation: https://github.com/lexiforest/curl_cffi
    - Camoufox OS pinning: AsyncCamoufox(os=["windows"]) → pin navigator.platform,
      WebGL renderer, fonts, screen properties theo Windows persona.
"""
from __future__ import annotations

# ─── Chrome version (single knob) ─────────────────────────────────────

CHROME_MAJOR = "145"
"""Chrome major version. Chrome stable Windows desktop phổ biến (≥30% desktop
traffic). Đồng bộ giữa UA, sec-ch-ua, sentinel sdk emulation, và TLS fingerprint."""

CHROME_FULL = f"{CHROME_MAJOR}.0.0.0"
"""Chrome full version theo format Mozilla UA. Chrome luôn dùng patch=0.0.0
trong UA string (greaseing) — không reveal patch level."""


# ─── HTTP User-Agent ──────────────────────────────────────────────────

WINDOWS_USER_AGENT = (
    f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    f"AppleWebKit/537.36 (KHTML, like Gecko) "
    f"Chrome/{CHROME_FULL} Safari/537.36"
)
"""User-Agent string Windows 10/11 desktop x64 Chrome stable.

Windows NT 10.0 cover cả Win10 và Win11 (Microsoft không bump NT version cho
Win11) → match >95% Windows desktop trên thực tế."""


# ─── Client Hints (sec-ch-ua family) ──────────────────────────────────

SEC_CH_UA = (
    f'"Chromium";v="{CHROME_MAJOR}", '
    f'"Google Chrome";v="{CHROME_MAJOR}", '
    f'"Not_A Brand";v="24"'
)
"""sec-ch-ua header — brand list theo GREASE spec.

Format Chrome thực tế gửi: 3 brand (Chromium / Google Chrome / GREASE brand).
Chromium rotate greasing brand qua các major version để force ecosystem handle
unknown brand gracefully. Chrome >= 130 dùng các giá trị: ``"Not_A Brand";v="24"``,
``"Not?A_Brand";v="24"``, ``"Not(A:Brand";v="8"``. Trước Chrome 117 từng dùng
``"Not.A/Brand";v="99"`` — đã obsolete.

Server (OpenAI sentinel + cloudfront) KHÔNG validate brand string cụ thể, chỉ
check 3 brand đều có và Chromium/Google Chrome version match. Giá trị greasing
chỉ ảnh hưởng anti-bot heuristic phân loại Chrome version range."""

SEC_CH_UA_MOBILE = "?0"
"""Desktop, không phải mobile."""

SEC_CH_UA_PLATFORM = '"Windows"'
"""Platform name. Phải bọc trong dấu nháy kép theo spec sec-ch-ua."""

SEC_CH_UA_PLATFORM_VERSION = '"15.0.0"'
"""Platform version cho Windows 11. Win10=10.0.0, Win11=15.0.0 (ư cầu API
GetHighEntropyValues — Microsoft map Win11 thành major 15+).

Chỉ dùng khi server gửi Accept-CH yêu cầu sec-ch-ua-platform-version (low
entropy hint, browser tự gửi nếu site có Critical-CH header)."""


def common_chrome_headers(*, referer: str = "https://chatgpt.com/") -> dict[str, str]:
    """Header tối thiểu Chrome desktop gửi cho mọi same-origin request.

    Bao gồm UA + 3 sec-ch-ua headers low-entropy (browser thật gửi mặc định
    không cần Accept-CH). KHÔNG bao gồm sec-fetch-* (caller tự thêm theo
    context request).

    Args:
        referer: URL referer. Origin được suy ra từ scheme+netloc.

    Returns:
        dict[str, str] — đủ key để merge vào headers request.
    """
    return {
        "User-Agent": WINDOWS_USER_AGENT,
        "sec-ch-ua": SEC_CH_UA,
        "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": referer,
    }


# ─── curl_cffi TLS fingerprint ────────────────────────────────────────

CURL_IMPERSONATE_PRIMARY = "chrome145"
"""Token impersonate chính. TLS hello + HTTP/2 settings + header order khớp
Chrome 145 trên Windows."""

CURL_IMPERSONATE_FALLBACK: tuple[str, ...] = ("chrome142", "chrome136")
"""Fallback chain khi TLS handshake error (curl: 35/56/7/handshake).

Thứ tự: cùng family Chrome, version giảm dần. Phải tồn tại trong curl_cffi
``BrowserType`` enum. KHÔNG fallback sang firefox/safari — sẽ làm UA ↔ TLS
mismatch."""

CURL_IMPERSONATE_CANDIDATES: tuple[str, ...] = (
    CURL_IMPERSONATE_PRIMARY,
    *CURL_IMPERSONATE_FALLBACK,
)
"""Full chain dùng cho TLS rotation: primary → fallback."""


# ─── Camoufox browser persona ─────────────────────────────────────────

CAMOUFOX_OS: tuple[str, ...] = ("windows",)
"""Pin Camoufox persona OS = Windows. Khi pass vào ``AsyncCamoufox(os=...)``
sẽ force navigator.platform="Win32", WebGL renderer "ANGLE Windows", screen
properties Windows desktop, và font list Windows."""


# ─── Sentinel sdk.js emulated navigator ───────────────────────────────

NAVIGATOR_LANGUAGE = "en-US"
NAVIGATOR_LANGUAGES: tuple[str, ...] = ("en-US", "en")
HARDWARE_CONCURRENCY = 12
"""logical core count. 12 = CPU 6c/12t (Win desktop / laptop tầm trung phổ
biến nhất trên Steam HW Survey + StatCounter)."""

DEVICE_MEMORY_GB = 8
"""navigator.deviceMemory rounded value. 8GB là mode phổ biến nhất."""


def _parse_brands_from_sec_ch_ua(value: str) -> list[dict[str, str]]:
    """Parse SEC_CH_UA string thành list ``[{"brand", "version"}]``.

    Input format: ``'"Brand A";v="1", "Brand B";v="2", ...'``
    """
    out: list[dict[str, str]] = []
    for chunk in value.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        # Pattern: "Brand";v="version"
        try:
            brand_part, ver_part = chunk.split(";", 1)
            brand = brand_part.strip().strip('"')
            ver = ver_part.split("=", 1)[1].strip().strip('"')
            out.append({"brand": brand, "version": ver})
        except (ValueError, IndexError):
            continue
    return out


def sentinel_navigator_payload() -> dict[str, object]:
    """Payload bổ sung pass cho ``openai_sentinel_quickjs.js`` (sdk.js context).

    JS file đọc payload để build ``navigator`` + ``navigator.userAgentData`` (Chrome
    90+ Client Hints API). Trước refactor caller không pass → fallback
    ``"Mozilla/5.0"`` + userAgentData=undefined → fingerprint sdk.js cực kỳ generic
    và bất thường (browser thật luôn có userAgentData).

    Bao gồm:
        - user_agent string (navigator.userAgent)
        - language / languages (navigator.language(s))
        - hardware_concurrency / device_memory
        - sec_ch_ua_brands (navigator.userAgentData.brands)
        - sec_ch_ua_mobile / platform / platform_version (high-entropy hints)
    """
    return {
        "user_agent": WINDOWS_USER_AGENT,
        "language": NAVIGATOR_LANGUAGE,
        "languages": list(NAVIGATOR_LANGUAGES),
        "hardware_concurrency": HARDWARE_CONCURRENCY,
        "device_memory": DEVICE_MEMORY_GB,
        # Client Hints — phải khớp với header sec-ch-ua* gửi cùng request.
        "sec_ch_ua_brands": _parse_brands_from_sec_ch_ua(SEC_CH_UA),
        "sec_ch_ua_mobile": False,  # SEC_CH_UA_MOBILE = "?0"
        "sec_ch_ua_platform": "Windows",
        "sec_ch_ua_platform_version": "15.0.0",
        "sec_ch_ua_arch": "x86",
        "sec_ch_ua_bitness": "64",
        "sec_ch_ua_model": "",
    }


__all__ = [
    "CHROME_MAJOR",
    "CHROME_FULL",
    "WINDOWS_USER_AGENT",
    "SEC_CH_UA",
    "SEC_CH_UA_MOBILE",
    "SEC_CH_UA_PLATFORM",
    "SEC_CH_UA_PLATFORM_VERSION",
    "common_chrome_headers",
    "CURL_IMPERSONATE_PRIMARY",
    "CURL_IMPERSONATE_FALLBACK",
    "CURL_IMPERSONATE_CANDIDATES",
    "CAMOUFOX_OS",
    "NAVIGATOR_LANGUAGE",
    "NAVIGATOR_LANGUAGES",
    "HARDWARE_CONCURRENCY",
    "DEVICE_MEMORY_GB",
    "sentinel_navigator_payload",
]
