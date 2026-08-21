"""OpenAI Sentinel Token — Python PoW fallback.

Adapted from https://github.com/Regert888/gpt-outlook-register (sentinel.py).
Implements FNV-1a 32-bit PoW to solve challenges from /sentinel/req.

This is the FALLBACK path. The primary path (sentinel_quickjs.py) runs OpenAI's
actual sdk.js in a Node subprocess and produces tokens that pass deep server-side
verification. This pure-Python path passes surface validation (200 OK) but OTP
dispatch may silent-drop. Use only when Node/QuickJS is unavailable.

Public API (matches sentinel_quickjs signature for drop-in):
    get_sentinel_token(session, device_id, flow) -> str
"""
from __future__ import annotations

import base64
import json
import logging
import random
import time
import uuid
from datetime import datetime, timezone

from user_agent_profile import (
    SEC_CH_UA as _SEC_CH_UA,
    WINDOWS_USER_AGENT as _WINDOWS_USER_AGENT,
)

logger = logging.getLogger(__name__)

SENTINEL_REQ_URL = "https://sentinel.openai.com/backend-api/sentinel/req"
SENTINEL_REFERER = "https://sentinel.openai.com/backend-api/sentinel/frame.html"
SENTINEL_SDK_URL = "https://sentinel.openai.com/sentinel/20260124ceb8/sdk.js"

# UA + sec-ch-ua đồng bộ với user_agent_profile (Windows + Chrome stable). Trước
# refactor sentinel hardcode Windows Chrome 145 trong khi request_phase hardcode
# Mac Chrome 136 → mismatch giữa sentinel ↔ register cho cùng device_id, anti-bot
# OpenAI có thể flag (200 OK nhưng OTP không gửi).
DEFAULT_UA = _WINDOWS_USER_AGENT
DEFAULT_SEC_CH_UA = _SEC_CH_UA

MAX_ATTEMPTS = 500_000
ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"

# Sentinel /req TLS recovery: curl_cffi/BoringSSL có thể corrupt state
# (`curl: (35) ... OPENSSL_internal:invalid library`) khi 1 Session đổi host
# (login dùng chatgpt.com/auth.openai.com, sentinel dùng sentinel.openai.com)
# hoặc khi nhiều job curl_cffi chạy đồng thời. Khi gặp lỗi này, retry trên
# Session TƯƠI (recreate clear corrupt context) — mirror `_RotatingSession`
# trong upi_runner. Bounded để không loop vô hạn.
_TLS_RETRY_MAX = 2


def _is_tls_library_error(exc: BaseException) -> bool:
    """True nếu exception là curl_cffi/BoringSSL TLS state corruption → worth
    recreate fresh session retry."""
    msg = str(exc).lower()
    markers = (
        "invalid library", "openssl_internal", "tls connect error",
        "curl: (35)", "curl: (56)", "curl: (7)", "sslerror", "handshake",
    )
    return any(m in msg for m in markers)


def _make_fresh_session(template_session):
    """Tạo curl_cffi Session tươi (clear corrupt BoringSSL state), copy proxy
    từ session gốc để sentinel vẫn đi qua đúng IP với login."""
    from curl_cffi import requests as _curl_requests
    from user_agent_profile import CURL_IMPERSONATE_PRIMARY as _IMPERSONATE

    fresh = _curl_requests.Session(impersonate=_IMPERSONATE)
    fresh.trust_env = False
    try:
        proxies = getattr(template_session, "proxies", None)
        if proxies:
            fresh.proxies = dict(proxies)
    except Exception:  # noqa: BLE001 — proxy copy best-effort
        pass
    return fresh


def _fnv1a_32(text: str) -> str:
    h = 2166136261
    for ch in text:
        h ^= ord(ch)
        h = (h * 16777619) & 0xFFFFFFFF
    h ^= h >> 16
    h = (h * 2246822507) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 3266489909) & 0xFFFFFFFF
    h ^= h >> 16
    return format(h & 0xFFFFFFFF, "08x")


def _b64_encode(data) -> str:
    raw = json.dumps(data, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _get_config(device_id: str, user_agent: str) -> list:
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)")
    perf_now = random.uniform(1000, 50000)
    time_origin = time.time() * 1000 - perf_now
    nav_prop = random.choice([
        "vendorSub", "productSub", "vendor", "maxTouchPoints",
        "scheduling", "userActivation", "doNotTrack", "geolocation",
        "connection", "plugins", "mimeTypes", "pdfViewerEnabled",
        "webkitTemporaryStorage", "webkitPersistentStorage",
        "hardwareConcurrency", "cookieEnabled", "credentials",
        "mediaDevices", "permissions", "locks", "ink",
    ])
    sid = str(uuid.uuid4())
    return [
        "1920x1080",
        date_str,
        4294705152,
        random.random(),
        user_agent,
        SENTINEL_SDK_URL,
        None,
        None,
        "en-US",
        "en-US,en",
        random.random(),
        f"{nav_prop}−undefined",
        random.choice(["location", "implementation", "URL", "documentURI", "compatMode"]),
        random.choice(["Object", "Function", "Array", "Number", "parseFloat", "undefined"]),
        perf_now,
        sid,
        "",
        random.choice([4, 8, 12, 16]),
        time_origin,
    ]


def _solve_pow(seed: str, difficulty: str, device_id: str, user_agent: str) -> str:
    """Run FNV-1a PoW until digest prefix <= difficulty."""
    config = _get_config(device_id, user_agent)
    start_time = time.time()
    for nonce in range(MAX_ATTEMPTS):
        config[3] = nonce
        config[9] = round((time.time() - start_time) * 1000)
        encoded = _b64_encode(config)
        digest = _fnv1a_32(seed + encoded)
        if digest[: len(difficulty)] <= difficulty:
            return "gAAAAAB" + encoded + "~S"
    return "gAAAAAB" + ERROR_PREFIX + _b64_encode(str(None))


def _generate_requirements_token(device_id: str, user_agent: str) -> str:
    config = _get_config(device_id, user_agent)
    config[3] = 1
    config[9] = round(random.uniform(5, 50))
    return "gAAAAAC" + _b64_encode(config)


def _fetch_challenge(session, device_id: str, flow: str, request_p: str) -> dict | None:
    """POST /sentinel/req → challenge JSON."""
    body = {"p": request_p, "id": device_id, "flow": flow}
    headers = {
        "Content-Type": "text/plain;charset=UTF-8",
        "Accept": "*/*",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Referer": SENTINEL_REFERER,
        "Origin": "https://sentinel.openai.com",
        "User-Agent": DEFAULT_UA,
        "sec-ch-ua": DEFAULT_SEC_CH_UA,
        "sec-ch-ua-mobile": "?0",
        'sec-ch-ua-platform': '"Windows"',
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
    }
    try:
        resp = session.post(
            SENTINEL_REQ_URL,
            data=json.dumps(body, separators=(",", ":")),
            headers=headers,
            timeout=20,
        )
        if resp.status_code == 200:
            return resp.json()
        logger.warning("Sentinel /req HTTP %s", resp.status_code)
        return None
    except Exception as e:
        # TLS-library corruption → recreate fresh session + retry bounded.
        # Lỗi khác (network thật, JSON parse) → giữ behavior cũ (return None).
        if not _is_tls_library_error(e):
            logger.warning("Sentinel /req error: %s", e)
            return None
        logger.warning(
            "Sentinel /req TLS-library error → retry trên fresh session: %s", e
        )

    payload = json.dumps(body, separators=(",", ":"))
    for attempt in range(1, _TLS_RETRY_MAX + 1):
        fresh = _make_fresh_session(session)
        try:
            resp = fresh.post(
                SENTINEL_REQ_URL,
                data=payload,
                headers=headers,
                timeout=20,
            )
            if resp.status_code == 200:
                logger.info(
                    "Sentinel /req OK trên fresh session (retry %d/%d)",
                    attempt, _TLS_RETRY_MAX,
                )
                return resp.json()
            logger.warning(
                "Sentinel /req HTTP %s (fresh retry %d/%d)",
                resp.status_code, attempt, _TLS_RETRY_MAX,
            )
            return None
        except Exception as e:  # noqa: BLE001
            if not _is_tls_library_error(e) or attempt >= _TLS_RETRY_MAX:
                logger.warning(
                    "Sentinel /req error sau %d fresh retry: %s", attempt, e
                )
                return None
            logger.warning(
                "Sentinel /req TLS-library error (fresh retry %d/%d) → recreate: %s",
                attempt, _TLS_RETRY_MAX, e,
            )
        finally:
            try:
                fresh.close()
            except Exception:  # noqa: BLE001
                pass
    return None


def get_sentinel_token(
    session,
    device_id: str,
    flow: str = "authorize_continue",
    user_agent: str = DEFAULT_UA,
) -> str:
    """Build sentinel token via pure-Python PoW. Always returns a string (never raises)."""
    did = device_id or str(uuid.uuid4())
    req_p = _generate_requirements_token(did, user_agent)

    challenge = _fetch_challenge(session, did, flow, req_p)
    if not challenge:
        logger.warning("Sentinel challenge fetch failed, returning fallback token")
        return json.dumps(
            {"p": req_p, "t": "", "c": "", "id": did, "flow": flow},
            separators=(",", ":"),
        )

    c_value = str(challenge.get("token") or "").strip()
    pow_data = challenge.get("proofofwork") or {}

    if pow_data.get("required") and pow_data.get("seed"):
        p_value = _solve_pow(
            seed=pow_data["seed"],
            difficulty=pow_data.get("difficulty", "0"),
            device_id=did,
            user_agent=user_agent,
        )
    else:
        p_value = req_p

    token = json.dumps(
        {"p": p_value, "t": "", "c": c_value, "id": did, "flow": flow},
        separators=(",", ":"),
    )
    logger.info("Sentinel token built (Python PoW, len=%d)", len(token))
    return token
