"""OpenAI Sentinel token — pure-Python PoW (FNV-1a) for password/verify + MFA."""

from __future__ import annotations

import base64
import json
import logging
import random
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Final

from curl_cffi.requests import AsyncSession

from chatgpt_auth import http_client as http
from chatgpt_auth.login_profile import CHATGPT_LOGIN_PROFILE

_SENTINEL_REQ_URL: Final[str] = "https://sentinel.openai.com/backend-api/sentinel/req"
_SENTINEL_REFERER: Final[str] = (
    "https://sentinel.openai.com/backend-api/sentinel/frame.html"
)
_SENTINEL_SDK_URL: Final[str] = (
    "https://sentinel.openai.com/sentinel/20260810913b/sdk.js"
)

_MAX_POW_ATTEMPTS: Final[int] = 500_000
_ERROR_PREFIX: Final[str] = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"
_MAX_RESPONSE_BYTES: Final[int] = 1024 * 1024  # 1 MiB streaming guard

_SENTINEL_UA: Final[str] = CHATGPT_LOGIN_PROFILE.user_agent

_NAV_PROPS: Final[tuple[str, ...]] = (
    "vendorSub", "productSub", "vendor", "maxTouchPoints", "scheduling",
    "userActivation", "doNotTrack", "geolocation", "connection", "plugins",
    "mimeTypes", "pdfViewerEnabled", "webkitTemporaryStorage",
    "webkitPersistentStorage", "hardwareConcurrency", "cookieEnabled",
    "credentials", "mediaDevices", "permissions", "locks", "ink",
)
_CHOICE_12: Final[tuple[str, ...]] = (
    "location", "implementation", "URL", "documentURI", "compatMode",
)
_CHOICE_13: Final[tuple[str, ...]] = (
    "Object", "Function", "Array", "Number", "parseFloat", "undefined",
)
_CHOICE_17: Final[tuple[int, ...]] = (4, 8, 12, 16)


def _fnv1a_32(text: str) -> str:
    """FNV-1a 32-bit hash with 3-round post-mixing."""
    h = 2166136261
    for ch in text:
        h ^= ord(ch)
        h = (h * 16777619) & 0xFFFFFFFF
    h ^= h >> 16
    h = (h * 2246822507) & 0xFFFFFFFF
    h ^= h >> 13
    h = (h * 3266489909) & 0xFFFFFFFF
    h ^= h >> 16
    return f"{h:08x}"


def _b64_encode_config(config: list[Any]) -> str:
    """Encode config array to compact UTF-8 JSON -> Base64 standard string."""
    raw = json.dumps(config, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _build_config(user_agent: str) -> list[Any]:
    """Build 19-element browser fingerprint array."""
    now = datetime.now(timezone.utc)
    date_str = now.strftime(
        "%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)"
    )
    perf_now = random.uniform(1000.0, 50000.0)
    time_origin = (now.timestamp() * 1000.0) - perf_now
    nav_prop = random.choice(_NAV_PROPS)
    sid = str(uuid.uuid4())

    return [
        "1920x1080",
        date_str,
        4_294_705_152,
        1,  # [3] nonce placeholder
        user_agent,
        _SENTINEL_SDK_URL,
        None,
        None,
        "en-US",
        int(random.uniform(5, 50)),  # [9] elapsed-ms placeholder
        random.random(),
        f"{nav_prop}\u2212undefined",
        random.choice(_CHOICE_12),
        random.choice(_CHOICE_13),
        perf_now,
        sid,
        "",
        random.choice(_CHOICE_17),
        time_origin,
    ]


def _solve_pow(seed: str, difficulty: str, user_agent: str) -> str:
    """Run PoW loop until FNV-1a hash of (seed + b64_config) <= difficulty."""
    config = _build_config(user_agent)
    start = time.perf_counter()
    dlen = len(difficulty)

    for nonce in range(_MAX_POW_ATTEMPTS):
        config[3] = nonce
        config[9] = int((time.perf_counter() - start) * 1000)
        encoded = _b64_encode_config(config)
        digest = _fnv1a_32(seed + encoded)
        if dlen <= len(digest) and digest[:dlen] <= difficulty:
            return f"gAAAAAB{encoded}~S"

    none_b64 = base64.b64encode(b'"None"').decode("ascii")
    return f"gAAAAAB{_ERROR_PREFIX}{none_b64}"


def _generate_requirements_token(user_agent: str) -> str:
    """Generate requirements_token (prefix gAAAAAC) for POST /sentinel/req."""
    config = _build_config(user_agent)
    config[3] = 1
    config[9] = int(random.uniform(5, 50))
    return f"gAAAAAC{_b64_encode_config(config)}"


async def _fetch_challenge(
    http_client: AsyncSession,
    device_id: str,
    flow: str,
    request_p: str,
    logger: logging.Logger,
) -> dict[str, Any] | None:
    """POST /sentinel/req to obtain challenge token and PoW requirements."""
    body = json.dumps({"p": request_p, "id": device_id, "flow": flow})
    headers = {
        "Accept": "*/*",
        "Referer": _SENTINEL_REFERER,
        "Origin": "https://sentinel.openai.com",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "Content-Type": "text/plain;charset=UTF-8",
    }
    try:
        response = await http_client.post(
            _SENTINEL_REQ_URL, data=body, headers=headers
        )
    except (http.TimeoutException, http.NetworkError, http.TransportError) as exc:
        logger.info("[sentinel] /req transport error: %s", exc)
        return None

    if response.status_code != 200:
        logger.info("[sentinel] /req HTTP %s", response.status_code)
        return None

    raw_content = getattr(response, "content", None)
    if raw_content is None:
        raw_content = (getattr(response, "text", "") or "").encode("utf-8")
    if len(raw_content) > _MAX_RESPONSE_BYTES:
        logger.warning("[sentinel] /req response too large: %d bytes", len(raw_content))
        return None

    try:
        payload = response.json()
        if isinstance(payload, dict):
            turnstile = payload.get("turnstile")
            if isinstance(turnstile, dict) and turnstile.get("required"):
                logger.info("[sentinel] turnstile required in challenge response")
            return payload
    except ValueError as exc:
        logger.info("[sentinel] /req invalid JSON: %s", exc)

    return None


async def get_sentinel_token(
    http_client: AsyncSession,
    device_id: str,
    flow: str,
    logger: logging.Logger,
) -> str:
    """Build sentinel token for header openai-sentinel-token."""
    did = device_id or str(uuid.uuid4())
    req_p = _generate_requirements_token(_SENTINEL_UA)

    challenge = await _fetch_challenge(http_client, did, flow, req_p, logger)
    if challenge is None:
        logger.info("[sentinel] challenge fetch failed -> fallback token")
        return json.dumps(
            {"p": req_p, "t": "", "c": "", "id": did, "flow": flow}
        )

    c_value = (challenge.get("token") or "").strip()
    pow_info = challenge.get("proofofwork") or {}
    required = bool(pow_info.get("required"))
    seed = str(pow_info.get("seed") or "")

    if required and seed:
        difficulty = str(pow_info.get("difficulty") or "0")
        p_value = _solve_pow(seed, difficulty, _SENTINEL_UA)
    else:
        p_value = req_p

    token = json.dumps(
        {"p": p_value, "t": "", "c": c_value, "id": did, "flow": flow}
    )
    logger.info("[sentinel] token built flow=%s (len=%d)", flow, len(token))
    return token


__all__ = ["get_sentinel_token"]
