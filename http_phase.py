"""Phase 2: extract session-token từ handoff cookies + fetch access_token.

Browser ở Phase 1 đã đi qua /api/auth/callback/openai và set sẵn cookie
`__Secure-next-auth.session-token` trên chatgpt.com. Phase 2 chỉ cần:
    1. Đọc cookies handoff → ghép session-token (có thể bị split nhiều chunk).
    2. Ưu tiên access_token Browser đã lấy trong cùng context/IP.
    3. Chỉ tạo curl_cffi session + GET /api/auth/session khi Browser không có token.

Lưu ý: validate-otp / create_account / callback HTTP flow đã được browser xử lý
trực tiếp ở Phase 1. Không còn replay request từ HTTP layer nữa.
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import json
import time
from typing import Any, Callable

from curl_cffi import requests as curl_requests

from models import BrowserHandoff, SignupRequest


class HttpPhaseError(Exception):
    """Phase 2 failed."""


_CHATGPT_BASE = "https://chatgpt.com"

# Retry policy cho /api/auth/session — endpoint duy nhất Phase 2 còn gọi.
# Retry chỉ với transient: connection error / timeout / 5xx.
_HTTP_RETRY_MAX = 3
_HTTP_RETRY_BACKOFF = (1.0, 2.0, 4.0)
_HTTP_RETRY_STATUS = frozenset({502, 503, 504, 408, 429})


def _request_with_retry(
    send: Callable[[], Any],
    *,
    log,
    label: str,
    max_attempts: int = _HTTP_RETRY_MAX,
) -> Any:
    """Gọi `send()` (closure trả curl_cffi Response), retry transient.

    Trả về response cuối cùng (caller check status). Raise nếu hết retry với exception.
    """
    last_exc: Exception | None = None
    last_response: Any = None
    for attempt in range(1, max_attempts + 1):
        try:
            response = send()
            if response.status_code in _HTTP_RETRY_STATUS:
                last_response = response
                log(f"[http] {label} HTTP {response.status_code} attempt {attempt}/{max_attempts} — retry")
            else:
                return response
        except Exception as exc:
            last_exc = exc
            log(f"[http] {label} attempt {attempt}/{max_attempts} error: {type(exc).__name__}: {exc}")

        if attempt < max_attempts:
            backoff = _HTTP_RETRY_BACKOFF[min(attempt - 1, len(_HTTP_RETRY_BACKOFF) - 1)]
            time.sleep(backoff)

    if last_response is not None:
        return last_response
    raise HttpPhaseError(f"{label} failed sau {max_attempts} attempts: {last_exc}") from last_exc


def _build_session(*, request: SignupRequest) -> curl_requests.Session:
    """curl_cffi Session với impersonate + optional proxy."""
    session = curl_requests.Session(impersonate=request.impersonate)
    if request.proxy:
        session.proxies = {"http": request.proxy, "https": request.proxy}
    return session


def _fetch_access_token(
    *,
    session: curl_requests.Session,
    request: SignupRequest,
    log,
) -> tuple[str | None, str | None]:
    """GET /api/auth/session với cookies đã inject. Trả về (access_token, user_id)."""
    url = f"{_CHATGPT_BASE}/api/auth/session"
    from user_agent_profile import (
        SEC_CH_UA,
        SEC_CH_UA_MOBILE,
        SEC_CH_UA_PLATFORM,
    )
    headers = {
        "User-Agent": request.user_agent,
        "Accept": "application/json",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": f"{_CHATGPT_BASE}/",
        "sec-ch-ua": SEC_CH_UA,
        "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
    }
    last_error = "unknown"
    # HTTP 200 nhưng body chưa có accessToken là trạng thái eventual-consistency,
    # không phải success. Retry cả trường hợp này thay vì lưu session thiếu token.
    for attempt in range(1, _HTTP_RETRY_MAX + 1):
        try:
            response = session.get(url, headers=headers, timeout=30)
            if response.status_code == 200:
                data = response.json()
                access = data.get("accessToken")
                user = data.get("user", {}) or {}
                if isinstance(access, str) and access:
                    return access, user.get("id")
                last_error = "HTTP 200 thiếu accessToken"
            else:
                last_error = f"HTTP {response.status_code}"
                if response.status_code not in _HTTP_RETRY_STATUS:
                    break
        except Exception as exc:
            last_error = f"{type(exc).__name__}: {exc}"

        log(
            f"[http] fetch-access-token attempt {attempt}/{_HTTP_RETRY_MAX} "
            f"chưa sẵn sàng: {last_error}"
        )
        if attempt < _HTTP_RETRY_MAX:
            backoff = _HTTP_RETRY_BACKOFF[
                min(attempt - 1, len(_HTTP_RETRY_BACKOFF) - 1)
            ]
            time.sleep(backoff)
    log(f"[http] WARN fetch access_token failed: {last_error}")
    return None, None


def _extract_session_from_handoff(handoff: BrowserHandoff) -> dict[str, Any]:
    """Đọc session-token + cookies chatgpt.com từ handoff (browser đã set sẵn).

    NextAuth có thể split token thành nhiều chunk: `.session-token.0`, `.session-token.1`.
    Phase 2 cần đầy đủ cả 2 chunk để decode đúng.
    """
    out_cookies: list[dict[str, Any]] = []
    session_token: str | None = None
    session_token_chunks: dict[str, str] = {}
    account_id: str | None = None
    for c in handoff.cookies:
        domain = (c.get("domain") or "").lower()
        if "chatgpt.com" not in domain:
            continue
        out_cookies.append({
            "name": c["name"],
            "value": c["value"],
            "domain": c.get("domain"),
            "path": c.get("path"),
            "secure": c.get("secure", False),
        })
        name = c["name"]
        if name == "__Secure-next-auth.session-token":
            session_token = c["value"]
        elif name.startswith("__Secure-next-auth.session-token."):
            idx = name.rsplit(".", 1)[-1]
            session_token_chunks[idx] = c["value"]
        elif name == "_account":
            account_id = c["value"]

    if session_token is None and session_token_chunks:
        ordered = "".join(session_token_chunks[k] for k in sorted(session_token_chunks))
        session_token = ordered

    if not session_token:
        raise HttpPhaseError("handoff cookies không có __Secure-next-auth.session-token")
    return {
        "cookies": out_cookies,
        "session_token": session_token,
        "account_id": account_id,
    }


def _extract_user_id_from_access_token(access_token: str) -> str | None:
    """Đọc user id từ JWT Browser mà không gọi thêm request mạng.

    Token đã được lấy từ ``/api/auth/session`` trong Browser context; decode ở
    đây chỉ để giữ metadata ``user_id`` của flow cũ, không dùng để xác thực JWT.
    """
    parts = access_token.split(".")
    if len(parts) != 3 or not parts[1]:
        return None
    try:
        payload_raw = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
        payload = json.loads(payload_raw.decode("utf-8"))
    except (ValueError, binascii.Error, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(payload, dict):
        return None

    for namespace in ("https://api.openai.com/profile", "https://api.openai.com/auth"):
        namespaced = payload.get(namespace)
        if isinstance(namespaced, dict):
            user_id = namespaced.get("user_id")
            if isinstance(user_id, str) and user_id:
                return user_id
    return None


async def run_http_phase(
    *,
    request: SignupRequest,
    handoff: BrowserHandoff,
    log,
) -> dict[str, Any]:
    """Phase 2: extract session-token và chỉ fetch token khi Browser chưa có."""
    def _sync() -> dict[str, Any]:
        result = _extract_session_from_handoff(handoff)
        log(f"[http] session-token from handoff ({len(result['session_token'])} bytes)")
        raw_browser_token = handoff.access_token
        browser_access_token = (
            raw_browser_token.strip() if isinstance(raw_browser_token, str) else ""
        )
        if browser_access_token:
            log("[bandwidth] dùng access_token từ Browser — bỏ qua curl /api/auth/session")
            return {
                **result,
                "access_token": browser_access_token,
                "user_id": _extract_user_id_from_access_token(browser_access_token),
            }

        session = _build_session(request=request)
        try:
            for c in result["cookies"]:
                session.cookies.set(
                    c["name"], c["value"],
                    domain=c.get("domain") or "chatgpt.com",
                    path=c.get("path") or "/",
                )
            access_token, user_id = _fetch_access_token(
                session=session, request=request, log=log,
            )
            if not access_token:
                raise HttpPhaseError(
                    "/api/auth/session không trả accessToken và Browser handoff rỗng"
                )
            return {**result, "access_token": access_token, "user_id": user_id}
        finally:
            try:
                session.close()
            except Exception:
                pass

    return await asyncio.to_thread(_sync)
