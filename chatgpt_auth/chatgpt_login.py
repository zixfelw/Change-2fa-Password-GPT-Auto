"""ChatGPT pure-HTTP login flow (password + TOTP MFA)."""

from __future__ import annotations

import asyncio
import logging
import re
import uuid
from typing import Any, Callable, Final
from urllib.parse import urljoin, urlparse

import pyotp

from chatgpt_auth import http_client as http
from chatgpt_auth.account_identity import canonical_email
from chatgpt_auth.errors import LoginError
from chatgpt_auth.login_profile import (
    CHATGPT_LOGIN_PROFILE,
    profile_chatgpt_login_http_client,
)
from chatgpt_auth.models import SessionBundle
from chatgpt_auth.safe_diagnostics import (
    build_safe_diagnostic,
    is_cloudflare_challenge_response,
)
from chatgpt_auth.sentinel import get_sentinel_token

_CHATGPT_BASE: Final[str] = "https://chatgpt.com"
_AUTH_BASE: Final[str] = "https://auth.openai.com"

_URL_PRIME: Final[str] = f"{_CHATGPT_BASE}/"
_URL_CSRF: Final[str] = f"{_CHATGPT_BASE}/api/auth/csrf"
_URL_SIGNIN_OPENAI: Final[str] = f"{_CHATGPT_BASE}/api/auth/signin/openai"
_URL_SESSION: Final[str] = f"{_CHATGPT_BASE}/api/auth/session"

_URL_AUTHORIZE_CONTINUE: Final[str] = f"{_AUTH_BASE}/api/accounts/authorize/continue"
_URL_PASSWORD_VERIFY: Final[str] = f"{_AUTH_BASE}/api/accounts/password/verify"
_URL_MFA_ISSUE: Final[str] = f"{_AUTH_BASE}/api/accounts/mfa/issue_challenge"
_URL_MFA_VERIFY: Final[str] = f"{_AUTH_BASE}/api/accounts/mfa/verify"

_MFA_CHALLENGE_RE: Final[re.Pattern[str]] = re.compile(r"/mfa-challenge/([a-f0-9]+)")
_ACCESS_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9\-._~+/]+=*$")

_MAX_REDIRECT_HOPS: Final[int] = 12
_CALLBACK_VERIFY_ATTEMPTS: Final[int] = 3
_HTTP_RETRY_ATTEMPTS: Final[int] = 3

_SESSION_TOKEN_COOKIE_BASE: Final[str] = "__Secure-next-auth.session-token"

_LOGIN_ERROR_INVALID_CREDENTIAL: Final[str] = "invalid_credential"
_LOGIN_ERROR_MFA_REQUIRED: Final[str] = "mfa_required"
_LOGIN_ERROR_ACCOUNT_LOCKED: Final[str] = "account_locked"
_LOGIN_ERROR_NETWORK: Final[str] = "network_error"
_LOGIN_ERROR_PUSH_AUTH_REQUIRED: Final[str] = "push_auth_required"

_ESSENTIAL_COOKIE_PREFIXES: Final[tuple[str, ...]] = (
    "__Secure-next-auth.session-token",
    "__Host-next-auth.csrf-token",
    "__Secure-next-auth.csrf-token",
    "oai-did",
    "oai-sc",
    "cf_clearance",
    "__cf_bm",
    "_cfuvid",
)

_STRUCTURED_CREDENTIAL_CODES: Final[frozenset[str]] = frozenset(
    {"invalid_password", "invalid_credential"}
)
_STRUCTURED_RESTRICTION_CODES: Final[frozenset[str]] = frozenset(
    {
        "account_locked",
        "account_disabled",
        "account_deactivated",
        "deactivated",
        "deleted",
        "banned",
        "suspended",
    }
)


def _short(s: str, n: int = 200) -> str:
    """Trim string for logging without leaking large bodies."""
    if len(s) <= n:
        return s
    return s[:n] + "…"


def _has_session_token(client: http.AsyncSession) -> bool:
    """True if cookie jar contains __Secure-next-auth.session-token (base or .0)."""
    try:
        jar = getattr(getattr(client, "cookies", None), "jar", None)
        if jar is not None:
            for cookie in jar:
                if cookie.name == _SESSION_TOKEN_COOKIE_BASE and cookie.value:
                    return True
                if cookie.name == f"{_SESSION_TOKEN_COOKIE_BASE}.0" and cookie.value:
                    return True
    except Exception:
        pass
    return False


def _snapshot_cookies(client: http.AsyncSession) -> dict[str, str]:
    """Snapshot essential cookies from jar into dict name -> value."""
    result: dict[str, str] = {}
    try:
        jar = getattr(getattr(client, "cookies", None), "jar", None)
        if jar is not None:
            for cookie in jar:
                domain = (cookie.domain or "").lstrip(".")
                if domain and "chatgpt.com" not in domain and "openai.com" not in domain:
                    continue
                name = cookie.name or ""
                if not any(name.startswith(p) for p in _ESSENTIAL_COOKIE_PREFIXES):
                    continue
                result[name] = cookie.value or ""
    except Exception:
        pass
    return result


def _seed_operation_device_cookie(client: http.AsyncSession, device_id: str) -> None:
    """Seed `oai-did` cookie with `.chatgpt.com` domain and clean up empty-domain entries."""
    try:
        jar = getattr(getattr(client, "cookies", None), "jar", None)
        if jar is not None:
            if hasattr(jar, "_cookies") and isinstance(jar._cookies, dict):
                jar._cookies.get("", {}).get("/", {}).pop("oai-did", None)
        client.cookies.set("oai-did", device_id, domain=".chatgpt.com", path="/")
    except Exception:
        pass


def _extract_structured_error_code(data: Any, depth: int = 0) -> str | None:
    """Recursively inspect response dict/list for structured error codes."""
    if depth > 3 or data is None:
        return None
    if isinstance(data, dict):
        code = data.get("code")
        if isinstance(code, str) and code.strip():
            return code.strip().lower()
        for k in ("error", "errors", "data", "result", "page"):
            sub = data.get(k)
            if sub is not None:
                res = _extract_structured_error_code(sub, depth + 1)
                if res:
                    return res
    elif isinstance(data, list):
        for item in data[:16]:
            res = _extract_structured_error_code(item, depth + 1)
            if res:
                return res
    return None


async def _get_follow(
    client: http.AsyncSession,
    url: str,
    headers: dict[str, str],
    logger: logging.Logger,
    max_hops: int = _MAX_REDIRECT_HOPS,
) -> tuple[http.Response, str]:
    """Manual redirect follow to capture Set-Cookie across each hop."""
    current = url
    for hop in range(max_hops):
        try:
            response = await client.get(
                current, headers=headers, allow_redirects=False
            )
        except (http.TimeoutException, http.NetworkError, http.TransportError) as exc:
            logger.warning("[login] redirect hop %d transport error at %s: %s", hop, _short(current, 100), exc)
            raise LoginError(
                reason=_LOGIN_ERROR_NETWORK,
                diagnostic=build_safe_diagnostic(stage="redirect", reason="transport_error", url=current),
            ) from exc

        if response.status_code in (301, 302, 303, 307, 308):
            loc = response.headers.get("location")
            if not loc:
                break
            current = urljoin(current, loc)
            continue
        return response, current

    raise LoginError(
        reason=_LOGIN_ERROR_NETWORK,
        message=f"Too many redirect hops ({max_hops})",
        diagnostic=build_safe_diagnostic(stage="redirect", reason="too_many_redirects", url=url),
    )


async def _prime(client: http.AsyncSession, device_id: str, logger: logging.Logger) -> None:
    """Step 0: warm Cloudflare & cookies by requesting root https://chatgpt.com/."""
    logger.info("[login] [0/8] prime chatgpt.com root")
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "oai-device-id": device_id,
    }

    for attempt in range(_HTTP_RETRY_ATTEMPTS):
        try:
            response = await client.get(_URL_PRIME, headers=headers, allow_redirects=True)
        except (http.TimeoutException, http.NetworkError, http.TransportError) as exc:
            logger.warning("[login] prime transport error (attempt %d/%d): %s", attempt + 1, _HTTP_RETRY_ATTEMPTS, exc)
            if attempt < _HTTP_RETRY_ATTEMPTS - 1:
                await asyncio.sleep((attempt + 1) * 2.0)
                continue
            raise LoginError(
                reason=_LOGIN_ERROR_NETWORK,
                diagnostic=build_safe_diagnostic(stage="prime", reason="transport_error", url=_URL_PRIME),
            ) from exc

        if is_cloudflare_challenge_response(response.status_code, response.headers, response.text):
            logger.warning(
                "[login] prime cloudflare challenge detected (HTTP %d, attempt %d/%d)",
                response.status_code,
                attempt + 1,
                _HTTP_RETRY_ATTEMPTS,
            )
            if attempt < _HTTP_RETRY_ATTEMPTS - 1:
                wait_s = (attempt + 1) * 3.0
                await asyncio.sleep(wait_s)
                continue
            raise LoginError(
                reason=_LOGIN_ERROR_NETWORK,
                message="Cloudflare challenge encountered on prime",
                diagnostic=build_safe_diagnostic(
                    stage="prime",
                    reason="cloudflare_challenge",
                    status_code=response.status_code,
                    url=_URL_PRIME,
                    headers=response.headers,
                    body_text=response.text,
                ),
            )

        if response.status_code == 403 and attempt < _HTTP_RETRY_ATTEMPTS - 1:
            wait_s = (attempt + 1) * 5.0
            logger.info("[login] prime 403 without CF challenge marker -> retry in %.1fs", wait_s)
            await asyncio.sleep(wait_s)
            continue

        if response.status_code >= 400:
            logger.warning("[login] prime returned HTTP %d", response.status_code)
            raise LoginError(
                reason=_LOGIN_ERROR_NETWORK,
                diagnostic=build_safe_diagnostic(
                    stage="prime",
                    reason="http_error",
                    status_code=response.status_code,
                    url=_URL_PRIME,
                    headers=response.headers,
                ),
            )
        return


async def _step_csrf(
    client: http.AsyncSession, device_id: str, session_id: str, logger: logging.Logger
) -> str:
    """Step 1: GET /api/auth/csrf -> csrfToken."""
    logger.info("[login] [1/8] CSRF token")
    headers = {
        "Accept": "application/json",
        "Origin": _CHATGPT_BASE,
        "Referer": f"{_CHATGPT_BASE}/",
        "oai-device-id": device_id,
        "oai-session-id": session_id,
    }

    for attempt in range(_HTTP_RETRY_ATTEMPTS):
        try:
            response = await client.get(_URL_CSRF, headers=headers, allow_redirects=False)
        except (http.TimeoutException, http.NetworkError, http.TransportError) as exc:
            logger.warning("[login] CSRF transport error (attempt %d/%d): %s", attempt + 1, _HTTP_RETRY_ATTEMPTS, exc)
            if attempt < _HTTP_RETRY_ATTEMPTS - 1:
                await asyncio.sleep((attempt + 1) * 2.0)
                continue
            raise LoginError(
                reason=_LOGIN_ERROR_NETWORK,
                diagnostic=build_safe_diagnostic(stage="csrf", reason="transport_error", url=_URL_CSRF),
            ) from exc

        if is_cloudflare_challenge_response(response.status_code, response.headers, response.text):
            logger.warning(
                "[login] CSRF cloudflare challenge detected (HTTP %d, attempt %d/%d)",
                response.status_code,
                attempt + 1,
                _HTTP_RETRY_ATTEMPTS,
            )
            if attempt < _HTTP_RETRY_ATTEMPTS - 1:
                wait_s = (attempt + 1) * 3.0
                await asyncio.sleep(wait_s)
                continue
            raise LoginError(
                reason=_LOGIN_ERROR_NETWORK,
                message="Cloudflare challenge on CSRF",
                diagnostic=build_safe_diagnostic(
                    stage="csrf",
                    reason="cloudflare_challenge",
                    status_code=response.status_code,
                    url=_URL_CSRF,
                    headers=response.headers,
                    body_text=response.text,
                ),
            )

        if response.status_code == 403 and attempt < _HTTP_RETRY_ATTEMPTS - 1:
            wait_s = (attempt + 1) * 5.0
            logger.info("[login] CSRF 403 -> retry in %.1fs", wait_s)
            await asyncio.sleep(wait_s)
            continue

        if response.status_code != 200:
            logger.warning("[login] CSRF HTTP %d", response.status_code)
            raise LoginError(
                reason=_LOGIN_ERROR_NETWORK,
                diagnostic=build_safe_diagnostic(
                    stage="csrf",
                    reason="http_error",
                    status_code=response.status_code,
                    url=_URL_CSRF,
                ),
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise LoginError(reason=_LOGIN_ERROR_NETWORK) from exc

        token = payload.get("csrfToken") if isinstance(payload, dict) else None
        if isinstance(token, str) and token.strip():
            return token.strip()

        logger.warning("[login] CSRF missing valid csrfToken")
        raise LoginError(reason=_LOGIN_ERROR_NETWORK)

    raise LoginError(reason=_LOGIN_ERROR_NETWORK)


async def _step_signin(
    client: http.AsyncSession,
    csrf: str,
    device_id: str,
    session_id: str,
    email: str,
    logger: logging.Logger,
) -> str:
    """Step 2: POST /api/auth/signin/openai -> auth URL on auth.openai.com."""
    logger.info("[login] [2/8] signin/openai authorize URL")
    params: list[tuple[str, str]] = [
        ("prompt", "login"),
        ("ext-passkey-client-capabilities", "01001"),
        ("auth_session_logging_id", session_id),
        ("screen_hint", "login_or_signup"),
        ("ext-oai-did", device_id),
    ]
    if email:
        params.append(("login_hint", email))

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": _CHATGPT_BASE,
        "Referer": f"{_CHATGPT_BASE}/",
        "oai-device-id": device_id,
        "oai-session-id": session_id,
    }
    form = {
        "csrfToken": csrf,
        "callbackUrl": f"{_CHATGPT_BASE}/",
        "json": "true",
    }

    try:
        response = await client.post(
            _URL_SIGNIN_OPENAI,
            params=params,
            data=form,
            headers=headers,
            allow_redirects=False,
        )
    except (http.TimeoutException, http.NetworkError, http.TransportError) as exc:
        logger.warning("[login] signin/openai transport error: %s", exc)
        raise LoginError(
            reason=_LOGIN_ERROR_NETWORK,
            diagnostic=build_safe_diagnostic(stage="signin", reason="transport_error", url=_URL_SIGNIN_OPENAI),
        ) from exc

    if response.status_code != 200:
        logger.warning("[login] signin/openai HTTP %d: %s", response.status_code, _short(response.text))
        raise LoginError(
            reason=_LOGIN_ERROR_NETWORK,
            diagnostic=build_safe_diagnostic(
                stage="signin",
                reason="http_error",
                status_code=response.status_code,
                url=_URL_SIGNIN_OPENAI,
                headers=response.headers,
                body_text=response.text,
            ),
        )

    try:
        payload = response.json()
    except ValueError as exc:
        raise LoginError(reason=_LOGIN_ERROR_NETWORK) from exc

    auth_url = payload.get("url") if isinstance(payload, dict) else None
    if not isinstance(auth_url, str) or not auth_url:
        logger.warning("[login] signin/openai missing url in response")
        raise LoginError(reason=_LOGIN_ERROR_NETWORK)

    parsed = urlparse(auth_url)
    if parsed.netloc != "auth.openai.com":
        logger.warning("[login] signin/openai url host mismatch: %s", parsed.netloc)
        raise LoginError(reason=_LOGIN_ERROR_NETWORK)

    return auth_url


async def _follow_authorize(
    client: http.AsyncSession, auth_url: str, logger: logging.Logger
) -> tuple[http.Response, str]:
    """Step 3: GET authorize URL and follow redirects to landing page."""
    logger.info("[login] [3/8] OAuth init (GET authorize)")
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "cross-site",
        "Referer": f"{_CHATGPT_BASE}/",
    }
    return await _get_follow(client, auth_url, headers, logger)


async def _password_verify(
    client: http.AsyncSession,
    password: str,
    device_id: str,
    logger: logging.Logger,
    on_credential_submitted: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Step 4: POST /api/accounts/password/verify with Sentinel token."""
    logger.info("[login] [4/8] password verify (Sentinel PoW)")
    sentinel_token = await get_sentinel_token(
        client, device_id=device_id, flow="password_verify", logger=logger
    )

    if on_credential_submitted is not None:
        try:
            on_credential_submitted()
        except Exception:
            pass

    headers = {
        "Accept": "application/json",
        "Origin": _AUTH_BASE,
        "Referer": f"{_AUTH_BASE}/log-in/password",
        "Content-Type": "application/json",
        "oai-device-id": device_id,
        "openai-sentinel-token": sentinel_token,
    }
    payload = {"password": password}

    try:
        response = await client.post(
            _URL_PASSWORD_VERIFY,
            json=payload,
            headers=headers,
            allow_redirects=False,
        )
    except (http.TimeoutException, http.NetworkError, http.TransportError) as exc:
        logger.warning("[login] password/verify transport error: %s", exc)
        raise LoginError(
            reason=_LOGIN_ERROR_NETWORK,
            diagnostic=build_safe_diagnostic(stage="password_verify", reason="transport_error", url=_URL_PASSWORD_VERIFY),
        ) from exc

    if is_cloudflare_challenge_response(response.status_code, response.headers, response.text):
        logger.warning("[login] password/verify cloudflare challenge detected")
        raise LoginError(
            reason=_LOGIN_ERROR_NETWORK,
            message="Cloudflare challenge on password verify",
            diagnostic=build_safe_diagnostic(
                stage="password_verify",
                reason="cloudflare_challenge",
                status_code=response.status_code,
                url=_URL_PASSWORD_VERIFY,
                headers=response.headers,
                body_text=response.text,
            ),
        )

    parsed_json: dict[str, Any] | None = None
    try:
        parsed_json = response.json() if response.text else None
    except Exception:
        pass

    if response.status_code in (400, 401, 403):
        code = _extract_structured_error_code(parsed_json)
        if code in _STRUCTURED_RESTRICTION_CODES:
            logger.warning("[login] account restricted/locked (code=%s)", code)
            raise LoginError(
                reason=_LOGIN_ERROR_ACCOUNT_LOCKED,
                message=f"Account restricted: {code}",
                diagnostic=build_safe_diagnostic(stage="password_verify", reason="account_locked", status_code=response.status_code),
            )
        if code in _STRUCTURED_CREDENTIAL_CODES:
            logger.warning("[login] invalid password/credential (code=%s)", code)
            raise LoginError(
                reason=_LOGIN_ERROR_INVALID_CREDENTIAL,
                message="Invalid password or credential",
                diagnostic=build_safe_diagnostic(stage="password_verify", reason="invalid_credential", status_code=response.status_code),
            )

        body_lower = (response.text or "").lower()
        if any(w in body_lower for w in ("deleted", "deactivated", "do not have an account")):
            raise LoginError(reason=_LOGIN_ERROR_INVALID_CREDENTIAL, message="Account deleted or deactivated")
        if any(w in body_lower for w in ("account_locked", "account_disabled", "banned", "suspended")):
            raise LoginError(reason=_LOGIN_ERROR_ACCOUNT_LOCKED, message="Account locked or suspended")

        logger.warning("[login] password/verify HTTP %d: %s", response.status_code, _short(response.text))
        raise LoginError(
            reason=_LOGIN_ERROR_INVALID_CREDENTIAL,
            diagnostic=build_safe_diagnostic(
                stage="password_verify",
                reason="invalid_credential_fallback",
                status_code=response.status_code,
            ),
        )

    if response.status_code != 200:
        logger.warning("[login] password/verify unexpected HTTP %d", response.status_code)
        raise LoginError(
            reason=_LOGIN_ERROR_NETWORK,
            diagnostic=build_safe_diagnostic(stage="password_verify", reason="http_error", status_code=response.status_code),
        )

    if not isinstance(parsed_json, dict):
        logger.warning("[login] password/verify 200 without valid JSON")
        raise LoginError(reason=_LOGIN_ERROR_NETWORK)

    return parsed_json


async def _mfa_issue(
    client: http.AsyncSession,
    challenge_id: str,
    device_id: str,
    logger: logging.Logger,
) -> None:
    """Best-effort POST /api/accounts/mfa/issue_challenge."""
    headers = {
        "Accept": "application/json",
        "Origin": _AUTH_BASE,
        "Referer": f"{_AUTH_BASE}/mfa-challenge",
        "Content-Type": "application/json",
        "oai-device-id": device_id,
    }
    payload = {
        "id": challenge_id,
        "type": "totp",
        "force_fresh_challenge": False,
    }
    try:
        resp = await client.post(_URL_MFA_ISSUE, json=payload, headers=headers, allow_redirects=False)
        logger.info("[login] issue_challenge HTTP %s: %s", resp.status_code, resp.text)
    except Exception as exc:
        logger.info("[login] issue_challenge exception (non-fatal): %s", exc)


async def _mfa_verify(
    client: http.AsyncSession,
    challenge_id: str,
    code: str,
    device_id: str,
    sentinel_token: str,
    logger: logging.Logger,
) -> dict[str, Any]:
    """Step 5: POST /api/accounts/mfa/verify with fresh TOTP and Sentinel token."""
    logger.info("[login] [5/8] MFA verify (TOTP + Sentinel PoW) code=%s", code)
    headers = {
        "Accept": "application/json",
        "Origin": _AUTH_BASE,
        "Referer": f"{_AUTH_BASE}/mfa-challenge",
        "Content-Type": "application/json",
        "oai-device-id": device_id,
        "openai-sentinel-token": sentinel_token,
    }
    payload = {
        "id": challenge_id,
        "type": "totp",
        "code": code,
    }

    try:
        response = await client.post(_URL_MFA_VERIFY, json=payload, headers=headers, allow_redirects=False)
    except (http.TimeoutException, http.NetworkError, http.TransportError) as exc:
        logger.warning("[login] MFA verify transport error: %s", exc)
        raise LoginError(
            reason=_LOGIN_ERROR_NETWORK,
            diagnostic=build_safe_diagnostic(stage="mfa_verify", reason="transport_error", url=_URL_MFA_VERIFY),
        ) from exc

    if response.status_code != 200:
        logger.warning("[login] MFA verify HTTP %d: %s", response.status_code, _short(response.text))
        parsed = None
        try:
            parsed = response.json()
        except Exception:
            pass
        code_str = _extract_structured_error_code(parsed)
        if code_str in _STRUCTURED_RESTRICTION_CODES:
            raise LoginError(reason=_LOGIN_ERROR_ACCOUNT_LOCKED, message=f"MFA account restricted: {code_str}")
        if code_str == "incorrect_code" or "incorrect" in (response.text or "").lower():
            raise LoginError(reason=_LOGIN_ERROR_MFA_REQUIRED, message="Mã 2FA (OTP) không đúng hoặc secret đã bị đổi")
        raise LoginError(reason=_LOGIN_ERROR_MFA_REQUIRED, message="MFA verification failed")

    try:
        return response.json()
    except ValueError as exc:
        raise LoginError(reason=_LOGIN_ERROR_NETWORK) from exc


async def _follow_redirects_to_callback(
    client: http.AsyncSession, start_url: str, logger: logging.Logger
) -> str | None:
    """Follow redirects until finding https://chatgpt.com/api/auth/callback/openai?code=..."""
    current = start_url
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Referer": f"{_AUTH_BASE}/",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "cross-site",
    }
    for _ in range(_MAX_REDIRECT_HOPS):
        parsed = urlparse(current)
        if parsed.netloc == "chatgpt.com" and parsed.path == "/api/auth/callback/openai" and "code=" in (parsed.query or ""):
            return current

        try:
            response = await client.get(current, headers=headers, allow_redirects=False)
        except Exception:
            return None

        if response.status_code in (301, 302, 303, 307, 308):
            loc = response.headers.get("location")
            if not loc:
                break
            current = urljoin(current, loc)
            continue
        break

    parsed = urlparse(current)
    if parsed.netloc == "chatgpt.com" and parsed.path == "/api/auth/callback/openai" and "code=" in (parsed.query or ""):
        return current
    return None


async def _consume_callback_verified(
    client: http.AsyncSession, callback_url: str, logger: logging.Logger
) -> bool:
    """Consume callback URL and verify that __Secure-next-auth.session-token is stored."""
    logger.info("[login] [6/8] consume callback")
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Referer": f"{_AUTH_BASE}/",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "cross-site",
    }
    for attempt in range(_CALLBACK_VERIFY_ATTEMPTS):
        try:
            await _get_follow(client, callback_url, headers, logger)
        except Exception as exc:
            logger.info("[login] consume callback attempt %d error: %s", attempt + 1, exc)

        if _has_session_token(client):
            return True
        if attempt < _CALLBACK_VERIFY_ATTEMPTS - 1:
            await asyncio.sleep(1.0)

    return _has_session_token(client)


async def _get_session(
    client: http.AsyncSession, device_id: str, session_id: str, logger: logging.Logger
) -> dict[str, Any]:
    """Step 7: GET /api/auth/session to retrieve NextAuth session JSON."""
    logger.info("[login] [7/8] GET session")
    headers = {
        "Accept": "application/json",
        "Origin": _CHATGPT_BASE,
        "Referer": f"{_CHATGPT_BASE}/",
        "oai-device-id": device_id,
        "oai-session-id": session_id,
    }
    try:
        response = await client.get(_URL_SESSION, headers=headers, allow_redirects=False)
    except (http.TimeoutException, http.NetworkError, http.TransportError) as exc:
        logger.warning("[login] GET /api/auth/session transport error: %s", exc)
        raise LoginError(
            reason=_LOGIN_ERROR_NETWORK,
            diagnostic=build_safe_diagnostic(stage="session_fetch", reason="transport_error", url=_URL_SESSION),
        ) from exc

    if response.status_code != 200:
        logger.warning("[login] /api/auth/session HTTP %d", response.status_code)
        raise LoginError(
            reason=_LOGIN_ERROR_NETWORK,
            diagnostic=build_safe_diagnostic(
                stage="session_fetch",
                reason="http_error",
                status_code=response.status_code,
                url=_URL_SESSION,
                headers=response.headers,
            ),
        )

    try:
        payload = response.json()
        if isinstance(payload, dict):
            return payload
    except ValueError as exc:
        raise LoginError(reason=_LOGIN_ERROR_NETWORK) from exc

    raise LoginError(reason=_LOGIN_ERROR_NETWORK)


def _extract_access_token(payload: dict[str, Any]) -> str | None:
    """Extract accessToken from /api/auth/session response."""
    candidates = [
        payload.get("accessToken"),
        (payload.get("user") or {}).get("accessToken") if isinstance(payload.get("user"), dict) else None,
        (payload.get("user") or {}).get("access_token") if isinstance(payload.get("user"), dict) else None,
    ]
    for cand in candidates:
        if isinstance(cand, str) and cand.strip():
            cleaned = cand.strip()
            if _ACCESS_TOKEN_RE.match(cleaned):
                return cleaned
    return None


async def _resolve_callback(
    client: http.AsyncSession,
    continue_url: str,
    device_id: str,
    session_id: str,
    logger: logging.Logger,
) -> str | None:
    """Resolve callback URL from continuation or reauthorize."""
    if continue_url and "auth.openai.com" in continue_url and "code=" not in continue_url:
        logger.info("[login] continue_url is an auth page -> reauthorizing")
        csrf2 = await _step_csrf(client, device_id, session_id, logger)
        auth_url2 = await _step_signin(client, csrf2, device_id, session_id, "", logger)
        return await _follow_redirects_to_callback(client, auth_url2, logger)
    elif continue_url:
        return await _follow_redirects_to_callback(client, continue_url, logger)
    else:
        logger.info("[login] no continue_url -> trying reauthorize")
        csrf2 = await _step_csrf(client, device_id, session_id, logger)
        auth_url2 = await _step_signin(client, csrf2, device_id, session_id, "", logger)
        return await _follow_redirects_to_callback(client, auth_url2, logger)


async def login_pure_request_with_payload(
    email: str,
    password: str,
    totp_secret: str | None,
    http_client: http.AsyncSession,
    logger: logging.Logger,
    *,
    use_login_hint: bool = True,
    on_credential_submitted: Callable[[], None] | None = None,
    log_fn: Callable[[str], None] | None = None,
) -> tuple[SessionBundle, dict[str, Any]]:
    """Execute full ChatGPT HTTP login flow -> (SessionBundle, session_payload)."""
    norm_email = canonical_email(email)
    logger.info("[login] start — email=%s", norm_email)
    if log_fn:
        log_fn("   ↳ Khởi tạo kết nối tới cổng xác thực OpenAI...")

    client = profile_chatgpt_login_http_client(http_client, CHATGPT_LOGIN_PROFILE)

    device_id = str(uuid.uuid4())
    session_id = str(uuid.uuid4())
    _seed_operation_device_cookie(client, device_id)

    await _prime(client, device_id, logger)
    csrf = await _step_csrf(client, device_id, session_id, logger)
    auth_url = await _step_signin(
        client,
        csrf,
        device_id,
        session_id,
        norm_email if use_login_hint else "",
        logger,
    )

    _, landing = await _follow_authorize(client, auth_url, logger)
    logger.info("[login] landing: %s", _short(landing, 100))

    if "/email-verification" in landing:
        logger.warning("[login] unsupported passwordless landing (email-verification)")
        raise LoginError(
            reason=_LOGIN_ERROR_INVALID_CREDENTIAL,
            message="Passwordless email verification not supported in password+totp flow",
        )

    _seed_operation_device_cookie(client, device_id)

    if log_fn:
        log_fn("   ↳ Xác thực thông tin mật khẩu (PoW Sentinel)...")

    data = await _password_verify(
        client,
        password,
        device_id,
        logger,
        on_credential_submitted=on_credential_submitted,
    )

    page_info = data.get("page") or {}
    page_type = str(page_info.get("type") or "").strip()
    continue_url = str(data.get("continue_url") or "").strip()
    logger.info("[login] post-password: page_type=%s continue=%s", page_type, _short(continue_url, 80))

    if page_type == "push_auth_verification" or "push-auth-verification" in continue_url:
        logger.warning("[login] push_auth_verification checkpoint (device approval required)")
        raise LoginError(
            reason=_LOGIN_ERROR_PUSH_AUTH_REQUIRED,
            message="Device approval required on user phone",
            diagnostic={"stage": "password_verify", "reason": "push_auth_required"},
        )

    if "mfa" in page_type or "mfa" in continue_url or "/mfa-challenge" in continue_url:
        match = _MFA_CHALLENGE_RE.search(continue_url)
        if not match:
            logger.warning("[login] MFA challenge required but challenge_id not found in %s", continue_url)
            raise LoginError(reason=_LOGIN_ERROR_MFA_REQUIRED)
        challenge_id = match.group(1)

        if not totp_secret:
            logger.warning("[login] MFA required but totp_secret is missing")
            raise LoginError(reason=_LOGIN_ERROR_MFA_REQUIRED, message="Tài khoản yêu cầu 2FA nhưng không có secret")

        if log_fn:
            log_fn("   ↳ Xác thực mã 2FA (TOTP + PoW)...")

        await _mfa_issue(client, challenge_id, device_id, logger)
        mfa_sentinel = await get_sentinel_token(
            client, device_id=device_id, flow="mfa_verify", logger=logger
        )

        try:
            totp_obj = pyotp.TOTP(totp_secret)
            code = totp_obj.now()
        except Exception as exc:
            logger.warning("[login] invalid TOTP secret: %s", exc)
            raise LoginError(reason=_LOGIN_ERROR_MFA_REQUIRED, message="Secret 2FA không hợp lệ") from exc

        try:
            mfa_data = await _mfa_verify(
                client, challenge_id, code, device_id, mfa_sentinel, logger
            )
        except LoginError as mfa_err:
            drift_ok = False
            mfa_msg = str(getattr(mfa_err, "message", None) or mfa_err)
            if "không đúng" in mfa_msg or "incorrect" in mfa_msg:
                import time as _t
                for offset in (-30, 30):
                    drift_code = totp_obj.at(_t.time() + offset)
                    if drift_code != code:
                        try:
                            mfa_sentinel_drift = await get_sentinel_token(
                                client, device_id=device_id, flow="mfa_verify", logger=logger
                            )
                            mfa_data = await _mfa_verify(
                                client, challenge_id, drift_code, device_id, mfa_sentinel_drift, logger
                            )
                            drift_ok = True
                            if log_fn:
                                log_fn(f"   ↳ [TOTP drift] Đồng bộ thành công với lệch giờ ({offset:+d}s)")
                            break
                        except Exception:
                            pass
            if not drift_ok:
                raise

        continue_url = str(mfa_data.get("continue_url") or "").strip()

    if continue_url.startswith("/"):
        continue_url = urljoin(_AUTH_BASE, continue_url)

    cb = await _resolve_callback(client, continue_url, device_id, session_id, logger)
    if not cb:
        logger.warning("[login] callback URL not found in redirect chain")
        raise LoginError(reason=_LOGIN_ERROR_NETWORK)

    if not await _consume_callback_verified(client, cb, logger):
        logger.warning("[login] callback consumed but session-token cookie NOT set")
        raise LoginError(reason=_LOGIN_ERROR_NETWORK)

    session_payload = await _get_session(client, device_id, session_id, logger)
    access_token = _extract_access_token(session_payload)
    if not access_token:
        logger.warning("[login] /api/auth/session missing accessToken: %s", _short(str(session_payload), 200))
        raise LoginError(reason=_LOGIN_ERROR_NETWORK)

    cookies_snapshot = _snapshot_cookies(client)
    logger.info(
        "[login] ✓ session OK — access_token_len=%d cookies=%d",
        len(access_token),
        len(cookies_snapshot),
    )
    if log_fn:
        log_fn("   ↳ Đăng nhập thành công! Đã lấy phiên làm việc an toàn.")

    bundle = SessionBundle(
        email=norm_email, access_token=access_token, cookies=cookies_snapshot
    )
    return bundle, session_payload


async def login_pure_request(
    email: str,
    password: str,
    totp_secret: str | None,
    http_client: http.AsyncSession,
    logger: logging.Logger,
    *,
    use_login_hint: bool = True,
    on_credential_submitted: Callable[[], None] | None = None,
) -> SessionBundle:
    """Execute full ChatGPT HTTP login flow -> SessionBundle."""
    bundle, _ = await login_pure_request_with_payload(
        email=email,
        password=password,
        totp_secret=totp_secret,
        http_client=http_client,
        logger=logger,
        use_login_hint=use_login_hint,
        on_credential_submitted=on_credential_submitted,
    )
    return bundle


__all__ = [
    "login_pure_request",
    "login_pure_request_with_payload",
]
