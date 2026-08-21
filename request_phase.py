"""Pure-request registration phase — no browser required.

Implements the full OpenAI signup state machine via HTTP requests (curl_cffi):
  1. chatgpt.com CSRF + signin/openai → authorize URL
  2. OAuth init → device_id
  3. Sentinel token (QuickJS primary, Python PoW fallback)
  4. authorize/continue (email submission)
  5. register password
  6. OTP send → poll via existing mail providers → verify
  7. create_account (name + birthdate)
  8. Follow redirect chain → callback URL
  9. Consume callback → session_token + access_token

Adapts the protocol from github.com/Regert888/gpt-outlook-register to work
with the existing gpt_signup_hybrid mail providers and SignupRequest/SignupResult.

Public API:
    run_request_phase(request, mail_provider, log) -> SignupResult
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import random
import re
import time
import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Callable
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from curl_cffi import requests as curl_requests

from user_agent_profile import (
    CURL_IMPERSONATE_CANDIDATES as _UA_IMPERSONATE_CANDIDATES,
    CURL_IMPERSONATE_PRIMARY as _UA_IMPERSONATE_PRIMARY,
    SEC_CH_UA,
    SEC_CH_UA_MOBILE,
    SEC_CH_UA_PLATFORM,
    WINDOWS_USER_AGENT,
)

if TYPE_CHECKING:
    from mail_providers import MailProvider
    from models import SignupRequest, SignupResult

logger = logging.getLogger(__name__)


class RequestPhaseError(Exception):
    """Pure-request registration failed."""


# ─── Constants ────────────────────────────────────────────────────────

# Re-export cho backward compatibility (session_phase + module khác đã import).
USER_AGENT = WINDOWS_USER_AGENT

_FIRST_NAMES = [
    "James", "John", "Robert", "Michael", "William", "David", "Richard",
    "Joseph", "Thomas", "Charles", "Mary", "Patricia", "Jennifer", "Linda",
    "Elizabeth", "Barbara", "Susan", "Jessica", "Sarah", "Karen",
]
_LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Rodriguez", "Martinez", "Wilson", "Anderson", "Taylor", "Thomas",
]


# ─── Datadog trace headers (critical for OTP delivery) ────────────────


def _datadog_trace_headers() -> dict[str, str]:
    """Generate Datadog APM trace headers.

    OpenAI frontend uses Datadog RUM — all real browser requests carry these.
    Missing headers cause silent OTP drop (200 OK but no email sent).
    """
    trace_id = str(random.getrandbits(64))
    parent_id = str(random.getrandbits(64))
    trace_hex = format(int(trace_id), "016x")
    parent_hex = format(int(parent_id), "016x")
    return {
        "traceparent": f"00-0000000000000000{trace_hex}-{parent_hex}-01",
        "tracestate": "dd=s:1;o:rum",
        "x-datadog-origin": "rum",
        "x-datadog-parent-id": parent_id,
        "x-datadog-sampling-priority": "1",
        "x-datadog-trace-id": trace_id,
    }


# ─── Session factory ─────────────────────────────────────────────────


def _create_session(proxy: str | None, impersonate: str = _UA_IMPERSONATE_PRIMARY) -> curl_requests.Session:
    session = curl_requests.Session(impersonate=impersonate)
    session.trust_env = False
    if proxy:
        normalized = proxy
        if proxy.startswith("socks5://"):
            normalized = "socks5h://" + proxy[len("socks5://"):]
        session.proxies = {"https": normalized, "http": normalized}
    else:
        session.proxies = {"https": "", "http": ""}
    return session


# TLS fingerprint candidates — rotate on TLS handshake failure (from gpt-outlook-register).
# Đồng bộ với UA: cùng Chrome family, version giảm dần. Defined in user_agent_profile
# để khớp với WINDOWS_USER_AGENT (CHROME_MAJOR).
_IMPERSONATE_CANDIDATES = list(_UA_IMPERSONATE_CANDIDATES)


def _is_tls_error(exc: BaseException) -> bool:
    """Detect curl_cffi TLS handshake errors → worth rotating fingerprint."""
    msg = str(exc).lower()
    markers = [
        "curl: (35)", "tls connect error", "openssl_internal", "sslerror",
        "curl: (56)", "curl: (7)", "ssl_error", "handshake",
    ]
    return any(m in msg for m in markers)


def _is_cloudflare_block_error(exc: BaseException) -> bool:
    """Detect HTTP 403 từ chatgpt.com prime/csrf → Cloudflare bot-management
    flag JA3/JA4 fingerprint cụ thể.

    CF rate-limit / fingerprint-flag thường target 1 impersonate. Rotate sang
    Chrome 142 / 136 (chain ``_IMPERSONATE_CANDIDATES``) thường bypass được.
    Pattern này paralle với ``_is_tls_error`` — cùng trigger rotation chain
    trong ``_bootstrap_with_tls_rotation`` / ``session_phase._do_bootstrap``.
    """
    msg = str(exc).lower()
    if "http 403" not in msg:
        return False
    # Restrict marker để 403 từ endpoint khác (vd Stripe, OAuth) KHÔNG nhầm
    # trigger rotation — chỉ chatgpt.com prime/csrf cần fingerprint rotation.
    markers = ("prime chatgpt session", "csrf fetch")
    return any(m in msg for m in markers)


def _is_rotatable_error(exc: BaseException) -> bool:
    """Bao trùm error đáng rotate impersonate fingerprint:
    TLS handshake (curl_cffi) OR Cloudflare 403 fingerprint flag."""
    return _is_tls_error(exc) or _is_cloudflare_block_error(exc)


# ─── Sentinel ─────────────────────────────────────────────────────────


def _get_sentinel_token(session, device_id: str, flow: str, log: Callable, worker=None) -> str:
    """Get sentinel token: QuickJS primary → Python PoW fallback.

    ``worker`` (SentinelNodeWorker | None): nếu có → dùng persistent Node process
    (warm) thay vì spawn one-shot mỗi action.
    """
    disable_quickjs = os.getenv("OPENAI_SENTINEL_DISABLE_QUICKJS", "0").lower() in (
        "1", "true", "yes",
    )

    if not disable_quickjs:
        try:
            from sentinel_quickjs import get_sentinel_token_via_quickjs
            token = get_sentinel_token_via_quickjs(
                session,
                device_id,
                flow=flow,
                log=log,
                worker=worker,
            )
            if token:
                return token
            log("[sentinel] QuickJS failed, falling back to Python PoW")
        except Exception as e:
            log(f"[sentinel] QuickJS import/call error, fallback: {e}")

    from sentinel_pow import get_sentinel_token as _pow_token
    return _pow_token(session, device_id, flow=flow)


# ─── Common headers ──────────────────────────────────────────────────


def _common_headers(referer: str = "https://chatgpt.com/") -> dict[str, str]:
    origin = "https://chatgpt.com"
    try:
        parsed = urlparse(referer)
        if parsed.scheme and parsed.netloc:
            origin = f"{parsed.scheme}://{parsed.netloc}"
    except Exception:
        pass

    headers = {
        "Accept": "application/json",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": referer,
        "Origin": origin,
        "User-Agent": USER_AGENT,
        # Client Hints — Chrome desktop luôn gửi 3 header này (low-entropy hints,
        # không cần Accept-CH). Bắt buộc đồng bộ với USER_AGENT để tránh mismatch.
        "sec-ch-ua": SEC_CH_UA,
        "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
    }
    headers.update(_datadog_trace_headers())
    return headers


def _navigation_headers(
    referer: str,
    *,
    sec_fetch_site: str,
) -> dict[str, str]:
    """Headers cho top-level HTML navigation, tách biệt API/fetch headers.

    Document GET không gửi ``Origin``/Datadog headers như ``_common_headers``.
    Giữ helper riêng để OAuth/password navigation không vô tình bị nhận diện
    như XHR và trả SPA/challenge landing sai state.
    """
    if sec_fetch_site not in {"same-origin", "cross-site", "none"}:
        raise ValueError(f"invalid Sec-Fetch-Site: {sec_fetch_site!r}")
    return {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Referer": referer,
        "User-Agent": USER_AGENT,
        "sec-ch-ua": SEC_CH_UA,
        "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": sec_fetch_site,
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Connection": "keep-alive",
    }


def _safe_url_without_query(value: str) -> str:
    """Giữ scheme/host/path để log, loại query OAuth có state nhạy cảm."""
    try:
        parsed = urlparse(value)
        return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
    except Exception:
        return (value or "").split("?", 1)[0][:200]


def _validate_auth_landing(
    response,
    *,
    step: str,
    requested_url: str,
    expected_path: str | None = None,
) -> str:
    """Validate response cuối của một auth document navigation.

    Chỉ HTTP 200 + HTTPS ``auth.openai.com`` + HTML thật mới được đi tiếp.
    Khi ``expected_path`` có giá trị, redirect sang login/error/landing khác bị
    chặn trước khi Sentinel hoặc ``user/register`` dùng state sai.
    """
    try:
        status = int(getattr(response, "status_code", -1))
    except (TypeError, ValueError):
        status = -1
    final_url = str(getattr(response, "url", "") or requested_url or "")
    safe_url = _safe_url_without_query(final_url)
    response_headers = getattr(response, "headers", {}) or {}
    content_type = str(
        response_headers.get("content-type")
        or response_headers.get("Content-Type")
        or ""
    ).casefold()
    cf_ray = str(
        response_headers.get("cf-ray")
        or response_headers.get("CF-RAY")
        or ""
    ).strip()
    ray_suffix = f" cf_ray={cf_ray[:80]}" if cf_ray else ""

    if status != 200:
        raise RequestPhaseError(
            f"{step} failed: HTTP {status} url={safe_url!r}{ray_suffix}"
        )

    try:
        parsed = urlparse(final_url)
        port = parsed.port
    except (TypeError, ValueError) as exc:
        raise RequestPhaseError(
            f"{step} failed: invalid final URL {safe_url!r}"
        ) from exc
    if (
        parsed.scheme.casefold() != "https"
        or (parsed.hostname or "").casefold() != "auth.openai.com"
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
    ):
        raise RequestPhaseError(
            f"{step} failed: invalid landing host url={safe_url!r}"
        )

    normalized_path = (parsed.path or "/").rstrip("/") or "/"
    if expected_path is not None:
        normalized_expected = expected_path.rstrip("/") or "/"
        if normalized_path != normalized_expected:
            raise RequestPhaseError(
                f"{step} failed: invalid landing path={normalized_path!r} "
                f"expected={normalized_expected!r}"
            )
    elif normalized_path == "/auth/error":
        raise RequestPhaseError(
            f"{step} failed: auth error landing url={safe_url!r}"
        )

    if content_type and not any(
        value in content_type for value in ("text/html", "application/xhtml+xml")
    ):
        raise RequestPhaseError(
            f"{step} failed: non-HTML landing content_type={content_type[:120]!r}"
        )

    try:
        body_preview = str(getattr(response, "text", "") or "")[:5000].casefold()
    except Exception:
        body_preview = ""
    challenge_markers = (
        "<title>just a moment",
        "cf-chl-",
        "challenge-platform",
        'id="challenge-running"',
        "attention required! | cloudflare",
    )
    if any(marker in body_preview for marker in challenge_markers):
        raise RequestPhaseError(
            f"{step} failed: Cloudflare challenge url={safe_url!r}{ray_suffix}"
        )
    return final_url


def _bootstrap_password_page(session, *, referer: str, log: Callable) -> str:
    """Mở và xác nhận đúng password page trước khi tạo Sentinel/register."""
    url = "https://auth.openai.com/create-account/password"
    try:
        response = session.get(
            url,
            headers=_navigation_headers(referer, sec_fetch_site="same-origin"),
            timeout=30,
            allow_redirects=True,
        )
    except Exception as exc:
        raise RequestPhaseError(
            "create-account password bootstrap failed: "
            f"{type(exc).__name__}: {exc}"
        ) from exc

    status = getattr(response, "status_code", "?")
    final_url = str(getattr(response, "url", "") or url)
    log(
        "[request] password page bootstrap: "
        f"HTTP {status} url={_safe_url_without_query(final_url)[:120]!r}"
    )
    return _validate_auth_landing(
        response,
        step="create-account password bootstrap",
        requested_url=url,
        expected_path="/create-account/password",
    )


# ─── Auth state machine steps ─────────────────────────────────────────


def _prime_chatgpt_session(session, log: Callable) -> None:
    """Prime chatgpt.com session bằng GET /auth/login (HTML SSR page).

    Bug observed (verified qua test/diag_login_bootstrap.py):
        Khi GET trực tiếp `/api/auth/csrf` với jar trống, NextAuth chatgpt.com
        TRẢ về ``csrfToken`` JSON nhưng KHÔNG set cookie
        ``__Host-next-auth.csrf-token`` đi kèm. Hệ quả: POST tiếp theo tới
        ``/api/auth/signin/openai`` bị NextAuth reject với
        ``{ url: "/api/auth/signin?csrf=true" }`` (CSRF mismatch — body có
        token nhưng cookie thiếu/khác). Cascade thành HTTP 409 ``invalid_state``
        khi state machine đi tiếp tới ``authorize/continue``.

    Root cause: chatgpt.com chỉ set cookie csrf-token qua `/api/auth/csrf` KHI
        jar đã có Cloudflare bot-management cookies (``__cf_bm``, ``_cfuvid``,
        ``__cflb``). Browser thật luôn navigate qua trang HTML trước khi gọi
        API → CF cookies tự có. Pure-request hit thẳng API → thiếu CF cookies
        → server degrade response (giữ token nhưng bỏ Set-Cookie).

    Fix: GET ``/auth/login`` HTML page TRƯỚC ``/api/auth/csrf``. CF middleware
        sẽ set ``__cf_bm`` + ``__cflb`` + ``_cfuvid`` ở response này. Lần GET
        ``/api/auth/csrf`` kế tiếp sẽ set csrf-token cookie chuẩn.

    Idempotent: skip nếu jar đã có ``__cf_bm`` (đã prime trước đó trong cùng
        session). An toàn gọi nhiều lần.
    """
    try:
        if any(c.name == "__cf_bm" for c in session.cookies.jar):
            return
    except Exception:
        # Cookie jar API không expose .jar → fall through, prime lại không hại.
        pass

    log("[request] [0/9] Priming chatgpt.com session (GET /auth/login)...")
    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br, zstd",
        "Referer": "https://chatgpt.com/",
        "User-Agent": USER_AGENT,
        "sec-ch-ua": SEC_CH_UA,
        "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Connection": "keep-alive",
    }
    # Retry up to 3x on Cloudflare 403 (transient bot-management challenge),
    # backoff 5s/10s — đồng bộ pattern `_step_csrf`. Cùng host (chatgpt.com)
    # → cùng kiểu lỗi: CF middleware đôi khi trả 403 trước khi cấp __cf_bm,
    # retry với jar warm sau 5-10s thường pass.
    resp = None
    for attempt in range(3):
        resp = session.get(
            "https://chatgpt.com/auth/login",
            headers=headers,
            timeout=30,
            allow_redirects=True,
        )
        if resp.status_code == 403 and attempt < 2:
            wait = (attempt + 1) * 5
            log(f"[request] prime 403, retrying in {wait}s ({attempt + 1}/3)...")
            time.sleep(wait)
            continue
        break
    if resp is None or resp.status_code >= 400:
        raise RequestPhaseError(
            f"prime chatgpt session failed: HTTP {resp.status_code if resp else '?'}"
        )


def _step_csrf(session, log: Callable) -> str:
    """Step 1: GET chatgpt.com/api/auth/csrf → csrfToken.

    Tự động prime session qua ``_prime_chatgpt_session`` trước để đảm bảo
    NextAuth set cookie ``__Host-next-auth.csrf-token`` cho lần POST
    ``/api/auth/signin/openai`` kế tiếp (xem docstring _prime_chatgpt_session).

    Retry up to 3x on Cloudflare 403 (transient rate-limit), backoff 5s/10s.
    """
    _prime_chatgpt_session(session, log)
    log("[request] [1/9] Fetching CSRF token...")
    headers = _common_headers("https://chatgpt.com/auth/login")
    resp = None
    for attempt in range(3):
        resp = session.get(
            "https://chatgpt.com/api/auth/csrf",
            headers=headers,
            timeout=30,
        )
        if resp.status_code == 403 and attempt < 2:
            wait = (attempt + 1) * 5
            log(f"[request] Cloudflare 403, retrying in {wait}s ({attempt + 1}/3)...")
            time.sleep(wait)
            continue
        break
    if resp is None or resp.status_code != 200:
        raise RequestPhaseError(f"CSRF fetch failed: HTTP {resp.status_code if resp else '?'}")
    csrf = resp.json().get("csrfToken", "")
    if not csrf:
        raise RequestPhaseError("CSRF token missing from response")
    log(f"[request] CSRF: {csrf[:20]}...")
    return csrf


def _bootstrap_with_tls_rotation(
    proxy: str | None,
    log: Callable,
    *,
    login_hint: str = "",
) -> tuple[Any, str, str]:
    """Bootstrap CSRF + auth_url + OAuth init with TLS fingerprint rotation.

    On TLS handshake error, rotates curl_cffi impersonate fingerprint
    qua các candidate trong ``_IMPERSONATE_CANDIDATES`` (chain Chrome desktop
    Windows: chrome145 → chrome142 → chrome136 — đồng bộ với
    ``user_agent_profile.WINDOWS_USER_AGENT``).
    Bootstrap steps carry no critical session state yet, so restarting is safe.

    Returns: (session, device_id, auth_url)
    """
    last_exc: BaseException | None = None
    for idx, impersonate in enumerate(_IMPERSONATE_CANDIDATES):
        session = _create_session(proxy=proxy, impersonate=impersonate)
        try:
            if idx > 0:
                log(f"[request] fingerprint rotation: retrying with impersonate={impersonate}")
            device_id = str(uuid.uuid4())
            try:
                session.cookies.set("oai-did", device_id, domain="chatgpt.com")
            except Exception as exc:
                log(f"[request] seed oai-did cookie skipped: {type(exc).__name__}")
            csrf = _step_csrf(session, log)
            auth_url = _step_auth_url(
                session,
                csrf,
                log,
                device_id=device_id,
                login_hint=login_hint,
                auth_session_logging_id=str(uuid.uuid4()),
            )
            device_id = _step_oauth_init(
                session,
                auth_url,
                log,
                expected_device_id=device_id,
            )
            return session, device_id, auth_url
        except Exception as e:
            last_exc = e
            try:
                session.close()
            except Exception:
                pass
            # Rotate impersonate khi: TLS handshake fail HOẶC CF 403 flag JA3
            # (cùng impersonate retry vô ích — phải đổi fingerprint Chrome).
            if _is_rotatable_error(e) and idx < len(_IMPERSONATE_CANDIDATES) - 1:
                continue
            raise
    # Exhausted all fingerprints
    if last_exc and _is_rotatable_error(last_exc):
        raise RequestPhaseError(
            f"Bootstrap failed với mọi impersonate fingerprint "
            f"({len(_IMPERSONATE_CANDIDATES)}× tried) — Cloudflare flag IP "
            f"hoặc network không reach chatgpt.com. Last error: {last_exc}"
        ) from last_exc
    if last_exc:
        raise last_exc
    raise RequestPhaseError("bootstrap failed unexpectedly")


def _step_auth_url(
    session,
    csrf_token: str,
    log: Callable,
    device_id: str = "",
    login_hint: str = "",
    auth_session_logging_id: str = "",
) -> str:
    """Step 2: POST chatgpt.com/api/auth/signin/openai → authorize URL.

    Must include query params matching browser:
    prompt=login, ext-oai-did, ext-passkey-client-capabilities, screen_hint=login_or_signup
    login_hint={email} for login flow (lets server route to password/verify directly).
    """
    log("[request] [2/8] Getting authorize URL...")
    headers = _common_headers("https://chatgpt.com/auth/login")
    headers["Content-Type"] = "application/x-www-form-urlencoded"

    # Query params matching browser (_nextauth_bootstrap.py)
    params = {
        "prompt": "login",
        "ext-passkey-client-capabilities": "01001",
        "screen_hint": "login_or_signup",
    }
    if device_id:
        params["ext-oai-did"] = device_id
    if auth_session_logging_id:
        params["auth_session_logging_id"] = auth_session_logging_id
    if login_hint:
        params["login_hint"] = login_hint

    from urllib.parse import urlencode as _urlencode
    url = "https://chatgpt.com/api/auth/signin/openai?" + _urlencode(params)

    resp = session.post(
        url,
        headers=headers,
        data={
            "csrfToken": csrf_token,
            "callbackUrl": "https://chatgpt.com/",
            "json": "true",
        },
        timeout=30,
    )
    if resp.status_code != 200:
        raise RequestPhaseError(f"signin/openai failed: HTTP {resp.status_code}")
    try:
        payload = resp.json()
    except Exception as exc:
        body_preview = (resp.text or "")[:400]
        raise RequestPhaseError(
            f"signin/openai: non-JSON response (HTTP {resp.status_code}): {body_preview}"
        ) from exc
    auth_url = payload.get("url", "") if isinstance(payload, dict) else ""
    if not auth_url:
        raise RequestPhaseError(
            f"signin/openai: no URL in response — payload={str(payload)[:300]}"
        )

    # Fail-fast: validate URL trỏ về auth.openai.com (OAuth provider thật).
    # NextAuth trả URL dạng `<chatgpt.com>/api/auth/signin?csrf=true&...` khi
    # CSRF validation fail (cookie `__Host-next-auth.csrf-token` không match
    # body `csrfToken`). Trước đây code accept URL này → đem GET → landing
    # trên chatgpt.com signin page → fallback gọi `authorize/continue` mà
    # OpenAI chưa có OAuth session → cascade thành HTTP 409 `invalid_state`.
    # Validate sớm để báo lỗi đúng chỗ + dump bằng chứng để debug.
    try:
        parsed_auth_url = urlparse(auth_url)
        auth_port = parsed_auth_url.port
    except (TypeError, ValueError):
        parsed_auth_url = None
        auth_port = None
    if (
        parsed_auth_url is None
        or parsed_auth_url.scheme.casefold() != "https"
        or (parsed_auth_url.hostname or "").casefold() != "auth.openai.com"
        or parsed_auth_url.username is not None
        or parsed_auth_url.password is not None
        or auth_port not in (None, 443)
    ):
        # Dump cookies hiện có (mask value) để diagnose CSRF mismatch.
        try:
            cookie_summary = ", ".join(
                sorted(
                    f"{c.name}={'<set>' if c.value else '<empty>'}"
                    for c in session.cookies.jar
                )
            )
        except Exception:
            cookie_summary = "<unavailable>"
        raise RequestPhaseError(
            "signin/openai trả URL không phải auth.openai.com — "
            "NextAuth từ chối (CSRF/origin/anti-bot). "
            f"Got: {_safe_url_without_query(auth_url)[:200]}. "
            f"Cookies: {cookie_summary[:300]}"
        )

    state_values = parse_qs(parsed_auth_url.query).get("state", [])
    if not any(str(value).strip() for value in state_values):
        raise RequestPhaseError(
            "signin/openai trả authorize URL thiếu OAuth state — "
            f"Got: {_safe_url_without_query(auth_url)[:200]}"
        )

    log(f"[request] Auth URL: {_safe_url_without_query(auth_url)[:100]}...")
    return auth_url


def _step_oauth_init(
    session,
    auth_url: str,
    log: Callable,
    *,
    expected_device_id: str = "",
) -> str:
    """Follow authorize URL and return one canonical, stable device ID."""
    log("[request] [3/9] OAuth init...")
    try:
        response = session.get(
            auth_url,
            headers=_navigation_headers(
                "https://chatgpt.com/",
                sec_fetch_site="cross-site",
            ),
            timeout=30,
            allow_redirects=True,
        )
    except Exception as exc:
        raise RequestPhaseError(
            f"OAuth bootstrap failed: {type(exc).__name__}: {exc}"
        ) from exc

    final_url = _validate_auth_landing(
        response,
        step="OAuth bootstrap",
        requested_url=auth_url,
    )
    log(
        "[request] OAuth landing: "
        f"HTTP {response.status_code} url={_safe_url_without_query(final_url)!r}"
    )

    # Extract device_id from cookies
    cookie_device_id = ""
    try:
        cookie_device_id = session.cookies.get("oai-did", "") or ""
    except Exception:
        pass

    if cookie_device_id:
        device_id = str(cookie_device_id)
        if expected_device_id and device_id != expected_device_id:
            log("[request] OAuth server refreshed oai-did; using cookie value")
        else:
            log("[request] OAuth oai-did confirmed")
    elif expected_device_id:
        device_id = expected_device_id
        log("[request] OAuth missing oai-did cookie; preserving seeded device_id")
    else:
        raise RequestPhaseError(
            "OAuth bootstrap failed: missing oai-did and expected device_id"
        )
    return device_id


def _step_authorize_continue(
    session,
    email: str,
    sentinel_token: str,
    screen_hint: str,
    referer: str,
    device_id: str,
    log: Callable,
) -> dict:
    """POST authorize/continue — submit email to auth state machine."""
    headers = _common_headers(referer)
    headers["Content-Type"] = "application/json"
    if sentinel_token:
        headers["openai-sentinel-token"] = sentinel_token
    if device_id:
        headers["oai-device-id"] = device_id

    payload = {
        "username": {"value": email, "kind": "email"},
        "screen_hint": screen_hint,
    }
    resp = session.post(
        "https://auth.openai.com/api/accounts/authorize/continue",
        headers=headers,
        json=payload,
        timeout=30,
    )
    if resp.status_code != 200:
        body = (resp.text or "")[:300]
        raise RequestPhaseError(
            f"authorize/continue failed: HTTP {resp.status_code} - {body}"
        )
    try:
        return resp.json()
    except Exception:
        return {}


def _step_signup(session, email: str, sentinel_token: str, device_id: str, log: Callable) -> bool:
    """Step 4: Submit email → detect new vs existing account.

    Returns True for new account, False for existing.
    """
    log("[request] [4/9] Submitting email...")
    data = _step_authorize_continue(
        session, email, sentinel_token,
        screen_hint="signup",
        referer="https://auth.openai.com/create-account",
        device_id=device_id,
        log=log,
    )

    page = data.get("page", {}) if isinstance(data, dict) else {}
    page_type = (page.get("type") or "").strip()
    continue_url = (data.get("continue_url") or "").strip()

    if page_type == "create_account_password" or "/create-account/password" in continue_url:
        log("[request] New account detected")
        return True

    if page_type in ("email_otp_verification", "login_password"):
        log(f"[request] Existing account detected (page_type={page_type})")
        return False

    log(f"[request] Unknown page_type={page_type!r}, treating as existing")
    return False


def _step_register_password(session, email: str, password: str, device_id: str, log: Callable) -> bool:
    """Step 5: Register password for new account."""
    log("[request] [5/9] Registering password...")

    # Visit password page first (establish server state)
    try:
        session.get(
            "https://auth.openai.com/create-account/password",
            headers=_common_headers("https://auth.openai.com/create-account"),
            timeout=15,
        )
    except Exception:
        pass

    # Refresh sentinel for username_password_create flow
    sentinel = _get_sentinel_token(session, device_id, "username_password_create", log)

    headers = _common_headers("https://auth.openai.com/create-account/password")
    headers["Content-Type"] = "application/json"
    if sentinel:
        headers["openai-sentinel-token"] = sentinel
    if device_id:
        headers["oai-device-id"] = device_id

    resp = session.post(
        "https://auth.openai.com/api/accounts/user/register",
        headers=headers,
        json={"password": password, "username": email},
        timeout=30,
    )
    if resp.status_code != 200:
        log(f"[request] Register password failed: {resp.status_code} - {(resp.text or '')[:200]}")
        return False
    log("[request] Password registered")
    return True


def _step_send_otp(session, device_id: str, log: Callable) -> None:
    """Step 6a: Trigger OTP email delivery."""
    log("[request] [6/9] Sending OTP...")
    headers = _common_headers("https://auth.openai.com/create-account/password")
    if device_id:
        headers["oai-device-id"] = device_id

    resp = session.get(
        "https://auth.openai.com/api/accounts/email-otp/send",
        headers=headers,
        timeout=30,
    )
    if resp.status_code != 200:
        # Fallback: try passwordless send
        headers2 = _common_headers("https://auth.openai.com/create-account/password")
        headers2["Content-Type"] = "application/json"
        if device_id:
            headers2["oai-device-id"] = device_id
        resp2 = session.post(
            "https://auth.openai.com/api/accounts/passwordless/send-otp",
            headers=headers2,
            timeout=30,
        )
        if resp2.status_code != 200:
            raise RequestPhaseError(
                f"OTP send failed: primary={resp.status_code} fallback={resp2.status_code}"
            )
    log("[request] OTP sent")


def _step_resend_otp(session, device_id: str, log: Callable) -> bool:
    """Resend OTP (for existing account flow)."""
    headers = _common_headers("https://auth.openai.com/email-verification")
    headers["Content-Type"] = "application/json"
    if device_id:
        headers["oai-device-id"] = device_id
    resp = session.post(
        "https://auth.openai.com/api/accounts/email-otp/resend",
        headers=headers,
        timeout=30,
    )
    if resp.status_code == 200:
        log("[request] OTP resent")
        return True
    log(f"[request] OTP resend failed: {resp.status_code}")
    return False


def _step_verify_otp(
    session, otp_code: str, device_id: str, log: Callable,
    *, raise_on_fail: bool = True,
) -> dict:
    """Step 7: Verify OTP code.

    raise_on_fail=True (mặc định, cho session_phase): raise RequestPhaseError nếu
    HTTP != 200. raise_on_fail=False (cho retry ở request_phase): trả dict kèm
    metadata ``_ok`` / ``_status`` / ``_body`` để caller tự quyết định retry.
    """
    log("[request] [7/9] Verifying OTP...")
    headers = _common_headers("https://auth.openai.com/email-verification")
    headers["Content-Type"] = "application/json"
    if device_id:
        headers["oai-device-id"] = device_id

    resp = session.post(
        "https://auth.openai.com/api/accounts/email-otp/validate",
        headers=headers,
        json={"code": otp_code},
        timeout=30,
    )
    if resp.status_code != 200:
        body = resp.text or ""
        if raise_on_fail:
            raise RequestPhaseError(
                f"OTP verify failed: HTTP {resp.status_code} - {body[:200]}"
            )
        log(f"[request] OTP verify HTTP {resp.status_code}: {body[:120]}")
        return {"_ok": False, "_status": resp.status_code, "_body": body}
    log("[request] OTP verified")
    try:
        data = resp.json()
    except Exception:
        data = {}
    if isinstance(data, dict):
        data["_ok"] = True
        data["_status"] = 200
    return data


def _step_create_account(
    session, name: str, birthdate: str, device_id: str, log: Callable,
    sentinel_token: str | None = None, worker=None,
) -> str:
    """Step 8: Create account (fill name + birthdate) → continue_url.

    ``sentinel_token``: nếu đã pre-compute sẵn (song song lúc poll OTP) thì dùng
    luôn, bỏ qua bước tính sentinel tại đây. None → tính mới.
    """
    log("[request] [8/9] Creating account...")

    # Refresh sentinel for create_account flow (dùng token pre-computed nếu có)
    sentinel = sentinel_token or _get_sentinel_token(
        session, device_id, "create_account", log, worker=worker,
    )

    headers = _common_headers("https://auth.openai.com/about-you")
    headers["Content-Type"] = "application/json"
    if sentinel:
        headers["openai-sentinel-token"] = sentinel
    if device_id:
        headers["oai-device-id"] = device_id

    resp = session.post(
        "https://auth.openai.com/api/accounts/create_account",
        headers=headers,
        json={"name": name, "birthdate": birthdate},
        timeout=30,
    )
    if resp.status_code != 200:
        raise RequestPhaseError(
            f"create_account failed: HTTP {resp.status_code} - {(resp.text or '')[:300]}"
        )
    data = resp.json()
    continue_url = (data.get("continue_url") or "").strip()
    if not continue_url:
        raise RequestPhaseError("create_account: no continue_url in response")
    log("[request] Account created")
    return continue_url


def _step_follow_redirects(session, start_url: str, log: Callable) -> tuple[str, str]:
    """Step 9: Follow redirect chain → (callback_url, final_url)."""
    log("[request] [9/9] Following redirect chain...")
    current = start_url
    callback_url = ""

    for i in range(12):
        if "/api/auth/callback/openai" in current and "code=" in current:
            callback_url = current
            break

        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": "https://chatgpt.com/",
            "User-Agent": USER_AGENT,
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
        }
        resp = session.get(current, headers=headers, timeout=30, allow_redirects=False)

        if resp.status_code in (301, 302, 303, 307, 308):
            location = (resp.headers.get("Location") or "").strip()
            if not location:
                break
            if location.startswith("/"):
                parsed = urlparse(current)
                location = f"{parsed.scheme}://{parsed.netloc}{location}"
            if "/api/auth/callback/openai" in location and "code=" in location:
                callback_url = location
                current = location
                break
            current = location
        else:
            break

    log(f"[request] Redirect chain done, callback={'found' if callback_url else 'missing'}")
    return callback_url, current


def _consume_callback(session, callback_url: str, log: Callable) -> bool:
    """Follow callback redirect chain hop-by-hop để NextAuth set + capture
    session-token cookie vào Python cookie jar.

    QUAN TRỌNG — KHÔNG dùng ``allow_redirects=True``: khi libcurl tự follow
    redirect, cookie ``__Secure-next-auth.session-token`` được set ở response
    TRUNG GIAN (302 của ``/api/auth/callback/openai``) chỉ nằm trong cookie
    store nội bộ của libcurl. curl_cffi chỉ sync Set-Cookie của response CUỐI
    về ``session.cookies`` phía Python → cookie session-token bị mất khỏi jar
    (dù request kế tiếp tới ``/api/auth/session`` vẫn gửi được nên accessToken
    vẫn lấy được). Hệ quả: ``session_token`` rỗng dù account đã đăng nhập.

    Fix: follow từng hop với ``allow_redirects=False`` để curl_cffi sync
    Set-Cookie của MỖI response về jar — giống ``_step_follow_redirects``.

    NextAuth có thể chunk cookie thành ``.0`` / ``.1`` khi JWT > 4KB; dừng sớm
    ngay khi ``_read_session_token_cookie`` ghép được token từ jar.
    """
    if not callback_url or "code=" not in callback_url:
        return False

    headers = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://auth.openai.com/",
        "User-Agent": USER_AGENT,
        "sec-ch-ua": SEC_CH_UA,
        "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
    }

    current = callback_url
    try:
        for _ in range(12):
            resp = session.get(
                current, headers=headers, timeout=30, allow_redirects=False,
            )

            # Cookie có thể được set ở bất kỳ hop nào → check ngay sau mỗi hop.
            if _read_session_token_cookie(session):
                return True

            if resp.status_code in (301, 302, 303, 307, 308):
                location = (resp.headers.get("Location") or "").strip()
                if not location:
                    break
                if location.startswith("/"):
                    parsed = urlparse(current)
                    location = f"{parsed.scheme}://{parsed.netloc}{location}"
                current = location
                continue
            break

        return bool(_read_session_token_cookie(session))
    except Exception as e:
        log(f"[request] Consume callback error: {e}")
        return False


def _read_session_token_cookie(session) -> str:
    """Đọc cookie ``__Secure-next-auth.session-token`` (kèm reassembly chunk).

    NextAuth chunk session-token thành ``.0`` / ``.1`` / ... khi JWT > 4KB
    (rất thường gặp với account ChatGPT vì payload lớn). curl_cffi
    ``cookies.get("...session-token")`` chỉ trả cookie tên gốc → rỗng khi bị
    chunk → ``session_token`` mất trắng dù account đã đăng nhập thật.

    Mirror logic ``http_phase._extract_session_from_handoff``: ưu tiên cookie
    tên gốc; nếu không có thì ghép các chunk ``.N`` theo thứ tự index tăng dần.
    """
    base = session.cookies.get("__Secure-next-auth.session-token", "") or ""
    if base:
        return base

    chunks: dict[int, str] = {}
    prefix = "__Secure-next-auth.session-token."
    try:
        for cookie in session.cookies:
            name = getattr(cookie, "name", "") or ""
            value = getattr(cookie, "value", "") or ""
            if name.startswith(prefix) and value:
                suffix = name[len(prefix):]
                try:
                    chunks[int(suffix)] = value
                except ValueError:
                    continue
    except Exception:
        return ""

    if not chunks:
        return ""
    return "".join(chunks[k] for k in sorted(chunks))


def _get_session_tokens(session, log: Callable) -> tuple[str, str, str]:
    """GET /api/auth/session → (session_token, access_token, user_id)."""
    headers = _common_headers("https://chatgpt.com/")
    resp = session.get(
        "https://chatgpt.com/api/auth/session",
        headers=headers,
        timeout=30,
    )
    if resp.status_code != 200:
        log(f"[request] /api/auth/session HTTP {resp.status_code}")
        return "", "", ""

    data = resp.json() if resp is not None else {}
    access_token = data.get("accessToken", "") or ""
    user = data.get("user", {}) or {}
    user_id = user.get("id", "") or ""

    # Session token from cookie (reassembly chunk .0/.1 nếu NextAuth split JWT).
    session_token = _read_session_token_cookie(session)
    return session_token, access_token, user_id


# ─── OTP polling bridge (async mail provider → sync wait) ─────────────


async def _poll_otp_async(
    provider: MailProvider,
    *,
    recipient: str,
    started_at: datetime,
    timeout_seconds: float,
    poll_interval_seconds: float,
    log: Callable,
) -> str:
    """Async wrapper for mail provider OTP polling."""
    return await provider.poll_otp(
        recipient=recipient,
        started_at=started_at,
        timeout_seconds=timeout_seconds,
        poll_interval_seconds=poll_interval_seconds,
        log=log,
    )


# ─── Main orchestrator ────────────────────────────────────────────────


def _acquire_fresh_otp(
    *,
    session,
    device_id: str,
    mail_provider: MailProvider,
    request: SignupRequest,
    log: Callable,
    loop,
    started_at: datetime,
    tried_codes: set[str],
    pending: list[str],
    max_resends: int,
    prefer_second_code: bool = False,
) -> tuple[str, int]:
    """Lấy 1 OTP code chưa nằm trong ``tried_codes`` — mirror vòng poll đầu của
    ``browser_phase._run_signup_flow``.

    Hành vi (theo thứ tự ưu tiên mỗi vòng):
      1. Pop ``pending`` (code dư từ ``poll_all_codes`` lần trước) chưa thử → trả ngay.
      2. Poll 1 chunk ngắn (15s) để kiểm tra ngưỡng resend kịp thời.
      3. Nhận code MỚI → ``poll_all_codes`` để bắt mail delay (iCloud HME hay gửi
         trễ/nhiều mail OTP); nạp code dư vào ``pending``, trả code đầu.
      4. RESEND khi đã chờ quá ngưỡng (random ~[base*0.5, base], base =
         otp_resend_after_seconds) mà CHƯA có code mới — bất kể mailbox trả code cũ
         (stale) hay rỗng. Khác browser ở chỗ này: account MỚI mailbox chỉ có đúng
         1 code; nếu code đó sai thì KHÔNG bao giờ có code mới nếu không resend.
         Resend reset mốc thời gian + chỉ nhận code về SAU resend (``cur_started``).
      5. Hết quota ``max_resends`` hoặc chưa tới ngưỡng → chờ tiếp tới hết
         ``otp_timeout_seconds`` rồi raise.

    Mutates ``pending`` in-place. Trả ``(code, resends_used)``. Raise
    ``RequestPhaseError`` khi hết ``otp_timeout_seconds`` mà không có code mới.

    ``prefer_second_code``: khi mailbox có ≥2 mã ở lần fetch đầu, submit mã THỨ 2
        (mã "sau") trước, mã đầu giữ lại trong ``pending`` làm fallback. Dùng cho
        lần poll đầu — iCloud worker đôi khi thiếu ``date`` nên thứ tự không chắc
        mới→cũ; thực tế mã thứ 2 thường là mã hợp lệ.
    """
    recipient = request.source_email or request.email
    poll_interval = max(5.0, request.otp_poll_interval_seconds)
    # Poll theo chunk ngắn để check ngưỡng resend kịp thời ngay cả khi mailbox
    # chỉ trả code cũ (stale) hoặc rỗng liên tục.
    poll_chunk = 15.0

    def _resend_threshold() -> float:
        # Random hoá thời điểm resend (human-like) trong [base*0.5, base];
        # base = otp_resend_after_seconds (config). base=120s → ~60-120s ("1-2 phút").
        base = max(10.0, float(request.otp_resend_after_seconds))
        return random.uniform(base * 0.5, base)

    resend_count = 0
    stale_count = 0
    cur_started = started_at
    deadline = time.monotonic() + request.otp_timeout_seconds
    # Mốc đo thời gian chờ code mới — reset sau mỗi resend.
    resend_window_start = time.monotonic()
    resend_threshold = _resend_threshold()

    while True:
        # 1. Pop pending chưa thử trước khi đụng mạng.
        while pending:
            candidate = pending.pop(0)
            if candidate not in tried_codes:
                return candidate, resend_count

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RequestPhaseError(
                f"OTP timeout {request.otp_timeout_seconds:.0f}s — không nhận được "
                f"code mới (đã resend {resend_count} lần)"
            )

        # 2. Poll 1 chunk ngắn.
        chunk = min(poll_chunk, remaining)
        try:
            candidate = loop.run_until_complete(
                mail_provider.poll_otp(
                    recipient=recipient,
                    started_at=cur_started,
                    timeout_seconds=chunk,
                    poll_interval_seconds=poll_interval,
                    log=log,
                )
            )
        except TimeoutError:
            candidate = ""
        except Exception as exc:
            log(f"[request] poll OTP lỗi (tiếp tục): {type(exc).__name__}: {exc}")
            candidate = ""

        # 3. Code MỚI → fetch all để bắt mail delay, trả code đầu.
        if candidate and candidate not in tried_codes:
            time.sleep(2.0)
            all_codes: list[str] = []
            if hasattr(mail_provider, "poll_all_codes"):
                try:
                    all_codes = loop.run_until_complete(
                        mail_provider.poll_all_codes(
                            recipient=recipient,
                            started_at=cur_started,
                            log=log,
                        )
                    )
                except Exception:
                    all_codes = []
            fresh = [c for c in all_codes if c not in tried_codes]
            if not fresh:
                fresh = [candidate]
            elif candidate not in fresh:
                fresh.insert(0, candidate)
            if len(fresh) > 1:
                log(f"[request] nhận {len(fresh)} OTP codes mới: {', '.join(fresh)}")
            # prefer_second_code: có ≥2 mã ở lần fetch đầu → lấy mã THỨ 2 ("mã sau")
            # trước; mã đầu giữ lại pending làm fallback. Thứ tự worker không chắc
            # mới→cũ (thiếu date) nên mã thứ 2 thường mới là mã hợp lệ.
            if prefer_second_code and len(fresh) >= 2:
                first = fresh.pop(1)
                log(f"[request] ưu tiên submit mã thứ 2 ({first}), giữ {fresh[0]} fallback")
            else:
                first = fresh.pop(0)
            pending[:] = fresh
            return first, resend_count

        # 4. Code cũ (đã thử) lặp lại — log theo dõi.
        if candidate and candidate in tried_codes:
            stale_count += 1
            log(
                f"[request] poll trả code đã thử ({candidate}) → chờ code mới "
                f"(lần {stale_count})"
            )

        # 5. Chưa có code mới (stale HOẶC rỗng). Resend khi đã chờ quá ngưỡng + còn
        #    quota. Account MỚI mailbox chỉ có 1 code: code sai → phải resend mới có
        #    code mới, KHÔNG thể chờ suông.
        waited = time.monotonic() - resend_window_start
        if resend_count < max_resends and waited >= resend_threshold:
            resend_count += 1
            log(
                f"[request] chờ {waited:.0f}s chưa có code mới — resend OTP "
                f"({resend_count}/{max_resends})"
            )
            try:
                if not _step_resend_otp(session, device_id, log):
                    _step_send_otp(session, device_id, log)
            except Exception as exc:
                log(f"[request] resend OTP lỗi (vẫn poll tiếp): {exc}")
            time.sleep(2.0)
            # Chỉ nhận code về SAU resend; reset cửa sổ chờ + random ngưỡng mới.
            cur_started = datetime.now(timezone.utc)
            resend_window_start = time.monotonic()
            resend_threshold = _resend_threshold()
            continue

        # Chưa tới ngưỡng resend (hoặc hết quota) → chờ rồi poll lại.
        time.sleep(poll_interval)


def _prefer_newest_untried_otp(
    *,
    current: str,
    mail_provider: MailProvider,
    loop,
    recipient: str,
    started_at: datetime,
    tried_codes: set[str],
    pending: list[str],
    log: Callable,
) -> str:
    """Refresh mailbox 1 lần (non-blocking) ngay trước khi verify, trả code MỚI
    NHẤT chưa thử.

    Lý do: ``_acquire_fresh_otp`` trả code newest tại thời điểm gọi, nhưng có nhịp
    human-delay (2-4s) trước khi submit. Code mới hơn (OpenAI gửi lại / mail
    in-flight) có thể về đúng trong khoảng này. OpenAI vô hiệu code cũ khi phát code
    mới → verify code cũ trước sẽ ăn 401 dư thừa rồi mới retry sang code mới.

    An toàn với lệch giờ HME: nếu có code mới hơn, code hiện tại KHÔNG bị bỏ — nó
    được đẩy lên đầu ``pending`` để retry vẫn thử lại nếu code mới sai. Vì vậy hành
    vi luôn ``>=`` logic cũ (không bao giờ mất code, chỉ tiết kiệm 1 lần 401 khi
    đoán đúng).

    Chỉ áp dụng cho provider có ``poll_all_codes`` (worker/iCloud). Provider khác
    trả ``current`` nguyên trạng.
    """
    if not hasattr(mail_provider, "poll_all_codes"):
        return current
    try:
        codes = loop.run_until_complete(
            mail_provider.poll_all_codes(
                recipient=recipient, started_at=started_at, log=log,
            )
        )
    except Exception:
        return current

    # poll_all_codes trả mới→cũ. Chọn code mới nhất chưa thử.
    untried = [c for c in codes if c not in tried_codes]
    if not untried:
        return current
    newest = untried[0]
    if newest == current:
        return current

    # Có code mới hơn current → verify code này. Đẩy current + các untried còn lại
    # vào đầu pending (giữ thứ tự mới→cũ) để retry không mất code nào.
    fallback = [current] + [c for c in untried[1:] if c != current]
    for code in reversed(fallback):
        if code not in tried_codes and code not in pending:
            pending.insert(0, code)
    log(
        f"[request] code mới hơn ({newest}) vừa về trong lúc chờ → "
        f"verify code này thay cho {current} (giữ {current} làm fallback)"
    )
    return newest


def _run_request_phase_sync(
    request: SignupRequest,
    mail_provider: MailProvider,
    log: Callable,
    on_checkpoint: Callable | None = None,
) -> dict[str, Any]:
    """Synchronous core — runs in thread via asyncio.to_thread.

    Flow (matching browser HAR):
      1. CSRF + signin/openai (login_hint) → auth_url
      2. GET auth_url (OAuth init) → device_id
      3. Sentinel token
      4. POST /api/accounts/user/register (email + password) — DIRECT, no authorize/continue
      5. GET /api/accounts/email-otp/send
      6. Poll OTP (started_at = exact send time) → POST email-otp/validate
      7. POST /api/accounts/create_account
      8. Follow redirect chain → callback → session
    """
    worker = None
    try:
        # Persistent Node worker cho sentinel (warm — tránh cold-start V8 mỗi action).
        # Dùng chung cho cả sentinel #1 (register) và #2 (create_account, pre-computed).
        from sentinel_quickjs import create_worker as _create_sentinel_worker
        try:
            worker = _create_sentinel_worker(log)
        except Exception as _e:
            log(f"[request] sentinel worker init failed, dùng one-shot: {_e}")
            worker = None

        # Step 1-5: Bootstrap + Register. Không lặp lại cùng bootstrap khi
        # HTTP 409 invalid_state vì OAuth state hiện tại đã mất hiệu lực.
        #
        # Khi server trả 409 ``invalid_state`` ("Your sign-in session is no
        # longer valid"), state machine OAuth đã desync (CSRF/auth_url/sentinel
        # cũ không còn hợp lệ). Thực tế re-bootstrap Pure Request bằng cùng
        # chiến lược thường lặp lại 409 và chỉ làm job chậm thêm. Chỉ thử một
        # bootstrap; trả lỗi để job giữ nguyên mode và xử lý theo cấu hình retry.
        max_register_attempts = 1
        session = None
        device_id = ""
        password = request.password or _default_password(request.email)
        reg_continue = ""
        reg_page_type = ""

        for register_attempt in range(1, max_register_attempts + 1):
            # Đóng session cũ trước khi re-bootstrap (nếu có)
            if session is not None:
                try:
                    session.close()
                except Exception:
                    pass
                session = None

            # Step 1-3: Bootstrap with TLS fingerprint rotation on handshake failure.
            # Pass login_hint=email so authorize routes to the correct account context.
            session, device_id, _auth_url = _bootstrap_with_tls_rotation(
                request.proxy, log, login_hint=request.email,
            )

            # Step 4: establish and validate the exact password-page state.
            # Document navigation headers are intentionally different from API
            # headers. Redirects to login/error/challenge must fail here, before
            # Sentinel or user/register can turn the mismatch into invalid_state.
            password_page_url = _bootstrap_password_page(
                session,
                referer="https://auth.openai.com/create-account",
                log=log,
            )

            # Step 5: Sentinel (flow=username_password_create) + user/register
            sentinel = _get_sentinel_token(
                session, device_id, "username_password_create", log, worker=worker,
            )

            log("[request] [4/8] Registering account (password)...")
            reg_headers = _common_headers("https://auth.openai.com/create-account/password")
            reg_headers["Content-Type"] = "application/json"
            if sentinel:
                reg_headers["openai-sentinel-token"] = sentinel
            if device_id:
                reg_headers["oai-device-id"] = device_id

            resp = session.post(
                "https://auth.openai.com/api/accounts/user/register",
                headers=reg_headers,
                json={"password": password, "username": request.email},
                timeout=30,
            )

            if resp.status_code == 200:
                reg_data = resp.json() if resp is not None else {}
                reg_continue = (reg_data.get("continue_url") or "").strip()
                reg_page_type = ((reg_data.get("page") or {}).get("type") or "").strip()
                log(f"[request] Register OK → page_type={reg_page_type!r} continue_url={reg_continue[:80]!r}")
                # LƯU Ý: page_type=email_otp_verification sau user/register LÀ HỢP LỆ cho
                # account MỚI (server yêu cầu verify email vừa nhập). KHÔNG được coi là
                # "đã tồn tại". Signal duy nhất cho email đã đăng ký là HTTP 400 invalid_auth_step.
                break  # success → exit retry loop

            # 400 invalid_auth_step = email đã đăng ký rồi → fail-fast, KHÔNG retry
            if resp.status_code == 400 and "invalid_auth_step" in (resp.text or ""):
                raise RequestPhaseError(
                    f"email {request.email} đã được đăng ký (invalid_auth_step) "
                    f"— cần email mới để reg"
                )

            body = (resp.text or "")[:300]

            # 409 invalid_state = state machine desync. Không lặp lại mù quáng
            # trong cùng attempt và không tự chuyển registration mode.
            if resp.status_code == 409 and "invalid_state" in body:
                log(
                    "[request] user/register HTTP 409 invalid_state: "
                    f"password_landing={_safe_url_without_query(password_page_url)!r} "
                    f"body={body[:200]}"
                )
                raise RequestPhaseError(
                    "user/register HTTP 409 invalid_state — auth state không hợp lệ; "
                    f"cần session mới hoặc Browser mode - {body}"
                )

            # Lỗi khác (5xx, 401, 422...) → fail-fast, không retry mù quáng
            raise RequestPhaseError(f"user/register failed: HTTP {resp.status_code} - {body}")

        # Random 2-4s sau khi register OK rồi mới send OTP (human-like — tránh
        # register → send OTP ngay trong cùng giây, fingerprint bot).
        _send_delay = random.uniform(2.0, 4.0)
        log(f"[request] chờ {_send_delay:.1f}s trước khi send OTP (human-like)")
        time.sleep(_send_delay)

        # Step 6: Send OTP
        log("[request] [5/8] Sending OTP...")
        otp_started_at = datetime.now(timezone.utc)

        if reg_continue and "/email-otp/send" in reg_continue:
            otp_headers = _common_headers("https://auth.openai.com/email-verification")
            if device_id:
                otp_headers["oai-device-id"] = device_id
            resp = session.get(reg_continue, headers=otp_headers, timeout=30)
            if resp.status_code not in (200, 302):
                log(f"[request] OTP send via continue_url returned {resp.status_code}")
                _step_send_otp(session, device_id, log)
        else:
            _step_send_otp(session, device_id, log)
        log("[request] OTP sent")

        # Step 6: Poll OTP với mini-timeout + resend có giới hạn (mirror vòng poll
        # đầu của browser_phase). started_at = send time → chỉ nhận code về SAU thời
        # điểm này, loại code cũ cùng inbox. Dùng 1 event loop xuyên suốt vòng poll
        # đầu + các vòng retry verify. tried_codes/pending_codes chia sẻ toàn phase:
        # thử hết code đã biết trước khi resend.
        log("[request] [6/8] Waiting for OTP...")
        import asyncio as _asyncio
        _loop = _asyncio.new_event_loop()
        tried_codes: set[str] = set()
        pending_codes: list[str] = []
        # Tổng quota resend cho cả OTP phase. iCloud HME là inbox cá nhân và có
        # safety policy riêng: chỉ cho 1 resend để tránh khuếch đại lượng mail.
        total_resend_budget = 3
        resends_used = 0
        try:
            otp_code, used = _acquire_fresh_otp(
                session=session, device_id=device_id, mail_provider=mail_provider,
                request=request, log=log, loop=_loop, started_at=otp_started_at,
                tried_codes=tried_codes, pending=pending_codes,
                max_resends=total_resend_budget - resends_used,
                prefer_second_code=True,
            )
            resends_used += used

            # Đã LẤY ĐƯỢC OTP → báo watchdog gia hạn deadline (tránh kill ngay sau khi có OTP).
            if on_checkpoint is not None:
                try:
                    on_checkpoint("otp")
                    log("[request] OTP secured — watchdog gia hạn để hoàn tất")
                except Exception:
                    pass

            # Step 7: Verify OTP với retry. Wrong code → lấy code mới (pop pending dư
            # hoặc poll/resend qua _acquire_fresh_otp) rồi verify lại. Chỉ raise khi
            # hết lượt hoặc gặp lỗi không phải wrong-code. 1 code đầu + tối đa 3 code
            # mới từ 3 lần resend = 4 lần verify.
            max_verify_attempts = 1 + total_resend_budget
            verified = False
            _otp_recipient = request.source_email or request.email
            for v_attempt in range(1, max_verify_attempts + 1):
                # Human-like delay trước khi submit OTP — tránh verify ngay trong
                # cùng giây nhận code (fingerprint bot). 2-4s random mỗi lần thử.
                _verify_delay = random.uniform(2.0, 4.0)
                log(f"[request] chờ {_verify_delay:.1f}s trước khi submit OTP (human-like)")
                time.sleep(_verify_delay)

                # Trong lúc chờ, code mới hơn có thể vừa về (OpenAI gửi lại / mail
                # in-flight). Ưu tiên verify code mới nhất — tránh ăn 401 dư rồi mới
                # retry. Code hiện tại được giữ làm fallback trong pending.
                otp_code = _prefer_newest_untried_otp(
                    current=otp_code, mail_provider=mail_provider, loop=_loop,
                    recipient=_otp_recipient, started_at=otp_started_at,
                    tried_codes=tried_codes, pending=pending_codes, log=log,
                )
                tried_codes.add(otp_code)
                otp_resp = _step_verify_otp(
                    session, otp_code, device_id, log, raise_on_fail=False,
                )
                if otp_resp.get("_ok"):
                    verified = True
                    break

                status = otp_resp.get("_status")
                body = str(otp_resp.get("_body") or "")
                is_wrong_code = (
                    status == 401
                    or "wrong_email_otp_code" in body
                    or "wrong code" in body.lower()
                )
                if not is_wrong_code:
                    raise RequestPhaseError(
                        f"OTP verify failed: HTTP {status} - {body[:200]}"
                    )
                if v_attempt >= max_verify_attempts:
                    raise RequestPhaseError(
                        f"OTP verify vẫn sai sau {max_verify_attempts} lần "
                        f"(HTTP {status}) — code stale/không hợp lệ"
                    )

                # Wrong code → lấy code mới. _acquire_fresh_otp ưu tiên pop pending
                # (code dư đã fetch) trước, chỉ resend khi cạn code + còn quota.
                log(f"[request] OTP sai (lần {v_attempt}/{max_verify_attempts}) → lấy code mới")
                otp_code, used = _acquire_fresh_otp(
                    session=session, device_id=device_id, mail_provider=mail_provider,
                    request=request, log=log, loop=_loop, started_at=otp_started_at,
                    tried_codes=tried_codes, pending=pending_codes,
                    max_resends=total_resend_budget - resends_used,
                )
                resends_used += used
                if on_checkpoint is not None:
                    try:
                        on_checkpoint("otp")
                    except Exception:
                        pass

            if not verified:
                raise RequestPhaseError("OTP verify thất bại")
        finally:
            _loop.close()

        # Step 8: Create account (sentinel create_account tính tuần tự tại đây)
        continue_url = _step_create_account(
            session, request.name, request.birthdate, device_id, log,
            sentinel_token=None,
            worker=worker,
        )

        # Step 9: Follow redirects + get session
        if not continue_url:
            raise RequestPhaseError("No continue_url after create_account")

        callback_url, final_url = _step_follow_redirects(session, continue_url, log)

        if callback_url:
            _consume_callback(session, callback_url, log)

        session_token, access_token, user_id = _get_session_tokens(session, log)

        if not session_token and not access_token:
            raise RequestPhaseError(
                "Registration completed but no session_token/access_token obtained"
            )

        # Extract all cookies for result
        cookies = []
        try:
            for cookie in session.cookies:
                name = getattr(cookie, "name", "") or ""
                value = getattr(cookie, "value", "") or ""
                domain = getattr(cookie, "domain", "") or ""
                if name and value:
                    cookies.append({
                        "name": name, "value": value,
                        "domain": domain, "path": "/", "secure": True,
                    })
        except Exception:
            pass

        # ── Inline 2FA enroll (CF-clean) — tái dùng session vừa pass CF ──
        # Session này vừa create_account thành công nên còn cf_clearance fresh
        # + đúng proxy/IP. Enroll ngay tại đây an toàn hơn spawn session mới.
        # NEVER fail registration vì account đã được tạo: lỗi enroll → để
        # caller fallback enable_2fa Phase 2.
        two_factor = None
        two_factor_partial = None
        if getattr(request, "mfa_inline", False) and access_token:
            from mfa_phase import MfaError, enable_2fa_in_session
            try:
                two_factor = enable_2fa_in_session(
                    session,
                    access_token=access_token,
                    user_agent=request.user_agent,
                    log=log,
                )
                log("[request] 2FA enrolled inline OK (CF-clean)")
            except MfaError as exc:
                partial = getattr(exc, "partial_state", None)
                if partial and partial.get("secret"):
                    two_factor_partial = partial
                    log(f"[request] 2FA inline: enroll OK nhưng activate fail → partial saved: {exc}")
                else:
                    log(f"[request] 2FA inline fail (fallback Phase 2): {exc}")
            except Exception as exc:
                log(f"[request] 2FA inline lỗi bất ngờ (fallback Phase 2): {exc}")

        return {
            "session_token": session_token,
            "access_token": access_token,
            "user_id": user_id,
            "password": password,
            "cookies": cookies,
            "device_id": device_id,
            "two_factor": two_factor,
            "two_factor_partial": two_factor_partial,
        }
    finally:
        try:
            session.close()
        except Exception:
            pass
        if worker is not None:
            try:
                worker.close()
            except Exception:
                pass


def _default_password(email: str) -> str:
    pwd = email.replace("@", "")
    if len(pwd) < 8:
        pwd = f"{pwd}2026OpenAI"
    return pwd


async def run_request_phase(
    *,
    request: SignupRequest,
    mail_provider: MailProvider,
    log: Callable = print,
    on_checkpoint: Callable | None = None,
) -> SignupResult:
    """Run pure-request registration. Returns SignupResult.

    on_checkpoint: callback(stage:str) — gọi khi đã lấy được OTP để watchdog
        bên ngoài gia hạn deadline (tránh kill job ngay sau khi có OTP).

    The sync core runs in a worker thread (asyncio.to_thread) and polls OTP
    inline via a fresh event loop, with started_at = exact OTP send time so
    stale codes from previous attempts are never picked up.
    """
    from models import SignupResult

    result = SignupResult(success=False, email=request.email)
    t_start = time.monotonic()

    try:
        phase_result = await asyncio.to_thread(
            _run_request_phase_sync, request, mail_provider, log, on_checkpoint,
        )

        result.success = True
        result.session_token = phase_result.get("session_token")
        result.access_token = phase_result.get("access_token")
        result.user_id = phase_result.get("user_id")
        result.password = phase_result.get("password") or request.password
        result.name = request.name
        result.cookies = phase_result.get("cookies", [])
        result.phase1_seconds = time.monotonic() - t_start
        result.phase2_seconds = 0.0  # No separate phase 2 in pure-request mode
        result.two_factor = phase_result.get("two_factor")
        result.two_factor_partial = phase_result.get("two_factor_partial")

        # Compute age
        try:
            y, m, d = request.birthdate.split("-")
            today = datetime.utcnow()
            result.age = today.year - int(y) - ((today.month, today.day) < (int(m), int(d)))
        except Exception:
            pass

        log(f"[request] Registration complete! session_token={'yes' if result.session_token else 'no'} "
            f"access_token={'yes' if result.access_token else 'no'}")

    except RequestPhaseError as e:
        result.error = f"RequestPhaseError: {e}"
        log(f"[request] FAILED: {result.error}")
    except TimeoutError as e:
        result.error = f"TimeoutError: {e}"
        log(f"[request] TIMEOUT: {result.error}")
    except Exception as e:
        result.error = f"{type(e).__name__}: {e}"
        log(f"[request] ERROR: {result.error}")
    finally:
        total = time.monotonic() - t_start
        log(f"[request] Total time: {total:.2f}s")

    return result
