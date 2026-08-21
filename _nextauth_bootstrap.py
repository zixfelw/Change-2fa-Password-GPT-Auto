"""Shared NextAuth bootstrap helpers for chatgpt.com auth flows."""
from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import urlparse

from _browser_retry import is_execution_context_destroyed_error


_CHATGPT_HOME_URL = "https://chatgpt.com/"
_CHATGPT_CSRF_URL = "https://chatgpt.com/api/auth/csrf"
_CONTEXT_RETRY_MAX = 3
_CONTEXT_RETRY_BACKOFF_SECONDS = 0.35


BOOTSTRAP_JS = r"""
async ({email, deviceId, loggingId, callbackUrl}) => {
    const sleep = (ms) => new Promise(r => setTimeout(r, ms));

    const buildParams = () => {
        const params = new URLSearchParams({
            'prompt': 'login',
            'ext-oai-did': deviceId,
            'ext-passkey-client-capabilities': '01001',
            'screen_hint': 'login_or_signup',
        });
        if (loggingId) params.set('auth_session_logging_id', loggingId);
        if (email) params.set('login_hint', email);
        return params;
    };

    let lastErr = '';
    // Retry up to 4 times — signin/openai 500 is often a transient server error
    // or stale CSRF; re-fetch CSRF each attempt.
    for (let attempt = 1; attempt <= 4; attempt++) {
        try {
            const csrfRes = await fetch('/api/auth/csrf', {credentials: 'include'});
            if (!csrfRes.ok) throw new Error('csrf HTTP ' + csrfRes.status);
            const csrfData = await csrfRes.json();
            const csrfToken = csrfData.csrfToken;
            if (!csrfToken) throw new Error('csrf token missing');

            const body = new URLSearchParams({
                callbackUrl: callbackUrl || 'https://chatgpt.com/',
                csrfToken,
                json: 'true',
            }).toString();
            const signRes = await fetch('/api/auth/signin/openai?' + buildParams().toString(), {
                method: 'POST',
                credentials: 'include',
                headers: {'Content-Type': 'application/x-www-form-urlencoded'},
                body,
            });
            if (signRes.status >= 500) {
                lastErr = 'signin HTTP ' + signRes.status;
                await sleep(attempt * 1500);
                continue;
            }
            if (!signRes.ok) throw new Error('signin HTTP ' + signRes.status);
            const signData = await signRes.json();
            if (!signData.url) {
                throw new Error('signin missing url: ' + JSON.stringify(signData));
            }
            return signData.url;
        } catch (e) {
            lastErr = String(e && e.message ? e.message : e);
            // Network/transient → retry; hard errors (missing token/url) → rethrow
            if (attempt < 4 && /HTTP 5\d\d|Failed to fetch|NetworkError/.test(lastErr)) {
                await sleep(attempt * 1500);
                continue;
            }
            throw e;
        }
    }
    throw new Error('signin failed after retries: ' + lastErr);
}
"""


def _log(log, message: str) -> None:
    if log is not None:
        log(message)


def _is_chatgpt_page(page: Any) -> bool:
    try:
        host = (urlparse(str(page.url)).hostname or "").casefold()
    except Exception:
        return False
    return host == "chatgpt.com" or host.endswith(".chatgpt.com")


async def _prime_chatgpt_origin(page: Any, *, log=None) -> None:
    """Mở endpoint CSRF nhẹ, fallback homepage khi không tương thích.

    Điều hướng thẳng tới endpoint JSON vẫn đi qua browser/proxy/TLS thật nhưng
    không tải ChatGPT SPA. Auth UI ở auth.openai.com sau đó vẫn tải đầy đủ.
    """
    try:
        response = await page.goto(_CHATGPT_CSRF_URL, wait_until="domcontentloaded")
        if response is not None and bool(getattr(response, "ok", False)):
            origin = await page.evaluate("location.origin")
            if origin == "https://chatgpt.com":
                _log(
                    log,
                    "[bandwidth] NextAuth bootstrap nhẹ qua /api/auth/csrf "
                    "— không tải ChatGPT SPA",
                )
                return
        status = getattr(response, "status", "no-response")
        _log(
            log,
            f"[browser] CSRF bootstrap nhẹ không dùng được ({status}) "
            "— fallback homepage",
        )
    except Exception as exc:
        _log(
            log,
            "[browser] CSRF bootstrap nhẹ lỗi "
            f"{type(exc).__name__}: {exc} — fallback homepage",
        )

    await page.goto(_CHATGPT_HOME_URL, wait_until="domcontentloaded")
    _log(log, "[browser] chatgpt.com fallback loaded")


async def _wait_for_replacement_context(page: Any, *, attempt: int, log=None) -> None:
    """Đợi navigation thay document xong và khôi phục origin nếu đã rời ChatGPT."""
    _log(
        log,
        f"[browser] bootstrap context bị navigation thay thế — retry tại chỗ "
        f"{attempt}/{_CONTEXT_RETRY_MAX}",
    )
    try:
        await page.wait_for_load_state("domcontentloaded", timeout=5_000)
    except Exception:
        # Chính evaluate retry bên dưới là phép kiểm tra context cuối cùng. Không
        # biến timeout chờ ổn định thành browser relaunch sớm.
        pass
    await asyncio.sleep(_CONTEXT_RETRY_BACKOFF_SECONDS * attempt)
    if _is_chatgpt_page(page):
        return
    await _prime_chatgpt_origin(page, log=log)


async def bootstrap_authorize_url(
    page: Any,
    *,
    device_id: str,
    email: str | None = None,
    logging_id: str | None = None,
    callback_url: str = "https://chatgpt.com/",
    prepare_page: bool = False,
    log=None,
) -> str:
    """Return authorize URL, retrying navigation races in the same browser.

    ``prepare_page=True`` primes the ChatGPT origin through the lightweight CSRF
    endpoint. This preserves the browser/proxy fingerprint while avoiding the
    SPA asset download during bootstrap.
    """
    if prepare_page:
        await _prime_chatgpt_origin(page, log=log)
    payload = {
        "email": email or "",
        "deviceId": device_id,
        "loggingId": logging_id or "",
        "callbackUrl": callback_url,
    }
    for attempt in range(1, _CONTEXT_RETRY_MAX + 1):
        try:
            url = await page.evaluate(BOOTSTRAP_JS, payload)
            break
        except Exception as exc:
            if (
                not is_execution_context_destroyed_error(exc)
                or attempt >= _CONTEXT_RETRY_MAX
            ):
                raise
            await _wait_for_replacement_context(
                page, attempt=attempt, log=log,
            )
    else:  # pragma: no cover — loop luôn return hoặc raise
        raise RuntimeError("NextAuth bootstrap exhausted without result")
    if not isinstance(url, str) or "auth.openai.com" not in url:
        raise ValueError(f"bootstrap returned bad URL: {url!r}")
    return url
