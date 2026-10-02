"""HTTP client facade wrapping curl_cffi.requests.AsyncSession.

Handles:
1. Windows non-ASCII path certifi fix for libcurl.
2. AsyncSession factory with Chrome impersonation.
3. Exception aliases matching httpx semantics.
"""
from __future__ import annotations

import os
import shutil
import tempfile
from typing import Any, Final

import certifi
from curl_cffi.requests import AsyncSession, Response
from curl_cffi.requests import exceptions as _cffi_exc
from curl_cffi.requests.errors import CookieConflict

# ─── Windows non-ASCII CA cert fix ────────────────────────────────────
def _ensure_ascii_cacert() -> None:
    try:
        current_cacert = certifi.where()
        # Test if path can be encoded in cp1252 / ascii without error
        try:
            current_cacert.encode("ascii")
            return  # Path is pure ASCII, libcurl will have no issues
        except UnicodeEncodeError:
            pass

        temp_cacert = os.path.join(tempfile.gettempdir(), "cacert.pem")
        if not os.path.exists(temp_cacert) or os.path.getsize(temp_cacert) != os.path.getsize(current_cacert):
            shutil.copyfile(current_cacert, temp_cacert)
        os.environ["CURL_CA_BUNDLE"] = temp_cacert
        os.environ["SSL_CERT_FILE"] = temp_cacert
        certifi.where = lambda: temp_cacert
    except Exception:
        pass

_ensure_ascii_cacert()

# ─── Exception aliases ────────────────────────────────────────────────
TimeoutException = _cffi_exc.Timeout
NetworkError = _cffi_exc.ConnectionError
TransportError = _cffi_exc.RequestException
HTTPError = _cffi_exc.RequestException
DecodingError = _cffi_exc.ContentDecodingError

DEFAULT_IMPERSONATE: Final[str] = "chrome142"


def create_async_client(
    *,
    proxy: str | None = None,
    timeout: float | tuple[float, float] = 30.0,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    allow_redirects: bool = True,
    verify: bool = True,
    impersonate: str | None = DEFAULT_IMPERSONATE,
    **extra: Any,
) -> AsyncSession:
    """Create a configured curl_cffi AsyncSession."""
    _ensure_ascii_cacert()
    proxies = None
    if proxy:
        proxies = {"http": proxy, "https": proxy}

    session = AsyncSession(
        timeout=timeout,
        proxies=proxies,
        headers=headers,
        cookies=cookies,
        allow_redirects=allow_redirects,
        verify=verify,
        impersonate=impersonate,
        **extra,
    )
    session.trust_env = False
    return session


__all__ = [
    "AsyncSession",
    "Response",
    "CookieConflict",
    "TimeoutException",
    "NetworkError",
    "TransportError",
    "HTTPError",
    "DecodingError",
    "create_async_client",
    "DEFAULT_IMPERSONATE",
]
