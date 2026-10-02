"""Process-local observations collected while probing concrete proxy URLs.

Only derived, non-secret metadata is exposed. Proxy URLs are keyed by SHA-256 so
credentials are not retained as dictionary keys or emitted to logs.
"""
from __future__ import annotations

import hashlib
import ipaddress
import threading
from collections import OrderedDict


_MAX_EXIT_IPS = 512
_LOCK = threading.Lock()
_EXIT_IPS: OrderedDict[bytes, str] = OrderedDict()


def _proxy_key(proxy_url: str) -> bytes:
    return hashlib.sha256(proxy_url.encode("utf-8")).digest()


def remember_proxy_exit_ip(proxy_url: str, candidate: str) -> str | None:
    """Validate and remember a bare IP returned by the configured probe."""
    try:
        normalized = str(ipaddress.ip_address(candidate.strip()))
    except (AttributeError, ValueError):
        return None

    key = _proxy_key(proxy_url)
    with _LOCK:
        _EXIT_IPS.pop(key, None)
        _EXIT_IPS[key] = normalized
        while len(_EXIT_IPS) > _MAX_EXIT_IPS:
            _EXIT_IPS.popitem(last=False)
    return normalized


def forget_proxy_exit_ip(proxy_url: str) -> None:
    """Discard an old observation before accepting a fresh probe response."""
    with _LOCK:
        _EXIT_IPS.pop(_proxy_key(proxy_url), None)


def get_proxy_exit_ip(proxy_url: str | None) -> str | None:
    """Return the newest observed exit IP for an exact concrete proxy URL."""
    if not proxy_url:
        return None
    key = _proxy_key(proxy_url)
    with _LOCK:
        value = _EXIT_IPS.get(key)
        if value is not None:
            _EXIT_IPS.move_to_end(key)
        return value


__all__ = [
    "forget_proxy_exit_ip",
    "get_proxy_exit_ip",
    "remember_proxy_exit_ip",
]
