"""Safe diagnostic utilities — structured error analysis without secret leaks."""

from __future__ import annotations

from typing import Any, Mapping
from urllib.parse import urlparse

_CF_CHALLENGE_MARKERS: tuple[str, ...] = (
    "cf-chl",
    "/cdn-cgi/challenge",
    "challenge-platform",
    "just a moment",
    "<title>access denied",
    "<title>blocked",
)


def is_cloudflare_challenge_response(
    status_code: int,
    headers: Mapping[str, str] | None,
    body_text: str | None,
) -> bool:
    """True if response indicates a Cloudflare challenge/mitigation."""
    if headers:
        for k, v in headers.items():
            if k.lower() == "cf-mitigated" and "challenge" in v.lower():
                return True

    if body_text:
        sample = body_text[:4096].lower()
        if any(marker in sample for marker in _CF_CHALLENGE_MARKERS):
            return True

    return False


def extract_host_path(url: str | None) -> str:
    """Extract safe host and path from a URL (strips query strings and credentials)."""
    if not url:
        return ""
    try:
        parsed = urlparse(url)
        return f"{parsed.netloc}{parsed.path}"
    except Exception:
        return ""


def build_safe_diagnostic(
    *,
    stage: str,
    reason: str,
    status_code: int | None = None,
    url: str | None = None,
    headers: Mapping[str, str] | None = None,
    body_text: str | None = None,
    elapsed_ms: int | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Construct an immutable safe diagnostic dictionary for logs and errors."""
    cf_mitigated = False
    cf_ray_present = False
    content_type = ""

    if headers:
        for k, v in headers.items():
            lk = k.lower()
            if lk == "cf-mitigated" and "challenge" in v.lower():
                cf_mitigated = True
            elif lk == "cf-ray" and v.strip():
                cf_ray_present = True
            elif lk == "content-type":
                content_type = v.split(";")[0].strip()

    if not cf_mitigated and status_code in (403, 503) and body_text:
        cf_mitigated = is_cloudflare_challenge_response(status_code, headers, body_text)

    diag: dict[str, Any] = {
        "stage": stage,
        "reason": reason,
        "status_code": status_code,
        "host_path": extract_host_path(url),
        "content_type": content_type or None,
        "cf_mitigated": cf_mitigated,
        "cf_ray_present": cf_ray_present,
    }
    if elapsed_ms is not None:
        diag["elapsed_ms"] = elapsed_ms
    if extra:
        for ek, ev in extra.items():
            if ek not in diag:
                diag[ek] = ev

    return diag


__all__ = [
    "is_cloudflare_challenge_response",
    "extract_host_path",
    "build_safe_diagnostic",
]
