"""Account identity helpers for canonical comparisons and caching."""

from __future__ import annotations


def canonical_email(raw_email: str) -> str:
    """Normalize email: strip whitespace and lowercase."""
    if not raw_email:
        return ""
    return raw_email.strip().lower()


__all__ = ["canonical_email"]
