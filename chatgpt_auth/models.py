"""Shared models for ChatGPT auth."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class SessionBundle:
    """Result of pure-HTTP login."""

    email: str
    access_token: str
    cookies: dict[str, str]


__all__ = ["SessionBundle"]
