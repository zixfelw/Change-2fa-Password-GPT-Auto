"""Login error types for the shared ChatGPT auth module."""

from __future__ import annotations

from typing import Any


class ChatgptLoginError(Exception):
    """ChatGPT pure-HTTP login failed."""

    def __init__(
        self,
        reason: str,
        message: str | None = None,
        diagnostic: dict[str, Any] | None = None,
    ) -> None:
        self.reason: str = reason
        self.error_code: str = "login_failed"
        self.step: str = "login"
        self.diagnostic: dict[str, Any] | None = diagnostic
        self.message: str = message or f"Login failed: reason={reason}"
        super().__init__(self.message)


LoginError = ChatgptLoginError

__all__ = ["ChatgptLoginError", "LoginError"]
