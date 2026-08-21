"""Registration-mode policy shared by API, settings, and the job manager."""

from __future__ import annotations


REG_MODE_BROWSER = "browser"
REG_MODE_PURE_REQUEST = "pure_request"

REG_MODE_EXECUTION_MODES: frozenset[str] = frozenset({
    REG_MODE_BROWSER,
    REG_MODE_PURE_REQUEST,
})
REG_MODE_POLICIES: frozenset[str] = REG_MODE_EXECUTION_MODES
REG_MODE_POLICY_PATTERN = r"^(browser|pure_request)$"
DEFAULT_REG_MODE_POLICY = REG_MODE_PURE_REQUEST
