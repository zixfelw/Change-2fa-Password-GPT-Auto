"""Repository layer — Data access abstraction cho SQLite persistence.

Cung cấp ComboRepository, JobRepository, SessionResultRepository, SettingsRepository.
Business logic modules inject repository qua constructor, không dùng raw SQL trực tiếp.
"""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from reg_modes import REG_MODE_POLICIES

from .engine import DatabaseError

if TYPE_CHECKING:
    from .engine import DatabaseEngine
    from icloud_hme.models import AppleAccount


# --- Exception classes ---


class RepositoryError(DatabaseError):
    """Repository operation failure.

    Attributes:
        operation: Tên method đã fail (e.g., "mark_success").
        cause: Original exception.
    """

    def __init__(self, operation: str, cause: Exception) -> None:
        self.operation = operation
        self.cause = cause
        super().__init__(f"{operation} failed: {cause}")


# --- Terminal error substrings cho pick_available filtering ---

TERMINAL_ERROR_SUBSTRINGS: list[str] = [
    "registration_disallowed",
    "invalid_grant",
    "AADSTS50173",
    "AADSTS70008",
]


# ---------------------------------------------------------------------------
# Settings whitelist constants & validation (R4, R8, R3.6)
# ---------------------------------------------------------------------------

_KEY_REGEX = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$")
_KEY_MAX_LEN = 128
_GCASH_PROXY_POOL_MAX_LINES = 500
_GCASH_PROXY_POOL_MAX_LINE_LEN = 2048
_GCASH_PROXY_POOL_MAX_TOTAL_LEN = 50000

# Exact keys whitelist (R8.1)
_EXACT_KEYS: frozenset[str] = frozenset([
    "browser.engine", "browser.channel",
    "reg.mode", "reg.headless", "reg.debug", "reg.default_password",
    "reg.job_timeout", "reg.post_reg_get_session", "reg.post_reg_get_link",
    "reg.post_reg_link_region", "reg.auto_retry", "reg.auto_retry_max",
    "reg.auto_retry_delay", "reg.auth_edge_cooldown_seconds",
    "reg.max_concurrent", "reg.use_proxy",
    "reg.mfa_inline",
    "proxy.pool", "proxy.rotation_mode",
    "proxy.probe_endpoint", "proxy.probe_timeout", "proxy.max_tries",
    "proxy.sid_len", "proxy.sid_retry_per_line", "proxy.probe_concurrency",
    "mail_mode.current", "mail_mode.worker_config",
    "mail_mode.icloud_imap_config",
    "mail_mode.icloud_imap_accounts", "mail_mode.icloud_imap_active_account",
    "mail_mode.custom_domain_config",
    "readmail.worker_config", "readmail.aliases", "readmail.mailboxes",
    "readmail.alias_accounts",
    "reg_mode.current",
    "hme.runner.action", "hme.runner.count_per_cycle",
    "hme.runner.retry_interval", "hme.runner.label", "hme.runner.note",
    "hme.privacy_mask",
    "autoreg.concurrency", "autoreg.poll_interval",
    "autoreg.logs_url", "autoreg.api_key",
    "upi.max_concurrent", "upi.job_timeout", "upi.approve_retries",
    "upi.approve_retry_delay",
    "upi.notify_enabled",
    "upi.approve.restart_threshold", "upi.approve.max_restarts",
    "upi.proxy_from_step", "upi.max_outer_cycles",
    "upi.relogin_block_streak",
    "session.login_flow", "session.mode", "session.max_concurrent", "session.job_timeout",
    "session.rotate_password", "session.rotate_security", "session.rotate_2fa_only",
    "session.usage_remaining_threshold", "session.check_gcash", "session.check_momo",
    "session.gcash_proxy_a", "session.gcash_proxy_b",
    "session.reuse_enabled", "session.revalidate_http", "session.cookie_max_age_hours",
    "twofa.max_concurrent", "twofa.job_timeout", "twofa.auto_retry",
    "twofa.auto_retry_max", "twofa.auto_retry_delay",
    "twofa.change_enabled", "twofa.input_draft",
    "telegram.bot_token", "telegram.chat_id",
    "ui.active_tab", "ui.link_mode",
    "web.auth_token",
])

# Sensitive keys — audit log redact value thành "***" (R10.5)
_SENSITIVE_KEYS: frozenset[str] = frozenset([
    "proxy.pool", "autoreg.api_key", "reg.default_password",
    "session.gcash_proxy_a", "session.gcash_proxy_b",
    "mail_mode.worker_config",
    "mail_mode.icloud_imap_config",
    "mail_mode.icloud_imap_accounts",
    "mail_mode.custom_domain_config",
    "readmail.worker_config", "readmail.mailboxes", "readmail.alias_accounts",
    "telegram.bot_token",
    "web.auth_token", "twofa.input_draft",
])


# --- Type constraint validators (design §3, R3.6) ---

def _validate_type_constraint(key: str, value: Any) -> None:
    """Validate type + range constraint cho một setting key.

    Raise RepositoryError nếu value không thoả ràng buộc kiểu/range.
    Không validate key thuộc whitelist (caller phải check trước).
    """
    if key == "browser.engine":
        allowed_engines = {
            "chromium", "camoufox", "chrome", "playwright", "chrome-stable",
        }
        if not isinstance(value, str) or value.casefold() not in allowed_engines:
            raise RepositoryError(
                "set",
                ValueError(
                    f"{key}: must be one of {sorted(allowed_engines)}, got {value!r}"
                ),
            )
        return

    if key == "browser.channel":
        if not isinstance(value, str) or not value.strip():
            raise RepositoryError(
                "set", ValueError(f"{key}: must be a non-empty string")
            )
        return

    # --- reg namespace ---
    if key == "reg.mode":
        _allowed_modes = (
            "single", "multi", "multi3", "multi5", "multi10",
        )
        if not isinstance(value, str) or value not in _allowed_modes:
            raise RepositoryError(
                "set", ValueError(f"{key}: must be str in {set(_allowed_modes)}, got {value!r}")
            )
        return

    if key == "session.mode":
        allowed_modes = ("single", "multi", "multi3", "multi5", "multi10", "multi20", "multi30")
        if not isinstance(value, str) or value not in allowed_modes:
            raise RepositoryError(
                "set", ValueError(f"{key}: must be str in {set(allowed_modes)}, got {value!r}")
            )
        return

    if key == "reg_mode.current":
        if not isinstance(value, str) or value not in REG_MODE_POLICIES:
            raise RepositoryError(
                "set",
                ValueError(
                    f"{key}: must be str in {sorted(REG_MODE_POLICIES)}, got {value!r}"
                ),
            )
        return

    if key in ("reg.headless", "reg.debug", "reg.post_reg_get_session",
               "reg.post_reg_get_link", "reg.auto_retry", "reg.use_proxy",
               "reg.mfa_inline"):
        if not isinstance(value, bool):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be bool, got {type(value).__name__}")
            )
        return

    if key == "reg.default_password":
        if value is not None and not isinstance(value, str):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be str or null, got {type(value).__name__}")
            )
        return

    if key == "reg.job_timeout":
        if not isinstance(value, int) or isinstance(value, bool):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be int, got {type(value).__name__}")
            )
        if not (30 <= value <= 600):
            raise RepositoryError(
                "set", ValueError(f"{key}: must be in [30, 600], got {value}")
            )
        return

    if key == "reg.post_reg_link_region":
        if not isinstance(value, str) or value not in ("VN", "ID", "IN", "US"):
            raise RepositoryError(
                "set", ValueError(f"{key}: must be str in {{\"VN\",\"ID\",\"IN\",\"US\"}}, got {value!r}")
            )
        return

    if key == "reg.auto_retry_max":
        if not isinstance(value, int) or isinstance(value, bool):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be int, got {type(value).__name__}")
            )
        if not (0 <= value <= 10):
            raise RepositoryError(
                "set", ValueError(f"{key}: must be in [0, 10], got {value}")
            )
        return

    if key == "reg.auto_retry_delay":
        if not isinstance(value, int) or isinstance(value, bool):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be int, got {type(value).__name__}")
            )
        if value < 0:
            raise RepositoryError(
                "set", ValueError(f"{key}: must be >= 0, got {value}")
            )
        return

    if key == "reg.auth_edge_cooldown_seconds":
        if not isinstance(value, int) or isinstance(value, bool):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be int, got {type(value).__name__}")
            )
        if not (60 <= value <= 86400):
            raise RepositoryError(
                "set", ValueError(f"{key}: must be in [60, 86400], got {value}")
            )
        return

    if key == "reg.max_concurrent":
        if not isinstance(value, int) or isinstance(value, bool):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be int, got {type(value).__name__}")
            )
        if not (1 <= value <= 10):
            raise RepositoryError(
                "set", ValueError(f"{key}: must be in [1, 10], got {value}")
            )
        return


    if key == "session.max_concurrent":
        if not isinstance(value, int) or isinstance(value, bool) or not (1 <= value <= 30):
            raise RepositoryError("set", ValueError(f"{key}: must be int in [1, 30], got {value!r}"))
        return

    if key in (
        "session.rotate_password",
        "session.rotate_security",
        "session.rotate_2fa_only",
        "session.check_gcash",
        "session.check_momo",
    ):
        if not isinstance(value, bool):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be bool, got {type(value).__name__}")
            )
        return

    if key in ("session.gcash_proxy_a", "session.gcash_proxy_b"):
        if not isinstance(value, str):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be str, got {type(value).__name__}")
            )
        if len(value) > _GCASH_PROXY_POOL_MAX_TOTAL_LEN:
            raise RepositoryError(
                "set",
                ValueError(
                    f"{key}: proxy pool exceeds "
                    f"{_GCASH_PROXY_POOL_MAX_TOTAL_LEN} chars"
                ),
            )
        lines = value.splitlines()
        if len(lines) > _GCASH_PROXY_POOL_MAX_LINES:
            raise RepositoryError(
                "set",
                ValueError(
                    f"{key}: proxy pool exceeds "
                    f"{_GCASH_PROXY_POOL_MAX_LINES} lines"
                ),
            )
        if any(
            not line.strip()
            or len(line.strip()) > _GCASH_PROXY_POOL_MAX_LINE_LEN
            or "\x00" in line
            for line in lines
        ):
            raise RepositoryError(
                "set",
                ValueError(
                    f"{key}: each proxy line must be non-empty and at most "
                    f"{_GCASH_PROXY_POOL_MAX_LINE_LEN} chars"
                ),
            )
        return

    if key == "session.usage_remaining_threshold":
        if not isinstance(value, int) or isinstance(value, bool) or not (0 <= value <= 100):
            raise RepositoryError(
                "set", ValueError(f"{key}: must be int in [0, 100], got {value!r}")
            )
        return

    if key == "session.job_timeout":
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not (30 <= value <= 600):
            raise RepositoryError("set", ValueError(f"{key}: must be number in [30, 600], got {value!r}"))
        return

    # --- Change 2FA Community namespace ---
    if key == "twofa.max_concurrent":
        if not isinstance(value, int) or isinstance(value, bool) or not (1 <= value <= 10):
            raise RepositoryError(
                "set", ValueError(f"{key}: must be int in [1, 10], got {value!r}")
            )
        return

    if key == "twofa.job_timeout":
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not (30 <= value <= 600):
            raise RepositoryError(
                "set", ValueError(f"{key}: must be number in [30, 600], got {value!r}")
            )
        return

    if key == "twofa.auto_retry":
        if not isinstance(value, bool):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be bool, got {type(value).__name__}")
            )
        return

    if key == "twofa.auto_retry_max":
        if not isinstance(value, int) or isinstance(value, bool) or not (0 <= value <= 5):
            raise RepositoryError(
                "set", ValueError(f"{key}: must be int in [0, 5], got {value!r}")
            )
        return

    if key == "twofa.auto_retry_delay":
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not (0 <= value <= 60):
            raise RepositoryError(
                "set", ValueError(f"{key}: must be number in [0, 60], got {value!r}")
            )
        return

    if key == "twofa.change_enabled":
        if not isinstance(value, bool):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be bool, got {type(value).__name__}")
            )
        return

    if key == "twofa.input_draft":
        if not isinstance(value, str):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be str, got {type(value).__name__}")
            )
        if len(value) > 1_000_000:
            raise RepositoryError(
                "set", ValueError(f"{key}: must be at most 1000000 chars, got {len(value)}")
            )
        return

    # --- proxy namespace ---
    if key == "proxy.pool":
        # List các proxy URL (str) để xoay vòng. Empty list = không dùng pool.
        if not isinstance(value, list):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be list, got {type(value).__name__}")
            )
        if len(value) > 200:
            raise RepositoryError(
                "set", ValueError(f"{key}: too many proxies ({len(value)}), max 200")
            )
        for idx, item in enumerate(value):
            if not isinstance(item, str):
                raise RepositoryError(
                    "set", TypeError(f"{key}[{idx}]: must be str, got {type(item).__name__}")
                )
            if len(item) > 500:
                raise RepositoryError(
                    "set", ValueError(f"{key}[{idx}]: proxy URL too long ({len(item)}), max 500")
                )
        return

    if key == "proxy.rotation_mode":
        if not isinstance(value, str) or value not in ("round_robin", "random", "probe"):
            raise RepositoryError(
                "set", ValueError(
                    f"{key}: must be str in {{\"round_robin\",\"random\",\"probe\"}}, got {value!r}"
                )
            )
        return

    if key == "proxy.probe_endpoint":
        if not isinstance(value, str) or not value.strip():
            raise RepositoryError(
                "set", ValueError(f"{key}: must be non-empty str, got {value!r}")
            )
        if not value.strip().lower().startswith("http"):
            raise RepositoryError(
                "set", ValueError(f"{key}: must be http(s) URL, got {value!r}")
            )
        return

    if key in ("proxy.probe_timeout", "proxy.max_tries", "proxy.sid_len",
               "proxy.sid_retry_per_line", "proxy.probe_concurrency"):
        _ranges = {
            "proxy.probe_timeout": (3, 15),
            "proxy.max_tries": (1, 20),
            "proxy.sid_len": (4, 32),
            "proxy.sid_retry_per_line": (0, 10),
            "proxy.probe_concurrency": (1, 10),
        }
        lo, hi = _ranges[key]
        if not isinstance(value, int) or isinstance(value, bool):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be int, got {type(value).__name__}")
            )
        if not (lo <= value <= hi):
            raise RepositoryError(
                "set", ValueError(f"{key}: must be in [{lo}, {hi}], got {value}")
            )
        return

    # --- session namespace ---
    if key == "session.login_flow":
        # Chọn flow login pure-HTTP cho get_session_pure_request:
        #   "anti409" (default) = flow dev: warm + pre-set oai-did +
        #     auth_session_logging_id + sentinel "password_verify" + assume-password
        #     fallback → tránh HTTP 409 invalid_state (tốt cho batch password combo).
        #   "legacy" = flow main: _step_auth_url + authorize/continue fallback +
        #     sentinel "login" → dò được passwordless/OTP khi landing không rõ.
        if not isinstance(value, str) or value not in ("legacy", "anti409"):
            raise RepositoryError(
                "set", ValueError(
                    f"{key}: must be str in {{\"legacy\",\"anti409\"}}, got {value!r}"
                )
            )
        return

    if key in ("session.reuse_enabled", "session.revalidate_http"):
        # session-cookie-cache: bật/tắt tái dùng session + cách revalidate.
        if not isinstance(value, bool):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be bool, got {type(value).__name__}")
            )
        return

    if key == "session.cookie_max_age_hours":
        # Ngưỡng tuổi record trước khi buộc full login (áp cả khi revalidate_http=false).
        if not isinstance(value, int) or isinstance(value, bool):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be int, got {type(value).__name__}")
            )
        if value < 1:
            raise RepositoryError(
                "set", ValueError(f"{key}: must be >= 1, got {value}")
            )
        return

    # --- mail_mode namespace ---
    if key == "mail_mode.current":
        if not isinstance(value, str) or len(value) == 0:
            raise RepositoryError(
                "set", ValueError(f"{key}: must be non-empty str, got {value!r}")
            )
        return

    if key == "mail_mode.worker_config":
        if value is None:
            return
        if not isinstance(value, dict):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be object or null, got {type(value).__name__}")
            )
        if "logs_url" not in value or "api_key" not in value:
            raise RepositoryError(
                "set", ValueError(f"{key}: object must have keys 'logs_url' and 'api_key'")
            )
        if not isinstance(value["logs_url"], str):
            raise RepositoryError(
                "set", TypeError(f"{key}.logs_url: must be str")
            )
        if not isinstance(value["api_key"], str):
            raise RepositoryError(
                "set", TypeError(f"{key}.api_key: must be str")
            )
        return

    if key == "mail_mode.icloud_imap_config":
        if value is None:
            return
        if not isinstance(value, dict):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be object or null, got {type(value).__name__}")
            )
        required = ("username", "app_password")
        if any(field not in value for field in required):
            raise RepositoryError(
                "set", ValueError(f"{key}: object must have keys {required!r}")
            )
        for field in required:
            if not isinstance(value[field], str):
                raise RepositoryError(
                    "set", TypeError(f"{key}.{field}: must be str")
                )
        try:
            from icloud_imap_policy import ICloudImapPolicy
            ICloudImapPolicy.from_mapping(value)
        except ValueError as exc:
            raise RepositoryError("set", exc) from exc
        return

    if key == "mail_mode.icloud_imap_accounts":
        if not isinstance(value, dict):
            raise RepositoryError(
                "set",
                TypeError(f"{key}: must be object, got {type(value).__name__}"),
            )
        try:
            from icloud_imap_accounts import load_icloud_imap_accounts

            load_icloud_imap_accounts({key: value})
        except (TypeError, ValueError) as exc:
            raise RepositoryError("set", exc) from exc
        return

    if key == "mail_mode.icloud_imap_active_account":
        try:
            from icloud_imap_accounts import normalize_icloud_imap_account_id

            normalize_icloud_imap_account_id(value)
        except (TypeError, ValueError) as exc:
            raise RepositoryError("set", exc) from exc
        return

    if key == "mail_mode.custom_domain_config":
        if value is None:
            return
        if not isinstance(value, dict):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be object or null, got {type(value).__name__}")
            )
        required = ("domain", "base_url", "admin_token")
        if any(field not in value for field in required):
            raise RepositoryError(
                "set", ValueError(f"{key}: object must have keys {required!r}")
            )
        if any(not isinstance(value[field], str) for field in required):
            raise RepositoryError("set", TypeError(f"{key}: all fields must be str"))
        domain = value["domain"].strip().casefold().rstrip(".")
        domain_re = re.compile(
            r"(?=^.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
            r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
        )
        if not domain_re.fullmatch(domain):
            raise RepositoryError("set", ValueError(f"{key}.domain: invalid domain name"))
        parsed_url = urlparse(value["base_url"].strip())
        if (
            parsed_url.scheme != "https"
            or not parsed_url.netloc
            or parsed_url.username
            or parsed_url.password
            or parsed_url.path not in ("", "/")
            or parsed_url.params
            or parsed_url.query
            or parsed_url.fragment
        ):
            raise RepositoryError(
                "set", ValueError(f"{key}.base_url: must be an https origin without path/query")
            )
        if len(value["admin_token"].strip()) < 32:
            raise RepositoryError(
                "set", ValueError(f"{key}.admin_token: must contain at least 32 characters")
            )
        return

    # --- readmail bridge namespace ---
    if key == "readmail.worker_config":
        if not isinstance(value, dict):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be object, got {type(value).__name__}")
            )
        required = ("base_url", "admin_token", "poll_interval_seconds")
        if any(field not in value for field in required):
            raise RepositoryError(
                "set", ValueError(f"{key}: object must have keys {required!r}")
            )
        base_url = value["base_url"]
        admin_token = value["admin_token"]
        interval = value["poll_interval_seconds"]
        if not isinstance(base_url, str) or not base_url.startswith("https://"):
            raise RepositoryError(
                "set", ValueError(f"{key}.base_url: must be an https URL")
            )
        if not isinstance(admin_token, str) or len(admin_token) < 32:
            raise RepositoryError(
                "set", ValueError(f"{key}.admin_token: must contain at least 32 characters")
            )
        if not isinstance(interval, int) or isinstance(interval, bool) or not 5 <= interval <= 300:
            raise RepositoryError(
                "set", ValueError(f"{key}.poll_interval_seconds: must be int in [5, 300]")
            )
        return

    if key == "readmail.aliases":
        if not isinstance(value, list) or len(value) > 1000:
            raise RepositoryError(
                "set", ValueError(f"{key}: must be a list with at most 1000 entries")
            )
        email_re = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
        if any(not isinstance(item, str) or not email_re.fullmatch(item) for item in value):
            raise RepositoryError("set", ValueError(f"{key}: contains an invalid email"))
        if len({item.casefold() for item in value}) != len(value):
            raise RepositoryError("set", ValueError(f"{key}: contains duplicate emails"))
        return

    if key == "readmail.mailboxes":
        if not isinstance(value, dict):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be object, got {type(value).__name__}")
            )
        if any(
            not isinstance(email, str)
            or not isinstance(url, str)
            or not url.startswith("https://")
            for email, url in value.items()
        ):
            raise RepositoryError(
                "set", ValueError(f"{key}: must map email strings to https URLs")
            )
        return

    if key == "readmail.alias_accounts":
        if not isinstance(value, dict) or len(value) > 10000:
            raise RepositoryError(
                "set",
                ValueError(f"{key}: must be an object with at most 10000 entries"),
            )
        email_re = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
        try:
            from icloud_imap_accounts import normalize_icloud_imap_account_id

            if any(
                not isinstance(email, str)
                or not email_re.fullmatch(email)
                or email.casefold() != email
                or not isinstance(account_id, str)
                or normalize_icloud_imap_account_id(account_id) != account_id
                for email, account_id in value.items()
            ):
                raise ValueError(
                    f"{key}: must map normalized email aliases to account ids"
                )
        except (TypeError, ValueError) as exc:
            raise RepositoryError("set", exc) from exc
        return

    # --- hme.runner namespace ---
    if key == "hme.runner.action":
        allowed = ("generate", "check_all", "deactivate_bulk", "reactivate_bulk",
                   "delete_bulk", "update_meta_bulk", "list_sync")
        if not isinstance(value, str) or value not in allowed:
            raise RepositoryError(
                "set", ValueError(f"{key}: must be str in {set(allowed)}, got {value!r}")
            )
        return

    if key == "hme.runner.count_per_cycle":
        if value is None:
            return
        if not isinstance(value, int) or isinstance(value, bool):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be int or null, got {type(value).__name__}")
            )
        if value <= 0:
            raise RepositoryError(
                "set", ValueError(f"{key}: must be > 0 when set, got {value}")
            )
        return

    if key == "hme.runner.retry_interval":
        if value is None:
            return
        if not isinstance(value, int) or isinstance(value, bool):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be int or null, got {type(value).__name__}")
            )
        if value < 10:
            raise RepositoryError(
                "set", ValueError(f"{key}: must be >= 10 when set, got {value}")
            )
        return

    if key == "hme.runner.label":
        if value is None:
            return
        if not isinstance(value, str):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be str or null, got {type(value).__name__}")
            )
        if len(value) > 200:
            raise RepositoryError(
                "set", ValueError(f"{key}: len must be <= 200, got {len(value)}")
            )
        return

    if key == "hme.runner.note":
        if value is None:
            return
        if not isinstance(value, str):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be str or null, got {type(value).__name__}")
            )
        if len(value) > 1000:
            raise RepositoryError(
                "set", ValueError(f"{key}: len must be <= 1000, got {len(value)}")
            )
        return

    if key == "hme.privacy_mask":
        if not isinstance(value, bool):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be bool, got {type(value).__name__}")
            )
        return

    # --- autoreg namespace ---
    if key == "autoreg.concurrency":
        if not isinstance(value, int) or isinstance(value, bool):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be int, got {type(value).__name__}")
            )
        if not (1 <= value <= 5):
            raise RepositoryError(
                "set", ValueError(f"{key}: must be in [1, 5], got {value}")
            )
        return

    if key == "autoreg.poll_interval":
        if not isinstance(value, int) or isinstance(value, bool):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be int, got {type(value).__name__}")
            )
        if value < 10:
            raise RepositoryError(
                "set", ValueError(f"{key}: must be >= 10, got {value}")
            )
        return

    if key in ("autoreg.logs_url", "autoreg.api_key"):
        if value is not None and not isinstance(value, str):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be str or null, got {type(value).__name__}")
            )
        return

    # --- upi namespace ---
    if key == "upi.max_concurrent":
        if not isinstance(value, int) or isinstance(value, bool):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be int, got {type(value).__name__}")
            )
        if not (1 <= value <= 200):
            raise RepositoryError(
                "set", ValueError(f"{key}: must be in [1, 200], got {value}")
            )
        return

    if key == "upi.job_timeout":
        if not isinstance(value, int) or isinstance(value, bool):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be int, got {type(value).__name__}")
            )
        if not (60 <= value <= 7200):
            raise RepositoryError(
                "set", ValueError(f"{key}: must be in [60, 7200], got {value}")
            )
        return

    if key == "upi.approve_retries":
        if not isinstance(value, int) or isinstance(value, bool):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be int, got {type(value).__name__}")
            )
        if not (1 <= value <= 2000):
            raise RepositoryError(
                "set", ValueError(f"{key}: must be in [1, 2000], got {value}")
            )
        return

    if key == "upi.approve_retry_delay":
        # Delay (giây) giữa 2 lần retry approve. Floor 2s.
        # Cap 60s — > 60s vô nghĩa với approve loop (QR expire sau 5 phút).
        # Float để cho phép 2.5, 5.0, 7.0, 10.0, ... mà vẫn validate tight.
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be number, got {type(value).__name__}")
            )
        if not (2.0 <= float(value) <= 60.0):
            raise RepositoryError(
                "set", ValueError(f"{key}: must be in [2, 60] seconds, got {value}")
            )
        return

    if key == "upi.notify_enabled":
        if not isinstance(value, bool):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be bool, got {type(value).__name__}")
            )
        return

    if key == "upi.approve.restart_threshold":
        # Số lần result=exception LIÊN TIẾP để trigger "new checkout session"
        # (refresh state Stripe-side, giữ login + retry counter cộng dồn).
        # 0 = disabled (no restart, behavior cũ).
        if not isinstance(value, int) or isinstance(value, bool):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be int, got {type(value).__name__}")
            )
        if not (0 <= value <= 1000):
            raise RepositoryError(
                "set", ValueError(f"{key}: must be in [0, 1000], got {value}")
            )
        return

    if key == "upi.approve.max_restarts":
        # Số lần restart tối đa trong 1 job. 0 = disabled (no restart).
        # Hết quota nhưng vẫn dính exception → fatal break.
        # Ceiling 2000 = match `upi.approve_retries` ceiling — vì khi restart
        # mỗi exception (default), tổng restart có thể bằng total approve.
        if not isinstance(value, int) or isinstance(value, bool):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be int, got {type(value).__name__}")
            )
        if not (0 <= value <= 2000):
            raise RepositoryError(
                "set", ValueError(f"{key}: must be in [0, 2000], got {value}")
            )
        return

    if key == "upi.max_outer_cycles":
        # Số outer-cycle re-login tối đa khi MỌI approve attempt của 1 cycle
        # đều IP/edge-reject (blocked | http 403/429). 1 = behavior cũ (không
        # re-login). >1 = re-login + checkout/token/IP mới, tối đa N cycle.
        # Range [1, 5] — trên 5 vô nghĩa (mỗi cycle tốn full approve budget).
        if not isinstance(value, int) or isinstance(value, bool):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be int, got {type(value).__name__}")
            )
        if not (1 <= value <= 5):
            raise RepositoryError(
                "set", ValueError(f"{key}: must be in [1, 5], got {value}")
            )
        return

    if key == "upi.relogin_block_streak":
        # Số approve attempt IP/edge-reject (blocked|403|429) LIÊN TIẾP để break
        # cycle sớm → re-login (chỉ áp dụng khi max_outer_cycles>1). 0 = off
        # (chạy hết approve_retries mới re-login). Range [0, 1000].
        if not isinstance(value, int) or isinstance(value, bool):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be int, got {type(value).__name__}")
            )
        if not (0 <= value <= 1000):
            raise RepositoryError(
                "set", ValueError(f"{key}: must be in [0, 1000], got {value}")
            )
        return

    if key == "upi.proxy_from_step":
        # Step bắt đầu áp proxy cho UPI flow (1-6) — đồng bộ với
        # `pay_upi_http._ProxyPolicy` schema:
        #   1 login → 2 checkout → 3 stripe_init → 4 stripe_elements
        #   → 5 token+confirm → 6 approve
        # Mọi step >= from_step đi via first_proxy; step nhỏ hơn DIRECT.
        # Default 3 (giữ behavior cũ — step 1-2 DIRECT).
        # Set =1 khi IP host không qua được chatgpt.com payment endpoint
        # (silent timeout 30s với 0 bytes — typical case IP non-IN).
        if not isinstance(value, int) or isinstance(value, bool):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be int, got {type(value).__name__}")
            )
        if not (1 <= value <= 6):
            raise RepositoryError(
                "set", ValueError(f"{key}: must be in [1, 6], got {value}")
            )
        return

    # --- telegram namespace ---
    if key == "telegram.bot_token":
        if value is not None and not isinstance(value, str):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be str or null, got {type(value).__name__}")
            )
        if isinstance(value, str) and len(value) > 200:
            raise RepositoryError(
                "set", ValueError(f"{key}: len must be <= 200, got {len(value)}")
            )
        return

    if key == "telegram.chat_id":
        if value is not None and not isinstance(value, str):
            raise RepositoryError(
                "set", TypeError(f"{key}: must be str or null, got {type(value).__name__}")
            )
        if isinstance(value, str) and len(value) > 64:
            raise RepositoryError(
                "set", ValueError(f"{key}: len must be <= 64, got {len(value)}")
            )
        return

    # --- ui namespace ---
    if key == "ui.active_tab":
        allowed_tabs = ("reg", "session", "link", "hme", "upi", "settings")
        if not isinstance(value, str) or value not in allowed_tabs:
            raise RepositoryError(
                "set", ValueError(f"{key}: must be str in {set(allowed_tabs)}, got {value!r}")
            )
        return

    if key == "ui.link_mode":
        allowed_modes = ("combo", "session_json", "access_token")
        if not isinstance(value, str) or value not in allowed_modes:
            raise RepositoryError(
                "set", ValueError(f"{key}: must be str in {set(allowed_modes)}, got {value!r}")
            )
        return

    # --- web namespace ---
    if key == "web.auth_token":
        if not isinstance(value, str) or len(value) == 0:
            raise RepositoryError(
                "set", ValueError(f"{key}: must be non-empty str, got {value!r}")
            )
        if len(value) > 256:
            raise RepositoryError(
                "set", ValueError(f"{key}: len must be <= 256, got {len(value)}")
            )
        return

    # Key trong whitelist nhưng chưa có constraint riêng → accept mọi JSON-serializable
    # (không raise — chỉ validate key đã biết ở trên)


# --- ComboRepository ---


class ComboRepository:
    """Data access cho `outlook_combos` table.

    Cung cấp CRUD operations + business logic queries (pick_available, mark_success/failure).
    """

    def __init__(self, engine: "DatabaseEngine") -> None:
        self._engine = engine

    def get_by_email(self, email: str) -> dict | None:
        """Lấy combo theo email.

        Returns:
            dict chứa tất cả columns, hoặc None nếu không tìm thấy.
        """
        conn = self._engine.raw_connection()
        row = conn.execute(
            "SELECT * FROM outlook_combos WHERE email = ?", (email,)
        ).fetchone()
        return dict(row) if row else None

    def upsert(self, combo_data: dict) -> None:
        """Insert hoặc update combo (explicit sync — dùng cho import-pool / CLI sync).

        Nếu email đã tồn tại: preserve used_for_signup, used_at, last_error, last_failed_at.
        Overwrite: password, refresh_token, client_id.

        Args:
            combo_data: dict với keys: email, password, refresh_token, client_id.

        Raises:
            RepositoryError: Nếu write operation fail.
        """
        try:
            with self._engine.get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO outlook_combos (email, password, refresh_token, client_id)
                    VALUES (:email, :password, :refresh_token, :client_id)
                    ON CONFLICT(email) DO UPDATE SET
                        password = excluded.password,
                        refresh_token = excluded.refresh_token,
                        client_id = excluded.client_id
                    """,
                    combo_data,
                )
        except Exception as exc:
            raise RepositoryError("upsert", exc) from exc

    def ensure_exists(self, combo_data: dict) -> None:
        """Insert combo nếu chưa có; nếu đã có thì chỉ update password/client_id,
        PRESERVE refresh_token đã rotate trong DB.

        Dùng cho runtime pre-upsert (web/manager add_jobs, CLI pool/signup) —
        tránh overwrite token đã rotate bằng token cũ từ pool file.

        Args:
            combo_data: dict với keys: email, password, refresh_token, client_id.

        Raises:
            RepositoryError: Nếu write operation fail.
        """
        try:
            with self._engine.get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO outlook_combos (email, password, refresh_token, client_id)
                    VALUES (:email, :password, :refresh_token, :client_id)
                    ON CONFLICT(email) DO UPDATE SET
                        password = excluded.password,
                        client_id = excluded.client_id
                    """,
                    combo_data,
                )
        except Exception as exc:
            raise RepositoryError("ensure_exists", exc) from exc

    def mark_success(self, email: str) -> None:
        """Đánh dấu combo đã signup thành công.

        Sets: used_for_signup=1, used_at=now(UTC), last_error=NULL.

        Raises:
            RepositoryError: Nếu write operation fail hoặc row không tồn tại.
        """
        try:
            with self._engine.get_connection() as conn:
                cursor = conn.execute(
                    """
                    UPDATE outlook_combos
                    SET used_for_signup = 1,
                        used_at = ?,
                        last_error = NULL
                    WHERE email = ?
                    """,
                    (datetime.now(timezone.utc).isoformat(), email),
                )
                if cursor.rowcount == 0:
                    raise RepositoryError(
                        "mark_success",
                        ValueError(f"no row found for email={email} — pre-upsert may have failed"),
                    )
        except RepositoryError:
            raise
        except Exception as exc:
            raise RepositoryError("mark_success", exc) from exc

    def mark_failure(self, email: str, error: str) -> None:
        """Đánh dấu combo bị lỗi signup.

        Sets: last_error=error, last_failed_at=now(UTC).
        KHÔNG thay đổi used_for_signup.

        Raises:
            RepositoryError: Nếu write operation fail hoặc row không tồn tại.
        """
        try:
            with self._engine.get_connection() as conn:
                cursor = conn.execute(
                    """
                    UPDATE outlook_combos
                    SET last_error = ?,
                        last_failed_at = ?
                    WHERE email = ?
                    """,
                    (error, datetime.now(timezone.utc).isoformat(), email),
                )
                if cursor.rowcount == 0:
                    raise RepositoryError(
                        "mark_failure",
                        ValueError(f"no row found for email={email} — pre-upsert may have failed"),
                    )
        except RepositoryError:
            raise
        except Exception as exc:
            raise RepositoryError("mark_failure", exc) from exc

    def pick_available(self) -> dict:
        """Chọn combo khả dụng cho signup — atomic SELECT + mark in-use.

        Trong single transaction:
        1. SELECT combo khả dụng (used_for_signup=0, không terminal error)
        2. Không có UPDATE đánh dấu vì caller sẽ mark_success/mark_failure sau signup

        Filter:
            - used_for_signup = 0
            - last_error IS NULL hoặc không chứa terminal error substrings
        Order: created_at ASC (lấy combo cũ nhất trước).

        NOTE: Method này KHÔNG concurrency-safe giữa multiple processes/threads.
        Nếu 2+ callers concurrent gọi pick_available(), cả hai có thể nhận cùng combo.
        Trong runtime thực tế, outlook_pool.py bypass method này (dùng get_by_email
        loop). Nếu cần concurrency-safe, caller phải wrap trong external lock hoặc
        dùng SELECT+UPDATE atomic pattern.

        Returns:
            dict chứa combo data.

        Raises:
            RepositoryError: Nếu pool exhausted (không còn combo khả dụng).
        """
        conn = self._engine.raw_connection()
        # Build NOT LIKE clauses dynamically from TERMINAL_ERROR_SUBSTRINGS
        not_like_clauses = " AND ".join(
            "last_error NOT LIKE ?" for _ in TERMINAL_ERROR_SUBSTRINGS
        )
        like_params = [f"%{s}%" for s in TERMINAL_ERROR_SUBSTRINGS]
        row = conn.execute(
            f"""
            SELECT * FROM outlook_combos
            WHERE used_for_signup = 0
              AND (
                last_error IS NULL
                OR (
                    {not_like_clauses}
                )
              )
            ORDER BY created_at ASC
            LIMIT 1
            """,
            like_params,
        ).fetchone()
        if row is None:
            total = conn.execute("SELECT COUNT(*) FROM outlook_combos").fetchone()[0]
            raise RepositoryError(
                "pick_available",
                ValueError(f"pool exhausted: {total} combo(s) total, none available"),
            )
        return dict(row)

    def update_refresh_token(self, email: str, token: str) -> None:
        """Cập nhật refresh token sau rotation.

        Sets: refresh_token=token, last_refresh_at=now(UTC).
        Chỉ UPDATE row đã tồn tại. Nếu email chưa có row trong DB thì fail-fast;
        caller phải pre-upsert combo trước khi chạy để refresh-token rotation không
        bị mất âm thầm.

        Raises:
            RepositoryError: Nếu write operation fail.
        """
        try:
            now = datetime.now(timezone.utc).isoformat()
            with self._engine.get_connection() as conn:
                cursor = conn.execute(
                    """
                    UPDATE outlook_combos
                    SET refresh_token = ?,
                        last_refresh_at = ?
                    WHERE email = ?
                    """,
                    (token, now, email),
                )
                if cursor.rowcount == 0:
                    raise RepositoryError(
                        "update_refresh_token",
                        ValueError(f"no row found for email={email} — token rotation not persisted"),
                    )
        except RepositoryError:
            raise
        except Exception as exc:
            raise RepositoryError("update_refresh_token", exc) from exc

    def list_all(self) -> list[dict]:
        """Trả về tất cả combos.

        Returns:
            List of dicts, mỗi dict là 1 row từ outlook_combos.
        """
        conn = self._engine.raw_connection()
        rows = conn.execute("SELECT * FROM outlook_combos").fetchall()
        return [dict(row) for row in rows]


# --- SessionResultRepository ---


class SessionResultRepository:
    """Data access cho `session_results` table.

    Cung cấp CRUD operations + serialization/deserialization cho JSON fields (cookies, two_factor).
    """

    def __init__(self, engine: "DatabaseEngine") -> None:
        self._engine = engine

    @property
    def engine(self) -> "DatabaseEngine":
        """Public access cho cross-repo transaction use cases."""
        return self._engine

    def create(self, result_data: dict) -> int:
        """Insert session result mới.

        Serialize `cookies` (list→JSON string) và `two_factor` (dict→JSON string) nếu có.
        Nếu `created_at` được truyền vào, dùng giá trị đó; ngược lại dùng DB DEFAULT.

        Args:
            result_data: dict với keys tương ứng columns trong session_results table.

        Returns:
            Auto-increment id của row vừa insert.

        Raises:
            RepositoryError: Nếu write operation fail.
        """
        try:
            with self._engine.get_connection() as conn:
                # Serialize JSON fields
                cookies_raw = result_data.get("cookies")
                cookies_json = json.dumps(cookies_raw) if cookies_raw is not None else None

                two_factor_raw = result_data.get("two_factor")
                two_factor_json = json.dumps(two_factor_raw) if two_factor_raw is not None else None

                created_at = result_data.get("created_at")

                if created_at is not None:
                    cursor = conn.execute(
                        """
                        INSERT INTO session_results
                            (email, password, name, age, user_id, account_id,
                             session_token, access_token, cookies, two_factor,
                             phase1_seconds, phase2_seconds, otp_seconds, created_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            result_data.get("email"),
                            result_data.get("password"),
                            result_data.get("name"),
                            result_data.get("age"),
                            result_data.get("user_id"),
                            result_data.get("account_id"),
                            result_data.get("session_token"),
                            result_data.get("access_token"),
                            cookies_json,
                            two_factor_json,
                            result_data.get("phase1_seconds"),
                            result_data.get("phase2_seconds"),
                            result_data.get("otp_seconds"),
                            created_at,
                        ),
                    )
                else:
                    cursor = conn.execute(
                        """
                        INSERT INTO session_results
                            (email, password, name, age, user_id, account_id,
                             session_token, access_token, cookies, two_factor,
                             phase1_seconds, phase2_seconds, otp_seconds)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            result_data.get("email"),
                            result_data.get("password"),
                            result_data.get("name"),
                            result_data.get("age"),
                            result_data.get("user_id"),
                            result_data.get("account_id"),
                            result_data.get("session_token"),
                            result_data.get("access_token"),
                            cookies_json,
                            two_factor_json,
                            result_data.get("phase1_seconds"),
                            result_data.get("phase2_seconds"),
                            result_data.get("otp_seconds"),
                        ),
                    )
                return cursor.lastrowid
        except RepositoryError:
            raise
        except Exception as exc:
            raise RepositoryError("create", exc) from exc

    def get_by_email(self, email: str) -> dict | None:
        """Lấy session result mới nhất theo email.

        Returns:
            dict chứa tất cả columns (raw, chưa deserialize JSON), hoặc None nếu không tìm thấy.
        """
        conn = self._engine.raw_connection()
        row = conn.execute(
            """
            SELECT * FROM session_results
            WHERE email = ?
            ORDER BY datetime(created_at) DESC, id DESC
            LIMIT 1
            """,
            (email,),
        ).fetchone()
        return dict(row) if row else None

    def update_2fa(self, email: str, mfa_data: dict) -> None:
        """Cập nhật two_factor cho session result mới nhất của email.

        Tìm row mới nhất (ORDER BY datetime(created_at) DESC, id DESC LIMIT 1),
        UPDATE two_factor column.

        Args:
            email: Email cần update.
            mfa_data: Dict chứa 2FA data, sẽ được serialize sang JSON.

        Raises:
            RepositoryError: Nếu không tìm thấy row cho email, hoặc write fail.
        """
        try:
            with self._engine.get_connection() as conn:
                # Tìm id của row mới nhất
                row = conn.execute(
                    """
                    SELECT id FROM session_results
                    WHERE email = ?
                    ORDER BY datetime(created_at) DESC, id DESC
                    LIMIT 1
                    """,
                    (email,),
                ).fetchone()

                if row is None:
                    raise RepositoryError(
                        "update_2fa",
                        ValueError(f"No session result found for email: {email}"),
                    )

                conn.execute(
                    "UPDATE session_results SET two_factor = ? WHERE id = ?",
                    (json.dumps(mfa_data), row["id"]),
                )
        except RepositoryError:
            raise
        except Exception as exc:
            raise RepositoryError("update_2fa", exc) from exc

    def set_mfa_pending(self, email: str, pending: dict) -> None:
        """Lưu enrollment state sau khi /mfa/enroll OK nhưng activate chưa OK.

        Cho phép retry-2fa tái dùng secret/factor_id/session_id thay vì enroll
        lại (server đã có active factor → conflict).

        ``pending`` phải chứa ``secret`` + ``factor_id`` + ``session_id``.
        Serialize sang JSON cho cột ``mfa_pending``.

        Raises:
            RepositoryError: Nếu không tìm thấy row, pending thiếu field, hoặc
                write fail.
        """
        for key in ("secret", "factor_id", "session_id"):
            if not pending.get(key):
                raise RepositoryError(
                    "set_mfa_pending",
                    ValueError(f"pending thiếu field bắt buộc: {key!r}"),
                )
        try:
            with self._engine.get_connection() as conn:
                row = conn.execute(
                    """
                    SELECT id FROM session_results
                    WHERE email = ?
                    ORDER BY datetime(created_at) DESC, id DESC
                    LIMIT 1
                    """,
                    (email,),
                ).fetchone()
                if row is None:
                    raise RepositoryError(
                        "set_mfa_pending",
                        ValueError(f"No session result found for email: {email}"),
                    )
                conn.execute(
                    "UPDATE session_results SET mfa_pending = ? WHERE id = ?",
                    (json.dumps(pending), row["id"]),
                )
        except RepositoryError:
            raise
        except Exception as exc:
            raise RepositoryError("set_mfa_pending", exc) from exc

    def get_mfa_pending(self, email: str) -> dict | None:
        """Đọc mfa_pending của session result mới nhất cho email.

        Returns:
            Dict ``{secret, factor_id, session_id, status}`` hoặc None nếu
            không có pending (column NULL hoặc không có row).
        """
        conn = self._engine.raw_connection()
        row = conn.execute(
            """
            SELECT mfa_pending FROM session_results
            WHERE email = ?
            ORDER BY datetime(created_at) DESC, id DESC
            LIMIT 1
            """,
            (email,),
        ).fetchone()
        if row is None or row["mfa_pending"] is None:
            return None
        try:
            return json.loads(row["mfa_pending"])
        except (json.JSONDecodeError, TypeError) as exc:
            raise RepositoryError("get_mfa_pending", exc) from exc

    def clear_mfa_pending(self, email: str) -> None:
        """Xóa mfa_pending sau khi activate OK + two_factor đã persist.

        Idempotent: không tìm thấy row → no-op.
        """
        try:
            with self._engine.get_connection() as conn:
                row = conn.execute(
                    """
                    SELECT id FROM session_results
                    WHERE email = ?
                    ORDER BY datetime(created_at) DESC, id DESC
                    LIMIT 1
                    """,
                    (email,),
                ).fetchone()
                if row is None:
                    return
                conn.execute(
                    "UPDATE session_results SET mfa_pending = NULL WHERE id = ?",
                    (row["id"],),
                )
        except Exception as exc:
            raise RepositoryError("clear_mfa_pending", exc) from exc

    def export_json(self, email: str) -> dict | None:
        """Export session result mới nhất cho email, format khớp SignupResult schema.

        Deserialize `cookies` (JSON→list) và `two_factor` (JSON→dict).
        Map output sang shape tương thích SignupResult.model_dump():
        - Thêm `success=True` (DB chỉ lưu successful results).
        - Loại bỏ DB-internal fields (`id`).
        - `error` luôn là None (chỉ successful sessions được lưu).

        Returns:
            dict tương thích SignupResult, hoặc None nếu không tìm thấy.
        """
        conn = self._engine.raw_connection()
        row = conn.execute(
            """
            SELECT * FROM session_results
            WHERE email = ?
            ORDER BY datetime(created_at) DESC, id DESC
            LIMIT 1
            """,
            (email,),
        ).fetchone()

        if row is None:
            return None

        raw = dict(row)

        # Deserialize cookies: JSON string → list
        cookies = raw.get("cookies")
        if cookies is not None:
            cookies = json.loads(cookies)
        else:
            cookies = []

        # Deserialize two_factor: JSON string → dict
        two_factor = raw.get("two_factor")
        if two_factor is not None:
            two_factor = json.loads(two_factor)

        return {
            "success": True,
            "email": raw.get("email"),
            "password": raw.get("password"),
            "name": raw.get("name"),
            "age": raw.get("age"),
            "user_id": raw.get("user_id"),
            "account_id": raw.get("account_id"),
            "session_token": raw.get("session_token"),
            "access_token": raw.get("access_token"),
            "cookies": cookies,
            "two_factor": two_factor,
            "phase1_seconds": raw.get("phase1_seconds", 0.0),
            "phase2_seconds": raw.get("phase2_seconds", 0.0),
            "otp_seconds": raw.get("otp_seconds", 0.0),
            "error": None,
            "created_at": raw.get("created_at"),
        }

    def list_all(self) -> list[dict]:
        """Trả về tất cả session results, ordered by datetime(created_at) DESC, id DESC.

        Returns:
            List of dicts, mỗi dict là 1 row (raw, chưa deserialize JSON fields).
        """
        conn = self._engine.raw_connection()
        rows = conn.execute(
            "SELECT * FROM session_results ORDER BY datetime(created_at) DESC, id DESC"
        ).fetchall()
        return [dict(row) for row in rows]

    def cleanup_old_results(self, max_age_days: int = 90) -> int:
        """RETENTION VĨNH VIỄN — KHÔNG xoá session_results (theo yêu cầu).

        Dữ liệu session là tài sản quan trọng (account + token + 2FA); giữ lại
        phòng trường hợp mất mát ở nơi khác. Đường DELETE đã bị vô hiệu hoá:
        method này luôn no-op, trả 0. Signature giữ nguyên để không vỡ caller
        nếu có. KHÔNG khôi phục logic DELETE nếu chưa có yêu cầu rõ ràng.

        Args:
            max_age_days: Bỏ qua (giữ để tương thích chữ ký cũ).

        Returns:
            Luôn 0 (không xoá gì).
        """
        return 0


# --- Terminal statuses for job lifecycle ---

_TERMINAL_STATUSES = ("success", "error", "cancelled")


# --- JobRepository ---


class JobRepository:
    """Data access cho `jobs` và `job_logs` tables.

    Quản lý job lifecycle: create, status transitions, log append,
    recovery sau restart, và cleanup finished jobs.
    """

    def __init__(self, engine: "DatabaseEngine") -> None:
        self._engine = engine

    @property
    def engine(self) -> "DatabaseEngine":
        """Public access cho cross-repo transaction use cases."""
        return self._engine

    def reserve_icloud_imap_attempt(
        self,
        daily_limit: int,
        account_id: str | None = None,
    ) -> tuple[bool, int]:
        """Atomically reserve one signup attempt in a rolling 24-hour window.

        The event is independent from ``jobs``, therefore clearing UI jobs does
        not reset the safety budget. Returns ``(reserved, used_count)``.
        """
        if not isinstance(daily_limit, int) or isinstance(daily_limit, bool):
            raise RepositoryError(
                "reserve_icloud_imap_attempt",
                TypeError("daily_limit must be int"),
            )
        if daily_limit <= 0:
            raise RepositoryError(
                "reserve_icloud_imap_attempt",
                ValueError("daily_limit must be positive"),
            )
        if account_id is not None:
            if not isinstance(account_id, str) or not account_id.strip():
                raise RepositoryError(
                    "reserve_icloud_imap_attempt",
                    ValueError("account_id must be a non-empty string or null"),
                )
            account_id = account_id.strip().casefold()
        try:
            with self._engine.get_connection() as conn:
                if account_id is None:
                    row = conn.execute(
                        """SELECT COUNT(*) AS used
                           FROM icloud_audit_log
                           WHERE event_type = 'icloud_imap_attempt_reserved'
                             AND timestamp_iso >= strftime(
                                 '%Y-%m-%dT%H:%M:%fZ', 'now', '-24 hours'
                             )"""
                    ).fetchone()
                else:
                    # NULL rows are legacy reservations. Count them for every
                    # account until they age out instead of resetting safety.
                    row = conn.execute(
                        """SELECT COUNT(*) AS used
                           FROM icloud_audit_log
                           WHERE event_type = 'icloud_imap_attempt_reserved'
                             AND (apple_id = ? OR apple_id IS NULL)
                             AND timestamp_iso >= strftime(
                                 '%Y-%m-%dT%H:%M:%fZ', 'now', '-24 hours'
                             )""",
                        (account_id,),
                    ).fetchone()
                used = int(row["used"] if row is not None else 0)
                if used >= daily_limit:
                    return False, used
                conn.execute(
                    """INSERT INTO icloud_audit_log
                           (event_type, apple_id, payload_json)
                       VALUES ('icloud_imap_attempt_reserved', ?, ?)""",
                    (
                        account_id,
                        json.dumps(
                            {
                                "daily_limit": daily_limit,
                                "account_id": account_id,
                            }
                        ),
                    ),
                )
                return True, used + 1
        except RepositoryError:
            raise
        except Exception as exc:
            raise RepositoryError("reserve_icloud_imap_attempt", exc) from exc

    def create(self, job_data: dict) -> str:
        """Tạo job mới.

        Args:
            job_data: dict chứa keys: id, email, combo, mail_mode, status,
                      created_at, job_type. Các fields khác optional.

        Returns:
            job_id (string) của job vừa tạo.

        Raises:
            RepositoryError: Nếu write operation fail.
        """
        try:
            with self._engine.get_connection() as conn:
                conn.execute(
                    """
                    INSERT INTO jobs (
                        id, email, combo, mail_mode, status, error, password,
                        secret, first_code, user_id, session_path, payment_link,
                        account_check, region, mail_account_id, created_at,
                        started_at, finished_at, job_type
                    ) VALUES (
                        :id, :email, :combo, :mail_mode, :status, :error, :password,
                        :secret, :first_code, :user_id, :session_path, :payment_link,
                        :account_check, :region, :mail_account_id, :created_at,
                        :started_at, :finished_at, :job_type
                    )
                    """,
                    {
                        "id": job_data["id"],
                        "email": job_data["email"],
                        "combo": job_data["combo"],
                        "mail_mode": job_data.get("mail_mode", "outlook"),
                        "status": job_data.get("status", "queued"),
                        "error": job_data.get("error"),
                        "password": job_data.get("password"),
                        "secret": job_data.get("secret"),
                        "first_code": job_data.get("first_code"),
                        "user_id": job_data.get("user_id"),
                        "session_path": job_data.get("session_path"),
                        "payment_link": job_data.get("payment_link"),
                        "account_check": job_data.get("account_check"),
                        "region": job_data.get("region"),
                        "mail_account_id": job_data.get("mail_account_id"),
                        "created_at": job_data["created_at"],
                        "started_at": job_data.get("started_at"),
                        "finished_at": job_data.get("finished_at"),
                        "job_type": job_data.get("job_type", "signup"),
                    },
                )
        except Exception as exc:
            raise RepositoryError("create", exc) from exc
        return job_data["id"]

    def update_status(self, job_id: str, status: str, **kwargs: object) -> None:
        """Cập nhật status của job.

        Nếu status == "running": set started_at = time.time().
        Nếu status in ("success", "error", "cancelled"): set finished_at = time.time().
        Accepts extra kwargs cho các fields khác (error, password, secret, etc.).
        Nếu `log_line` được truyền, insert log line trong cùng transaction (atomic).

        Args:
            job_id: ID của job.
            status: Status mới.
            **kwargs: Extra fields để update (error, password, secret, first_code,
                      user_id, session_path, payment_link, log_line).

        Raises:
            RepositoryError: Nếu write operation fail.
        """
        # Extract log_line trước khi build SQL
        log_line = kwargs.pop("log_line", None)

        set_clauses = ["status = ?"]
        params: list[object] = [status]

        if status == "queued":
            # Reset: clear timestamps + error + stale result fields khi retry
            set_clauses.append("started_at = NULL")
            set_clauses.append("finished_at = NULL")
            set_clauses.append("error = NULL")
            # Clear stale result fields unless caller explicitly preserves them.
            if "secret" not in kwargs:
                set_clauses.append("secret = NULL")
            if "first_code" not in kwargs:
                set_clauses.append("first_code = NULL")
            if "user_id" not in kwargs:
                set_clauses.append("user_id = NULL")
            if "session_path" not in kwargs:
                set_clauses.append("session_path = NULL")
            if "payment_link" not in kwargs:
                set_clauses.append("payment_link = NULL")
            if "session_data" not in kwargs:
                set_clauses.append("session_data = NULL")
            if "account_check" not in kwargs:
                set_clauses.append("account_check = NULL")
        elif status == "running":
            set_clauses.append("started_at = ?")
            params.append(time.time())
        elif status in _TERMINAL_STATUSES:
            set_clauses.append("finished_at = ?")
            params.append(time.time())

        # Extra kwargs — chỉ update các columns hợp lệ
        _allowed_extra = (
            "error", "password", "secret", "first_code",
            "user_id", "session_path", "payment_link", "session_data",
            "account_check", "region",
        )
        for key, value in kwargs.items():
            if key in _allowed_extra:
                set_clauses.append(f"{key} = ?")
                params.append(value)

        params.append(job_id)

        try:
            with self._engine.get_connection() as conn:
                cursor = conn.execute(
                    f"UPDATE jobs SET {', '.join(set_clauses)} WHERE id = ?",
                    params,
                )
                if cursor.rowcount == 0:
                    raise RepositoryError(
                        "update_status",
                        ValueError(f"job not found in DB: {job_id}"),
                    )
                # Atomic: insert log line trong cùng transaction nếu có
                if log_line is not None:
                    conn.execute(
                        "INSERT INTO job_logs (job_id, line) VALUES (?, ?)",
                        (job_id, log_line),
                    )
        except RepositoryError:
            raise
        except Exception as exc:
            raise RepositoryError("update_status", exc) from exc

    def append_log(self, job_id: str, line: str) -> None:
        """Thêm log line cho job.

        Args:
            job_id: ID của job.
            line: Nội dung log line.

        Raises:
            RepositoryError: Nếu write operation fail.
        """
        try:
            with self._engine.get_connection() as conn:
                conn.execute(
                    "INSERT INTO job_logs (job_id, line) VALUES (?, ?)",
                    (job_id, line),
                )
        except Exception as exc:
            raise RepositoryError("append_log", exc) from exc

    def update_email(self, job_id: str, email: str) -> None:
        """Cập nhật email cho job (khi gmail_advanced resolve email thật từ API).

        Args:
            job_id: ID của job.
            email: Email mới đã resolve.

        Raises:
            RepositoryError: Nếu write operation fail hoặc job không tồn tại.
        """
        try:
            with self._engine.get_connection() as conn:
                cursor = conn.execute(
                    "UPDATE jobs SET email = ? WHERE id = ?",
                    (email, job_id),
                )
                if cursor.rowcount == 0:
                    raise RepositoryError(
                        "update_email",
                        ValueError(f"job not found in DB: {job_id}"),
                    )
        except RepositoryError:
            raise
        except Exception as exc:
            raise RepositoryError("update_email", exc) from exc

    def update_mail_account_id(
        self,
        job_id: str,
        mail_account_id: str,
    ) -> None:
        """Persist the IMAP account selected for a signup job."""
        if not isinstance(mail_account_id, str) or not mail_account_id.strip():
            raise RepositoryError(
                "update_mail_account_id",
                ValueError("mail_account_id must be a non-empty string"),
            )
        try:
            with self._engine.get_connection() as conn:
                cursor = conn.execute(
                    "UPDATE jobs SET mail_account_id = ? WHERE id = ?",
                    (mail_account_id.strip().casefold(), job_id),
                )
                if cursor.rowcount == 0:
                    raise RepositoryError(
                        "update_mail_account_id",
                        ValueError(f"job not found in DB: {job_id}"),
                    )
        except RepositoryError:
            raise
        except Exception as exc:
            raise RepositoryError("update_mail_account_id", exc) from exc

    def delete(self, job_id: str) -> None:
        """Xóa job và log lines liên quan khỏi SQLite.

        Cascade: xóa job_logs trước (FK constraint), rồi jobs row.

        Args:
            job_id: ID của job cần xóa.

        Raises:
            RepositoryError: Nếu write operation fail.
        """
        try:
            with self._engine.get_connection() as conn:
                conn.execute("DELETE FROM job_logs WHERE job_id = ?", (job_id,))
                conn.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
        except Exception as exc:
            raise RepositoryError("delete", exc) from exc

    def get_by_id(self, job_id: str) -> dict | None:
        """Lấy job theo ID.

        Returns:
            dict chứa tất cả columns của job, hoặc None nếu không tìm thấy.
        """
        conn = self._engine.raw_connection()
        row = conn.execute(
            "SELECT * FROM jobs WHERE id = ?", (job_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_all(self) -> list[dict]:
        """Trả về tất cả jobs, ordered by created_at ASC.

        Returns:
            List of dicts.
        """
        conn = self._engine.raw_connection()
        rows = conn.execute(
            "SELECT * FROM jobs ORDER BY created_at ASC"
        ).fetchall()
        return [dict(row) for row in rows]

    def list_by_status(self, status: str) -> list[dict]:
        """Trả về jobs theo status, ordered by created_at ASC.

        Args:
            status: Status để filter.

        Returns:
            List of dicts.
        """
        conn = self._engine.raw_connection()
        rows = conn.execute(
            "SELECT * FROM jobs WHERE status = ? ORDER BY created_at ASC",
            (status,),
        ).fetchall()
        return [dict(row) for row in rows]

    def list_completed(self) -> list[dict]:
        """Trả về jobs đã hoàn thành (success/error/cancelled), ordered by created_at ASC.

        Dùng để load job history vào UI sau restart.

        Returns:
            List of dicts.
        """
        conn = self._engine.raw_connection()
        rows = conn.execute(
            "SELECT * FROM jobs WHERE status IN ('success', 'error', 'cancelled') ORDER BY created_at ASC",
        ).fetchall()
        return [dict(row) for row in rows]

    def delete_finished(self, job_type: str | None = None) -> int:
        """Xoá jobs đã hoàn thành (status = 'success' hoặc 'error').

        Args:
            job_type: Nếu truyền, chỉ xoá jobs có job_type tương ứng.
                      None = xoá tất cả finished jobs (backward compat).

        Cascade xoá job_logs liên quan.

        Returns:
            Số lượng jobs đã xoá.

        Raises:
            RepositoryError: Nếu write operation fail.
        """
        try:
            with self._engine.get_connection() as conn:
                if job_type is not None:
                    cursor = conn.execute(
                        "DELETE FROM jobs WHERE status IN ('success', 'error') AND job_type = ?",
                        (job_type,),
                    )
                else:
                    cursor = conn.execute(
                        "DELETE FROM jobs WHERE status IN ('success', 'error')"
                    )
                return cursor.rowcount
        except Exception as exc:
            raise RepositoryError("delete_finished", exc) from exc

    def delete_all(self, job_type: str | None = None) -> int:
        """Xoá TẤT CẢ jobs bất kể status.

        Args:
            job_type: Nếu truyền, chỉ xoá jobs có job_type tương ứng.
                      None = xoá tất cả jobs.

        Cascade xoá job_logs liên quan.

        Returns:
            Số lượng jobs đã xoá.

        Raises:
            RepositoryError: Nếu write operation fail.
        """
        try:
            with self._engine.get_connection() as conn:
                if job_type is not None:
                    cursor = conn.execute(
                        "DELETE FROM jobs WHERE job_type = ?",
                        (job_type,),
                    )
                else:
                    cursor = conn.execute("DELETE FROM jobs")
                return cursor.rowcount
        except Exception as exc:
            raise RepositoryError("delete_all", exc) from exc

    def get_logs(self, job_id: str) -> list[dict]:
        """Lấy tất cả log lines của job, ordered by created_at ASC.

        Args:
            job_id: ID của job.

        Returns:
            List of dicts với keys: id, job_id, line, created_at.
        """
        conn = self._engine.raw_connection()
        rows = conn.execute(
            "SELECT * FROM job_logs WHERE job_id = ? ORDER BY created_at ASC",
            (job_id,),
        ).fetchall()
        return [dict(row) for row in rows]

    def recover_interrupted(self) -> list[dict]:
        """Recover jobs bị interrupted (queued hoặc running).

        - SELECT jobs WHERE status IN ('queued', 'running')
        - Reset running → queued, clear started_at
        - Return tất cả ordered by created_at ASC

        Returns:
            List of dicts (jobs đã được recover, status = 'queued').

        Raises:
            RepositoryError: Nếu write operation fail.
        """
        try:
            with self._engine.get_connection() as conn:
                # Reset running → queued, clear started_at
                conn.execute(
                    """
                    UPDATE jobs
                    SET status = 'queued', started_at = NULL
                    WHERE status = 'running'
                    """
                )
        except Exception as exc:
            raise RepositoryError("recover_interrupted", exc) from exc

        # Read all queued jobs (bao gồm cả jobs vừa được reset)
        conn = self._engine.raw_connection()
        rows = conn.execute(
            """
            SELECT * FROM jobs
            WHERE status IN ('queued', 'running')
            ORDER BY created_at ASC
            """,
        ).fetchall()
        return [dict(row) for row in rows]

    def cleanup_old_logs(self, max_age_days: int = 30) -> int:
        """Xoá job_logs entries cũ hơn max_age_days cho jobs đã terminal.

        Chỉ xoá logs của jobs có status IN ('success', 'error', 'cancelled').
        Logs của queued/running jobs được giữ nguyên.

        Args:
            max_age_days: Số ngày tối đa giữ logs. Default 30.

        Returns:
            Số lượng log entries đã xoá.

        Raises:
            RepositoryError: Nếu write operation fail.
        """
        try:
            with self._engine.get_connection() as conn:
                cursor = conn.execute(
                    """
                    DELETE FROM job_logs
                    WHERE job_id IN (
                        SELECT id FROM jobs
                        WHERE status IN ('success', 'error', 'cancelled')
                    )
                    AND created_at < unixepoch('now') - ? * 86400
                    """,
                    (max_age_days,),
                )
                return cursor.rowcount
        except Exception as exc:
            raise RepositoryError("cleanup_old_logs", exc) from exc


# --- AuditLogRepository (R6) ---

# Tập 42 event_type được phép GHI (R6.2). Source of truth = design.md
# §Bảng & cột chi tiết — bảng `icloud_audit_log`. CHECK enum CỐ TÌNH KHÔNG đặt
# ở schema (set quá lớn, dễ kẹt khi thêm event mới); validate ở repository layer.
WRITABLE_EVENT_TYPES: tuple[str, ...] = (
    # --- HME generation lifecycle (R3) ---
    "create_attempt",
    "create_success",
    "create_fail",
    "candidate_retry",
    "email_skip_quota_full",  # R3.22 — skip profile khi hme_count >= HME_QUOTA_LIMIT
    # --- Pool transition (R2) ---
    "mark_limited",
    "limited_retry",
    "mark_session_expired",
    "mark_disabled",
    "mark_quota_full",  # R2.10
    "quota_retry",  # R2.12 — quota_full → active transition
    "pool_pick_locked",  # R2.15 — SQLite write-lock timeout
    # --- Infinite mode (R3.23) ---
    "infinite_wait_start",  # R3.23 — bắt đầu sleep giữa 2 vòng generate
    "infinite_wait_end",  # R3.23 — kết thúc sleep, vòng generate tiếp theo
    # --- Profile lifecycle (R5, R12) ---
    "profile_bootstrap",
    "profile_bootstrap_fail",  # R12.17 — Bootstrap retry fail attempt
    "profile_reactivate",
    "profile_delete",
    "profile_delete_fail",
    # --- Add_Profile_Flow web extension (R14) ---
    "profile_add_start",  # R14.1 — POST /add/start, Camoufox đã launch
    "profile_add_success",  # R14.3 — save thành công, profile persist
    "profile_add_cancel",  # R14.7 — user click `Huỷ`
    "profile_add_timeout",  # R14.8 — watchdog timeout, server tự cancel
    "profile_add_fail",  # R14.4-R14.6, R14.11-R14.12 — extract / cookies / conflict / move / crash
    # --- Open_Profile_Flow web + CLI extension (R15) ---
    "profile_reopen_start",  # R15.1 — acquire lock + launch Camoufox HEADED OK
    "profile_reopen_save",  # R15.6 — user Save thành công, verify cookies pass + DB updated
    "profile_reopen_close",  # R15.8 — user Close thường (không sửa DB)
    "profile_reopen_timeout",  # R15.9 — watchdog auto-close
    "profile_reopen_fail",  # R15.3, R15.7, R15.11 — lock conflict / cookies_not_ready / unexpected
    # --- HME manager actions (R9) ---
    "email_deactivate",
    "email_deactivate_fail",
    "email_reactivate",
    "email_reactivate_fail",
    "email_delete",
    "email_delete_fail",
    "email_update_meta",
    "email_update_meta_fail",
    "email_mark_used",
    "email_export",
    # --- Recording (R1) ---
    "recording_start",
    "recording_stop",
    # --- Session_Bundle extractor (R12) ---
    "session_extract",
    "session_extract_fail",
    # --- Pool internals (R2.15) ---
    "cursor_update_failed",
    # --- Reconcile (R8) ---
    "reconcile_add",
    "reconcile_disable",
    # --- Job lifecycle (R13) ---
    "job_started",
    "job_paused",
    "job_resumed",
    "job_completed",
    "job_failed",
    "job_cancelled",
    # --- Direct iCloud IMAP safety budget ---
    "icloud_imap_attempt_reserved",
)
"""Tập event_type SHALL được dùng cho `AuditLogRepository.write()` (R6.6).

Validate ở write-time, raise `ValueError` nếu event_type không nằm trong tập này."""


# Alias backward-compat (R6.6): row audit cũ còn lưu dưới tên `email_revoke` /
# `email_revoke_fail` (tiền-v6). Hai event này SHALL NOT được ghi mới (đã thay
# bằng `email_deactivate` / `email_deactivate_fail`), nhưng list/filter VẪN cho
# phép truyền vào để truy vấn lịch sử.
_BACKCOMPAT_EVENT_ALIASES: tuple[str, ...] = (
    "email_revoke",
    "email_revoke_fail",
)


READABLE_EVENT_TYPES: tuple[str, ...] = WRITABLE_EVENT_TYPES + _BACKCOMPAT_EVENT_ALIASES
"""Superset của WRITABLE — dùng cho `AuditLogRepository.list(event_type=...)` filter (R6.6)."""


# Public alias (R6.2 / task 11): tập đầy đủ event_type hợp lệ cho ghi mới.
AUDIT_EVENT_TYPES: tuple[str, ...] = WRITABLE_EVENT_TYPES
"""Alias công khai cho WRITABLE_EVENT_TYPES — tên dùng trong task spec."""


class AuditLogRepository:
    """Data access cho `icloud_audit_log` table (R6).

    Methods:
        write: INSERT 1 audit event. Caller PHẢI gọi từ trong outer
            `engine.transaction()` khi event đi cùng mutation state (R6.3,
            P3 atomicity); event độc lập (`recording_start`/`recording_stop`)
            có thể gọi không cần outer tx — repository tự mở tx nội bộ qua
            `engine.transaction()` reentrant.
        list: SELECT audit event với filter động (apple_id, event_type, since,
            limit). ORDER BY timestamp_iso DESC (R6.4, P9).
        cleanup_older_than: DELETE event có `timestamp_iso < now - N days`
            (R6.5, P10). Trả về `rowcount`.

    Validation:
        - `write(event_type=X)` → X PHẢI thuộc `WRITABLE_EVENT_TYPES` (42 event),
          không thuộc → raise `ValueError`.
        - `list(event_type=X)` → X PHẢI thuộc `READABLE_EVENT_TYPES` (42 +
          2 alias backward-compat), không thuộc → raise `ValueError`.
    """

    def __init__(self, engine: "DatabaseEngine") -> None:
        self._engine = engine

    @property
    def engine(self) -> "DatabaseEngine":
        """Public access cho cross-repo transaction use cases (R6.3)."""
        return self._engine

    def write(
        self,
        *,
        event_type: str,
        apple_id: str | None,
        payload: dict,
        error: str | None = None,
    ) -> int:
        """INSERT 1 audit event vào `icloud_audit_log`.

        Args:
            event_type: Phải thuộc `WRITABLE_EVENT_TYPES`. Sai → `ValueError`.
            apple_id: Apple ID liên quan (NULL nếu event không gắn account, vd
                `recording_start`).
            payload: Dict serialize sang JSON (UTF-8 safe, `ensure_ascii=False`)
                lưu vào cột `payload_json`. NULL → store `'{}'` (default schema).
            error: Optional error message (text). NULL → cột `error` = NULL.

        Returns:
            `lastrowid` (auto-increment id của row mới).

        Raises:
            ValueError: Nếu event_type không thuộc WRITABLE_EVENT_TYPES.
            RepositoryError: Nếu write operation fail (FK violation, IO error,
                JSON serialize fail, …).
        """
        if event_type not in WRITABLE_EVENT_TYPES:
            raise ValueError(
                f"event_type={event_type!r} not in WRITABLE_EVENT_TYPES "
                f"(R6.6). Use one of {len(WRITABLE_EVENT_TYPES)} writable events; "
                f"deprecated aliases ({', '.join(_BACKCOMPAT_EVENT_ALIASES)}) SHALL NOT "
                f"be written — use email_deactivate / email_deactivate_fail instead."
            )

        try:
            payload_json = json.dumps(payload if payload is not None else {}, ensure_ascii=False)
        except (TypeError, ValueError) as exc:
            raise RepositoryError(
                "write",
                ValueError(f"payload not JSON-serializable: {exc}"),
            ) from exc

        try:
            with self._engine.transaction() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO icloud_audit_log
                        (event_type, apple_id, payload_json, error)
                    VALUES (?, ?, ?, ?)
                    """,
                    (event_type, apple_id, payload_json, error),
                )
                return cursor.lastrowid
        except RepositoryError:
            raise
        except Exception as exc:
            raise RepositoryError("write", exc) from exc

    def list(
        self,
        *,
        apple_id: str | None = None,
        event_type: str | None = None,
        since: str | None = None,
        limit: int = 100,
    ) -> list[dict]:
        """SELECT audit event với filter động + ordering DESC (R6.4, P9).

        Args:
            apple_id: Filter `apple_id = ?`. None → không filter.
            event_type: Filter `event_type = ?`. PHẢI thuộc READABLE_EVENT_TYPES
                nếu khác None; sai → `ValueError`. Cho phép alias backward-compat
                (`email_revoke`, `email_revoke_fail`) để truy vấn row cũ (R6.6).
            since: ISO 8601 UTC timestamp lower bound (`timestamp_iso >= ?`).
                None → không filter.
            limit: Tối đa số row trả về. Mặc định 100. Phải >= 0.

        Returns:
            List of dicts với keys `id`, `timestamp_iso`, `event_type`,
            `apple_id`, `payload`, `error`. `payload` đã được parse từ JSON
            string sang dict; nếu parse fail → `payload` = `{}` + warning silent.

        Raises:
            ValueError: Nếu event_type không thuộc READABLE_EVENT_TYPES, hoặc
                limit < 0.
        """
        if event_type is not None and event_type not in READABLE_EVENT_TYPES:
            raise ValueError(
                f"event_type={event_type!r} not in READABLE_EVENT_TYPES "
                f"(R6.6). Filter only accepts {len(READABLE_EVENT_TYPES)} known "
                f"events ({len(WRITABLE_EVENT_TYPES)} writable + "
                f"{len(_BACKCOMPAT_EVENT_ALIASES)} backward-compat aliases)."
            )
        if limit < 0:
            raise ValueError(f"limit must be >= 0, got {limit}")

        clauses: list[str] = []
        params: list[object] = []
        if apple_id is not None:
            clauses.append("apple_id = ?")
            params.append(apple_id)
        if event_type is not None:
            clauses.append("event_type = ?")
            params.append(event_type)
        if since is not None:
            clauses.append("timestamp_iso >= ?")
            params.append(since)

        sql = "SELECT id, timestamp_iso, event_type, apple_id, payload_json, error FROM icloud_audit_log"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY timestamp_iso DESC, id DESC LIMIT ?"
        params.append(limit)

        conn = self._engine.raw_connection()
        rows = conn.execute(sql, params).fetchall()

        result: list[dict] = []
        for row in rows:
            payload_raw = row["payload_json"]
            try:
                payload_obj = json.loads(payload_raw) if payload_raw else {}
            except (json.JSONDecodeError, TypeError):
                # Fail-safe: row có payload_json corrupt → trả {} thay vì raise
                # (audit list là read-only observability, không nên fail toàn bộ
                # query vì 1 row corrupt). Caller có thể detect qua payload == {}
                # nếu cần.
                payload_obj = {}
            result.append(
                {
                    "id": row["id"],
                    "timestamp_iso": row["timestamp_iso"],
                    "event_type": row["event_type"],
                    "apple_id": row["apple_id"],
                    "payload": payload_obj,
                    "error": row["error"],
                }
            )
        return result

    def cleanup_older_than(self, days: int) -> int:
        """DELETE row có `timestamp_iso < now - days` (R6.5, P10).

        Args:
            days: Số ngày retention. Phải >= 0. `days=0` → xoá toàn bộ row có
                `timestamp_iso < strftime(now)` tại thời điểm execute (effective:
                xoá mọi row đã ghi trước "now"; row được ghi trong cùng tick có
                thể giữ lại).

        Returns:
            `rowcount` — số row đã xoá.

        Raises:
            ValueError: Nếu days < 0.
            RepositoryError: Nếu write operation fail.
        """
        if days < 0:
            raise ValueError(f"days must be >= 0, got {days}")

        try:
            with self._engine.transaction() as conn:
                cursor = conn.execute(
                    "DELETE FROM icloud_audit_log WHERE timestamp_iso < "
                    "strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)",
                    (f"-{days} days",),
                )
                return cursor.rowcount
        except Exception as exc:
            raise RepositoryError("cleanup_older_than", exc) from exc


# ---------------------------------------------------------------------------
# IcloudPoolRepository — Pool persistence cho feature `icloud-hme-pool`
# ---------------------------------------------------------------------------
#
# Mapping SQLite ↔ AppleAccount (icloud_hme.models, frozen dataclass):
#   apple_id          TEXT PK            → str
#   profile_dir       TEXT (NOT NULL ở schema; delete_profile set NULL,
#                           xem note dưới)
#                                       → Path | None
#   status            TEXT NOT NULL      → str  (active|limited|quota_full|
#                                                session_expired|disabled|deleted)
#   hme_count         INTEGER NOT NULL   → int
#   limited_until     TEXT (ISO 8601, %Y-%m-%dT%H:%M:%fZ)
#                                       → datetime | None
#   quota_retry_until TEXT               → datetime | None
#   last_used_at      TEXT               → datetime | None
#   last_error        TEXT               → str | None
#
# Quy ước:
#   - Mọi mutation method dùng engine.transaction() reentrant để caller
#     (Pool_Manager / Generator / HME_Manager) gộp INSERT email + UPDATE
#     account + INSERT audit thành 1 outer-tx (R6.3, R3.5, R8.3).
#   - Read methods dùng raw_connection() (không bắt đầu transaction).
#   - Timestamp ISO format chuẩn: '%Y-%m-%dT%H:%M:%S.%fZ' (Property 30,
#     Timestamp_Format). Trùng SQL strftime('%Y-%m-%dT%H:%M:%fZ','now').

# AppleAccount runtime import được defer xuống `_row_to_apple_account()` (lazy)
# để tránh kích hoạt chain `icloud_hme/__init__.py` → `repository.py` →
# `from ..db.engine` (relative-beyond-top) khi module `db.repositories` được
# load từ test contract `from db.repositories import ...` (top-level package =
# `db`, không có parent). TYPE_CHECKING block đầu file đã có forward-ref cho IDE.

# ISO 8601 UTC + millisecond + 'Z' (Property 30, Timestamp_Format).
_ISO_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"


def _iso_to_dt(value: str | None) -> "datetime | None":
    """Parse ISO 8601 UTC string sang naive UTC datetime.

    Accepts:
      - '2026-01-01T12:34:56.789Z' (Z suffix, microsecond)
      - '2026-01-01T12:34:56.789000Z'
      - '2026-01-01T12:34:56Z' (no fractional)
      - '2026-01-01T12:34:56.789+00:00' (offset)
    """
    if value is None:
        return None
    raw = value
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError as exc:
        raise RepositoryError(
            "iso_to_dt", ValueError(f"không parse được timestamp ISO: {value!r}")
        ) from exc
    # Trả naive UTC (drop tzinfo) — toàn bộ codebase dùng UTC implicit.
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _dt_to_iso(value: "datetime | None") -> str | None:
    """Format datetime → ISO 8601 UTC + 'Z'. None → None."""
    if value is None:
        return None
    if value.tzinfo is not None:
        value = value.astimezone(timezone.utc).replace(tzinfo=None)
    return value.strftime(_ISO_FORMAT)


def _row_to_apple_account(row) -> "AppleAccount":
    """Map sqlite3.Row → frozen AppleAccount dataclass."""
    from pathlib import Path  # local import — Path là leaf type

    # Lazy + dual import — `db.repositories` có thể được load như absolute
    # (`db.repositories`, repo root trên sys.path) hoặc dotted
    # (`gpt_signup_hybrid.db.repositories`, parent dir trên sys.path). Defer
    # import xuống đây để tránh kích hoạt `icloud_hme/__init__.py` ở module-level
    # (chain `..db.engine` → relative-beyond-top khi top-level package = `db`).
    try:
        from icloud_hme.models import AppleAccount
    except ImportError:  # pragma: no cover — fallback dotted import path
        from gpt_signup_hybrid.icloud_hme.models import AppleAccount  # type: ignore[no-redef]

    raw_profile = row["profile_dir"]
    profile_dir = Path(raw_profile) if raw_profile else None
    return AppleAccount(
        apple_id=row["apple_id"],
        profile_dir=profile_dir,
        status=row["status"],
        hme_count=row["hme_count"],
        limited_until=_iso_to_dt(row["limited_until"]),
        quota_retry_until=_iso_to_dt(row["quota_retry_until"]),
        last_used_at=_iso_to_dt(row["last_used_at"]),
        last_error=row["last_error"],
    )


class IcloudPoolRepository:
    """Data access cho `icloud_accounts`, `icloud_emails`, `pool_state`.

    Service layer (Pool_Manager, HME_Generator, HME_Manager) inject repo này
    qua constructor. Không call SQL trực tiếp ở service layer.

    Mọi mutation method wrap trong ``engine.transaction()`` reentrant — caller
    có thể gộp INSERT email + UPDATE account + INSERT audit thành 1 outer-tx
    (R6.3 / R3.5 / R8.3 / R5.6).
    """

    # ---- Whitelist cho update_email_status (chống SQL injection tham số tên cột) ----
    _EMAIL_TIMESTAMP_FIELDS: tuple[str, ...] = (
        "deactivated_at",
        "reactivated_at",
        "deleted_at",
        "last_sync_at",
    )
    _EMAIL_OPTIONAL_FIELDS: tuple[str, ...] = (
        "label",
        "note",
        "used_for_email",
    )

    def __init__(self, engine: "DatabaseEngine") -> None:
        self._engine = engine

    @property
    def engine(self) -> "DatabaseEngine":
        """Public access cho cross-repo transaction use cases (Pool_Manager)."""
        return self._engine

    # =====================================================================
    # group: icloud_accounts
    # =====================================================================

    def get(self, apple_id: str) -> AppleAccount | None:
        """Lấy 1 row icloud_accounts theo apple_id.

        Returns: AppleAccount frozen dataclass, hoặc None nếu không tồn tại.
        """
        conn = self._engine.raw_connection()
        row = conn.execute(
            """
            SELECT apple_id, profile_dir, status, hme_count,
                   limited_until, quota_retry_until, last_used_at, last_error
            FROM icloud_accounts
            WHERE apple_id = ?
            """,
            (apple_id,),
        ).fetchone()
        return _row_to_apple_account(row) if row else None

    def list_all(self) -> list[AppleAccount]:
        """Trả về toàn bộ icloud_accounts ordered by apple_id ASC."""
        conn = self._engine.raw_connection()
        rows = conn.execute(
            """
            SELECT apple_id, profile_dir, status, hme_count,
                   limited_until, quota_retry_until, last_used_at, last_error
            FROM icloud_accounts
            ORDER BY apple_id ASC
            """
        ).fetchall()
        return [_row_to_apple_account(r) for r in rows]

    def upsert(self, apple_id: str, profile_dir) -> None:
        """Insert mới hoặc update profile_dir cho apple_id đã tồn tại.

        Behavior:
          - Apple_ID mới → INSERT (default status='active', hme_count=0).
          - Apple_ID đã tồn tại → CHỈ update profile_dir; KHÔNG đụng status,
            hme_count, limited_until, quota_retry_until, last_used_at,
            last_error. Caller (Bootstrap_Flow / Pool_Manager) tự gọi
            update_status để reset trạng thái khi cần — tách riêng để giữ
            semantics rõ ràng cho audit (R12.10).

        Args:
            apple_id: Email Apple ID.
            profile_dir: pathlib.Path tới Camoufox profile_dir.

        Raises:
            RepositoryError: Nếu write fail.
        """
        try:
            with self._engine.transaction() as conn:
                conn.execute(
                    """
                    INSERT INTO icloud_accounts (apple_id, profile_dir)
                    VALUES (?, ?)
                    ON CONFLICT(apple_id) DO UPDATE SET
                        profile_dir = excluded.profile_dir
                    """,
                    (apple_id, str(profile_dir) if profile_dir is not None else None),
                )
        except Exception as exc:
            raise RepositoryError("upsert", exc) from exc

    def update_status(
        self,
        apple_id: str,
        *,
        status: str,
        limited_until: "datetime | None" = None,
        quota_retry_until: "datetime | None" = None,
        last_error: str | None = None,
        clear_error: bool = False,
        clear_limited_until: bool = False,
        clear_quota_retry_until: bool = False,
    ) -> None:
        """Single UPDATE icloud_accounts. Caller wrap trong outer tx + audit.

        Semantics:
          - status: bắt buộc. Phải nằm trong Profile_Status enum
            (active|limited|quota_full|session_expired|disabled|deleted).
            Repository không validate enum — caller (Pool_Manager) chịu.
          - limited_until / quota_retry_until / last_error: chỉ UPDATE khi
            không None.
          - clear_error / clear_limited_until / clear_quota_retry_until:
            khi True → SET cột tương ứng = NULL (override mọi giá trị truyền
            song song của cùng cột).

        Raises:
            RepositoryError: Nếu apple_id không tồn tại hoặc write fail.
        """
        set_clauses: list[str] = ["status = ?"]
        params: list[object] = [status]

        if clear_limited_until:
            set_clauses.append("limited_until = NULL")
        elif limited_until is not None:
            set_clauses.append("limited_until = ?")
            params.append(_dt_to_iso(limited_until))

        if clear_quota_retry_until:
            set_clauses.append("quota_retry_until = NULL")
        elif quota_retry_until is not None:
            set_clauses.append("quota_retry_until = ?")
            params.append(_dt_to_iso(quota_retry_until))

        if clear_error:
            set_clauses.append("last_error = NULL")
        elif last_error is not None:
            set_clauses.append("last_error = ?")
            params.append(last_error)

        params.append(apple_id)
        sql = (
            f"UPDATE icloud_accounts SET {', '.join(set_clauses)} "
            f"WHERE apple_id = ?"
        )
        try:
            with self._engine.transaction() as conn:
                cursor = conn.execute(sql, params)
                if cursor.rowcount == 0:
                    raise RepositoryError(
                        "update_status",
                        ValueError(f"apple_id không tồn tại: {apple_id}"),
                    )
        except RepositoryError:
            raise
        except Exception as exc:
            raise RepositoryError("update_status", exc) from exc

    def increment_hme_count_and_set_last_used(
        self,
        apple_id: str,
        *,
        when: "datetime",
    ) -> int:
        """Atomic increment hme_count + update last_used_at. Trả new count.

        Caller (HME_Generator) PHẢI wrap trong outer tx cùng INSERT email +
        audit `create_success` để đảm bảo counter và email row + audit cùng
        commit hoặc cùng rollback (R3.5).

        Args:
            apple_id: Apple ID cần increment.
            when: timestamp last_used_at (UTC datetime).

        Returns:
            int — hme_count mới sau increment.

        Raises:
            RepositoryError: Nếu apple_id không tồn tại hoặc write fail.
        """
        iso = _dt_to_iso(when)
        try:
            with self._engine.transaction() as conn:
                cursor = conn.execute(
                    """
                    UPDATE icloud_accounts
                    SET hme_count = hme_count + 1,
                        last_used_at = ?
                    WHERE apple_id = ?
                    """,
                    (iso, apple_id),
                )
                if cursor.rowcount == 0:
                    raise RepositoryError(
                        "increment_hme_count_and_set_last_used",
                        ValueError(f"apple_id không tồn tại: {apple_id}"),
                    )
                row = conn.execute(
                    "SELECT hme_count FROM icloud_accounts WHERE apple_id = ?",
                    (apple_id,),
                ).fetchone()
                return int(row["hme_count"])
        except RepositoryError:
            raise
        except Exception as exc:
            raise RepositoryError(
                "increment_hme_count_and_set_last_used", exc
            ) from exc

    # =====================================================================
    # group: icloud_emails
    # =====================================================================

    def insert_email(
        self,
        *,
        email: str,
        apple_id: str,
        label: str,
        note: str | None,
        hme_id: str | None,
        status: str = "created",
    ) -> int:
        """Insert 1 row icloud_emails. Default status='created'.

        Status enum (CHECK constraint ở schema v6):
            created|reconciled|deactivated|revoked|deleted|disabled|used_for_chatgpt.

        Args:
            email: Email mới sinh (UNIQUE).
            apple_id: Profile sở hữu (FK icloud_accounts.apple_id).
            label: Label tùy ý (thường là 'YYYYMMDD').
            note: Note tùy chọn.
            hme_id: Apple anonymousId/hmeId. None cho email reconciled chưa đối chiếu.
            status: Trạng thái ban đầu, default 'created'.

        Returns:
            int — id auto-increment của row vừa insert.

        Raises:
            RepositoryError: Nếu UNIQUE/FK/CHECK constraint fail.
        """
        try:
            with self._engine.transaction() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO icloud_emails
                        (email, apple_id, label, note, hme_id, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (email, apple_id, label, note, hme_id, status),
                )
                return int(cursor.lastrowid)
        except Exception as exc:
            raise RepositoryError("insert_email", exc) from exc

    def update_email_status(
        self,
        email: str,
        *,
        status: str,
        deactivated_at: "datetime | None" = None,
        reactivated_at: "datetime | None" = None,
        deleted_at: "datetime | None" = None,
        last_sync_at: "datetime | None" = None,
        label: str | None = None,
        note: str | None = None,
        used_for_email: str | None = None,
    ) -> None:
        """UPDATE icloud_emails theo email. Single UPDATE, caller wrap audit.

        Mọi field timestamp / label / note / used_for_email đều opt-in:
        chỉ UPDATE cột truyền non-None. Status bắt buộc (CHECK enum áp dụng
        ở DB layer).

        Raises:
            RepositoryError: Nếu email không tồn tại hoặc CHECK constraint fail.
        """
        set_clauses: list[str] = ["status = ?"]
        params: list[object] = [status]

        timestamp_values = {
            "deactivated_at": deactivated_at,
            "reactivated_at": reactivated_at,
            "deleted_at": deleted_at,
            "last_sync_at": last_sync_at,
        }
        for col in self._EMAIL_TIMESTAMP_FIELDS:
            value = timestamp_values[col]
            if value is not None:
                set_clauses.append(f"{col} = ?")
                params.append(_dt_to_iso(value))

        optional_values = {
            "label": label,
            "note": note,
            "used_for_email": used_for_email,
        }
        for col in self._EMAIL_OPTIONAL_FIELDS:
            value = optional_values[col]
            if value is not None:
                set_clauses.append(f"{col} = ?")
                params.append(value)

        params.append(email)
        sql = (
            f"UPDATE icloud_emails SET {', '.join(set_clauses)} "
            f"WHERE email = ?"
        )
        try:
            with self._engine.transaction() as conn:
                cursor = conn.execute(sql, params)
                if cursor.rowcount == 0:
                    raise RepositoryError(
                        "update_email_status",
                        ValueError(f"email không tồn tại: {email}"),
                    )
        except RepositoryError:
            raise
        except Exception as exc:
            raise RepositoryError("update_email_status", exc) from exc

    def list_emails(
        self,
        *,
        status: str | None = None,
        apple_id: str | None = None,
        label: str | None = None,
        date_range: tuple[str, str] | None = None,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[dict]:
        """Liệt kê icloud_emails với các filter optional, ORDER BY id DESC.

        Args:
            status: Filter theo `status` enum.
            apple_id: Filter theo `apple_id`.
            label: Filter theo `label`.
            date_range: tuple (start_iso, end_iso) — filter
                ``created_at >= start AND created_at < end``. Caller chuẩn
                hoá ISO format trước khi truyền.
            limit: LIMIT N row.
            offset: OFFSET cho pagination.

        Returns:
            List of dicts (raw rows từ icloud_emails).
        """
        clauses: list[str] = []
        params: list[object] = []
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        if apple_id is not None:
            clauses.append("apple_id = ?")
            params.append(apple_id)
        if label is not None:
            clauses.append("label = ?")
            params.append(label)
        if date_range is not None:
            start_iso, end_iso = date_range
            clauses.append("created_at >= ? AND created_at < ?")
            params.extend([start_iso, end_iso])

        sql = "SELECT * FROM icloud_emails"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY id DESC"
        if limit is not None:
            sql += " LIMIT ?"
            params.append(int(limit))
        if offset > 0:
            sql += " OFFSET ?"
            params.append(offset)

        conn = self._engine.raw_connection()
        rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def count_emails(
        self,
        *,
        status: str | None = None,
        apple_id: str | None = None,
        label: str | None = None,
    ) -> int:
        """Đếm tổng số icloud_emails theo filter (cho pagination metadata)."""
        clauses: list[str] = []
        params: list[object] = []
        if status is not None:
            clauses.append("status = ?")
            params.append(status)
        if apple_id is not None:
            clauses.append("apple_id = ?")
            params.append(apple_id)
        if label is not None:
            clauses.append("label = ?")
            params.append(label)

        sql = "SELECT COUNT(*) FROM icloud_emails"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)

        conn = self._engine.raw_connection()
        return int(conn.execute(sql, params).fetchone()[0])

    def list_emails_by_label(
        self,
        label: str,
        *,
        statuses: tuple[str, ...] = ("created", "reconciled"),
    ) -> list[dict]:
        """Liệt kê icloud_emails theo label, filter status ∈ statuses.

        Default statuses=('created','reconciled') — chỉ trả email còn 'sống'
        Apple-side, dùng cho HME_Manager.deactivate_by_label / list_sync.

        Args:
            label: Label cần lọc.
            statuses: Tuple status acceptable (mặc định active set).

        Returns:
            List of dicts ORDER BY id ASC.

        Raises:
            ValueError: Nếu statuses rỗng.
        """
        if not statuses:
            raise ValueError("statuses tuple không được rỗng")
        placeholders = ",".join("?" * len(statuses))
        sql = (
            f"SELECT * FROM icloud_emails "
            f"WHERE label = ? AND status IN ({placeholders}) "
            f"ORDER BY id ASC"
        )
        params: list[object] = [label, *statuses]
        conn = self._engine.raw_connection()
        rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]

    def get_email(self, email: str) -> dict | None:
        """Lấy 1 row icloud_emails theo email."""
        conn = self._engine.raw_connection()
        row = conn.execute(
            "SELECT * FROM icloud_emails WHERE email = ?", (email,)
        ).fetchone()
        return dict(row) if row else None

    # =====================================================================
    # group: pool_state
    # =====================================================================

    _ROUND_ROBIN_KEY = "round_robin_cursor"

    def read_round_robin_cursor(self) -> str | None:
        """Đọc apple_id được pick gần nhất từ pool_state.

        Returns:
            apple_id (str) hoặc None nếu chưa từng được set.
        """
        conn = self._engine.raw_connection()
        row = conn.execute(
            "SELECT value FROM pool_state WHERE key = ?",
            (self._ROUND_ROBIN_KEY,),
        ).fetchone()
        return row["value"] if row else None

    def write_round_robin_cursor(self, apple_id: str) -> None:
        """Set/replace apple_id vào pool_state.round_robin_cursor.

        Idempotent — caller (Pool_Manager.pick_active_profile) gọi mỗi lần
        pick xong, trong CÙNG transaction BEGIN IMMEDIATE với SELECT next
        profile (R2.3, R2.15).

        Raises:
            RepositoryError: Nếu write fail.
        """
        try:
            with self._engine.transaction() as conn:
                conn.execute(
                    """
                    INSERT INTO pool_state (key, value)
                    VALUES (?, ?)
                    ON CONFLICT(key) DO UPDATE SET value = excluded.value
                    """,
                    (self._ROUND_ROBIN_KEY, apple_id),
                )
        except Exception as exc:
            raise RepositoryError("write_round_robin_cursor", exc) from exc


# --- ChatGptAccountRepository (auto-reg-gpt, R4) ---


class ChatGptAccountRepository:
    """Data access cho `chatgpt_accounts` table.

    Cung cấp persistence cho ChatGPT accounts đã đăng ký thành công qua
    AutoRegRunner. Atomic persist_success đảm bảo INSERT account + UPDATE
    icloud_emails status trong single transaction (R4.1, R4.2, R4.3).
    """

    def __init__(self, engine: "DatabaseEngine") -> None:
        self._engine = engine

    @property
    def engine(self) -> "DatabaseEngine":
        """Public access cho cross-repo transaction use cases."""
        return self._engine

    def persist_success(
        self,
        email: str,
        password: str,
        secret_2fa: str | None,
    ) -> None:
        """Atomic: INSERT chatgpt_accounts + UPDATE icloud_emails.status trong single transaction.

        INSERT OR IGNORE cho idempotent retry (nếu email đã tồn tại, skip).
        UPDATE chỉ affect row có status='created' (tránh overwrite status khác).

        Args:
            email: Email iCloud đã dùng đăng ký ChatGPT.
            password: Mật khẩu tài khoản ChatGPT.
            secret_2fa: TOTP secret (None nếu không enable 2FA).

        Raises:
            RepositoryError: Nếu transaction fail.
        """
        try:
            with self._engine.transaction() as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO chatgpt_accounts (email, password, secret_2fa) "
                    "VALUES (?, ?, ?)",
                    (email, password, secret_2fa),
                )
                conn.execute(
                    "UPDATE icloud_emails SET status = 'used_for_chatgpt' "
                    "WHERE email = ? AND status = 'created'",
                    (email,),
                )
        except Exception as exc:
            raise RepositoryError("persist_success", exc) from exc

    def list_accounts(
        self,
        *,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[list[dict], int]:
        """Paginated SELECT chatgpt_accounts.

        Args:
            page: Trang hiện tại (1-indexed). Mặc định 1.
            page_size: Số row mỗi trang. Mặc định 50.

        Returns:
            Tuple (rows, total_count). rows là list[dict] cho trang hiện tại,
            total_count là tổng số row trong bảng.

        Raises:
            ValueError: Nếu page < 1 hoặc page_size < 1.
        """
        if page < 1:
            raise ValueError(f"page must be >= 1, got {page}")
        if page_size < 1:
            raise ValueError(f"page_size must be >= 1, got {page_size}")

        conn = self._engine.raw_connection()
        total = conn.execute(
            "SELECT COUNT(*) FROM chatgpt_accounts"
        ).fetchone()[0]

        offset = (page - 1) * page_size
        rows = conn.execute(
            "SELECT * FROM chatgpt_accounts ORDER BY created_at DESC, id DESC "
            "LIMIT ? OFFSET ?",
            (page_size, offset),
        ).fetchall()

        return [dict(row) for row in rows], total

    def get_created_emails(self, limit: int = 10) -> list[str]:
        """SELECT email FROM icloud_emails WHERE status='created' LIMIT ?.

        Trả về danh sách email iCloud sẵn sàng cho ChatGPT registration.

        Args:
            limit: Số lượng email tối đa. Mặc định 10.

        Returns:
            List email strings.
        """
        conn = self._engine.raw_connection()
        rows = conn.execute(
            "SELECT email FROM icloud_emails WHERE status = 'created' LIMIT ?",
            (limit,),
        ).fetchall()
        return [row["email"] for row in rows]

# ---------------------------------------------------------------------------
# SettingsRepository — Unified settings store (unified-settings-store spec)
# ---------------------------------------------------------------------------


class SettingsRepository:
    """Data access cho bảng `settings` (flat KV, dot-namespaced key, JSON value).

    Cung cấp CRUD: get / set / delete / list / bulk_get / bulk_set.
    Mọi write method ghi audit log vào `icloud_audit_log` trong cùng transaction.
    Retry busy-lock (R11.3) qua `_with_retry`.
    """

    def __init__(self, engine: "DatabaseEngine") -> None:
        self._engine = engine

    # ── Key validation ──────────────────────────────────────────────────────

    def _validate_key(self, key: str) -> None:
        """Validate key format: regex + length (R3.4, R3.5)."""
        if not isinstance(key, str):
            raise RepositoryError(
                "set", TypeError(f"key must be str, got {type(key).__name__}")
            )
        if len(key) > _KEY_MAX_LEN:
            raise RepositoryError(
                "set", ValueError(f"key too long: {len(key)} > {_KEY_MAX_LEN}")
            )
        if not _KEY_REGEX.match(key):
            raise RepositoryError(
                "set", ValueError(f"invalid key format: {key!r}")
            )

    def _validate_whitelist(self, key: str, op: str = "set") -> None:
        """Validate key thuộc whitelist (R4.2, R4.3)."""
        if key not in _EXACT_KEYS:
            raise RepositoryError(
                op, ValueError(f"key not in whitelist: {key}")
            )

    def _validate_type(self, key: str, value) -> None:
        """Type-check theo bảng R3.6. Dispatch tới module-level validator."""
        _validate_type_constraint(key, value)

    # ── CRUD ────────────────────────────────────────────────────────────────

    def get(self, key: str):
        """R2.1: Read key, JSON-decode, return None nếu không tồn tại.

        Raise RepositoryError nếu value corrupt (R3.3).
        """
        conn = self._engine.raw_connection()
        row = conn.execute(
            "SELECT value FROM settings WHERE key = ?", (key,)
        ).fetchone()
        if row is None:
            return None
        if row["value"] is None:
            return None
        try:
            return json.loads(row["value"])
        except json.JSONDecodeError as exc:
            raise RepositoryError("get", exc) from exc

    def set(self, key: str, value) -> None:
        """R2.2: Validate + UPSERT + audit log."""
        self._validate_key(key)
        self._validate_whitelist(key)
        self._validate_type(key, value)
        encoded = json.dumps(
            value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        self._with_retry(lambda: self._do_set(key, encoded))

    def _do_set(self, key: str, encoded: str) -> None:
        with self._engine.get_connection() as conn:
            existing = conn.execute(
                "SELECT 1 FROM settings WHERE key = ?", (key,)
            ).fetchone()
            conn.execute(
                """INSERT INTO settings (key, value) VALUES (?, ?)
                   ON CONFLICT(key) DO UPDATE SET
                     value = excluded.value,
                     updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')""",
                (key, encoded),
            )
            # Audit log (R10.1) — redact sensitive keys
            audit_value = "***" if key in _SENSITIVE_KEYS else encoded
            conn.execute(
                """INSERT INTO icloud_audit_log (event_type, payload_json)
                   VALUES ('settings.set', ?)""",
                (json.dumps({
                    "key": key,
                    "old_present": existing is not None,
                    "new_value": audit_value,
                }),),
            )

    def delete(self, key: str) -> bool:
        """R2.3: Delete key, return True nếu xoá được."""
        self._validate_key(key)
        self._validate_whitelist(key, "delete")
        return self._with_retry(lambda: self._do_delete(key))

    def _do_delete(self, key: str) -> bool:
        with self._engine.get_connection() as conn:
            cursor = conn.execute(
                "DELETE FROM settings WHERE key = ?", (key,)
            )
            if cursor.rowcount > 0:
                conn.execute(
                    """INSERT INTO icloud_audit_log (event_type, payload_json)
                       VALUES ('settings.delete', ?)""",
                    (json.dumps({"key": key}),),
                )
                return True
            return False

    def list(self, prefix: str | None = None) -> dict:
        """R2.4: List all hoặc filter theo prefix. Chỉ trả key trong whitelist."""
        conn = self._engine.raw_connection()
        if prefix:
            rows = conn.execute(
                "SELECT key, value FROM settings WHERE key = ? OR key LIKE ?",
                (prefix, f"{prefix}.%"),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT key, value FROM settings"
            ).fetchall()
        result = {}
        for row in rows:
            if row["key"] in _EXACT_KEYS:
                result[row["key"]] = (
                    json.loads(row["value"]) if row["value"] else None
                )
        return result

    def bulk_get(self, keys) -> dict:
        """R2.5: Get nhiều key cùng lúc."""
        if not keys:
            return {}
        conn = self._engine.raw_connection()
        placeholders = ",".join("?" for _ in keys)
        rows = conn.execute(
            f"SELECT key, value FROM settings WHERE key IN ({placeholders})",
            tuple(keys),
        ).fetchall()
        return {
            row["key"]: json.loads(row["value"])
            for row in rows
            if row["value"]
        }

    def bulk_set(self, items) -> None:
        """R2.6: Validate all → single transaction UPSERT + audit (R11.1)."""
        for key in items:
            self._validate_key(key)
            self._validate_whitelist(key)
            self._validate_type(key, items[key])
        self._with_retry(lambda: self._do_bulk_set(items))

    def _do_bulk_set(self, items) -> None:
        with self._engine.get_connection() as conn:
            keys_written = []
            for key, value in items.items():
                encoded = json.dumps(
                    value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
                )
                conn.execute(
                    """INSERT INTO settings (key, value) VALUES (?, ?)
                       ON CONFLICT(key) DO UPDATE SET
                         value = excluded.value,
                         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now')""",
                    (key, encoded),
                )
                keys_written.append(key)
            # Audit 1 entry cho bulk (R10.3)
            conn.execute(
                """INSERT INTO icloud_audit_log (event_type, payload_json)
                   VALUES ('settings.bulk_set', ?)""",
                (json.dumps({"keys": keys_written}),),
            )

    # ── Retry busy-lock (R11.3) ─────────────────────────────────────────────

    def _with_retry(self, fn, max_retries: int = 3):
        """Wrap fn() với retry logic cho SQLite busy-lock.

        Backoff: [50ms, 150ms, 400ms]. Max 3 retries.
        Catch cả RepositoryError wrapping OperationalError("locked")
        lẫn raw OperationalError("locked").
        """
        import sqlite3 as _sqlite3

        backoffs = [0.05, 0.15, 0.4]
        for attempt in range(max_retries + 1):
            try:
                return fn()
            except RepositoryError as e:
                if (
                    isinstance(e.cause, _sqlite3.OperationalError)
                    and "locked" in str(e.cause)
                ):
                    if attempt < max_retries:
                        time.sleep(backoffs[attempt])
                        continue
                raise
            except _sqlite3.OperationalError as e:
                if "locked" in str(e) and attempt < max_retries:
                    time.sleep(backoffs[attempt])
                    continue
                raise RepositoryError("set", e) from e
