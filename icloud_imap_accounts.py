"""Shared iCloud IMAP account-pool normalization and lookup."""
from __future__ import annotations

import re
from typing import Any, Mapping

from icloud_imap_policy import ICloudImapPolicy


ICLOUD_IMAP_ACCOUNTS_KEY = "mail_mode.icloud_imap_accounts"
ICLOUD_IMAP_ACTIVE_ACCOUNT_KEY = "mail_mode.icloud_imap_active_account"
ICLOUD_IMAP_LEGACY_CONFIG_KEY = "mail_mode.icloud_imap_config"
READMAIL_ALIAS_ACCOUNTS_KEY = "readmail.alias_accounts"
MAX_ICLOUD_IMAP_ACCOUNTS = 100

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_icloud_imap_account_id(username: str) -> str:
    """Return the stable account id derived from an IMAP username."""
    value = str(username or "").strip().casefold()
    if not _EMAIL_RE.fullmatch(value):
        raise ValueError("iCloud IMAP username must be a valid email address")
    return value


def canonicalize_icloud_imap_config(
    value: Mapping[str, Any],
) -> dict[str, Any]:
    """Validate and copy one account config without discarding its policy."""
    if not isinstance(value, Mapping):
        raise ValueError("iCloud IMAP account config must be an object")
    username = str(value.get("username") or "").strip()
    app_password = str(value.get("app_password") or "").strip()
    normalize_icloud_imap_account_id(username)
    if not app_password:
        raise ValueError("iCloud app-specific password is required")
    policy = ICloudImapPolicy.from_mapping(value)
    return {
        "username": username,
        "app_password": app_password,
        **policy.to_config(),
    }


def load_icloud_imap_accounts(
    settings: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    """Load the account pool and merge the legacy single-account config."""
    raw_accounts = settings.get(ICLOUD_IMAP_ACCOUNTS_KEY)
    if raw_accounts is None:
        raw_accounts = {}
    if not isinstance(raw_accounts, Mapping):
        raise ValueError(f"{ICLOUD_IMAP_ACCOUNTS_KEY} must be an object")
    if len(raw_accounts) > MAX_ICLOUD_IMAP_ACCOUNTS:
        raise ValueError(
            f"iCloud IMAP account pool exceeds {MAX_ICLOUD_IMAP_ACCOUNTS} entries"
        )

    accounts: dict[str, dict[str, Any]] = {}
    for raw_account_id, raw_config in raw_accounts.items():
        if not isinstance(raw_account_id, str):
            raise ValueError("iCloud IMAP account id must be a string")
        config = canonicalize_icloud_imap_config(raw_config)
        account_id = normalize_icloud_imap_account_id(config["username"])
        if raw_account_id.strip().casefold() != account_id:
            raise ValueError(
                "iCloud IMAP account id must match the normalized username"
            )
        if account_id in accounts:
            raise ValueError(f"duplicate iCloud IMAP account: {account_id}")
        accounts[account_id] = config

    legacy = settings.get(ICLOUD_IMAP_LEGACY_CONFIG_KEY)
    if isinstance(legacy, Mapping):
        legacy_config = canonicalize_icloud_imap_config(legacy)
        legacy_id = normalize_icloud_imap_account_id(legacy_config["username"])
        accounts.setdefault(legacy_id, legacy_config)
    if len(accounts) > MAX_ICLOUD_IMAP_ACCOUNTS:
        raise ValueError(
            f"iCloud IMAP account pool exceeds {MAX_ICLOUD_IMAP_ACCOUNTS} entries"
        )
    return accounts


def resolve_icloud_imap_account(
    settings: Mapping[str, Any],
    account_id: str | None = None,
) -> tuple[str, dict[str, Any]]:
    """Resolve a requested/active account while preserving legacy behavior."""
    accounts = load_icloud_imap_accounts(settings)
    if not accounts:
        raise ValueError("configure at least one iCloud IMAP account")

    requested = (
        normalize_icloud_imap_account_id(account_id)
        if account_id
        else None
    )
    if requested is None:
        raw_active = settings.get(ICLOUD_IMAP_ACTIVE_ACCOUNT_KEY)
        if isinstance(raw_active, str) and raw_active.strip():
            requested = normalize_icloud_imap_account_id(raw_active)

    if requested is None:
        legacy = settings.get(ICLOUD_IMAP_LEGACY_CONFIG_KEY)
        if isinstance(legacy, Mapping):
            requested = normalize_icloud_imap_account_id(
                str(legacy.get("username") or "")
            )
        elif len(accounts) == 1:
            requested = next(iter(accounts))
        else:
            raise ValueError("select an iCloud IMAP account")

    config = accounts.get(requested)
    if config is None:
        raise ValueError(f"unknown iCloud IMAP account: {requested}")
    return requested, dict(config)


def upsert_icloud_imap_account(
    settings: Mapping[str, Any],
    config: Mapping[str, Any],
) -> tuple[str, dict[str, dict[str, Any]], dict[str, Any]]:
    """Insert or update one account without removing existing entries."""
    canonical = canonicalize_icloud_imap_config(config)
    account_id = normalize_icloud_imap_account_id(canonical["username"])
    accounts = load_icloud_imap_accounts(settings)
    if account_id not in accounts and len(accounts) >= MAX_ICLOUD_IMAP_ACCOUNTS:
        raise ValueError(
            f"iCloud IMAP account pool is limited to {MAX_ICLOUD_IMAP_ACCOUNTS}"
        )
    accounts[account_id] = canonical
    return account_id, accounts, canonical
