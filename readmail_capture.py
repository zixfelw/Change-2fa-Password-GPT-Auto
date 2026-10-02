"""Short-lived in-memory snapshots of iCloud OTP messages before IMAP cleanup."""
from __future__ import annotations

import threading
import time
from typing import Any


_CAPTURE_TTL_SECONDS = 30 * 60.0
_lock = threading.Lock()
_records: dict[str, tuple[float, list[dict[str, Any]]]] = {}


def capture_otp_records(
    *,
    recipient: str,
    records: list[dict[str, Any]],
    matched_uids: set[str],
) -> None:
    mailbox = recipient.strip().casefold()
    if not mailbox or not matched_uids:
        return
    captured = []
    for record in records:
        if str(record.get("uid") or "") not in matched_uids:
            continue
        snapshot = dict(record)
        # poll_otp/poll_all_codes already matched this UID to the serialized
        # registration job. Preserve that decision when iCloud removed +tag.
        snapshot["recipients"] = {mailbox}
        captured.append(snapshot)
    if not captured:
        return
    now = time.monotonic()
    with _lock:
        _prune_locked(now)
        _records[mailbox] = (now, captured)


def get_captured_otp_records(recipient: str) -> list[dict[str, Any]]:
    mailbox = recipient.strip().casefold()
    now = time.monotonic()
    with _lock:
        _prune_locked(now)
        entry = _records.get(mailbox)
        return [dict(record) for record in entry[1]] if entry else []


def clear_captured_otp_records(recipient: str) -> None:
    with _lock:
        _records.pop(recipient.strip().casefold(), None)


def _prune_locked(now: float) -> None:
    expired = [
        mailbox
        for mailbox, (captured_at, _) in _records.items()
        if now - captured_at > _CAPTURE_TTL_SECONDS
    ]
    for mailbox in expired:
        _records.pop(mailbox, None)
