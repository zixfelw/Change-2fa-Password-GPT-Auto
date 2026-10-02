"""Mail providers cho OTP polling.

5 backends + 1 wrapper:
    - WorkerMailProvider:          Cloudflare Worker logs API (icloud-cf-mail style).
    - ICloudImapMailProvider:      iCloud IMAP inbox dùng chung cho Hide My Email.
    - OutlookMailProvider:         Microsoft Graph API qua refresh_token (combo Outlook).
    - DongVanFBOutlookProvider:    tools.dongvanfb.net API qua refresh_token (combo Outlook).
    - GmailAdvancedProvider:       checkotpgmail.live API.
    - OutlookCascadeProvider:      Wrapper — DongVanFB trước, fallback Microsoft Graph
                                   khi DongVanFB API down hoặc poll timeout. Sticky
                                   bypass khi DongVanFB fail trong cùng process.

Factory `build_provider_outlook` mặc định trả OutlookCascadeProvider (auto-fallback);
muốn fix-provider thì dùng `build_provider_dongvanfb` trực tiếp.

Mỗi provider có method:
    async def poll_otp(*, recipient, started_at, timeout_seconds, poll_interval_seconds, log) -> str
"""
from __future__ import annotations

import asyncio
import imaplib
import json
import logging
import re
import ssl
import threading
import time
from datetime import datetime, timedelta, timezone
from email.message import Message
from email.parser import BytesParser
from email.policy import default as default_email_policy
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import quote

import httpx

if TYPE_CHECKING:
    from db.repositories import ComboRepository


# UA browser: Cloudflare (Bot Fight Mode/WAF, error 1010) chặn UA httpx/urllib.
_BROWSER_UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

_OTP_REGEX = re.compile(
    r"(?:verification\s+code|one[-\s]*time\s+(?:password|code)|security\s+code|login\s+code)"
    r"[^0-9]{0,40}(\d{6})"
    r"|(?<!\d)(\d{6})(?!\d)",
    re.IGNORECASE | re.DOTALL,
)


def _parse_dt(value: Any) -> datetime | None:
    """Parse datetime từ nhiều format khác nhau."""
    if not value:
        return None
    if isinstance(value, (int, float)):
        ts = float(value)
        if ts > 1e12:
            ts /= 1000.0
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    s = str(value).strip()
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except ValueError:
        pass
    for fmt in ("%a, %d %b %Y %H:%M:%S GMT", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ"):
        try:
            dt = datetime.strptime(s, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _extract_otp(subject: str, body: str) -> str | None:
    """Tìm code 6 chữ số trong subject + body."""
    cleaned = re.sub(r"<[^>]*>", " ", f"{subject}\n{body}")
    cleaned = re.sub(r"https?://\S+", " ", cleaned)
    match = _OTP_REGEX.search(cleaned)
    if not match:
        return None
    return match.group(1) or match.group(2)


def _sort_messages_newest_first(messages: list[dict[str, Any]]) -> None:
    """Sort in-place mới→cũ theo date/receivedAt/created_at.

    Nếu KHÔNG message nào có date hợp lệ (iCloud worker đôi khi không trả) →
    giữ nguyên thứ tự gốc của API (không đảo lung tung).
    """
    has_any_date = any(
        _parse_dt(m.get("date") or m.get("receivedAt") or m.get("created_at"))
        for m in messages
    )
    if has_any_date:
        messages.sort(
            key=lambda m: (
                _parse_dt(m.get("date") or m.get("receivedAt") or m.get("created_at"))
                or datetime.min.replace(tzinfo=timezone.utc)
            ),
            reverse=True,
        )


def _is_openai_sender(sender: str) -> bool:
    """Filter mail từ OpenAI để tránh nhặt nhầm OTP của dịch vụ khác."""
    s = (sender or "").lower()
    return any(d in s for d in ("openai.com", "auth.openai.com", "noreply@openai", "tm.openai.com"))


def _worker_message_is_openai(message: dict[str, Any]) -> bool:
    """Reject an explicit non-OpenAI sender without breaking sparse relay payloads."""
    raw_sender = (
        message.get("from")
        or message.get("sender")
        or message.get("fromAddress")
        or message.get("from_address")
    )
    if isinstance(raw_sender, dict):
        raw_sender = (
            raw_sender.get("address")
            or raw_sender.get("email")
            or raw_sender.get("emailAddress", {}).get("address")
        )
    sender = str(raw_sender or "").strip()
    subject = str(message.get("subject") or "")
    # Some Worker deployments omit sender entirely. Preserve compatibility in
    # that case; when sender exists, require OpenAI evidence in sender/subject.
    return not sender or _is_openai_sender(sender) or "openai" in subject.lower()


class MailProvider(Protocol):
    """Interface chung."""

    async def poll_otp(
        self,
        *,
        recipient: str,
        started_at: datetime,
        timeout_seconds: float,
        poll_interval_seconds: float,
        log,
    ) -> str:
        ...


# ─────────────────────────────────────────────────────────────────────
# Worker provider (icloud-cf-mail style)
# ─────────────────────────────────────────────────────────────────────


# NOTE: Worker provider KHÔNG còn lọc OTP theo thời gian (`started_at`). Recipient
# là +alias duy nhất cho mỗi phiên đăng ký nên mailbox chỉ chứa mã của phiên hiện
# tại; mã được sort mới→cũ và caller dedup qua tried_codes. Lọc theo `date` (HME
# relay lệch giờ, poll_started reset sau resend) trước đây gây loại nhầm mã hợp lệ.
# Param `started_at` vẫn giữ trong signature để đồng nhất interface MailProvider
# (các provider inbox-dùng-lại như Outlook/DongVanFB/Gmail vẫn cần lọc thời gian).

# Số mã OTP tối đa lấy về trong 1 lần poll_all_codes (mới→cũ). Đủ để bắt mail-delay
# trong cùng phiên (vài lần resend) mà không thử dồn mã cũ đã bị vô hiệu.
_WORKER_MAX_CODES = 5


class WorkerMailProvider:
    """Cloudflare Worker logs API.

    Worker trả JSON:
        - list trực tiếp [{to, subject, body, date, ...}, ...]
        - hoặc dict {messages|items|logs|emails|data: [...]}
    """

    def __init__(self, *, logs_url: str, api_key: str | None, insecure_tls: bool = False):
        if not logs_url:
            raise ValueError("Worker logs_url is required")
        self.logs_url = logs_url
        self.api_key = api_key
        self.insecure_tls = insecure_tls
        if insecure_tls:
            from config import warn_insecure_tls
            warn_insecure_tls("mail_providers.WorkerMailProvider")

    @staticmethod
    def _normalize(payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            for key in ("messages", "items", "logs", "emails", "data"):
                value = payload.get(key)
                if isinstance(value, list):
                    return value
        return []

    async def poll_otp(
        self,
        *,
        recipient: str,
        started_at: datetime,
        timeout_seconds: float,
        poll_interval_seconds: float,
        log,
    ) -> str:
        mailbox = recipient.strip().lower()
        if not mailbox:
            raise ValueError("recipient is required")

        headers: dict[str, str] = {"Accept": "application/json", "User-Agent": _BROWSER_UA}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        if self.insecure_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            verify: Any = ctx
        else:
            verify = True

        deadline = time.monotonic() + max(timeout_seconds, 1.0)
        log(f"[otp:worker] polling {mailbox} (timeout {timeout_seconds:.0f}s)")

        async with httpx.AsyncClient(verify=verify, timeout=20.0, follow_redirects=True) as client:
            attempt = 0
            consecutive_errors = 0  # fail-fast khi worker endpoint down liên tục
            _max_consecutive = 3
            while True:
                attempt += 1
                try:
                    response = await client.get(
                        f"{self.logs_url}?mail={quote(mailbox)}",
                        headers=headers,
                    )
                    if response.status_code != 200:
                        log(f"[otp:worker] HTTP {response.status_code} attempt {attempt}")
                        consecutive_errors += 1
                        if consecutive_errors >= _max_consecutive:
                            raise TimeoutError(
                                f"Worker logs API HTTP error {consecutive_errors} lần liên tiếp "
                                f"(last status={response.status_code}) — endpoint có thể đang down"
                            )
                    else:
                        consecutive_errors = 0
                        messages = self._normalize(response.json())
                        # Sort mới nhất trước (helper xử lý case thiếu date).
                        _sort_messages_newest_first(messages)
                        for msg in messages:
                            msg_to = str(msg.get("to") or "").strip().lower()
                            if msg_to and msg_to != mailbox:
                                continue
                            if not _worker_message_is_openai(msg):
                                log(
                                    "[otp:worker] skip code candidate from "
                                    "explicit non-OpenAI sender"
                                )
                                continue
                            # KHÔNG lọc theo thời gian: recipient là +alias DUY NHẤT
                            # cho mỗi phiên nên mailbox chỉ chứa mã của phiên này. Mã
                            # đã sort mới→cũ; caller (browser_phase) dedup qua tried_codes
                            # nên luôn thử mã mới nhất chưa thử. Lọc theo `date` (HME relay
                            # lệch giờ + poll_started reset sau resend) dễ loại nhầm mã đúng.
                            subject = str(msg.get("subject") or "")
                            body = (
                                msg.get("bodyText") or msg.get("text") or msg.get("body")
                                or msg.get("htmlBody") or msg.get("content") or msg.get("html") or ""
                            )
                            code = _extract_otp(subject, str(body))
                            if code:
                                log(f"[otp:worker] found {code} (attempt {attempt})")
                                return code
                except (httpx.HTTPError, ValueError) as exc:
                    consecutive_errors += 1
                    log(
                        f"[otp:worker] error attempt {attempt} "
                        f"({consecutive_errors}/{_max_consecutive}): {type(exc).__name__}: {exc!r}"
                    )
                    if consecutive_errors >= _max_consecutive:
                        raise TimeoutError(
                            f"Worker logs API network error {consecutive_errors} lần liên tiếp: "
                            f"{type(exc).__name__}: {exc}"
                        ) from exc

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(f"OTP timeout after {timeout_seconds}s for {mailbox}")
                await asyncio.sleep(min(poll_interval_seconds, remaining))

    async def poll_all_codes(
        self,
        *,
        recipient: str,
        started_at: datetime,
        log,
    ) -> list[str]:
        """Lấy TẤT CẢ OTP codes mới (sau started_at) trong 1 lần call API.

        Return list unique codes theo thứ tự API trả về (có thể mới nhất trước hoặc sau
        tuỳ worker). Không block/poll — chỉ fetch 1 lần.
        Dùng cho case: sau khi nhận 1 code, fetch lại để bắt thêm mail delay.
        """
        mailbox = recipient.strip().lower()
        if not mailbox:
            return []

        headers: dict[str, str] = {"Accept": "application/json", "User-Agent": _BROWSER_UA}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        if self.insecure_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            verify: Any = ctx
        else:
            verify = True

        try:
            async with httpx.AsyncClient(verify=verify, timeout=20.0, follow_redirects=True) as client:
                response = await client.get(
                    f"{self.logs_url}?mail={quote(mailbox)}",
                    headers=headers,
                )
                if response.status_code != 200:
                    return []
                messages = self._normalize(response.json())
                # Sort mới→cũ để caller thử mã mới nhất trước (mirror poll_otp).
                _sort_messages_newest_first(messages)
                codes: list[str] = []
                seen: set[str] = set()
                for msg in messages:
                    msg_to = str(msg.get("to") or "").strip().lower()
                    if msg_to and msg_to != mailbox:
                        continue
                    if not _worker_message_is_openai(msg):
                        continue
                    # KHÔNG lọc theo thời gian — xem giải thích ở poll_otp (alias duy
                    # nhất mỗi phiên + dedup tried_codes + thử mới→cũ ở caller).
                    subject = str(msg.get("subject") or "")
                    body = (
                        msg.get("bodyText") or msg.get("text") or msg.get("body")
                        or msg.get("htmlBody") or msg.get("content") or msg.get("html") or ""
                    )
                    code = _extract_otp(subject, str(body))
                    if code and code not in seen:
                        seen.add(code)
                        codes.append(code)
                        # Chỉ lấy tối đa N mã MỚI NHẤT — đã sort mới→cũ nên cắt sớm.
                        # Tránh thử dồn quá nhiều mã cũ (đã bị OpenAI vô hiệu).
                        if len(codes) >= _WORKER_MAX_CODES:
                            break
                return codes
        except Exception:
            return []


# ─────────────────────────────────────────────────────────────────────
# iCloud IMAP provider (Hide My Email aliases → one shared inbox)
# ─────────────────────────────────────────────────────────────────────


class ICloudImapError(Exception):
    """Base error for the direct iCloud IMAP provider."""


class ICloudImapAuthError(ICloudImapError):
    """iCloud rejected the username/app-specific password."""


class ICloudImapConnectionError(ICloudImapError):
    """Cannot connect to or read from the iCloud IMAP server."""


_ICLOUD_IMAP_HOST = "imap.mail.me.com"
_ICLOUD_IMAP_PORT = 993
_ICLOUD_IMAP_FETCH_LIMIT = 80
_ICLOUD_IMAP_CLEANUP_FETCH_LIMIT = 500
_ICLOUD_IMAP_CACHE_SECONDS = 3.0
_ICLOUD_IMAP_STALE_CLEANUP_SECONDS = 30 * 60.0
_ICLOUD_IMAP_DATE_GRACE = timedelta(minutes=10)
_ICLOUD_PLUS_DATE_GRACE = timedelta(seconds=30)
_ICLOUD_RECIPIENT_HEADERS = (
    "To",
    "Cc",
    "X-ICLOUD-HME",
    "Delivered-To",
    "X-Original-To",
    "X-Envelope-To",
    "Envelope-To",
    "X-Forwarded-To",
    "Original-Recipient",
    "Final-Recipient",
    "X-Original-Recipient",
)
_ICLOUD_AUTHENTICATED_DOMAIN_RE = re.compile(
    r"\b(?:header\.d|header\.from|smtp\.mailfrom)\s*=\s*"
    r"(?:[^@\s;]+@)?([A-Z0-9.-]+)",
    re.IGNORECASE,
)
_EMAIL_ADDRESS_RE = re.compile(
    r"[A-Z0-9.!#$%&'*+/=?^_{|}~-]+@[A-Z0-9.-]+\.[A-Z]{2,}",
    re.IGNORECASE,
)

_ICLOUD_CACHE_GUARD = threading.Lock()
_ICLOUD_MAILBOX_LOCKS: dict[tuple[str, int, str], threading.Lock] = {}
_ICLOUD_MESSAGE_CACHE: dict[
    tuple[str, int, str], tuple[float, list[dict[str, Any]]]
] = {}
_ICLOUD_JUNK_MESSAGE_CACHE: dict[
    tuple[str, int, str], tuple[float, list[dict[str, Any]]]
] = {}
_ICLOUD_MESSAGE_CURSOR: dict[tuple[str, int, str], int] = {}
_ICLOUD_LAST_STALE_CLEANUP: dict[tuple[str, int, str], float] = {}


def _icloud_mailbox_lock(key: tuple[str, int, str]) -> threading.Lock:
    with _ICLOUD_CACHE_GUARD:
        lock = _ICLOUD_MAILBOX_LOCKS.get(key)
        if lock is None:
            lock = threading.Lock()
            _ICLOUD_MAILBOX_LOCKS[key] = lock
        return lock


def _icloud_message_body(message: Message) -> str:
    parts: list[str] = []
    candidates = message.walk() if message.is_multipart() else (message,)
    for part in candidates:
        if part.get_content_maintype() != "text":
            continue
        if (part.get_content_disposition() or "").lower() == "attachment":
            continue
        try:
            content = part.get_content()
        except (LookupError, UnicodeError):
            payload = part.get_payload(decode=True)
            charset = part.get_content_charset() or "utf-8"
            content = payload.decode(charset, errors="replace") if payload else ""
        if isinstance(content, str) and content:
            parts.append(content)
    return "\n".join(parts)


def _icloud_message_recipients(message: Message) -> set[str]:
    raw_values: list[str] = []
    for header in _ICLOUD_RECIPIENT_HEADERS:
        raw_values.extend(str(value) for value in message.get_all(header, []))

    # Apple/iCloud deployments do not expose one stable HME header.  In
    # particular, plus-addresses are sometimes preserved only in a Received
    # ``for <base+tag@icloud.com>`` clause while To is rewritten to the inbox.
    # Inspect recipient-like extension headers and Received, but deliberately
    # exclude sender/auth headers so matching remains exact and alias-isolated.
    recipient_hints = (
        "recipient",
        "delivered",
        "original-to",
        "envelope-to",
        "forwarded-to",
        "rcpt-to",
    )
    for header, value in message.items():
        normalized = str(header).strip().casefold()
        if normalized == "received" or any(
            hint in normalized for hint in recipient_hints
        ):
            raw_values.append(str(value))

    recipients = {
        address.strip().casefold()
        for _, address in getaddresses(raw_values)
        if address and "@" in address
    }
    for value in raw_values:
        recipients.update(match.casefold() for match in _EMAIL_ADDRESS_RE.findall(value))
    return recipients


def _icloud_has_authenticated_openai_origin(message: Message) -> bool:
    """Accept Apple HME relay only when iCloud reports aligned OpenAI auth.

    Hide My Email rewrites the RFC sender to an iCloud relay address. iCloud
    preserves the original DKIM/DMARC verdict in Authentication-Results, so a
    direct sender-address check alone incorrectly rejects valid OTP messages.
    """
    for value in message.get_all("Authentication-Results", []):
        for clause in str(value).split(";"):
            if not re.search(r"\b(?:dkim|dmarc)\s*=\s*pass\b", clause, re.IGNORECASE):
                continue
            for match in _ICLOUD_AUTHENTICATED_DOMAIN_RE.finditer(clause):
                domain = match.group(1).strip().rstrip(".").casefold()
                if domain == "openai.com" or domain.endswith(".openai.com"):
                    return True
    return False


def _icloud_message_record(raw_message: bytes) -> dict[str, Any]:
    message = BytesParser(policy=default_email_policy).parsebytes(raw_message)
    sender_values = [
        str(value)
        for header in ("From", "Sender", "Return-Path")
        for value in message.get_all(header, [])
    ]
    senders = {
        address.strip().casefold()
        for _, address in getaddresses(sender_values)
        if address and "@" in address
    }

    received_at: datetime | None = None
    raw_date = message.get("Date")
    if raw_date:
        try:
            received_at = parsedate_to_datetime(str(raw_date))
            if received_at.tzinfo is None:
                received_at = received_at.replace(tzinfo=timezone.utc)
            else:
                received_at = received_at.astimezone(timezone.utc)
        except (TypeError, ValueError, OverflowError):
            received_at = None

    return {
        "subject": str(message.get("Subject") or ""),
        "body": _icloud_message_body(message),
        "senders": senders,
        "authenticated_openai": _icloud_has_authenticated_openai_origin(message),
        "recipients": _icloud_message_recipients(message),
        "received_at": received_at,
    }


def _icloud_code_matches_for_recipient(
    records: list[dict[str, Any]],
    *,
    recipient: str,
    started_at: datetime,
) -> tuple[list[str], set[str]]:
    target = recipient.strip().casefold()
    if not target:
        return [], set()
    if started_at.tzinfo is None:
        normalized_start = started_at.replace(tzinfo=timezone.utc)
    else:
        normalized_start = started_at.astimezone(timezone.utc)
    cutoff = normalized_start - _ICLOUD_IMAP_DATE_GRACE
    is_plus_address = "+" in target.partition("@")[0]

    codes: list[str] = []
    matched_uids: set[str] = set()
    seen: set[str] = set()
    for record in records:
        recipients = record.get("recipients", set())
        exact_recipient = target in recipients
        if not exact_recipient and not is_plus_address:
            continue
        if not exact_recipient and any(
            "+" in str(address).partition("@")[0] for address in recipients
        ):
            # A preserved +tag belongs to a different job.  Date fallback is
            # only for messages where Apple actually removed every +tag.
            continue
        senders = record.get("senders", set())
        if not (
            record.get("authenticated_openai") is True
            or any(_is_openai_sender(str(sender)) for sender in senders)
        ):
            continue
        received_at = record.get("received_at")
        if exact_recipient:
            if isinstance(received_at, datetime) and received_at < cutoff:
                continue
        else:
            # Recipient-less fallback is allowed only for plus-addresses.  The
            # JobManager serializes every iCloud IMAP job across its complete
            # lifecycle, so the first trusted OTP sent after this job started
            # belongs to the sole active registration.  Missing/older Date is
            # rejected rather than risking an OTP from the previous job.
            if not isinstance(received_at, datetime):
                continue
            normalized_received = (
                received_at.replace(tzinfo=timezone.utc)
                if received_at.tzinfo is None
                else received_at.astimezone(timezone.utc)
            )
            if normalized_received < normalized_start - _ICLOUD_PLUS_DATE_GRACE:
                continue
        code = _extract_otp(
            str(record.get("subject") or ""),
            str(record.get("body") or ""),
        )
        if not code:
            continue
        uid = str(record.get("uid") or "").strip()
        if uid.isdigit():
            matched_uids.add(uid)
        if code not in seen:
            seen.add(code)
            codes.append(code)
            if len(codes) >= _WORKER_MAX_CODES:
                break
    return codes, matched_uids


def _icloud_codes_for_recipient(
    records: list[dict[str, Any]],
    *,
    recipient: str,
    started_at: datetime,
) -> list[str]:
    codes, _ = _icloud_code_matches_for_recipient(
        records,
        recipient=recipient,
        started_at=started_at,
    )
    return codes


def _icloud_records_from_fetch(
    payload: list[Any] | tuple[Any, ...] | None,
    requested_uids: list[bytes],
) -> list[dict[str, Any]]:
    """Parse UID FETCH payload while retaining the UID needed for safe cleanup."""
    records: list[dict[str, Any]] = []
    items = [
        item
        for item in (payload or [])
        if isinstance(item, tuple)
        and len(item) >= 2
        and isinstance(item[1], bytes)
    ]
    for index, item in enumerate(items):
        metadata = item[0]
        metadata_text = (
            metadata.decode("ascii", errors="ignore")
            if isinstance(metadata, bytes)
            else str(metadata)
        )
        match = re.search(r"\bUID\s+(\d+)\b", metadata_text, re.IGNORECASE)
        if match:
            uid = match.group(1)
        elif index < len(requested_uids):
            uid = requested_uids[index].decode("ascii", errors="ignore")
        else:
            uid = ""
        record = _icloud_message_record(item[1])
        if uid.isdigit():
            record["uid"] = uid
        records.append(record)
    return records


class ICloudImapMailProvider:
    """Read HME OTPs from one shared iCloud inbox over IMAP SSL.

    The original alias must still be present in a recipient header. There is no
    fallback to an arbitrary OpenAI email because concurrent jobs share the
    inbox and such a fallback could submit another account's OTP.
    """

    def __init__(
        self,
        *,
        username: str,
        app_password: str,
        host: str = _ICLOUD_IMAP_HOST,
        port: int = _ICLOUD_IMAP_PORT,
    ):
        self.username = username.strip()
        self.app_password = app_password.strip()
        self.host = host.strip()
        self.port = int(port)
        if not self.username:
            raise ValueError("iCloud IMAP username is required")
        if not self.app_password:
            raise ValueError("iCloud app-specific password is required")
        if not self.host or self.port <= 0:
            raise ValueError("invalid iCloud IMAP endpoint")
        self._consumed_uids: set[str] = set()

    @property
    def _cache_key(self) -> tuple[str, int, str]:
        return (self.host.casefold(), self.port, self.username.casefold())

    def _connect(self) -> imaplib.IMAP4_SSL:
        try:
            client = imaplib.IMAP4_SSL(
                self.host,
                self.port,
                ssl_context=ssl.create_default_context(),
                timeout=20.0,
            )
        except (OSError, ssl.SSLError) as exc:
            raise ICloudImapConnectionError(
                "cannot connect to iCloud IMAP"
            ) from exc
        try:
            client.login(self.username, self.app_password)
        except imaplib.IMAP4.abort as exc:
            try:
                client.shutdown()
            except Exception:
                pass
            # Some iCloud endpoints close the IMAP session with BYE instead of
            # returning IMAP4.error when credentials are rejected. Treat the
            # well-known auth responses as authentication failures so the UI
            # can tell the user to regenerate the app-specific password.
            abort_reason = str(exc).casefold()
            auth_markers = (
                "authenticationfailed",
                "authentication failed",
                "authenticate failed",
                "login failed",
                "invalid credentials",
                "invalid username or password",
                "auth failed",
            )
            if any(marker in abort_reason for marker in auth_markers):
                raise ICloudImapAuthError(
                    "iCloud IMAP authentication failed; check the app-specific password"
                ) from exc
            raise ICloudImapConnectionError(
                "iCloud IMAP connection aborted during login"
            ) from exc
        except imaplib.IMAP4.error as exc:
            try:
                client.shutdown()
            except Exception:
                pass
            raise ICloudImapAuthError(
                "iCloud IMAP authentication failed; check the app-specific password"
            ) from exc
        except (OSError, ssl.SSLError) as exc:
            try:
                client.shutdown()
            except Exception:
                pass
            raise ICloudImapConnectionError(
                "iCloud IMAP connection failed during login"
            ) from exc
        return client

    @staticmethod
    def _close(client: imaplib.IMAP4_SSL) -> None:
        try:
            client.logout()
        except Exception:
            try:
                client.shutdown()
            except Exception:
                pass

    def check_connection(self) -> None:
        client = self._connect()
        try:
            status, _ = client.select("INBOX", readonly=True)
            if status != "OK":
                raise ICloudImapConnectionError("cannot select iCloud INBOX")
        except imaplib.IMAP4.error as exc:
            raise ICloudImapConnectionError("cannot read iCloud INBOX") from exc
        finally:
            self._close(client)

    def _fetch_recent_messages_sync(self) -> list[dict[str, Any]]:
        lock = _icloud_mailbox_lock(self._cache_key)
        with lock:
            cached = _ICLOUD_MESSAGE_CACHE.get(self._cache_key)
            if cached and time.monotonic() - cached[0] <= _ICLOUD_IMAP_CACHE_SECONDS:
                return list(cached[1])
            cached_records = list(cached[1]) if cached else []

            client = self._connect()
            try:
                status, _ = client.select("INBOX", readonly=True)
                if status != "OK":
                    raise ICloudImapConnectionError("cannot select iCloud INBOX")
                status, data = client.uid("search", None, "ALL")
                if status != "OK":
                    raise ICloudImapConnectionError("cannot search iCloud INBOX")
                uids = data[0].split() if data and data[0] else []
                if not uids:
                    records: list[dict[str, Any]] = []
                    _ICLOUD_MESSAGE_CURSOR.pop(self._cache_key, None)
                else:
                    numeric_uids = [
                        int(uid) for uid in uids if uid.decode("ascii", errors="ignore").isdigit()
                    ]
                    newest_uid = max(numeric_uids) if numeric_uids else 0
                    last_uid = _ICLOUD_MESSAGE_CURSOR.get(self._cache_key)
                    if (
                        last_uid is not None
                        and cached is not None
                        and newest_uid >= last_uid
                    ):
                        fetch_uids = [
                            uid
                            for uid in uids
                            if uid.decode("ascii", errors="ignore").isdigit()
                            and int(uid) > last_uid
                        ]
                    else:
                        # First scan or UIDVALIDITY/mailbox reset: seed recent cache.
                        fetch_uids = uids[-_ICLOUD_IMAP_FETCH_LIMIT:]

                    if fetch_uids:
                        sequence_set = b",".join(fetch_uids)
                        status, payload = client.uid(
                            "fetch", sequence_set, "(BODY.PEEK[])"
                        )
                        if status != "OK":
                            raise ICloudImapConnectionError(
                                "cannot fetch messages from iCloud INBOX"
                            )
                        new_records = _icloud_records_from_fetch(payload, fetch_uids)
                        new_records.reverse()
                    else:
                        new_records = []

                    merged = new_records + cached_records
                    records = []
                    seen_uids: set[str] = set()
                    for record in merged:
                        uid = str(record.get("uid") or "")
                        if uid and uid in seen_uids:
                            continue
                        if uid:
                            seen_uids.add(uid)
                        records.append(record)
                        if len(records) >= _ICLOUD_IMAP_FETCH_LIMIT:
                            break
                    if newest_uid > 0:
                        _ICLOUD_MESSAGE_CURSOR[self._cache_key] = newest_uid
            except imaplib.IMAP4.error as exc:
                raise ICloudImapConnectionError("cannot read iCloud INBOX") from exc
            finally:
                self._close(client)

            _ICLOUD_MESSAGE_CACHE[self._cache_key] = (time.monotonic(), records)
            return list(records)

    def _fetch_recent_junk_messages_sync(self) -> list[dict[str, Any]]:
        """Read recent Junk messages without affecting the INBOX UID cursor."""
        lock = _icloud_mailbox_lock(self._cache_key)
        with lock:
            cached = _ICLOUD_JUNK_MESSAGE_CACHE.get(self._cache_key)
            if cached and time.monotonic() - cached[0] <= _ICLOUD_IMAP_CACHE_SECONDS:
                return list(cached[1])

            client = self._connect()
            try:
                status, _ = client.select("Junk", readonly=True)
                if status != "OK":
                    records: list[dict[str, Any]] = []
                else:
                    status, data = client.uid("search", None, "ALL")
                    if status != "OK":
                        records = []
                    else:
                        uids = data[0].split() if data and data[0] else []
                        fetch_uids = uids[-_ICLOUD_IMAP_FETCH_LIMIT:]
                        if not fetch_uids:
                            records = []
                        else:
                            status, payload = client.uid(
                                "fetch", b",".join(fetch_uids), "(BODY.PEEK[])"
                            )
                            if status != "OK":
                                records = []
                            else:
                                records = _icloud_records_from_fetch(
                                    payload, fetch_uids,
                                )
                                records.reverse()
                                # Junk UID space is independent from INBOX. A
                                # namespaced UID can never be deleted by INBOX cleanup.
                                for record in records:
                                    uid = str(record.get("uid") or "")
                                    record["uid"] = f"Junk:{uid}"
            except imaplib.IMAP4.error:
                # Junk is an optional fallback; INBOX polling must keep working
                # when the folder is unavailable or localized differently.
                records = []
            finally:
                self._close(client)

            _ICLOUD_JUNK_MESSAGE_CACHE[self._cache_key] = (
                time.monotonic(), records,
            )
            return list(records)

    async def fetch_recent_messages(self) -> list[dict[str, Any]]:
        """Return the recent parsed INBOX records without consuming messages."""
        return await asyncio.to_thread(self._fetch_recent_messages_sync)

    @staticmethod
    def _is_trusted_otp_record(record: dict[str, Any]) -> bool:
        senders = record.get("senders", set())
        trusted = (
            record.get("authenticated_openai") is True
            or any(_is_openai_sender(str(sender)) for sender in senders)
        )
        if not trusted or not record.get("recipients"):
            return False
        return bool(
            _extract_otp(
                str(record.get("subject") or ""),
                str(record.get("body") or ""),
            )
        )

    def _cleanup_after_success_sync(
        self,
        *,
        retention_hours: float,
    ) -> tuple[int, str | None]:
        """Delete consumed OTPs and periodically purge authenticated stale OTPs.

        iCloud does not advertise UIDPLUS. To avoid expunging unrelated messages,
        cleanup aborts when INBOX already contains another ``\\Deleted`` UID.
        """
        lock = _icloud_mailbox_lock(self._cache_key)
        with lock:
            now_monotonic = time.monotonic()
            last_cleanup = _ICLOUD_LAST_STALE_CLEANUP.get(self._cache_key, 0.0)
            stale_due = (
                now_monotonic - last_cleanup
                >= _ICLOUD_IMAP_STALE_CLEANUP_SECONDS
            )
            target_uids = {uid for uid in self._consumed_uids if uid.isdigit()}
            if not target_uids and not stale_due:
                return 0, None

            client = self._connect()
            try:
                status, _ = client.select("INBOX", readonly=False)
                if status != "OK":
                    raise ICloudImapConnectionError("cannot select iCloud INBOX")

                if stale_due:
                    cutoff = datetime.now(timezone.utc) - timedelta(
                        hours=retention_hours
                    )
                    # IMAP BEFORE has day precision. Include cutoff day then apply
                    # the exact parsed Date check locally before deleting.
                    before_day = (cutoff + timedelta(days=1)).strftime("%d-%b-%Y")
                    status, data = client.uid(
                        "search", None, "BEFORE", before_day
                    )
                    if status != "OK":
                        raise ICloudImapConnectionError(
                            "cannot search stale iCloud messages"
                        )
                    stale_candidates = (
                        data[0].split()[-_ICLOUD_IMAP_CLEANUP_FETCH_LIMIT:]
                        if data and data[0]
                        else []
                    )
                    if stale_candidates:
                        status, payload = client.uid(
                            "fetch",
                            b",".join(stale_candidates),
                            "(BODY.PEEK[])",
                        )
                        if status != "OK":
                            raise ICloudImapConnectionError(
                                "cannot fetch stale iCloud messages"
                            )
                        for record in _icloud_records_from_fetch(
                            payload, stale_candidates
                        ):
                            received_at = record.get("received_at")
                            uid = str(record.get("uid") or "")
                            if (
                                uid.isdigit()
                                and isinstance(received_at, datetime)
                                and received_at < cutoff
                                and self._is_trusted_otp_record(record)
                            ):
                                target_uids.add(uid)
                    _ICLOUD_LAST_STALE_CLEANUP[self._cache_key] = now_monotonic

                if not target_uids:
                    return 0, None

                status, deleted_data = client.uid("search", None, "DELETED")
                if status != "OK":
                    raise ICloudImapConnectionError(
                        "cannot inspect deleted flags in iCloud INBOX"
                    )
                already_deleted = {
                    uid.decode("ascii", errors="ignore")
                    for uid in (
                        deleted_data[0].split()
                        if deleted_data and deleted_data[0]
                        else []
                    )
                }
                unrelated_deleted = already_deleted - target_uids
                if unrelated_deleted:
                    return 0, "INBOX has unrelated messages marked Deleted"

                sequence_set = ",".join(sorted(target_uids, key=int))
                status, _ = client.uid(
                    "store",
                    sequence_set,
                    "+FLAGS.SILENT",
                    r"(\Deleted)",
                )
                if status != "OK":
                    raise ICloudImapConnectionError(
                        "cannot mark consumed iCloud OTP messages for deletion"
                    )
                status, _ = client.expunge()
                if status != "OK":
                    # Restore flags when expunge failed; do not leave a future
                    # unrelated EXPUNGE able to delete these messages silently.
                    client.uid(
                        "store",
                        sequence_set,
                        "-FLAGS.SILENT",
                        r"(\Deleted)",
                    )
                    raise ICloudImapConnectionError(
                        "cannot expunge consumed iCloud OTP messages"
                    )

                self._consumed_uids.difference_update(target_uids)
                cached = _ICLOUD_MESSAGE_CACHE.get(self._cache_key)
                if cached:
                    remaining = [
                        record
                        for record in cached[1]
                        if str(record.get("uid") or "") not in target_uids
                    ]
                    _ICLOUD_MESSAGE_CACHE[self._cache_key] = (
                        time.monotonic(),
                        remaining,
                    )
                return len(target_uids), None
            except imaplib.IMAP4.error as exc:
                raise ICloudImapConnectionError(
                    "cannot clean up iCloud OTP messages"
                ) from exc
            finally:
                self._close(client)

    async def cleanup_after_success(
        self,
        *,
        retention_hours: float,
        log,
    ) -> None:
        deleted, skipped = await asyncio.to_thread(
            self._cleanup_after_success_sync,
            retention_hours=retention_hours,
        )
        if deleted:
            log(f"[otp:icloud-imap] cleanup deleted {deleted} OTP message(s)")
        elif skipped:
            log(f"[otp:icloud-imap] cleanup skipped safely: {skipped}")

    async def poll_otp(
        self,
        *,
        recipient: str,
        started_at: datetime,
        timeout_seconds: float,
        poll_interval_seconds: float,
        log,
    ) -> str:
        mailbox = recipient.strip().casefold()
        if not mailbox:
            raise ValueError("recipient is required")
        deadline = time.monotonic() + max(timeout_seconds, 1.0)
        attempt = 0
        log(
            f"[otp:icloud-imap] polling alias {mailbox} "
            f"(timeout {timeout_seconds:.0f}s)"
        )
        while True:
            attempt += 1
            records = await asyncio.to_thread(self._fetch_recent_messages_sync)
            codes, matched_uids = _icloud_code_matches_for_recipient(
                records, recipient=mailbox, started_at=started_at,
            )
            source = "INBOX"
            if not codes:
                junk_records = await asyncio.to_thread(
                    self._fetch_recent_junk_messages_sync
                )
                junk_codes, junk_uids = _icloud_code_matches_for_recipient(
                    junk_records, recipient=mailbox, started_at=started_at,
                )
                if junk_codes:
                    records = junk_records
                    codes = junk_codes
                    matched_uids = junk_uids
                    source = "Junk"
            self._consumed_uids.update(matched_uids)
            if codes:
                from readmail_capture import capture_otp_records

                capture_otp_records(
                    recipient=mailbox,
                    records=records,
                    matched_uids=matched_uids,
                )
                log(
                    f"[otp:icloud-imap] found {codes[0]} in {source} "
                    f"(attempt {attempt})"
                )
                return codes[0]
            if attempt == 1 or attempt % 6 == 0:
                if not records:
                    log(
                        "[otp:icloud-imap] IMAP INBOX is empty; verify that "
                        "the configured username is the primary iCloud Mail "
                        f"mailbox linked to this app-specific password (attempt {attempt})"
                    )
                else:
                    otp_candidates = 0
                    trusted_candidates = 0
                    recipient_matches = 0
                    for record in records:
                        has_otp = bool(
                            _extract_otp(
                                str(record.get("subject") or ""),
                                str(record.get("body") or ""),
                            )
                        )
                        if not has_otp:
                            continue
                        otp_candidates += 1
                        senders = record.get("senders", set())
                        trusted = (
                            record.get("authenticated_openai") is True
                            or any(
                                _is_openai_sender(str(sender))
                                for sender in senders
                            )
                        )
                        if trusted:
                            trusted_candidates += 1
                        if mailbox in record.get("recipients", set()):
                            recipient_matches += 1
                    log(
                        f"[otp:icloud-imap] no matching OpenAI OTP for alias yet "
                        f"(attempt {attempt}); records={len(records)} "
                        f"otp={otp_candidates} trusted={trusted_candidates} "
                        f"recipient_match={recipient_matches}"
                    )
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError(
                    f"OTP timeout after {timeout_seconds}s for {mailbox}; "
                    "no authenticated OpenAI mail for the HME alias was found"
                )
            await asyncio.sleep(min(poll_interval_seconds, remaining))

    async def poll_all_codes(
        self,
        *,
        recipient: str,
        started_at: datetime,
        log,
    ) -> list[str]:
        records = await asyncio.to_thread(self._fetch_recent_messages_sync)
        codes, matched_uids = _icloud_code_matches_for_recipient(
            records, recipient=recipient, started_at=started_at,
        )
        junk_records = await asyncio.to_thread(self._fetch_recent_junk_messages_sync)
        junk_codes, junk_uids = _icloud_code_matches_for_recipient(
            junk_records, recipient=recipient, started_at=started_at,
        )
        codes.extend(code for code in junk_codes if code not in codes)
        matched_uids.update(junk_uids)
        self._consumed_uids.update(matched_uids)
        if codes:
            from readmail_capture import capture_otp_records

            capture_otp_records(
                recipient=recipient,
                records=records,
                matched_uids=matched_uids,
            )
        return codes


# ─────────────────────────────────────────────────────────────────────
# Outlook provider (Microsoft Graph)
# ─────────────────────────────────────────────────────────────────────


_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_TOKEN_URL = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token"
_DEFAULT_SCOPE = "https://graph.microsoft.com/.default offline_access"

# Folder names dùng tìm OTP — Inbox + Junk vì OpenAI mail thi thoảng vào spam.
_OTP_FOLDERS = ("Inbox", "Junk Email")

# Microsoft refresh / Graph: timeout tổng 12s, connect 6s — đủ để fail nhanh + retry.
# read=12s là per-byte-interval, KHÔNG phải tổng response time.
# Hard cap tổng dùng asyncio.wait_for trong _ensure_access.
_OUTLOOK_HTTP_TIMEOUT = httpx.Timeout(connect=6.0, read=12.0, write=12.0, pool=6.0)
_OUTLOOK_REFRESH_TOTAL_TIMEOUT = 15.0  # hard cap cho toàn bộ token refresh (s)

# Sau N lần network/HTTP transient liên tiếp → coi combo này transient-dead trong run hiện tại.
# Raise terminal error để job kết thúc nhanh thay vì chờ OTP timeout (180s).
_OUTLOOK_CONNECT_FAIL_THRESHOLD = 3

# Grace window cho filter `receivedDateTime < started_at`. Đề phòng caller set
# `started_at` lệch sau khi mail đã thực sự về (ví dụ browser_phase đặt
# poll_started SAU khi đợi OTP form load → mail có thể về sớm hơn vài giây).
# 30s đủ rộng để bắt mail OTP đến nhanh, vẫn loại được mail từ session cũ.
_OUTLOOK_GRAPH_DATE_GRACE = timedelta(seconds=30)

# Auth-fail strings → combo dead vĩnh viễn (revoke / disabled / format invalid)
_OUTLOOK_AUTH_FATAL_KEYS = (
    "invalid_grant",
    "AADSTS50173",  # FreshTokenNeeded — refresh token revoked
    "AADSTS70008",  # Refresh token expired
    "AADSTS50034",  # User account does not exist
    "AADSTS50057",  # User account is disabled
    "AADSTS700016",  # Application not found
    "unauthorized_client",
)


class OutlookComboError(Exception):
    """Combo Outlook parse/refresh fail (terminal — combo coi như dead)."""


class OutlookProviderUnavailable(Exception):
    """Outlook provider tạm thời không thể hoạt động (network/proxy fail).

    Khác với OutlookComboError ở chỗ: combo có thể vẫn sống, chỉ là network
    đến Microsoft đang fail. Caller có thể retry sau hoặc rotate proxy.
    """


class OutlookCombo:
    """Combo format: `email|password|refresh_token|client_id`.

    Component:
        email          — bpkknbrl2278@hotmail.com
        password       — không dùng cho refresh flow, lưu để re-login fallback
        refresh_token  — M.C535_BAY... (rotate sau mỗi refresh)
        client_id      — 8b4ba9dd-3ea5-4e5f-86f1-ddba2230dcf2 (Outlook desktop pre-auth)
    """

    __slots__ = ("email", "password", "refresh_token", "client_id")

    def __init__(self, email: str, password: str, refresh_token: str, client_id: str):
        self.email = email
        self.password = password
        self.refresh_token = refresh_token
        self.client_id = client_id

    @classmethod
    def parse(cls, combo: str) -> "OutlookCombo":
        parts = combo.split("|")
        if len(parts) != 4:
            raise OutlookComboError(
                f"combo phải có 4 phần (email|password|refresh_token|client_id), nhận {len(parts)}"
            )
        email, password, refresh_token, client_id = (p.strip() for p in parts)
        if not email or "@" not in email:
            raise OutlookComboError(f"email không hợp lệ: {email!r}")
        if not refresh_token.startswith("M.C"):
            raise OutlookComboError("refresh_token không bắt đầu bằng 'M.C' (sai format)")
        if len(client_id) != 36 or client_id.count("-") != 4:
            raise OutlookComboError(f"client_id không phải UUID: {client_id!r}")
        return cls(email=email, password=password, refresh_token=refresh_token, client_id=client_id)


class OutlookMailProvider:
    """Microsoft Graph mail provider.

    - Tự động refresh token khi access expire.
    - Persist rotate refresh_token ra disk (`runtime/outlook_state/<email>.json`).
      Nếu không persist, lần sau dùng refresh_token cũ sẽ bị `invalid_grant`.
    """

    def __init__(
        self,
        *,
        combo: OutlookCombo,
        state_dir: Path,
        scope: str = _DEFAULT_SCOPE,
        proxy: str | None = None,
        combo_repo: ComboRepository | None = None,
    ):
        self.combo = combo
        self.scope = scope
        self.state_dir = state_dir
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.state_path = state_dir / f"{combo.email.replace('/', '_')}.json"
        self.proxy = proxy.strip() if isinstance(proxy, str) and proxy.strip() else None
        self._combo_repo = combo_repo
        self._access_token: str | None = None
        self._access_expires_at: float = 0.0
        # Hydrate state nếu đã từng refresh
        self._hydrate_state()

    def _hydrate_state(self) -> None:
        """Hydrate refresh_token từ persisted state.

        Khi combo_repo (SQLite) available: đọc từ DB (single source of truth).
        Khi không có combo_repo: fallback sang JSON state file (backward compat).
        """
        if self._combo_repo is not None:
            row = self._combo_repo.get_by_email(self.combo.email)
            if row is not None:
                latest = row.get("refresh_token")
                if isinstance(latest, str) and latest.startswith("M.C"):
                    self.combo.refresh_token = latest
            return
        # Fallback: JSON state file
        if not self.state_path.exists():
            return
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        latest = data.get("refresh_token")
        if isinstance(latest, str) and latest.startswith("M.C"):
            self.combo.refresh_token = latest

    def _persist_state(self, token_data: dict[str, Any]) -> None:
        # Prefer SQLite persist via ComboRepository — fail-fast khi DB là source of truth
        if self._combo_repo is not None:
            # Nếu combo_repo present → DB là authority. Fail = raise, không fallback JSON.
            self._combo_repo.update_refresh_token(
                self.combo.email, self.combo.refresh_token
            )
            return
        # Fallback: JSON file persist (backward compat khi không có combo_repo)
        record = {
            "email": self.combo.email,
            "client_id": self.combo.client_id,
            "refresh_token": self.combo.refresh_token,
            "last_refresh_at": datetime.now(timezone.utc).isoformat(),
            "expires_in": token_data.get("expires_in"),
            "scope": token_data.get("scope"),
        }
        tmp = self.state_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(record, indent=2), encoding="utf-8")
        tmp.replace(self.state_path)

    def _safe_proxy(self) -> str | None:
        """Trả URL proxy đã ẩn user:pass cho log (không log credential)."""
        if not self.proxy:
            return None
        # Format: scheme://user:pass@host:port → scheme://***@host:port
        if "@" in self.proxy:
            scheme_split = self.proxy.split("://", 1)
            if len(scheme_split) == 2:
                scheme, rest = scheme_split
                _, _, host = rest.partition("@")
                return f"{scheme}://***@{host}"
        return self.proxy

    def _build_client(self) -> httpx.AsyncClient:
        """httpx client kèm proxy + timeout chuẩn cho Outlook."""
        kwargs: dict[str, Any] = {"timeout": _OUTLOOK_HTTP_TIMEOUT}
        if self.proxy:
            kwargs["proxy"] = self.proxy
        return httpx.AsyncClient(**kwargs)

    async def _refresh_access(self, *, log) -> None:
        log(f"[otp:outlook] refreshing access token for {self.combo.email}"
            + (f" via proxy {self._safe_proxy()}" if self.proxy else ""))
        async with self._build_client() as client:
            response = await client.post(
                _TOKEN_URL,
                data={
                    "client_id": self.combo.client_id,
                    "scope": self.scope,
                    "refresh_token": self.combo.refresh_token,
                    "grant_type": "refresh_token",
                },
            )
        if response.status_code != 200:
            body = response.text[:500]
            # Phân biệt fatal (combo dead) vs transient (network blip / 5xx)
            fatal = any(key in body for key in _OUTLOOK_AUTH_FATAL_KEYS)
            if fatal or 400 <= response.status_code < 500:
                if "AADSTS70000" in body or "service abuse" in body.lower():
                    raise OutlookComboError(
                        f"Hotmail bị Microsoft khóa (service abuse mode) — combo dead, không retry. "
                        f"HTTP {response.status_code}"
                    )
                raise OutlookComboError(
                    f"refresh failed HTTP {response.status_code}: {body}"
                )
            raise OutlookProviderUnavailable(
                f"refresh transient HTTP {response.status_code}: {body[:200]}"
            )
        data = response.json()
        access = data.get("access_token")
        new_refresh = data.get("refresh_token")
        if not access:
            raise OutlookComboError(f"refresh response missing access_token: {data}")
        # Persist trước, mutate in-memory sau — nếu persist fail, token cũ còn nguyên
        # tránh mất token khi process crash sau mutate nhưng trước persist.
        old_refresh = self.combo.refresh_token
        if new_refresh and new_refresh != old_refresh:
            self.combo.refresh_token = new_refresh
        try:
            self._persist_state(data)
        except Exception:
            # Rollback in-memory — DB vẫn giữ token cũ, đảm bảo nhất quán
            self.combo.refresh_token = old_refresh
            raise
        self._access_token = access
        self._access_expires_at = time.monotonic() + max(int(data.get("expires_in", 3600)) - 60, 60)

    async def _ensure_access(self, *, log) -> str:
        if self._access_token and time.monotonic() < self._access_expires_at:
            return self._access_token
        try:
            await asyncio.wait_for(
                self._refresh_access(log=log),
                timeout=_OUTLOOK_REFRESH_TOTAL_TIMEOUT,
            )
        except asyncio.TimeoutError:
            raise OutlookProviderUnavailable(
                f"refresh token request timed out after {_OUTLOOK_REFRESH_TOTAL_TIMEOUT}s "
                f"(login.microsoftonline.com không phản hồi)"
            )
        assert self._access_token
        return self._access_token

    async def _list_messages(
        self,
        *,
        client: httpx.AsyncClient,
        access_token: str,
        folder_name: str | None,
        top: int = 10,
    ) -> list[dict[str, Any]]:
        """Lấy `top` message mới nhất, optional theo tên folder."""
        if folder_name is None:
            url = f"{_GRAPH_BASE}/me/messages"
        else:
            # Filter folder by displayName
            folder_resp = await client.get(
                f"{_GRAPH_BASE}/me/mailFolders",
                params={"$filter": f"displayName eq '{folder_name}'"},
                headers={"Authorization": f"Bearer {access_token}"},
            )
            folder_resp.raise_for_status()
            folders = folder_resp.json().get("value", [])
            if not folders:
                return []
            folder_id = folders[0]["id"]
            url = f"{_GRAPH_BASE}/me/mailFolders/{folder_id}/messages"

        resp = await client.get(
            url,
            params={
                "$top": top,
                "$orderby": "receivedDateTime desc",
                "$select": "subject,from,receivedDateTime,bodyPreview,body",
            },
            headers={"Authorization": f"Bearer {access_token}"},
        )
        resp.raise_for_status()
        return resp.json().get("value", [])

    async def poll_otp(
        self,
        *,
        recipient: str,
        started_at: datetime,
        timeout_seconds: float,
        poll_interval_seconds: float,
        log,
    ) -> str:
        # Recipient phải khớp combo email — nếu không, OTP sẽ vào account khác.
        if recipient.strip().lower() != self.combo.email.strip().lower():
            log(
                f"[otp:outlook] WARNING recipient={recipient} != combo={self.combo.email} "
                f"— vẫn poll combo mailbox"
            )

        deadline = time.monotonic() + max(timeout_seconds, 1.0)
        log(f"[otp:outlook] polling {self.combo.email} (timeout {timeout_seconds:.0f}s)"
            + (f" via proxy {self._safe_proxy()}" if self.proxy else " direct"))

        async with self._build_client() as client:
            attempt = 0
            consecutive_transient = 0
            while True:
                attempt += 1
                try:
                    access = await self._ensure_access(log=log)
                    # Strategy: query toàn bộ mailbox (folder=None) để bắt mail dù
                    # ở Inbox, Junk, hoặc folder lạ. Nhanh hơn và tin cậy hơn loop folder.
                    messages = await self._list_messages(
                        client=client, access_token=access, folder_name=None,
                        top=5,
                    )
                    consecutive_transient = 0  # reset khi 1 round thành công
                    threshold = (
                        started_at - _OUTLOOK_GRAPH_DATE_GRACE
                        if started_at is not None else None
                    )
                    for msg in messages:
                        received = _parse_dt(msg.get("receivedDateTime"))
                        # Chỉ accept mail received SAU started_at (trừ grace).
                        # Trước đây so trực tiếp `received < started_at` → khi
                        # caller set started_at vài giây sau khi mail đã về (vd
                        # browser_phase chờ form load 2-3s) thì mail đúng bị
                        # loại. Grace 30s cover khoảng lệch này, vẫn rớt mail
                        # OTP từ session cũ (cách đây vài phút trở lên).
                        if received is not None and threshold is not None:
                            if received < threshold:
                                continue
                        sender = (
                            (msg.get("from") or {}).get("emailAddress", {}).get("address", "")
                        )
                        subject = msg.get("subject") or ""
                        body_obj = msg.get("body") or {}
                        body = body_obj.get("content") or msg.get("bodyPreview") or ""
                        code = _extract_otp(subject, body)
                        if code and (_is_openai_sender(sender) or "openai" in subject.lower()):
                            log(f"[otp:outlook] found {code} (sender={sender} attempt {attempt})")
                            return code
                        elif code:
                            log(
                                f"[otp:outlook] suspicious code {code} from {sender} "
                                f"subject={subject!r} — skip (non-OpenAI sender)"
                            )
                except (httpx.HTTPError, OutlookProviderUnavailable) as exc:
                    consecutive_transient += 1
                    # Dùng repr để bắt được cả ConnectTimeout("") không có message.
                    log(
                        f"[otp:outlook] network error attempt {attempt}"
                        f" ({consecutive_transient}/{_OUTLOOK_CONNECT_FAIL_THRESHOLD}): "
                        f"{type(exc).__name__}: {exc!r}"
                    )
                    if consecutive_transient >= _OUTLOOK_CONNECT_FAIL_THRESHOLD:
                        # Không thể kết nối Microsoft → bail nhanh thay vì chờ hết OTP timeout
                        raise OutlookProviderUnavailable(
                            f"connect Microsoft thất bại {consecutive_transient} lần liên tiếp "
                            f"(proxy={self._safe_proxy() or 'direct'}). Last error: "
                            f"{type(exc).__name__}: {exc!r}"
                        ) from exc
                except OutlookComboError as exc:
                    log(f"[otp:outlook] auth error attempt {attempt}: {exc}")
                    raise

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        f"OTP timeout after {timeout_seconds}s for {self.combo.email}"
                    )
                await asyncio.sleep(min(poll_interval_seconds, remaining))


# ─────────────────────────────────────────────────────────────────────
# DongVanFB Outlook provider (tools.dongvanfb.net API)
# ─────────────────────────────────────────────────────────────────────

_DONGVANFB_URL = "https://tools.dongvanfb.net/api/get_messages_oauth2"
_DONGVANFB_HTTP_TIMEOUT = httpx.Timeout(connect=10.0, read=20.0, write=10.0, pool=6.0)
_DONGVANFB_HEADERS = {
    "Accept": "*/*",
    "Content-Type": "application/json",
    "Origin": "https://dongvanfb.net",
    "Referer": "https://dongvanfb.net/",
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
    ),
}


# DongVanFB API trả `date` theo giờ VN (UTC+7), KHÔNG phải UTC. Phải gán đúng
# offset rồi convert sang UTC để so sánh với started_at (UTC). Trước đây gán nhầm
# tzinfo=UTC khiến lệch +7h → filter started_at vô hiệu, lấy nhầm OTP cũ.
_DONGVANFB_TZ = timezone(timedelta(hours=7))

# Grace window cho filter date của DongVanFB.
# - API trả date precision = phút (HH:MM) → mất tới 59s độ chính xác.
# - Mail OpenAI thi thoảng tới chỉ vài giây sau khi click submit → có thể về
#   trước khi caller kịp set `started_at`.
# Đặt 90s để cover cả 2 case mà vẫn loại được mail OTP cũ từ session reg trước
# (cách đây vài phút trở lên).
_DONGVANFB_DATE_GRACE = timedelta(seconds=90)


def _parse_dongvanfb_date(date_str: str) -> datetime | None:
    """Parse format 'HH:MM - DD/MM/YYYY' (giờ VN, UTC+7) → datetime UTC."""
    if not date_str:
        return None
    try:
        dt = datetime.strptime(date_str.strip(), "%H:%M - %d/%m/%Y")
        return dt.replace(tzinfo=_DONGVANFB_TZ).astimezone(timezone.utc)
    except ValueError:
        return None


class DongVanFBOutlookProvider:
    """Poll OTP Outlook qua API tools.dongvanfb.net/api/get_messages_oauth2.

    Request body: {"email": ..., "pass": ..., "refresh_token": ..., "client_id": ...}
    Response:
        {
            "email": "...",
            "status": true,
            "messages": [
                {
                    "from": "noreply@tm.openai.com",
                    "subject": "Your temporary ChatGPT login code",
                    "code": "",
                    "message": "<html>...957952...</html>",
                    "date": "19:20 - 20/05/2026"
                },
                ...
            ],
            "content": "Mail loaded successfully."
        }
    """

    def __init__(self, *, combo: OutlookCombo, proxy: str | None = None):
        self.combo = combo
        self.proxy = proxy.strip() if isinstance(proxy, str) and proxy.strip() else None

    def _build_client(self) -> httpx.AsyncClient:
        kwargs: dict[str, Any] = {"timeout": _DONGVANFB_HTTP_TIMEOUT}
        if self.proxy:
            kwargs["proxy"] = self.proxy
        return httpx.AsyncClient(**kwargs)

    async def poll_otp(
        self,
        *,
        recipient: str,
        started_at: datetime,
        timeout_seconds: float,
        poll_interval_seconds: float,
        log,
    ) -> str:
        deadline = time.monotonic() + max(timeout_seconds, 1.0)
        log(f"[otp:dongvanfb] polling {self.combo.email} (timeout {timeout_seconds:.0f}s)")

        payload = {
            "email": self.combo.email,
            "pass": self.combo.password,
            "refresh_token": self.combo.refresh_token,
            "client_id": self.combo.client_id,
        }

        async with self._build_client() as client:
            attempt = 0
            consecutive_errors = 0
            # Filter mail theo date thay vì baseline-by-value.
            # Trước đây: vòng poll #1 capture mọi code OpenAI có sẵn = "cũ" rồi
            # các vòng sau chỉ accept code MỚI ngoài baseline. Bug: nếu mail
            # OTP về kịp trong vòng đầu (DongVanFB cache nhanh, mail server
            # cùng region) → code đúng bị nhầm là "cũ" → loop đến timeout.
            # Giờ: chỉ chấp nhận mail có date >= (started_at - grace). Mail OTP
            # cũ từ session trước (vài phút trở lên) sẽ rớt ngoài window.
            threshold = started_at - _DONGVANFB_DATE_GRACE
            log(
                f"[otp:dongvanfb] filter window: date >= {threshold.isoformat()} "
                f"(started_at={started_at.isoformat()}, grace={_DONGVANFB_DATE_GRACE.total_seconds():.0f}s)"
            )
            while True:
                attempt += 1
                try:
                    response = await client.post(
                        _DONGVANFB_URL,
                        headers=_DONGVANFB_HEADERS,
                        json=payload,
                    )
                    if response.status_code != 200:
                        log(f"[otp:dongvanfb] HTTP {response.status_code} attempt {attempt}")
                        consecutive_errors += 1
                    else:
                        data = response.json()

                        if not data.get("status"):
                            content = data.get("content", "")
                            consecutive_errors += 1
                            log(f"[otp:dongvanfb] status=false attempt {attempt}: {content}")
                        else:
                            consecutive_errors = 0
                            messages: list[dict] = data.get("messages") or []

                            # Sort mới nhất trước theo date (đã fix tz UTC+7).
                            def _msg_dt(m: dict) -> datetime:
                                return (
                                    _parse_dongvanfb_date(m.get("date") or "")
                                    or datetime.min.replace(tzinfo=timezone.utc)
                                )

                            messages_sorted = sorted(messages, key=_msg_dt, reverse=True)

                            stale_count = 0
                            for msg in messages_sorted:
                                sender = str(msg.get("from") or "")
                                subject = str(msg.get("subject") or "")
                                msg_dt = _parse_dongvanfb_date(msg.get("date") or "")
                                # Skip mail không parse được date — không thể
                                # phân biệt cũ/mới, chấp nhận false-positive an
                                # toàn hơn là nhặt nhầm code cũ.
                                if msg_dt is None:
                                    continue
                                if msg_dt < threshold:
                                    stale_count += 1
                                    continue
                                code = str(msg.get("code") or "").strip()
                                if not (code and len(code) == 6 and code.isdigit()):
                                    code = _extract_otp(subject, str(msg.get("message") or "")) or ""
                                if not code:
                                    continue
                                if not (_is_openai_sender(sender) or "openai" in subject.lower()):
                                    log(
                                        f"[otp:dongvanfb] suspicious code {code} "
                                        f"from {sender!r} — skip (non-OpenAI sender)"
                                    )
                                    continue
                                log(
                                    f"[otp:dongvanfb] found {code} "
                                    f"(date={msg_dt.isoformat()}, attempt {attempt})"
                                )
                                return code

                            if attempt <= 3 or attempt % 5 == 0:
                                log(
                                    f"[otp:dongvanfb] chưa có mail OpenAI mới "
                                    f"(total={len(messages)}, stale={stale_count}, "
                                    f"attempt {attempt})"
                                )

                    if consecutive_errors >= 3:
                        raise OutlookProviderUnavailable(
                            f"dongvanfb API thất bại {consecutive_errors} lần liên tiếp"
                        )

                except (httpx.HTTPError, ValueError) as exc:
                    consecutive_errors += 1
                    log(
                        f"[otp:dongvanfb] error attempt {attempt} "
                        f"({consecutive_errors}/3): {type(exc).__name__}: {exc!r}"
                    )
                    if consecutive_errors >= 3:
                        raise OutlookProviderUnavailable(
                            f"dongvanfb API lỗi network {consecutive_errors} lần liên tiếp: {exc}"
                        ) from exc

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        f"OTP timeout after {timeout_seconds}s for {self.combo.email}"
                    )
                await asyncio.sleep(min(poll_interval_seconds, remaining))


# ─────────────────────────────────────────────────────────────────────
# Gmail Advanced provider (checkgmail.live API)
# ─────────────────────────────────────────────────────────────────────


class GmailAdvancedParseError(Exception):
    """Parse input line fail cho Gmail Advanced mode."""


class GmailAdvancedProvider:
    """Provider poll OTP qua API checkgmail.live.

    Input format: email|api_url
    API response:
        {
            "ok": true,
            "order_id": "...",
            "service": "chatgpt",
            "email": "...",
            "status": "success",
            "mail_status": "live",
            "otp": "123456",       ← poll đến khi non-empty
            "otp_history": [...],
            "timeout_sec": 600,
            ...
        }

    Poll logic: gọi GET api_url liên tục, khi field `otp` có giá trị 6 số → return.
    Nếu `status` != "success" hoặc `ok` != true → báo lỗi.
    """

    def __init__(self, *, api_url: str, email: str = ""):
        if not api_url:
            raise ValueError("Gmail Advanced api_url is required")
        self.api_url = api_url
        self.email = email

    @classmethod
    def parse_line(cls, line: str) -> tuple[str, str]:
        """Parse line → (email, api_url).

        Hỗ trợ 2 format:
            - email|api_url  (cũ)
            - api_url        (chỉ paste link, email sẽ lấy từ API response)

        Raises GmailAdvancedParseError nếu format sai.
        """
        stripped = line.strip()
        # Format 1: chỉ URL (bắt đầu bằng http)
        if stripped.startswith(("http://", "https://")):
            return "", stripped
        # Format 2: email|url
        parts = stripped.split("|", 1)
        if len(parts) != 2:
            raise GmailAdvancedParseError(
                f"format phải là email|api_url hoặc chỉ api_url, nhận: {line[:80]}"
            )
        email_part = parts[0].strip()
        url_part = parts[1].strip()
        if not email_part or "@" not in email_part:
            raise GmailAdvancedParseError(f"email không hợp lệ: {email_part!r}")
        if not url_part.startswith(("http://", "https://")):
            raise GmailAdvancedParseError(f"api_url phải bắt đầu bằng http(s)://: {url_part[:60]}")
        return email_part, url_part

    async def pre_check(self, *, log) -> None:
        """Gọi API 1 lần để verify mail_status == 'live' trước khi chạy signup.

        Side-effects:
            - Nếu self.email rỗng (URL-only input) → tự fill email từ response.
            - Nếu mail_status != 'live' → raise ValueError (job fail ngay).
        """
        log(f"[otp:gmail_advanced] pre-check: {self.api_url}")
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            try:
                response = await client.get(self.api_url)
            except httpx.HTTPError as exc:
                raise ValueError(
                    f"Gmail Advanced pre-check failed (network): {type(exc).__name__}: {exc}"
                ) from exc

        if response.status_code != 200:
            raise ValueError(
                f"Gmail Advanced pre-check HTTP {response.status_code}: {response.text[:200]}"
            )

        try:
            data = response.json()
        except ValueError as exc:
            raise ValueError(f"Gmail Advanced pre-check: response không phải JSON") from exc

        # Extract email nếu chưa có (URL-only mode)
        api_email = str(data.get("email") or "").strip()
        if not self.email and api_email:
            self.email = api_email
            log(f"[otp:gmail_advanced] email from API: {self.email}")

        # Check ok field
        if not data.get("ok"):
            status = data.get("status", "unknown")
            raise ValueError(
                f"Gmail Advanced pre-check failed: ok=false, status={status}"
            )

        # Check mail_status
        mail_status = str(data.get("mail_status") or "").strip().lower()
        if mail_status != "live":
            raise ValueError(
                f"Gmail Advanced pre-check: mail_status='{mail_status}' (cần 'live') — "
                f"email={api_email or self.email}, dừng job."
            )

        log(f"[otp:gmail_advanced] pre-check OK: mail_status=live, email={self.email}")

    async def poll_otp(
        self,
        *,
        recipient: str,
        started_at: datetime,
        timeout_seconds: float,
        poll_interval_seconds: float,
        log,
    ) -> str:
        deadline = time.monotonic() + max(timeout_seconds, 1.0)
        log(f"[otp:gmail_advanced] polling {self.email} (timeout {timeout_seconds:.0f}s)")
        log(f"[otp:gmail_advanced] api: {self.api_url}")

        async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
            attempt = 0
            consecutive_errors = 0  # fail-fast khi API down liên tục
            _max_consecutive = 3
            while True:
                attempt += 1
                try:
                    response = await client.get(self.api_url)
                    if response.status_code != 200:
                        log(f"[otp:gmail_advanced] HTTP {response.status_code} attempt {attempt}")
                        consecutive_errors += 1
                        if consecutive_errors >= _max_consecutive:
                            raise TimeoutError(
                                f"Gmail Advanced API HTTP error {consecutive_errors} lần liên tiếp "
                                f"(last status={response.status_code}) — endpoint có thể đang down"
                            )
                    else:
                        consecutive_errors = 0
                        data = response.json()
                        # Check API errors
                        if not data.get("ok"):
                            status = data.get("status", "unknown")
                            log(f"[otp:gmail_advanced] api ok=false status={status} attempt {attempt}")
                            # Nếu status rõ ràng là lỗi terminal → raise
                            if status in ("expired", "cancelled", "not_found"):
                                raise TimeoutError(
                                    f"Gmail Advanced API error: status={status} for {self.email}"
                                )
                        else:
                            otp = str(data.get("otp") or "").strip()
                            if otp and len(otp) == 6 and otp.isdigit():
                                log(f"[otp:gmail_advanced] found OTP {otp} (attempt {attempt})")
                                return otp

                            # Check otp_history — lấy code mới nhất nếu có
                            otp_history = data.get("otp_history")
                            if isinstance(otp_history, list) and otp_history:
                                # otp_history có thể là list string hoặc list dict
                                latest = otp_history[-1]
                                if isinstance(latest, dict):
                                    code = str(latest.get("otp") or latest.get("code") or "").strip()
                                else:
                                    code = str(latest).strip()
                                if code and len(code) == 6 and code.isdigit():
                                    log(f"[otp:gmail_advanced] found OTP from history {code} (attempt {attempt})")
                                    return code

                            if attempt <= 3 or attempt % 5 == 0:
                                log(f"[otp:gmail_advanced] waiting... otp='{otp}' attempt {attempt}")
                except (httpx.HTTPError, ValueError) as exc:
                    consecutive_errors += 1
                    log(
                        f"[otp:gmail_advanced] error attempt {attempt} "
                        f"({consecutive_errors}/{_max_consecutive}): {type(exc).__name__}: {exc!r}"
                    )
                    if consecutive_errors >= _max_consecutive:
                        raise TimeoutError(
                            f"Gmail Advanced API network error {consecutive_errors} lần liên tiếp: "
                            f"{type(exc).__name__}: {exc}"
                        ) from exc

                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError(
                        f"OTP timeout after {timeout_seconds}s for {self.email} (gmail_advanced)"
                    )
                await asyncio.sleep(min(poll_interval_seconds, remaining))


# ─────────────────────────────────────────────────────────────────────
# Outlook cascade provider (DongVanFB → fallback Microsoft Graph)
# ─────────────────────────────────────────────────────────────────────


# Cache email đã fail DongVanFB trong 1 lần process. Process tiếp theo cho cùng
# email sẽ bypass DongVanFB luôn → tiết kiệm consecutive_errors retry wait.
# Reset khi process restart (in-memory, không persist DB — DongVanFB có thể up lại).
_DONGVANFB_FAILED_EMAILS: set[str] = set()

# Ngưỡng tối thiểu để fallback Microsoft Graph còn ý nghĩa. < ngưỡng này thì
# re-raise luôn vì Microsoft refresh token round-trip ~3-6s → không đủ 1 vòng poll.
_CASCADE_FALLBACK_MIN_SECONDS: float = 30.0


def _mark_dongvanfb_failed(email: str) -> None:
    """Đánh dấu email vừa fail DongVanFB → process kế bypass DongVanFB."""
    _DONGVANFB_FAILED_EMAILS.add(email.strip().lower())


def _is_dongvanfb_recently_failed(email: str) -> bool:
    return email.strip().lower() in _DONGVANFB_FAILED_EMAILS


class OutlookCascadeProvider:
    """Wrapper cascade: thử DongVanFB trước, fallback Microsoft Graph nếu transient.

    Logic phân biệt:
        - OutlookProviderUnavailable (DongVanFB API down / network / 5xx)
                                                          → fallback Microsoft với remaining
        - TimeoutError (DongVanFB poll hết hạn nhưng API alive)
                                                          → fallback Microsoft với remaining
        - OutlookComboError                               → re-raise luôn (combo chết).
            DongVanFB không raise loại này; nếu xảy ra ở fallback Microsoft path
            (token revoked) thì cũng không có gì cứu được.

    Sticky: sau khi DongVanFB fail 1 lần cho email → process kế đi thẳng Microsoft.

    Tradeoff về token rotation: DongVanFB không tự rotate refresh_token. Khi
    DongVanFB là primary và alive liên tục, token Microsoft không được refresh
    → có thể stale dần. Khi nào DongVanFB fail → fallback Microsoft mới rotate
    qua `OutlookMailProvider._persist_state`. Đây là chấp nhận đánh đổi để
    DongVanFB nhận traffic chính (nhanh + ổn định hơn cho mục đích poll OTP).
    """

    def __init__(
        self,
        *,
        combo: OutlookCombo,
        state_dir: Path,
        proxy: str | None = None,
        combo_repo: "ComboRepository | None" = None,
    ):
        self.combo = combo
        self._microsoft = OutlookMailProvider(
            combo=combo, state_dir=state_dir, proxy=proxy, combo_repo=combo_repo,
        )
        self._dongvanfb = DongVanFBOutlookProvider(combo=combo, proxy=proxy)

    async def poll_otp(
        self,
        *,
        recipient: str,
        started_at: datetime,
        timeout_seconds: float,
        poll_interval_seconds: float,
        log,
    ) -> str:
        email = self.combo.email
        deadline = time.monotonic() + max(timeout_seconds, 1.0)

        # Sticky bypass: email đã fail DongVanFB trong process này → đi thẳng Microsoft
        if _is_dongvanfb_recently_failed(email):
            log(f"[otp:cascade] {email} đã fail DongVanFB trước đó — dùng Microsoft Graph luôn")
            return await self._microsoft.poll_otp(
                recipient=recipient,
                started_at=started_at,
                timeout_seconds=timeout_seconds,
                poll_interval_seconds=poll_interval_seconds,
                log=log,
            )

        # Thử DongVanFB trước
        log(f"[otp:cascade] thử DongVanFB trước (timeout {timeout_seconds:.0f}s)")
        try:
            return await self._dongvanfb.poll_otp(
                recipient=recipient,
                started_at=started_at,
                timeout_seconds=timeout_seconds,
                poll_interval_seconds=poll_interval_seconds,
                log=log,
            )
        except OutlookProviderUnavailable as exc:
            # DongVanFB API down / network / 5xx liên tiếp 3 lần → fallback Microsoft.
            # KHÔNG nâng remaining lên min 30s — caller set deadline cứng,
            # kéo dài sẽ vi phạm contract. Nếu remaining < ngưỡng tối thiểu
            # cho 1 vòng Microsoft refresh+poll thì re-raise luôn.
            _mark_dongvanfb_failed(email)
            remaining = deadline - time.monotonic()
            if remaining < _CASCADE_FALLBACK_MIN_SECONDS:
                log(
                    f"[otp:cascade] DongVanFB unavailable ({exc}), "
                    f"remaining {remaining:.0f}s < {_CASCADE_FALLBACK_MIN_SECONDS:.0f}s "
                    f"không đủ cho Microsoft Graph — re-raise"
                )
                raise
            log(
                f"[otp:cascade] DongVanFB unavailable ({exc}) — "
                f"fallback Microsoft Graph với {remaining:.0f}s còn lại"
            )
        except TimeoutError as exc:
            # DongVanFB API alive nhưng OTP không về trong timeout. Có thể mail
            # delay phía Outlook server → cho Microsoft Graph 1 cơ hội với
            # remaining time nếu còn ≥ngưỡng.
            remaining = deadline - time.monotonic()
            if remaining < _CASCADE_FALLBACK_MIN_SECONDS:
                log(
                    f"[otp:cascade] DongVanFB timeout, remaining {remaining:.0f}s "
                    f"không đủ cho Microsoft Graph — re-raise"
                )
                raise
            _mark_dongvanfb_failed(email)
            log(
                f"[otp:cascade] DongVanFB poll timeout ({exc}) — "
                f"thử Microsoft Graph với {remaining:.0f}s còn lại"
            )

        # Fallback Microsoft Graph — dùng đúng remaining, không nâng floor.
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError(
                f"cascade deadline đã hết trước khi gọi Microsoft Graph ({remaining:.1f}s)"
            )
        return await self._microsoft.poll_otp(
            recipient=recipient,
            started_at=started_at,
            timeout_seconds=remaining,
            poll_interval_seconds=poll_interval_seconds,
            log=log,
        )


# ─────────────────────────────────────────────────────────────────────
# Factory
# ─────────────────────────────────────────────────────────────────────


def build_provider_worker(
    *, logs_url: str, api_key: str | None, insecure_tls: bool = False,
) -> WorkerMailProvider:
    return WorkerMailProvider(logs_url=logs_url, api_key=api_key, insecure_tls=insecure_tls)


def build_provider_icloud_imap(
    *, username: str, app_password: str,
) -> ICloudImapMailProvider:
    return ICloudImapMailProvider(
        username=username,
        app_password=app_password,
    )


def build_provider_outlook(
    *,
    combo: str,
    state_dir: Path,
    proxy: str | None = None,
    combo_repo: "ComboRepository | None" = None,
) -> OutlookCascadeProvider:
    """Build cascade provider: DongVanFB trước, fallback Microsoft Graph khi transient.

    Cascade logic ở `OutlookCascadeProvider.poll_otp` — caller không cần biết
    đang dùng provider nào. mail_provider="outlook" trong SignupRequest tự động
    được lợi từ fallback.
    """
    parsed = OutlookCombo.parse(combo)
    return OutlookCascadeProvider(
        combo=parsed, state_dir=state_dir, proxy=proxy, combo_repo=combo_repo,
    )


def build_provider_gmail_advanced(
    *, email: str, api_url: str,
) -> GmailAdvancedProvider:
    return GmailAdvancedProvider(api_url=api_url, email=email)


def build_provider_dongvanfb(
    *, combo: str, proxy: str | None = None,
) -> DongVanFBOutlookProvider:
    parsed = OutlookCombo.parse(combo)
    return DongVanFBOutlookProvider(combo=parsed, proxy=proxy)
