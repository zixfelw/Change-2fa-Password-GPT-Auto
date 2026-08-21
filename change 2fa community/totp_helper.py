"""TOTP helper — gen 6-digit code từ secret base32.

OpenAI MFA (2FA) trả về `secret` ở `/backend-api/accounts/mfa/enroll`. Secret này là
base32 string (vd: `B2P3OQCCXINLHGPUDIS55DHQDW5MENK5`), tương thích chuẩn Google Authenticator.

Thuật toán:
    TOTP-SHA1(secret, T=floor(unix_time/30), digits=6)
"""
from __future__ import annotations

import re
import time

import pyotp


_BASE32_RE = re.compile(r"^[A-Z2-7]+=*$")


class TotpError(Exception):
    """TOTP fail."""


def normalize_secret(raw: str) -> str:
    """Chuẩn hoá secret: bỏ space, uppercase. Reject ký tự invalid."""
    s = (raw or "").strip().replace(" ", "").replace("-", "").upper()
    if not s:
        raise TotpError("secret rỗng")
    if not _BASE32_RE.match(s):
        raise TotpError(f"secret chứa ký tự không phải base32: {s!r}")
    return s


def generate_code(secret: str, *, at: float | None = None) -> str:
    """Generate 6-digit TOTP code.

    Args:
        secret: base32 secret từ /mfa/enroll.
        at: unix timestamp. None = now.

    Returns: 6-digit string.
    """
    sec = normalize_secret(secret)
    totp = pyotp.TOTP(sec)
    if at is None:
        return totp.now()
    return totp.at(at)


def time_remaining(*, at: float | None = None) -> int:
    """Số giây còn lại đến lúc code hiện tại expire (TOTP step = 30s)."""
    t = at if at is not None else time.time()
    return 30 - int(t) % 30


def provisioning_uri(secret: str, *, account: str, issuer: str = "ChatGPT") -> str:
    """`otpauth://` URI để cài vào Google Authenticator/Authy."""
    sec = normalize_secret(secret)
    return pyotp.TOTP(sec).provisioning_uri(name=account, issuer_name=issuer)


def verify_code(secret: str, code: str, *, valid_window: int = 1) -> bool:
    """Kiểm tra code có khớp với secret không.

    `valid_window=1` cho phép code của cửa sổ trước/sau (clock skew tolerance).
    """
    sec = normalize_secret(secret)
    return pyotp.TOTP(sec).verify(code, valid_window=valid_window)
