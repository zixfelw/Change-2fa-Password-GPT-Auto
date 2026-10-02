"""Pydantic models cho signup hybrid."""
from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field

from user_agent_profile import (
    CURL_IMPERSONATE_PRIMARY as _CURL_IMPERSONATE_PRIMARY,
    WINDOWS_USER_AGENT as _WINDOWS_USER_AGENT,
)


class SignupRequest(BaseModel):
    """Input cho 1 lần signup."""

    email: str = Field(..., description="Email đăng ký, phải nhận được OTP qua Worker logs API.")
    name: str = Field(default="ChatGPT User", description="Tên hiển thị (POST create_account).")
    birthdate: str = Field(default="2000-01-01", description="YYYY-MM-DD, tuổi >= 13.")
    password: str | None = Field(
        default=None,
        description="Password để register account. Nếu None, runner gen random 12 ký tự.",
    )

    # Registration mode: "browser" (Camoufox/Playwright) or "pure_request" (curl_cffi only)
    reg_mode: str = Field(
        default="browser",
        description="Registration mode: 'browser' (default, anti-detect browser) or 'pure_request' (HTTP only, faster but easier to flag).",
        pattern="^(browser|pure_request)$",
    )
    source_email: str | None = Field(
        default=None,
        description="Mailbox poll OTP. Nếu None thì dùng `email`. Dùng khi smail khác email form.",
    )

    # Browser
    headless: bool = Field(default=False, description="Camoufox headless (không khuyến nghị, dễ bị flag).")
    keep_browser_open: bool = Field(
        default=False,
        description="Giữ browser mở sau khi xong (debug). Chỉ có tác dụng khi headed.",
    )
    off_font: bool = Field(default=False, description="Tắt camoufox font randomization.")
    profile_template: bool = Field(default=True, description="Clone profile template (cookies, addons).")
    tls_insecure: bool = Field(
        default=False,
        description=(
            "Bỏ TLS cert verification cho browser context (chỉ dùng debug/MITM proxy). "
            "Production phải để False — bật qua env GPT_SIGNUP_INSECURE_TLS=1 hoặc CLI flag."
        ),
    )

    # Polling OTP — chọn provider:
    #   - iCloud IMAP trực tiếp — cho Hide My Email chuyển tiếp về một inbox.
    #   - Worker logs API (icloud-cf-mail style) — default cho mail @icloud.com qua relay.
    #   - Outlook combo (Microsoft Graph) — cho mail @hotmail.com / @outlook.com.
    #   - Gmail Advanced (checkgmail.live API) — cho mail @gmail.com mua qua dịch vụ.
    mail_provider: str = Field(
        default="worker",
        description="Provider: 'icloud_imap', 'worker', 'outlook', 'dongvanfb', hoặc 'gmail_advanced'.",
        pattern="^(icloud_imap|worker|outlook|dongvanfb|gmail_advanced)$",
    )
    # Direct iCloud IMAP config (Hide My Email aliases → shared inbox)
    icloud_imap_username: str | None = Field(
        default=None,
        description="iCloud inbox username, thường là địa chỉ @icloud.com đầy đủ.",
    )
    icloud_imap_app_password: str | None = Field(
        default=None,
        description="Apple app-specific password; không dùng mật khẩu Apple Account chính.",
    )
    icloud_imap_cleanup_after_hours: float = Field(
        default=24.0,
        ge=1.0,
        le=720.0,
        description="Xóa OTP iCloud đã dùng; dùng ngưỡng này để dọn OTP cũ.",
    )
    # Gmail Advanced config
    gmail_api_url: str | None = Field(
        default=None,
        description="API URL checkgmail.live (dùng khi mail_provider='gmail_advanced').",
    )
    # Worker config
    email_logs_url: str = Field(
        default="https://icloud-cf-mail.n5pskgzs9g.workers.dev/logs",
        description="Worker URL trả JSON array messages cho ?mail=<recipient>.",
    )
    email_api_key: str = Field(
        default="",
        description="Bearer token cho Authorization header. Để rỗng nếu Worker không yêu cầu.",
    )
    email_insecure_tls: bool = Field(
        default=False,
        description=(
            "Bỏ verify TLS khi poll OTP từ Worker (chỉ dùng debug/local dev). "
            "Production phải để False — bật chỉ qua flag/env opt-in."
        ),
    )
    # Outlook combo config
    outlook_combo: str | None = Field(
        default=None,
        description="Combo `email|password|refresh_token|client_id` (Microsoft Graph).",
    )
    # Polling chung
    otp_timeout_seconds: float = Field(default=180.0, ge=10, description="Thời gian tối đa đợi OTP về.")
    otp_poll_interval_seconds: float = Field(default=4.0, ge=0.5)
    otp_resend_after_seconds: float = Field(
        default=90.0,
        ge=15,
        description=(
            "Đợi mail OTP bao lâu (giây) trước khi click Resend. "
            "Mail provider thực tế (iCloud HME, Outlook) có thể delay 1-2 phút — "
            "set quá thấp sẽ gây spam Resend, dễ bị OpenAI rate-limit."
        ),
    )

    # Form readiness wait
    sentinel_cookie_timeout_seconds: float = Field(
        default=30.0, ge=5,
        description="Thời gian đợi OTP form ready trên /email-verification.",
    )
    har_capture: bool = Field(
        default=False,
        description="Bật HAR capture cho Phase 1 (debug). Output: runtime/har_hybrid/<ts>.har",
    )

    # Hybrid Phase 2
    user_agent: str = Field(
        default=_WINDOWS_USER_AGENT,
        description="UA ép cho curl_cffi (phải khớp browser fingerprint Phase 1 — Windows Chrome).",
    )
    impersonate: str = Field(
        default=_CURL_IMPERSONATE_PRIMARY,
        description="curl_cffi browser impersonation key (đồng bộ với UA Chrome major).",
    )
    proxy: str | None = Field(default=None, description="HTTP/HTTPS proxy cho cả 2 phase.")

    # MFA inline — enroll 2FA NGAY trong context vừa tạo account (browser page
    # hoặc curl session còn sống), tái dùng CF clearance + đúng IP. Tránh spawn
    # curl_cffi session mới sau khi context chết → bị Cloudflare 403 → mất acc.
    mfa_inline: bool = Field(
        default=True,
        description="Enroll 2FA inline trong phase signup (CF-clean). Tắt → fallback enable_2fa Phase 2 (curl_cffi).",
    )


class BrowserHandoff(BaseModel):
    """Output Phase 1 — context để Phase 2 dùng."""

    cookies: list[dict[str, Any]] = Field(default_factory=list, description="Playwright cookies dict list.")
    state_param: str = Field(..., description="OAuth state lấy từ URL /authorize?...&state=<...>.")
    device_id: str = Field(..., description="ext-oai-did UUID (cũng là id field cho /sentinel/req).")
    auth_session_logging_id: str = Field(..., description="Logging ID từ /api/auth/signin/openai redirect URL.")
    callback_redirect_uri: str = Field(
        default="https://chatgpt.com/api/auth/callback/openai",
        description="redirect_uri của OAuth (giống nhau cho mọi run, copy từ HAR).",
    )
    callback_url: str = Field(
        ...,
        description="Full callback URL (kèm code + state) trả về từ create_account, dùng cho Phase 2.",
    )
    access_token: str | None = Field(
        default=None,
        description="Access token lấy trực tiếp trong browser trước khi đóng context.",
    )

    # Kết quả enroll 2FA inline (browser page còn sống — CF-clean). None nếu
    # mfa_inline tắt hoặc enroll fail (caller fallback enable_2fa Phase 2).
    two_factor: dict[str, Any] | None = Field(
        default=None,
        description="MFA result inline {secret, factor_id, session_id, first_code, activated, ...}.",
    )
    two_factor_partial: dict[str, Any] | None = Field(
        default=None,
        description="State {secret, factor_id, session_id} khi enroll OK nhưng activate fail — để retry activate-only.",
    )

    # Cookies Phase 2 cần dùng (helpers)
    @property
    def cookies_dict_for(self) -> dict[str, dict[str, str]]:
        """Map domain → {name: value} cho dễ inject vào curl_cffi."""
        out: dict[str, dict[str, str]] = {}
        for c in self.cookies:
            domain = (c.get("domain") or "").lstrip(".")
            out.setdefault(domain, {})[c["name"]] = c["value"]
        return out


class SignupResult(BaseModel):
    """Output cuối: session token NextAuth + metadata."""

    success: bool
    email: str
    password: str | None = Field(default=None, description="Password đã set khi register.")
    name: str | None = Field(default=None, description="Tên hiển thị đã dùng.")
    age: int | None = Field(default=None, description="Tuổi đã dùng (compute từ birthdate).")
    user_id: str | None = None
    account_id: str | None = None
    session_token: str | None = Field(default=None, description="__Secure-next-auth.session-token JWT.")
    access_token: str | None = Field(default=None, description="Bearer JWT cho /backend-api/.")
    cookies: list[dict[str, Any]] = Field(default_factory=list, description="Cookies sau callback (chatgpt.com).")
    phase1_seconds: float = 0.0
    phase2_seconds: float = 0.0
    otp_seconds: float = 0.0
    error: str | None = None

    # MFA enroll inline (CF-clean) — set bởi phase signup khi mfa_inline=True.
    # two_factor: enroll + activate đầy đủ. two_factor_partial: enroll OK nhưng
    # activate fail → caller persist + retry activate-only (không enroll lại).
    two_factor: dict[str, Any] | None = Field(default=None, description="MFA result inline (đầy đủ).")
    two_factor_partial: dict[str, Any] | None = Field(default=None, description="MFA partial state (activate fail).")
