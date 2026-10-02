"""Phase 1: Browser signup — register (email+pass) → OTP → /about-you → session.

Flow (theo HAR mới):
  1. chatgpt.com → bootstrap NextAuth (csrf + signin/openai) → authorize URL
  2. Navigate authorize → /email-verification page load
  3. Click "Continue with password" → /create-account/password
  4. Fill password → submit → POST /api/accounts/user/register {username, password}
  5. Server trigger OTP (GET /email-otp/send) → redirect /email-verification (OTP form)
  6. Poll OTP → submit → POST /email-otp/validate
  7. /about-you → fill name+age → POST /create_account
  8. Đợi session-token cookie (đã login)
  9. Exfil cookies → BrowserHandoff

Retry (account đã tồn tại):
  - Register trả lỗi "already exists" → fallback OTP-only login
  - HOẶC: OTP → login → chatgpt.com

Kết quả: BrowserHandoff đủ context để Phase 2 extract session/access_token.
"""
from __future__ import annotations

import asyncio
import json
import re
import shutil
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from config import Settings, ensure_runtime_dirs, prepare_profile_dir
from mail_providers import MailProvider, OutlookComboError
from models import BrowserHandoff, SignupRequest
from _nextauth_bootstrap import bootstrap_authorize_url
from _proxy_observation import get_proxy_exit_ip
from _browser_retry import (
    DRIVER_DEAD_MARKERS as _DRIVER_DEAD_MARKERS,
    LAUNCH_RETRY_BACKOFF as _LAUNCH_RETRY_BACKOFF,
    LAUNCH_RETRY_MAX as _LAUNCH_RETRY_MAX,
    is_driver_dead_error as _is_driver_dead_error,
    is_execution_context_destroyed_error as _is_context_destroyed_error,
    is_navigation_abort_error as _is_navigation_abort_error,
    is_navigation_timeout as _is_navigation_timeout,
    is_network_error as _is_network_error,
    is_browser_launch_error as _is_browser_launch_error,
    browser_launch_order as _browser_launch_order,
    parse_proxy_for_playwright as _parse_proxy,
)
from _socks5_http_bridge import Socks5HttpBridge, needs_socks5_http_bridge
from user_agent_profile import CAMOUFOX_OS as _CAMOUFOX_OS


class BrowserPhaseError(Exception):
    """Phase 1 failed."""


class OtpValidationRateLimitError(BrowserPhaseError):
    """Auth session hiện tại đã bị khóa vì submit OTP quá nhiều lần."""


class AccountAlreadyExistsError(BrowserPhaseError):
    """Server trả ``error_code: user_already_exists`` trên ``/about-you``.

    Fatal: account đã tồn tại trong hệ thống OpenAI — KHÔNG retry submit
    nữa, caller (signup runner) bỏ luôn account này, chuyển combo kế tiếp.
    Dùng subclass để caller có thể phân biệt nếu cần (vd mark "duplicate"
    riêng thay vì gộp chung "error"); mặc định caller chỉ catch
    ``BrowserPhaseError`` → tự nhiên propagate.
    """


# Các error_code của /about-you mà server commit là vĩnh viễn (retry không
# bao giờ pass). Detect → raise fatal, dừng retry submit ngay.
_ABOUT_YOU_FATAL_ERROR_CODES: tuple[str, ...] = (
    "user_already_exists",
)


# Cookies bắt buộc cho Phase 2 (chatgpt.com session).
_REQUIRED_AUTH_COOKIES = (
    "oai-did",
    "__cf_bm",
    "cf_clearance",
)


# ─────────────────────────────────────────────────────────────────────
# JS helpers
# ─────────────────────────────────────────────────────────────────────

def _classify_register_error(status: object, body: object) -> tuple[str, str]:
    """Classify register failure semantically, never from HTTP 409 alone.

    Returns ``(kind, body_text)`` where kind is ``invalid_state``,
    ``already_exists`` or ``other``. ``invalid_state`` takes priority because
    treating a stale auth session as an existing account leaves the page on
    password-create and makes the production state machine wait until timeout.
    """
    try:
        body_text = (
            json.dumps(body, ensure_ascii=False, default=str)
            if isinstance(body, dict)
            else str(body or "")
        )
    except Exception:
        body_text = str(body or "")

    codes: list[str] = []
    messages: list[str] = []
    if isinstance(body, dict):
        mappings = [body]
        nested_error = body.get("error")
        if isinstance(nested_error, dict):
            mappings.append(nested_error)
        for mapping in mappings:
            for key in ("code", "error_code", "type"):
                value = mapping.get(key)
                if value is not None:
                    codes.append(str(value).casefold().strip())
            value = mapping.get("message")
            if value is not None:
                messages.append(str(value).casefold().strip())

    normalized = " ".join([body_text.casefold(), *codes, *messages])
    if "invalid_state" in codes or "invalid_state" in normalized:
        return "invalid_state", body_text
    if "sign-in session is no longer valid" in normalized:
        return "invalid_state", body_text

    duplicate_codes = {
        "user_already_exists",
        "account_already_exists",
        "email_already_exists",
        "invalid_auth_step",
    }
    if duplicate_codes.intersection(codes):
        return "already_exists", body_text
    duplicate_phrases = (
        "already exists",
        "already registered",
        "account exists",
        "user exists",
    )
    if any(phrase in normalized for phrase in duplicate_phrases):
        return "already_exists", body_text
    return "other", body_text


async def _submit_password_registration_form(page, *, password: str, log) -> dict[str, object]:
    """Submit form tạo password và trả response của user/register.

    Không gọi trực tiếp private endpoint: frontend phải tự tạo request để giữ
    nguyên auth state/cookie/telemetry của phiên đang hiển thị.
    """
    password_input = None
    for selector in ('input[name="password"]', 'input[type="password"]'):
        try:
            locator = page.locator(selector).first
            if await locator.is_visible(timeout=2_000):
                password_input = locator
                break
        except Exception:
            continue
    if password_input is None:
        raise BrowserPhaseError(
            f"không tìm thấy ô tạo mật khẩu trên form. URL: {page.url}"
        )

    submit_button = None
    for selector in ('button[type="submit"]', 'button:has-text("Continue")'):
        try:
            locator = page.locator(selector).first
            if await locator.is_visible(timeout=2_000):
                submit_button = locator
                break
        except Exception:
            continue
    if submit_button is None:
        raise BrowserPhaseError(
            f"không tìm thấy nút submit form tạo mật khẩu. URL: {page.url}"
        )

    await password_input.click(timeout=5_000)
    await password_input.fill(password, timeout=5_000)
    log("[flow] submitting password form via UI")

    try:
        async with page.expect_response(
            lambda response: urlparse(response.url).path
            == "/api/accounts/user/register",
            timeout=20_000,
        ) as pending_response:
            await submit_button.click(timeout=5_000)
        response = await pending_response.value
    except Exception as exc:
        raise BrowserPhaseError(
            "submit form tạo mật khẩu không nhận được response user/register; "
            f"URL: {page.url}; lỗi: {type(exc).__name__}: {exc}"
        ) from exc

    try:
        response_text = await response.text()
    except Exception as exc:
        raise BrowserPhaseError(
            f"không đọc được response user/register: {type(exc).__name__}: {exc}"
        ) from exc

    try:
        body: object = json.loads(response_text) if response_text else {}
    except (TypeError, json.JSONDecodeError):
        body = response_text
    return {"status": response.status, "body": body}


async def _follow_register_continue_url(page, continue_url: object, *, log) -> None:
    """Để frontend điều hướng trước; chỉ fallback đúng một lần nếu nó chưa đi."""
    if not isinstance(continue_url, str) or not continue_url:
        return
    target_url = (
        f"https://auth.openai.com{continue_url}"
        if continue_url.startswith("/")
        else continue_url
    )
    try:
        await page.wait_for_url(
            lambda url: "/create-account/password" not in str(url),
            timeout=5_000,
        )
        log(f"[flow] frontend followed continue_url: {page.url.split('?')[0]}")
        return
    except Exception:
        pass

    if "/create-account/password" in page.url:
        log(f"[flow] frontend navigation pending — opening {target_url.split('?')[0]}")
        await page.goto(target_url, wait_until="domcontentloaded")

# JS: fill /about-you (Sentinel monitor form interactions)
_PAGE_CREATE_ACCOUNT_JS = r"""
async ({name, birthdate}) => {
    const res = await fetch('/api/accounts/create_account', {
        method: 'POST',
        credentials: 'include',
        headers: {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({name, birthdate}),
    });
    const text = await res.text();
    let body = null;
    try { body = JSON.parse(text); } catch { body = text; }
    return {status: res.status, body};
}
"""


# ─────────────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────────────


def _browser_health(ctx, page) -> str:
    """Non-blocking snapshot trạng thái browser/context/page để log debug.

    Trả về chuỗi short, không raise — dùng trước/sau thao tác có thể fail
    do target closed (Plan D: observability).

    Format: 'page=open ctx_pages=2 browser=connected'
            'page=CLOSED ctx_pages=0 browser=disconnected'
    """
    try:
        page_closed = page.is_closed()
        page_state = "CLOSED" if page_closed else "open"
    except Exception as exc:
        page_state = f"ERR({type(exc).__name__})"

    try:
        pages = list(getattr(ctx, "pages", []) or [])
        live_pages = sum(1 for p in pages if not _safe_is_closed(p))
        ctx_state = f"{live_pages}/{len(pages)}"
    except Exception as exc:
        ctx_state = f"ERR({type(exc).__name__})"

    try:
        browser = getattr(ctx, "browser", None)
        if browser is None:
            br_state = "n/a"
        else:
            br_state = "connected" if browser.is_connected() else "DISCONNECTED"
    except Exception as exc:
        br_state = f"ERR({type(exc).__name__})"

    return f"page={page_state} ctx_pages_live={ctx_state} browser={br_state}"


def _safe_is_closed(p) -> bool:
    try:
        return bool(p.is_closed())
    except Exception:
        return True


_GEOIP_CACHE_MAX_AGE = 86400  # 24h


def _ensure_geoip_cache(runtime_dir: Path, *, log) -> None:
    """Cache GeoIP mmdb locally so camoufox doesn't re-download every launch."""
    try:
        # Camoufox >= 0.5.x.
        from camoufox.geolocation import (
            download_mmdb,
            geoip_allowed,
            get_mmdb_path,
            load_geoip_config,
        )

        geoip_allowed()
        geoip_config = load_geoip_config()
        database_paths = tuple(dict.fromkeys((
            get_mmdb_path("ipv4", geoip_config),
            get_mmdb_path("ipv6", geoip_config),
        )))
    except ImportError as modern_error:
        # Camoufox <= 0.4.x used ``camoufox.locale.MMDB_FILE``. Only fall back
        # when that API really exists; a missing GeoIP extra must fail early.
        try:
            from camoufox.locale import MMDB_FILE, download_mmdb  # type: ignore[no-redef]

            database_paths = (MMDB_FILE,)
        except ImportError as legacy_error:
            raise BrowserPhaseError(
                "Thiếu Camoufox GeoIP dependency. Chạy lại setup.bat hoặc: "
                '.venv\\Scripts\\python.exe -m pip install "camoufox[geoip]"'
            ) from (modern_error or legacy_error)

    cache_dir = runtime_dir / "geoip"
    cache_dir.mkdir(parents=True, exist_ok=True)

    for database_path in database_paths:
        if database_path.exists():
            continue
        cache_path = cache_dir / database_path.name
        if (
            cache_path.exists()
            and (time.time() - cache_path.stat().st_mtime) < _GEOIP_CACHE_MAX_AGE
        ):
            database_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(cache_path, database_path)
            log(f"[geoip] restored from cache ({cache_path})")

    missing = [path for path in database_paths if not path.exists()]
    if missing:
        log("[geoip] downloading GeoIP database (cached for 24h)...")
        try:
            download_mmdb()
        except Exception as exc:  # noqa: BLE001
            raise BrowserPhaseError(
                f"Không tải được Camoufox GeoIP database: {type(exc).__name__}: {exc}"
            ) from exc

    still_missing = [path for path in database_paths if not path.exists()]
    if still_missing:
        names = ", ".join(path.name for path in still_missing)
        raise BrowserPhaseError(f"Camoufox GeoIP database bị thiếu sau khi tải: {names}")

    for database_path in database_paths:
        cache_path = cache_dir / database_path.name
        shutil.copy2(database_path, cache_path)
    log(f"[geoip] ready ({', '.join(path.name for path in database_paths)})")


async def _bootstrap_oauth_url(page, *, email: str, device_id: str, logging_id: str, log) -> str:
    """Gọi /api/auth/csrf + POST /signin/openai trong page context chatgpt.com."""
    log("[browser] bootstrapping NextAuth (csrf + signin)...")
    url = await bootstrap_authorize_url(
        page,
        email=email,
        device_id=device_id,
        logging_id=logging_id,
        prepare_page=True,
        log=log,
    )
    log(f"[browser] authorize URL ready: {url[:120]}...")
    return url


async def _register_with_password(page, *, email: str, password: str, log) -> str:
    """Đăng ký account bằng form password trên auth.openai.com.

    Flow:
      1. Click "Continue with password" (nếu cần)
      2. Điền và submit form để frontend gửi user/register
      3. GET continue_url (/email-otp/send) → trigger OTP

    Returns: "otp_sent" (success) hoặc raise error.
    """
    # Click "Continue with password" button nếu đang ở /email-verification
    try:
        pwd_btn = page.locator(
            'button:has-text("password"), a:has-text("password"), '
            '[role="button"]:has-text("password")'
        )
        if await pwd_btn.count() > 0:
            btn_text = await pwd_btn.first.text_content(timeout=1000)
            await pwd_btn.first.click(timeout=3000)
            log(f"[browser] clicked password button: {(btn_text or '').strip()[:60]}")
            # Đợi page navigate tới /create-account/password (SPA)
            deadline = time.monotonic() + 10.0
            while time.monotonic() < deadline:
                if "password" in page.url:
                    break
                # Hoặc password input visible
                try:
                    pwd_input = page.locator('input[type="password"]').first
                    if await pwd_input.is_visible(timeout=500):
                        break
                except Exception:
                    pass
                await asyncio.sleep(0.3)
            log(f"[browser] page ready: {page.url.split('?')[0]}")
    except Exception:
        pass

    await asyncio.sleep(0.5)

    # Check: nếu page ở /log-in/password → account đã tồn tại → login thay vì register
    if "log-in" in page.url:
        log("[browser] account exists → login with password")
        # Fill password form
        pwd_input = None
        for sel in ('input[type="password"]', 'input[name="password"]'):
            try:
                loc = page.locator(sel).first
                if await loc.is_visible(timeout=2000):
                    pwd_input = loc
                    break
            except Exception:
                continue
        if pwd_input:
            await pwd_input.click(force=True, timeout=3000)
            await pwd_input.fill("", timeout=3000)
            await pwd_input.type(password, delay=50)
            await asyncio.sleep(0.3)
            for btn in ('button[type="submit"]', 'button:has-text("Continue")'):
                try:
                    await page.click(btn, timeout=3000)
                    break
                except Exception:
                    continue
            log("[browser] submitted login password")
            return "login"
        raise BrowserPhaseError(f"login page but no password input. URL: {page.url}")

    log(f"[browser] submit password form (email={email})")
    result = await _submit_password_registration_form(
        page,
        password=password,
        log=log,
    )

    if not isinstance(result, dict):
        raise BrowserPhaseError(f"register unexpected result: {result}")

    status = result.get("status")
    body = result.get("body") or {}

    if status == 200:
        # Success → navigate tới continue_url để trigger OTP send
        continue_url = None
        if isinstance(body, dict):
            continue_url = body.get("continue_url")
        log(f"[browser] register OK → continue_url={continue_url}")

        if continue_url:
            await _follow_register_continue_url(page, continue_url, log=log)
            log("[browser] OTP send triggered")
        # Đợi 1s để page settle — otp_started_at sẽ được set SAU đây bởi caller
        await asyncio.sleep(1.0)
        return "otp_sent"

    # Error cases — HTTP status alone không đủ để phân biệt duplicate/state.
    error_kind, body_str = _classify_register_error(status, body)
    if error_kind == "invalid_state":
        raise BrowserPhaseError(
            "user/register HTTP 409 invalid_state — auth session không còn hợp lệ; "
            f"cần browser context mới: {body_str[:200]}"
        )

    # Account already exists → fallback: submit OTP/login theo caller.
    if error_kind == "already_exists":
        log(f"[browser] register: account already exists (HTTP {status}) — fallback OTP login")
        return "already_exists"

    raise BrowserPhaseError(f"register failed HTTP {status}: {body_str[:200]}")


async def _wait_otp_form(page, *, timeout_seconds: float, log) -> str:
    """Đợi OTP form xuất hiện. Return selector."""
    selectors = (
        'input[name="code"]',
        'input[autocomplete="one-time-code"]',
        'input[inputmode="numeric"]',
    )
    for sel in selectors:
        try:
            await page.wait_for_selector(sel, state="visible", timeout=int(timeout_seconds * 1000))
            log(f"[browser] OTP input ready ({sel})")
            return sel
        except Exception:
            continue
    raise BrowserPhaseError(f"OTP input không xuất hiện sau {timeout_seconds}s. URL: {page.url}")


async def _submit_otp(ctx, page, *, otp_code: str, otp_selector: str, log) -> None:
    """Fill OTP via UI, then use the bounded API fallback when needed."""
    log(f"[browser] typing OTP {otp_code} ({_browser_health(ctx, page)})")

    if _safe_is_closed(page):
        log(f"[browser] page closed before OTP fill — fallback API ({_browser_health(ctx, page)})")
        await _submit_otp_api_and_sync(
            ctx, page, otp_code=otp_code, log=log, prefix="[browser]"
        )
        return

    # UI path: fill input + click submit
    ui_failed_with: BaseException | None = None
    try:
        await page.fill(otp_selector, otp_code, timeout=3000)
    except Exception as exc:
        ui_failed_with = exc
        if _is_driver_dead_error(exc):
            log(
                f"[browser] page.fill failed — driver/page dead "
                f"({type(exc).__name__}: {exc}) — fallback API "
                f"({_browser_health(ctx, page)})"
            )
            await _submit_otp_api_and_sync(
                ctx, page, otp_code=otp_code, log=log, prefix="[browser]"
            )
            return
        log(
            f"[browser] page.fill error (non-driver) "
            f"{type(exc).__name__}: {exc} — vẫn thử click submit"
        )

    if ui_failed_with is None:
        for btn in ('button[type="submit"]', 'button:has-text("Continue")', 'button:has-text("Verify")'):
            try:
                await page.click(btn, timeout=2000)
                log(f"[browser] clicked {btn}")
                return
            except Exception as exc:
                if _is_driver_dead_error(exc):
                    log(
                        f"[browser] click {btn} — driver dead "
                        f"({type(exc).__name__}: {exc}) — fallback API "
                        f"({_browser_health(ctx, page)})"
                    )
                    await _submit_otp_api_and_sync(
                        ctx, page, otp_code=otp_code, log=log, prefix="[browser]"
                    )
                    return
                continue

    log(
        f"[browser] no submit button worked — fallback API "
        f"({_browser_health(ctx, page)})"
    )
    await _submit_otp_api_and_sync(
        ctx, page, otp_code=otp_code, log=log, prefix="[browser]"
    )


async def _submit_otp_via_api(ctx, *, otp_code: str, log) -> str | None:
    """Submit OTP qua context.request — không phụ thuộc page sống.

    Dùng cookies từ context (đã chia sẻ với page) để giữ session.
    Fail-fast nếu HTTP status không OK.
    """
    request_ctx = getattr(ctx, "request", None)
    if request_ctx is None:
        raise BrowserPhaseError(
            "OTP fallback failed: context.request không khả dụng "
            "(Camoufox/Playwright version cũ?)"
        )
    url = "https://auth.openai.com/api/accounts/email-otp/validate"
    try:
        resp = await request_ctx.post(
            url,
            data={"code": otp_code},
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Origin": "https://auth.openai.com",
                "Referer": "https://auth.openai.com/email-verification",
            },
            timeout=10_000,
        )
    except Exception as exc:
        raise BrowserPhaseError(
            f"OTP fallback API request failed: {type(exc).__name__}: {exc}"
        ) from exc

    status = resp.status
    try:
        body_text = await resp.text()
    except Exception:
        body_text = "<no body>"
    try:
        payload = json.loads(body_text)
    except (TypeError, ValueError):
        payload = {}
    error_obj = payload.get("error") if isinstance(payload, dict) else None
    error_code = ""
    if isinstance(error_obj, dict):
        error_code = str(error_obj.get("code") or "").strip().casefold()
    elif isinstance(error_obj, str):
        error_code = error_obj.strip().casefold()
    if not error_code and isinstance(payload, dict):
        error_code = str(
            payload.get("code") or payload.get("error_code") or ""
        ).strip().casefold()
    if not error_code and "max_check_attempts" in body_text.casefold():
        error_code = "max_check_attempts"
    log(
        f"[browser] OTP fallback API → HTTP {status} "
        f"error_code={error_code or '-'}"
    )
    if error_code == "max_check_attempts":
        raise OtpValidationRateLimitError(
            "OTP max_check_attempts: auth session đã bị khóa; "
            "dừng ngay, không poll hoặc submit thêm mã"
        )
    if status >= 400:
        raise BrowserPhaseError(
            f"OTP validate API rejected: HTTP {status}: "
            f"{error_code or body_text[:200]}"
        )
    continue_url = payload.get("continue_url") if isinstance(payload, dict) else None
    if not isinstance(continue_url, str) or not continue_url.strip():
        return None
    return continue_url.strip()


def _normalize_otp_code(value: object) -> str | None:
    """Return a six-digit OTP or ``None`` for an unusable cached value."""
    if not isinstance(value, str):
        return None
    code = value.strip()
    return code if len(code) == 6 and code.isdigit() else None


async def _restore_cached_otp_input(page, otp_code: str | None) -> bool:
    """Refill a re-rendered OTP input using only short, bounded DOM waits."""
    code = _normalize_otp_code(otp_code)
    if code is None or _safe_is_closed(page):
        return False
    try:
        otp_input = page.locator(
            'input[name="code"], '
            'input[autocomplete="one-time-code"], '
            'input[inputmode="numeric"]'
        ).first
        if not await otp_input.is_visible(timeout=500):
            return False
        current_value = await otp_input.input_value(timeout=500)
        if current_value.strip() != code:
            await otp_input.fill(code, timeout=1000)
        return True
    except Exception:
        return False


async def _sync_page_after_otp_api(
    page,
    *,
    continue_url: str | None,
    log,
    prefix: str,
) -> None:
    """Reflect a successful API validation back into the browser page."""
    if _safe_is_closed(page):
        log(f"{prefix} OTP API accepted; page is closed so navigation is skipped")
        return

    current_url = str(getattr(page, "url", "") or "")
    if (
        ("chatgpt.com" in current_url and "auth.openai.com" not in current_url)
        or "/about-you" in current_url
        or "/auth/error" in current_url
    ):
        return

    target_url = continue_url
    if target_url and target_url.startswith("/"):
        target_url = f"https://auth.openai.com{target_url}"
    if target_url:
        target_host = (urlparse(target_url).hostname or "").casefold()
        if target_host not in {"auth.openai.com", "chatgpt.com"}:
            log(f"{prefix} OTP API returned an untrusted continue_url; skipped")
            return
    try:
        if target_url:
            await page.goto(target_url, wait_until="commit", timeout=10_000)
            log(
                f"{prefix} OTP API accepted; navigated to "
                f"{target_url.split('?')[0]}"
            )
        else:
            await page.reload(wait_until="commit", timeout=10_000)
            log(f"{prefix} OTP API accepted; reloaded auth state")
    except Exception as exc:
        # Validation has already succeeded server-side. Do not submit the code
        # again merely because the top-level page is mid-redirect.
        log(
            f"{prefix} OTP API accepted; page sync deferred: "
            f"{type(exc).__name__}: {exc}"
        )


async def _submit_otp_api_and_sync(
    ctx,
    page,
    *,
    otp_code: str,
    log,
    prefix: str,
) -> None:
    continue_url = await _submit_otp_via_api(ctx, otp_code=otp_code, log=log)
    await _sync_page_after_otp_api(
        page,
        continue_url=continue_url,
        log=log,
        prefix=prefix,
    )


async def _try_cached_otp_api_fallback(
    ctx,
    page,
    *,
    otp_code: str | None,
    log,
    prefix: str,
) -> bool:
    """Try API validation without waiting on a possibly detached OTP input.

    The UI may navigate away immediately after the click.  Reading the old
    locator at that point invokes Playwright's default 30-second wait and
    obscures the real navigation result, so callers pass the code they already
    submitted instead.
    """
    code = _normalize_otp_code(otp_code)
    if code is None:
        log(f"{prefix} API fallback skipped: no cached 6-digit OTP")
        return False
    if _safe_is_closed(page):
        log(f"{prefix} API fallback skipped: page is closed")
        return False
    current_url = str(getattr(page, "url", "") or "")
    if (
        ("chatgpt.com" in current_url and "auth.openai.com" not in current_url)
        or "/about-you" in current_url
        or "/auth/error" in current_url
    ):
        log(f"{prefix} API fallback skipped: page already left OTP flow")
        return False
    try:
        await _submit_otp_api_and_sync(
            ctx,
            page,
            otp_code=code,
            log=log,
            prefix=prefix,
        )
    except OtpValidationRateLimitError:
        # Đây là trạng thái terminal của auth session. Không được nuốt lỗi rồi
        # quay lại poll/submission loop.
        raise
    except Exception as exc:
        log(f"{prefix} API fallback failed: {type(exc).__name__}: {exc}")
        return False
    return True


async def _wait_after_login(page, *, timeout_seconds: float, log) -> str:
    """Sau submit login password, đợi:
    - chatgpt.com (login OK, không cần OTP)
    - /email-verification (cần OTP)
    - error
    Returns: 'chatgpt' hoặc 'otp_required'.
    """
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        cur = page.url
        if "chatgpt.com" in cur and "auth.openai.com" not in cur and "/auth/error" not in cur:
            log("[browser] login OK — redirected to chatgpt.com")
            return "chatgpt"
        if "/email-verification" in cur or "/email-otp" in cur:
            log("[browser] login requires OTP")
            return "otp_required"
        if "/auth/error" in cur:
            raise BrowserPhaseError(f"login error page: {cur}")
        # Detect OTP form xuất hiện (SPA case)
        try:
            otp_input = page.locator('input[name="code"], input[autocomplete="one-time-code"]').first
            if await otp_input.is_visible(timeout=300):
                log("[browser] login OTP form detected (SPA)")
                return "otp_required"
        except Exception:
            pass
        # Detect login error (sai password)
        try:
            err_el = page.locator('[role="alert"], [class*="error"]').first
            err_text = await err_el.text_content(timeout=300)
            if err_text and ("incorrect" in err_text.lower() or "wrong password" in err_text.lower() or "invalid" in err_text.lower()):
                raise BrowserPhaseError(f"login error: {err_text.strip()}")
        except BrowserPhaseError:
            raise
        except Exception:
            pass
        await asyncio.sleep(0.5)
    raise BrowserPhaseError(f"timeout {timeout_seconds}s after login submit. URL: {page.url}")


async def _detect_screen(page) -> str:
    """Detect màn hình hiện tại từ URL + DOM. Return 1 trong:
      - 'chatgpt'              : đã login xong, page ở chatgpt.com
      - 'about_you'            : form name+age (auth.openai.com/about-you)
      - 'mfa_challenge'        : account có 2FA → cần TOTP code từ authenticator
      - 'turnstile_challenge'  : Cloudflare Turnstile challenge visible
      - 'otp'                  : OTP input visible (/email-verification or SPA)
      - 'password_create'      : /create-account/password (form set password mới)
      - 'password_login'       : /log-in/password (form login với account đã tồn tại)
      - 'continue'             : /email-verification trang chọn 'Continue with password'
      - 'auth_error'           : page lỗi /auth/error
      - 'unknown'              : không nhận diện được
    """
    cur = page.url
    if "/auth/error" in cur:
        return "auth_error"
    if "chatgpt.com" in cur and "auth.openai.com" not in cur:
        return "chatgpt"
    if "auth.openai.com/about-you" in cur:
        return "about_you"
    if "passkey" in cur.lower():
        return "passkey_enroll"
    # Nội dung SPA có thể đã render /about-you mà URL chưa đổi
    try:
        name_el = page.locator('input[name="name"], input[autocomplete="name"]').first
        if await name_el.is_visible(timeout=200):
            return "about_you"
    except Exception:
        pass

    # MFA challenge — phải check TRƯỚC OTP vì input selector trùng nhau
    # (cả MFA và OTP đều dùng input[name="code"] / inputmode=numeric).
    # Phân biệt qua URL pattern hoặc text marker đặc trưng MFA.
    if "/mfa" in cur or "/totp" in cur or "/two-factor" in cur:
        return "mfa_challenge"
    try:
        # Text marker: "authenticator app", "two-factor", "Enter the 6-digit code from your authenticator"
        mfa_text = page.locator(
            'text=/authenticator app/i, text=/two[- ]factor/i, text=/from your authenticator/i'
        ).first
        if await mfa_text.is_visible(timeout=200):
            return "mfa_challenge"
    except Exception:
        pass

    if "/create-account/password" in cur:
        return "password_create"
    if "/log-in/password" in cur:
        # SPA case: URL vẫn là /log-in/password nhưng content đã chuyển sang OTP form
        # hoặc "Check your inbox" page (email verification sau login)
        try:
            otp_input = page.locator('input[name="code"], input[autocomplete="one-time-code"]').first
            if await otp_input.is_visible(timeout=200):
                return "otp"
        except Exception:
            pass
        try:
            inbox_el = page.locator(
                'text="Check your inbox", text="Check your email", text="Enter the verification code"'
            ).first
            if await inbox_el.is_visible(timeout=200):
                return "otp"
        except Exception:
            pass
        return "password_login"
    # /email-verification: ƯU TIÊN button "password" để bắt buộc set password
    # Nếu cả OTP input và password button cùng visible, password button thắng
    _PWD_BTN_SELECTOR = (
        'button:has-text("password"), a:has-text("password"), '
        '[role="button"]:has-text("password")'
    )
    if "/email-verification" in cur or "/email-otp" in cur or "/identifier" in cur:
        try:
            pwd_btn = page.locator(_PWD_BTN_SELECTOR).first
            if await pwd_btn.is_visible(timeout=800):
                return "continue"
        except Exception:
            pass
    # Broad check: trên bất kỳ auth.openai.com page nào có nút password → ưu tiên click
    if "auth.openai.com" in cur:
        try:
            pwd_btn = page.locator(_PWD_BTN_SELECTOR).first
            if await pwd_btn.is_visible(timeout=300):
                return "continue"
        except Exception:
            pass
    # Turnstile / Cloudflare challenge — check trước OTP vì có thể overlay trên OTP form
    try:
        turnstile = page.locator(
            'iframe[src*="challenges.cloudflare.com"], '
            'iframe[src*="turnstile"], '
            '#cf-turnstile, .cf-turnstile, '
            '[data-turnstile-callback]'
        ).first
        if await turnstile.is_visible(timeout=200):
            return "turnstile_challenge"
    except Exception:
        pass
    # OTP form (URL có thể là /email-verification, /email-otp, /log-in/email-verification, ...)
    try:
        otp_input = page.locator('input[name="code"], input[autocomplete="one-time-code"]').first
        if await otp_input.is_visible(timeout=200):
            return "otp"
    except Exception:
        pass
    if "/email-verification" in cur or "/email-otp" in cur:
        return "otp"  # fallback: chỉ có OTP form, không có password button
    return "unknown"


async def _skip_passkey(page, *, log, leave_timeout: float = 10.0) -> bool:
    """Skip passkey enrollment page. Returns True khi đã rời khỏi passkey URL.

    Strategy:
      1. Click explicit skip/dismiss buttons (text-based)
      2. Click any secondary/non-primary button or link
    Sau khi click, ĐỢI URL không còn chứa "passkey" (timeout `leave_timeout`s).
    Nếu click rồi mà page vẫn ở passkey → return False (caller xử lý).
    KHÔNG fallback goto chatgpt.com — sẽ cướp navigation OAuth callback inflight,
    làm Set-Cookie session-token bị abort.
    """
    async def _wait_leave_passkey() -> bool:
        try:
            await page.wait_for_url(
                lambda u: "passkey" not in (u or "").lower(),
                timeout=int(leave_timeout * 1000),
            )
            return True
        except Exception:
            return False

    # 1. Explicit skip buttons
    for sel in (
        'button:has-text("Skip")',
        'button:has-text("Maybe later")',
        'button:has-text("Do this later")',
        'button:has-text("Not now")',
        'button:has-text("I\'ll do this later")',
        'a:has-text("Skip")',
        'a:has-text("Maybe later")',
        'a:has-text("Do this later")',
        'a:has-text("Not now")',
        'a:has-text("I\'ll do this later")',
        '[data-testid*="skip" i]',
        '[data-testid*="dismiss" i]',
    ):
        try:
            btn = page.locator(sel).first
            if await btn.is_visible(timeout=800):
                await btn.click(timeout=3000)
                log(f"[browser] clicked skip passkey: {sel}")
                if await _wait_leave_passkey():
                    log("[browser] passkey page left after skip click")
                    return True
                log("[browser] click landed but URL still passkey — continue trying")
                break  # đừng click thêm selector khác, page đã transition
        except Exception:
            continue

    # 2. Log page content for debugging
    try:
        buttons_info = await page.evaluate(r"""
            () => {
                const els = [...document.querySelectorAll('button, a[href], [role="button"]')];
                return els.slice(0, 10).map(e => ({
                    tag: e.tagName, text: (e.textContent || '').trim().substring(0, 60),
                    cls: (e.className || '').substring(0, 40),
                }));
            }
        """)
        log(f"[browser] passkey page elements: {json.dumps(buttons_info, ensure_ascii=False)}")
    except Exception:
        pass

    # 3. Try clicking non-primary buttons (secondary/tertiary)
    try:
        all_buttons = page.locator('button, a[role="button"]')
        count = await all_buttons.count()
        for i in range(count):
            btn = all_buttons.nth(i)
            text = ((await btn.text_content()) or "").strip().lower()
            if any(k in text for k in ("create", "set up", "enable", "passkey")):
                continue
            if text and await btn.is_visible(timeout=500):
                await btn.click(timeout=3000)
                log(f"[browser] clicked non-primary button on passkey page: {text!r}")
                if await _wait_leave_passkey():
                    log("[browser] passkey page left after non-primary click")
                    return True
                break
    except Exception:
        pass

    log("[browser] could not leave passkey page after click attempts")
    return False


# Khi đã LẤY ĐƯỢC OTP, đảm bảo còn tối thiểu ngần này giây để hoàn tất các bước
# ngắn còn lại (submit OTP + /about-you + chờ session) — KHÔNG để wall-clock kill
# job ngay sau khi đã có OTP (lãng phí email + code). Áp cho cả deadline nội bộ
# của flow lẫn watchdog bên ngoài (qua on_checkpoint).
_POST_OTP_GRACE_SECONDS = 150.0
# Budget cho các bước TRƯỚC khi có OTP (load trang + send + submit ban đầu),
# cộng thêm vào otp_timeout để overall flow deadline phủ trọn thời gian chờ mail.
_PRE_OTP_MARGIN_SECONDS = 60.0
# Tính cả submit ban đầu và các escalation UI/JS/API. Giới hạn theo request
# thực tế thay vì chỉ đếm mã khác nhau để không tự đẩy auth session vào
# ``max_check_attempts``.
_MAX_OTP_SUBMITS_PER_FLOW = 5


async def _drive_signup_flow(
    *, ctx, page, request, mail_provider, callback_holder, otp_started_at, log,
    overall_timeout: float = 240.0,
    on_checkpoint=None,
    on_otp_started=None,
    post_otp_grace: float = _POST_OTP_GRACE_SECONDS,
) -> tuple[str, float]:
    """State machine: check URL/DOM hiện tại, dispatch handler tương ứng.
    Lặp đến khi đến được chatgpt.com (có session) hoặc gặp lỗi không phục hồi.

    on_checkpoint: callback(stage:str) gọi khi vượt mốc quan trọng (đã lấy được
        OTP) để watchdog bên ngoài gia hạn deadline tương ứng.

    Returns: (callback_url, otp_seconds).
    """
    flow_started_at = time.monotonic()
    deadline = flow_started_at + overall_timeout
    hard_deadline = deadline + max(0.0, float(post_otp_grace))
    otp_checkpoint_used = False
    otp_seconds_total = 0.0
    otp_already_polled = False  # tránh poll OTP nhiều lần trong cùng batch
    register_attempted = False
    login_attempted = False
    continue_clicked = False
    otp_submitted = False
    _otp_submit_ts: float | None = None
    _otp_reclick_done = False
    _otp_js_submit_done = False
    _otp_api_done = False
    last_submitted_otp: str | None = None
    tried_codes: set[str] = set()  # codes đã submit + bị reject
    pending_codes: list[str] = []  # codes chưa submit (mail delay catch)
    otp_submit_count = 0
    last_screen = None
    same_screen_count = 0

    def _reserve_otp_submit(reason: str) -> None:
        nonlocal otp_submit_count
        if otp_submit_count >= _MAX_OTP_SUBMITS_PER_FLOW:
            raise BrowserPhaseError(
                "OTP submit limit reached: đã dùng "
                f"{otp_submit_count}/{_MAX_OTP_SUBMITS_PER_FLOW} lượt; "
                "dừng flow để tránh max_check_attempts"
            )
        otp_submit_count += 1
        log(
            f"[flow] OTP submit {otp_submit_count}/"
            f"{_MAX_OTP_SUBMITS_PER_FLOW} ({reason})"
        )

    while time.monotonic() < min(deadline, hard_deadline):
        screen = await _detect_screen(page)

        if screen != last_screen:
            log(f"[flow] screen={screen} url={page.url.split('?')[0]}")
            last_screen = screen
            same_screen_count = 0
        else:
            same_screen_count += 1

        if screen == "chatgpt":
            await _wait_chatgpt_session(ctx, page, timeout_seconds=30.0, log=log)
            return callback_holder.get("url") or page.url, otp_seconds_total

        if screen == "auth_error":
            raise BrowserPhaseError(f"auth error page: {page.url}")

        if screen == "turnstile_challenge":
            if same_screen_count == 0:
                log("[flow] Turnstile/Cloudflare challenge detected — waiting for auto-solve")
            if same_screen_count > 60:
                raise BrowserPhaseError(
                    f"Turnstile challenge stuck >60 iterations. URL: {page.url}"
                )
            await asyncio.sleep(1.0)
            continue

        if screen == "mfa_challenge":
            # Account đã enable 2FA từ trước (combo đã từng dùng signup + 2FA).
            # Signup flow KHÔNG có TOTP secret để pass — fail-fast với message
            # rõ ràng để user biết dùng "Get Session" flow (cung cấp secret) thay vì retry signup.
            raise BrowserPhaseError(
                f"account đã có 2FA enabled — signup flow không có TOTP secret. "
                f"Dùng Get Session flow với combo email|password|secret. URL: {page.url}"
            )

        if screen == "continue":
            if continue_clicked:
                # Đã click rồi mà page chưa chuyển → đợi thêm rồi retry detect
                await asyncio.sleep(1.0)
                continue
            _pwd_sel = (
                'button:has-text("password"), a:has-text("password"), '
                '[role="button"]:has-text("password")'
            )
            try:
                pwd_btn = page.locator(_pwd_sel).first
                btn_text = await pwd_btn.text_content(timeout=1000)
                await pwd_btn.click(timeout=3000)
                log(f"[flow] clicked password button: {(btn_text or '').strip()[:60]}")
                continue_clicked = True
            except Exception as exc:
                log(f"[flow] click password button failed: {exc}")
            await asyncio.sleep(1.5)
            continue

        if screen == "password_create":
            if register_attempted:
                await asyncio.sleep(1.0)
                continue
            log(f"[flow] submit password form (email={request.email})")
            result = await _submit_password_registration_form(
                page,
                password=request.password,
                log=log,
            )
            register_attempted = True
            if not isinstance(result, dict):
                raise BrowserPhaseError(f"register unexpected result: {result}")
            status = result.get("status")
            body = result.get("body") or {}
            if status == 200:
                continue_url = body.get("continue_url") if isinstance(body, dict) else None
                log(f"[flow] register OK → continue_url={continue_url}")
                if continue_url:
                    await _follow_register_continue_url(page, continue_url, log=log)
                await asyncio.sleep(1.0)
                continue
            error_kind, body_str = _classify_register_error(status, body)
            if error_kind == "invalid_state":
                raise BrowserPhaseError(
                    "user/register HTTP 409 invalid_state — auth session không còn hợp lệ; "
                    f"cần browser context mới: {body_str[:200]}"
                )
            if error_kind == "already_exists":
                continue_url = body.get("continue_url") if isinstance(body, dict) else None
                if continue_url:
                    if continue_url.startswith("/"):
                        continue_url = f"https://auth.openai.com{continue_url}"
                    log(
                        "[flow] account already exists — "
                        f"navigate continue_url={continue_url.split('?')[0]}"
                    )
                    await page.goto(continue_url, wait_until="domcontentloaded")
                    await asyncio.sleep(1.0)
                    continue
                raise BrowserPhaseError(
                    "user/register: account already exists nhưng server không trả "
                    "continue_url; dùng login/Get Session flow"
                )
            raise BrowserPhaseError(f"register failed HTTP {status}: {body_str[:200]}")

        if screen == "password_login":
            if login_attempted:
                try:
                    err_el = page.locator('[role="alert"], [class*="error"]').first
                    err_text = await err_el.text_content(timeout=300)
                except Exception:
                    err_text = None
                if err_text and any(
                    marker in err_text.casefold()
                    for marker in ("incorrect", "wrong", "invalid")
                ):
                    message = " ".join(err_text.split())
                    log(f"[flow] login password rejected: {message[:200]}")
                    raise BrowserPhaseError(f"login password rejected: {message[:200]}")
                await asyncio.sleep(1.0)
                continue
            log("[flow] login with password")
            pwd_input = None
            for sel in ('input[type="password"]', 'input[name="password"]'):
                try:
                    loc = page.locator(sel).first
                    if await loc.is_visible(timeout=2000):
                        pwd_input = loc
                        break
                except Exception:
                    continue
            if not pwd_input:
                raise BrowserPhaseError(f"login page but no password input. URL: {page.url}")
            await pwd_input.click(force=True, timeout=3000)
            await pwd_input.fill("", timeout=3000)
            await pwd_input.type(request.password, delay=50)
            await asyncio.sleep(0.3)
            for btn in ('button[type="submit"]', 'button:has-text("Continue")'):
                try:
                    await page.click(btn, timeout=3000)
                    break
                except Exception:
                    continue
            log("[flow] submitted login password")
            login_attempted = True
            await asyncio.sleep(1.5)
            continue

        if screen == "otp":
            # Detect "incorrect code" error → thử code kế (nếu có) hoặc resend + poll
            # Gate bằng `otp_submitted`: chỉ check error sau khi đã submit ít nhất 1 OTP.
            # Lý do: trang /email-verification fresh load có thể có element
            # `[role="alert"]` hoặc class chứa "error" với text khớp keyword
            # ("expired", "invalid"...) cho mục đích banner thông tin/validation hint
            # → false positive trigger Resend → gửi mail OTP thứ 2 dù chưa submit code nào.
            if otp_submitted:
                try:
                    err_el = page.locator('[role="alert"], [class*="error"]').first
                    err_text = await err_el.text_content(timeout=200)
                    if err_text and any(
                        marker in err_text.casefold()
                        for marker in (
                            "max_check_attempts",
                            "too many tries",
                            "too many attempts",
                        )
                    ):
                        raise OtpValidationRateLimitError(
                            "OTP max_check_attempts hiển thị trên trang; "
                            "dừng ngay, không poll hoặc submit thêm mã"
                        )
                    if err_text and any(k in err_text.lower() for k in ("incorrect", "wrong", "invalid", "expired")):
                        # Clear input trước
                        try:
                            otp_inp = page.locator('input[name="code"]').first
                            await otp_inp.fill("", timeout=500)
                        except Exception:
                            pass
                        # Nếu còn pending code (mail delay) → thử ngay, không resend
                        if pending_codes:
                            next_code = pending_codes.pop(0)
                            log(f"[flow] OTP rejected: {err_text.strip()[:60]} — thử code kế: {next_code}")
                            otp_selector = await _wait_otp_form(page, timeout_seconds=5.0, log=log)
                            _reserve_otp_submit("pending code")
                            await _submit_otp(ctx, page, otp_code=next_code, otp_selector=otp_selector, log=log)
                            last_submitted_otp = next_code
                            tried_codes.add(next_code)
                            otp_submitted = True
                            _otp_submit_ts = time.monotonic()
                            _otp_reclick_done = False
                            _otp_js_submit_done = False
                            _otp_api_done = False
                            same_screen_count = 0
                            await asyncio.sleep(2.0)
                            continue
                        # Không còn pending → resend
                        log(f"[flow] OTP rejected: {err_text.strip()[:80]} — resend email & poll lại")
                        try:
                            resend_btn = page.locator('button:has-text("Resend"), a:has-text("Resend")').first
                            await resend_btn.click(timeout=3000)
                            log("[flow] clicked 'Resend email'")
                        except Exception as exc:
                            log(f"[flow] resend button not found: {exc}")
                        # Reset state để poll code mới
                        otp_submitted = False
                        _otp_submit_ts = None
                        last_submitted_otp = None
                        same_screen_count = 0
                        await asyncio.sleep(2.0)
                except OtpValidationRateLimitError:
                    raise
                except Exception:
                    pass

            if otp_submitted:
                # Đã submit rồi, đợi page chuyển.
                # Dùng wall-clock time (không phải counter) vì mỗi iteration ~1-2s.
                if _otp_submit_ts is None:
                    _otp_submit_ts = time.monotonic()
                _otp_wait_elapsed = time.monotonic() - _otp_submit_ts

                if _otp_wait_elapsed > 10.0 and not _otp_reclick_done:
                    if await _restore_cached_otp_input(page, last_submitted_otp):
                        log(f"[flow] OTP screen vẫn ở đây sau {_otp_wait_elapsed:.0f}s — thử click submit lại (url={page.url})")
                        _reserve_otp_submit("UI re-click")
                        for btn in ('button[type="submit"]', 'button:has-text("Continue")', 'button:has-text("Verify")'):
                            try:
                                await page.click(btn, timeout=2000)
                                break
                            except Exception:
                                continue
                    _otp_reclick_done = True
                elif _otp_wait_elapsed > 18.0 and not _otp_js_submit_done:
                    log("[flow] OTP UI click không work — thử form.submit() qua JS")
                    _reserve_otp_submit("JS form.submit")
                    try:
                        await page.evaluate("""() => {
                            const form = document.querySelector('form');
                            if (form) form.submit();
                        }""")
                    except Exception as exc:
                        log(f"[flow] JS form.submit() failed: {type(exc).__name__}: {exc}")
                    _otp_js_submit_done = True
                elif _otp_wait_elapsed > 25.0 and not _otp_api_done:
                    log("[flow] OTP UI+JS submit không work — thử validate qua API")
                    _reserve_otp_submit("API fallback")
                    await _try_cached_otp_api_fallback(
                        ctx,
                        page,
                        otp_code=last_submitted_otp,
                        log=log,
                        prefix="[flow]",
                    )
                    _otp_api_done = True
                elif _otp_wait_elapsed > 35.0:
                    log("[flow] OTP stuck >35s — re-poll code mới")
                    otp_submitted = False
                    _otp_submit_ts = None
                    _otp_reclick_done = False
                    _otp_js_submit_done = False
                    _otp_api_done = False
                    last_submitted_otp = None
                    try:
                        otp_inp = page.locator('input[name="code"]').first
                        await otp_inp.fill("", timeout=500)
                    except Exception:
                        pass
                await asyncio.sleep(0.5)
                continue
            # Đợi OTP input fully ready
            try:
                otp_selector = await _wait_otp_form(page, timeout_seconds=10.0, log=log)
            except BrowserPhaseError:
                await asyncio.sleep(0.5)
                continue
            # Fallback chỉ sau khi OTP input thật sự visible. `_detect_screen`
            # có URL-only fallback nên mark sớm hơn có thể khóa retry oan.
            if on_otp_started is not None:
                on_otp_started()
            await asyncio.sleep(1.0)
            # Reset timestamp khi sắp poll — bỏ qua code cũ trước thời điểm này
            poll_started = datetime.now(timezone.utc).replace(microsecond=0)
            t_otp = time.monotonic()
            recipient = request.source_email or request.email
            log(f"[flow] polling OTP (recipient={recipient}) since {poll_started.isoformat()}")
            
            # Poll OTP, skip codes đã thử.
            # Nếu đợi >resend_after_seconds chưa có code mới → click Resend rồi poll tiếp.
            # iCloud có thể gửi mail mới trước, mail cũ delay → lấy nhiều codes
            # rồi thử lần lượt trước khi resend.
            resend_after_seconds = float(request.otp_resend_after_seconds)
            resend_count = 0
            # Resend tối đa 1 lần: HME delay cao, resend nhiều chỉ vô hiệu mã đang
            # bay + spam → OpenAI rate-limit. Chỉ resend khi mail HOÀN TOÀN chưa về
            # sau resend_after_seconds, KHÔNG resend chỉ vì code cũ lặp lại.
            max_resends = 1
            stale_poll_count = 0  # đếm lần poll chỉ nhận code cũ (chỉ để log)
            while True:
                # Nếu có codes pending chưa submit → thử từng cái
                if pending_codes:
                    otp_code = pending_codes.pop(0)
                    break
                remaining = request.otp_timeout_seconds - (time.monotonic() - t_otp)
                if remaining <= 0:
                    raise BrowserPhaseError(f"OTP timeout {request.otp_timeout_seconds}s, chỉ nhận được codes cũ")
                # Poll với mini-timeout = min(resend_after_seconds, remaining)
                mini_timeout = min(resend_after_seconds, remaining)
                try:
                    otp_code = await mail_provider.poll_otp(
                        recipient=recipient,
                        started_at=poll_started,
                        timeout_seconds=mini_timeout,
                        poll_interval_seconds=request.otp_poll_interval_seconds,
                        log=log,
                    )
                except OutlookComboError:
                    raise
                except Exception:
                    otp_code = None
                if otp_code and otp_code not in tried_codes:
                    # Nhận code mới → fetch lại tất cả codes để catch mail delay
                    await asyncio.sleep(3.0)
                    all_codes: list[str] = []
                    if hasattr(mail_provider, 'poll_all_codes'):
                        all_codes = await mail_provider.poll_all_codes(
                            recipient=recipient,
                            started_at=poll_started,
                            log=log,
                        )
                    # Lọc codes chưa thử, giữ thứ tự
                    new_codes = [c for c in all_codes if c not in tried_codes]
                    if not new_codes:
                        new_codes = [otp_code]
                    elif otp_code not in new_codes:
                        new_codes.insert(0, otp_code)
                    if len(new_codes) > 1:
                        log(f"[flow] got {len(new_codes)} OTP codes: {', '.join(new_codes)}")
                    pending_codes = new_codes
                    continue  # loop lại → pop từ pending_codes
                if otp_code and otp_code in tried_codes:
                    # Code cũ nằm lại mailbox là bình thường khi mail mới còn delay —
                    # KHÔNG resend (resend chỉ vô hiệu mã mới đang bay). Cứ poll tiếp
                    # cho tới khi code mới về hoặc hết otp_timeout.
                    stale_poll_count += 1
                    log(f"[flow] OTP={otp_code} đã thử rồi, chờ code mới... (lần {stale_poll_count})")
                    await asyncio.sleep(request.otp_poll_interval_seconds)
                    continue
                # otp_code is None → hết resend_after_seconds mà KHÔNG có mail nào về
                if resend_count < max_resends:
                    resend_count += 1
                    log(f"[flow] OTP chưa nhận sau {mini_timeout:.0f}s — click Resend ({resend_count}/{max_resends})")
                    try:
                        resend_btn = page.locator('button:has-text("Resend"), a:has-text("Resend")').first
                        await resend_btn.click(timeout=3000)
                        log("[flow] clicked 'Resend email'")
                    except Exception as exc:
                        log(f"[flow] resend button not found: {exc}")
                    # Reset poll_started để chỉ nhận code mới sau resend
                    await asyncio.sleep(2.0)
                    poll_started = datetime.now(timezone.utc).replace(microsecond=0)
                else:
                    # Đã resend hết hạn mức — không resend thêm, tiếp tục poll tới
                    # khi code về hoặc hết otp_timeout (tránh spam resend).
                    log(f"[flow] OTP chưa về sau {mini_timeout:.0f}s — đã resend {resend_count} lần, tiếp tục chờ...")
            
            otp_seconds_total += time.monotonic() - t_otp
            log(f"[flow] OTP={otp_code} got in {time.monotonic() - t_otp:.1f}s")
            now = time.monotonic()
            if now >= hard_deadline:
                raise BrowserPhaseError(
                    "flow hard timeout reached sau "
                    f"{hard_deadline - flow_started_at:.0f}s"
                )
            # OTP đầu tiên là checkpoint duy nhất. Mọi mã mới sau đó không được
            # dịch deadline; hard_deadline là trần tuyệt đối của flow.
            if not otp_checkpoint_used:
                otp_checkpoint_used = True
                grace_deadline = min(
                    now + max(0.0, float(post_otp_grace)),
                    hard_deadline,
                )
                if grace_deadline > deadline:
                    deadline = grace_deadline
                    log(
                        "[flow] OTP secured — gia hạn flow một lần tới "
                        f"{deadline - flow_started_at:.0f}s"
                    )
                if on_checkpoint is not None:
                    try:
                        on_checkpoint("otp")
                    except Exception:
                        pass
            tried_codes.add(otp_code)
            _reserve_otp_submit("new code")
            await _submit_otp(ctx, page, otp_code=otp_code, otp_selector=otp_selector, log=log)
            last_submitted_otp = otp_code
            otp_submitted = True
            _otp_submit_ts = time.monotonic()
            _otp_reclick_done = False
            _otp_js_submit_done = False
            _otp_api_done = False
            otp_already_polled = True
            await asyncio.sleep(2.0)
            continue

        if screen == "passkey_enroll":
            log("[flow] passkey enrollment page — skipping")
            if await _skip_passkey(page, log=log):
                await asyncio.sleep(2.0)
            else:
                log("[flow] no skip button found on passkey page — waiting for page change")
                await asyncio.sleep(1.5)
            continue

        if screen == "about_you":
            try:
                await _wait_oai_sc(ctx, timeout_seconds=15, log=log)
            except BrowserPhaseError:
                pass  # cookie có thể chưa cần thiết, thử fill xem có pass không
            callback_url = await _fill_about_you(
                page, name=request.name, birthdate=request.birthdate,
                timeout_seconds=60.0, log=log,
            )
            # Sau /about-you có thể vẫn còn step (rare), tiếp tục loop để chờ chatgpt.com
            await _wait_chatgpt_session(ctx, page, timeout_seconds=60.0, log=log)
            return callback_url, otp_seconds_total

        # screen == 'unknown' → đợi page settle
        await asyncio.sleep(0.7)

    elapsed = time.monotonic() - flow_started_at
    raise BrowserPhaseError(
        f"flow timeout after {elapsed:.0f}s "
        f"(hard wall {hard_deadline - flow_started_at:.0f}s). "
        f"last URL: {page.url}, last screen: {last_screen}"
    )


async def _handle_login_after_password(
    *, ctx, page, request, mail_provider, callback_holder, log,
) -> tuple[str, float]:
    """Sau khi submit login password, xử lý cả 2 case:
    - Login thẳng → chatgpt.com
    - Cần OTP → poll OTP → submit → /about-you HOẶC chatgpt.com
    Returns: (callback_url, otp_seconds).
    """
    otp_seconds = 0.0
    login_branch = await _wait_after_login(page, timeout_seconds=20.0, log=log)
    if login_branch == "chatgpt":
        await _wait_chatgpt_session(ctx, page, timeout_seconds=30.0, log=log)
        return callback_holder.get("url") or page.url, otp_seconds

    # Cần OTP cho login (hoặc account chưa hoàn thành onboarding)
    otp_selector = await _wait_otp_form(page, timeout_seconds=15.0, log=log)
    await asyncio.sleep(2.0)
    otp_started_at = datetime.now(timezone.utc).replace(microsecond=0)

    t_otp = time.monotonic()
    recipient = request.source_email or request.email
    log(f"[browser] polling OTP for login (recipient={recipient})")
    otp_code = await mail_provider.poll_otp(
        recipient=recipient,
        started_at=otp_started_at,
        timeout_seconds=request.otp_timeout_seconds,
        poll_interval_seconds=request.otp_poll_interval_seconds,
        log=log,
    )
    otp_seconds = time.monotonic() - t_otp
    log(f"[browser] login OTP={otp_code} in {otp_seconds:.1f}s")
    await _submit_otp(ctx, page, otp_code=otp_code, otp_selector=otp_selector, log=log)

    # Sau OTP có 2 case:
    # 1. /about-you (account chưa onboard) → fill name+age → callback
    # 2. chatgpt.com (login bình thường) → wait session-token
    otp_branch = await _wait_after_otp(
        page,
        ctx=ctx,
        otp_code=otp_code,
        timeout_seconds=60.0,
        log=log,
    )
    if otp_branch == "signup":
        await _wait_oai_sc(ctx, timeout_seconds=15, log=log)
        callback_url = await _fill_about_you(
            page,
            name=request.name,
            birthdate=request.birthdate,
            timeout_seconds=30.0,
            log=log,
        )
    else:
        callback_url = callback_holder.get("url") or page.url

    await _wait_chatgpt_session(ctx, page, timeout_seconds=60.0, log=log)
    return callback_url, otp_seconds


async def _wait_after_otp(
    page,
    *,
    ctx,
    otp_code: str,
    timeout_seconds: float,
    log,
) -> str:
    """Sau submit OTP, đợi navigation: /about-you (signup) hoặc chatgpt.com (login).

    Returns: "signup" hoặc "login".
    Escalation: 10s re-click → 18s JS submit → 25s API fallback → timeout.
    """
    deadline = time.monotonic() + timeout_seconds
    start_ts = time.monotonic()
    _reclick_done = False
    _js_done = False
    _api_done = False
    while time.monotonic() < deadline:
        cur = page.url
        if "auth.openai.com/about-you" in cur:
            log("[browser] reached /about-you (signup)")
            return "signup"
        if "chatgpt.com" in cur and "auth.openai.com" not in cur and "/auth/error" not in cur:
            log("[browser] redirected to chatgpt.com (login — account exists)")
            return "login"
        if "auth/error" in cur:
            raise BrowserPhaseError(f"error page: {cur}")
        # SPA case: URL vẫn /email-verification nhưng form /about-you đã render
        try:
            name_el = page.locator('input[name="name"], input[autocomplete="name"]').first
            if await name_el.is_visible(timeout=300):
                log("[browser] detected /about-you form (SPA, URL unchanged)")
                return "signup"
        except Exception:
            pass
        # Check OTP error message (wrong code)
        try:
            err_el = page.locator('[role="alert"], [class*="error"]').first
            err_text = await err_el.text_content(timeout=300)
            if err_text and ("wrong" in err_text.lower() or "invalid" in err_text.lower() or "incorrect" in err_text.lower()):
                raise BrowserPhaseError(f"OTP wrong code: {err_text.strip()}")
        except BrowserPhaseError:
            raise
        except Exception:
            pass
        # Escalation: re-click → JS submit → API fallback
        elapsed = time.monotonic() - start_ts
        if elapsed > 10.0 and not _reclick_done:
            try:
                if await _restore_cached_otp_input(page, otp_code):
                    log(f"[browser] OTP form still visible after {elapsed:.0f}s — retrying submit (url={cur})")
                    for btn in ('button[type="submit"]', 'button:has-text("Continue")'):
                        try:
                            await page.click(btn, timeout=2000)
                            log(f"[browser] re-clicked {btn}")
                            break
                        except Exception:
                            continue
            except Exception:
                pass
            _reclick_done = True
        elif elapsed > 18.0 and not _js_done:
            log("[browser] OTP UI click không work — thử form.submit() qua JS")
            try:
                await page.evaluate("() => { const f = document.querySelector('form'); if (f) f.submit(); }")
            except Exception as exc:
                log(f"[browser] JS form.submit() failed: {type(exc).__name__}: {exc}")
            _js_done = True
        elif elapsed > 25.0 and not _api_done:
            log("[browser] OTP UI+JS không work — thử validate qua API")
            await _try_cached_otp_api_fallback(
                ctx,
                page,
                otp_code=otp_code,
                log=log,
                prefix="[browser]",
            )
            _api_done = True
        await asyncio.sleep(0.5)
    raise BrowserPhaseError(f"timeout {timeout_seconds}s after OTP submit. URL: {page.url}")


async def _check_about_you_extras(page, *, log) -> None:
    """Check + handle các element bổ sung trên /about-you (checkbox TOS, select, etc.)."""
    # Checkbox — check tất cả unchecked checkboxes (TOS, marketing opt-in, etc.)
    try:
        checkboxes = page.locator('input[type="checkbox"]')
        count = await checkboxes.count()
        for i in range(count):
            cb = checkboxes.nth(i)
            if await cb.is_visible(timeout=300) and not await cb.is_checked():
                await cb.check(timeout=2000)
                label = ""
                try:
                    parent = cb.locator("xpath=ancestor::label")
                    label = (await parent.text_content(timeout=500) or "").strip()[:60]
                except Exception:
                    pass
                log(f"[browser] /about-you checked checkbox: {label or f'#{i}'}")
    except Exception:
        pass

    # Select dropdowns — nếu có select chưa chọn, chọn option đầu tiên có value
    try:
        selects = page.locator("select")
        count = await selects.count()
        for i in range(count):
            sel = selects.nth(i)
            if await sel.is_visible(timeout=300):
                val = await sel.input_value(timeout=500)
                if not val:
                    # Chọn option đầu tiên có value thực
                    first_option = await sel.evaluate("""
                        (el) => {
                            const opts = [...el.options].filter(o => o.value && o.value !== '');
                            return opts.length > 0 ? opts[0].value : null;
                        }
                    """)
                    if first_option:
                        await sel.select_option(first_option, timeout=2000)
                        log(f"[browser] /about-you selected option: {first_option}")
    except Exception:
        pass


async def _click_submit_about_you(page, *, log) -> None:
    """Click submit button trên /about-you form."""
    for btn in (
        'button[type="submit"]',
        'button:has-text("Continue")',
        'button:has-text("Agree")',
        'button:has-text("Next")',
        'button:has-text("Submit")',
    ):
        try:
            btn_el = page.locator(btn).first
            if await btn_el.is_visible(timeout=800) and await btn_el.is_enabled(timeout=500):
                await btn_el.click(timeout=3000)
                log(f"[browser] clicked {btn}")
                return
        except Exception:
            continue
    # Fallback: click bất kỳ button nào visible + enabled (trừ modal dismiss)
    try:
        all_btns = page.locator("button")
        count = await all_btns.count()
        for i in range(count):
            b = all_btns.nth(i)
            if await b.is_visible(timeout=300) and await b.is_enabled(timeout=300):
                text = ((await b.text_content(timeout=500)) or "").strip().lower()
                if text and not any(k in text for k in ("cancel", "back", "sign out", "log out")):
                    await b.click(timeout=3000)
                    log(f"[browser] fallback clicked button: {text[:40]}")
                    return
    except Exception:
        pass


async def _detect_about_you_form_error(page) -> str | None:
    """Detect validation error message trên /about-you form. Return message hoặc None."""
    try:
        for sel in (
            '[role="alert"]',
            '[class*="error"]',
            '[class*="Error"]',
            '[aria-invalid="true"]',
            '.field-error',
            '[data-testid*="error"]',
        ):
            el = page.locator(sel).first
            if await el.is_visible(timeout=200):
                text = (await el.text_content(timeout=500) or "").strip()
                if text:
                    return text[:200]
    except Exception:
        pass
    return None


async def _log_about_you_dom(page, *, log) -> None:
    """Log DOM snapshot nhẹ của /about-you form khi hết retry — giúp debug."""
    try:
        snapshot = await page.evaluate("""
            () => {
                const form = document.querySelector('form');
                if (!form) return {form: null, buttons: [], inputs: [], spinbuttons: []};
                const visible = (el) => {
                    const style = window.getComputedStyle(el);
                    return style.display !== 'none'
                        && style.visibility !== 'hidden'
                        && el.getClientRects().length > 0;
                };
                const inputs = [...form.querySelectorAll('input, select, textarea')].map(el => ({
                    tag: el.tagName, type: el.type || '', name: el.name || '',
                    value: el.value ? el.value.substring(0, 30) : '',
                    visible: visible(el), required: Boolean(el.required),
                    valid: el.validity ? el.validity.valid : true,
                    validationMsg: el.validationMessage || '',
                }));
                const spinbuttons = [...form.querySelectorAll('[role="spinbutton"]')].map(el => ({
                    dataType: el.getAttribute('data-type') || '',
                    dataSegment: el.getAttribute('data-segment') || '',
                    label: el.getAttribute('aria-label') || '',
                    now: el.getAttribute('aria-valuenow'),
                    min: el.getAttribute('aria-valuemin'),
                    max: el.getAttribute('aria-valuemax'),
                    text: (el.textContent || '').trim().substring(0, 30),
                    visible: visible(el), active: document.activeElement === el,
                }));
                const buttons = [...form.querySelectorAll('button')].map(el => ({
                    text: (el.textContent || '').trim().substring(0, 40),
                    type: el.type || '', disabled: el.disabled,
                }));
                return {inputs, spinbuttons, buttons};
            }
        """)
        log(f"[browser] /about-you DOM snapshot: {json.dumps(snapshot, ensure_ascii=False)[:1200]}")
    except Exception as exc:
        log(f"[browser] /about-you DOM snapshot failed: {exc}")


async def _fill_segmented_birthdate(
    page,
    *,
    birthdate: str,
    age: int,
    log,
) -> bool:
    """Điền DateField dạng các segment ``month/day/year``.

    UI mới render các ``div[role=spinbutton]`` và giữ giá trị submit trong
    ``input[name=birthday]``/``input[name=age]`` ẩn. Không được gõ tuổi vào
    segment đầu tiên: component sẽ hiểu ``25`` thành ngày/tháng và tự nhảy tới
    segment năm.
    """
    segments = page.locator('form [role="spinbutton"]')
    metadata = await segments.evaluate_all(r"""
        (nodes) => {
            const form = document.querySelector('form');
            const visible = (el) => {
                const style = window.getComputedStyle(el);
                return style.display !== 'none'
                    && style.visibility !== 'hidden'
                    && el.getClientRects().length > 0;
            };
            const localeOrder = new Intl.DateTimeFormat(undefined, {
                year: 'numeric', month: 'numeric', day: 'numeric',
            }).formatToParts(new Date(2001, 10, 22))
                .map(part => part.type)
                .filter(type => ['month', 'day', 'year'].includes(type));
            return {
                hasBirthdayInput: Boolean(form?.querySelector('input[name="birthday"]')),
                localeOrder,
                segments: nodes.map((el, index) => {
                    const labelledBy = (el.getAttribute('aria-labelledby') || '')
                        .split(/\s+/)
                        .filter(Boolean)
                        .map(id => document.getElementById(id)?.textContent || '')
                        .join(' ');
                    return {
                        index,
                        visible: visible(el),
                        dataType: el.getAttribute('data-type') || '',
                        dataSegment: el.getAttribute('data-segment') || '',
                        label: el.getAttribute('aria-label') || '',
                        labelledBy,
                        placeholder: el.getAttribute('data-placeholder')
                            || el.getAttribute('placeholder') || '',
                        min: el.getAttribute('aria-valuemin'),
                        max: el.getAttribute('aria-valuemax'),
                    };
                }).filter(item => item.visible),
            };
        }
    """)
    items = metadata.get("segments") or []
    # Một số variant dùng đúng 1 spinbutton cho Age. Đây không phải DateField;
    # để caller xử lý qua semantic age selector thay vì báo thiếu 3 segment.
    if not metadata.get("hasBirthdayInput") or len(items) < 3:
        return False

    positions: dict[str, int] = {}
    used_indexes: set[int] = set()
    for item in items:
        hint = " ".join(
            str(item.get(key) or "")
            for key in ("dataType", "dataSegment", "label", "labelledBy", "placeholder")
        ).casefold()
        kind = None
        if "month" in hint or " mm" in f" {hint}":
            kind = "month"
        elif "day" in hint or " dd" in f" {hint}":
            kind = "day"
        elif "year" in hint or "yyyy" in hint:
            kind = "year"
        else:
            try:
                maximum = int(item["max"]) if item.get("max") is not None else None
            except (TypeError, ValueError):
                maximum = None
            if maximum == 12:
                kind = "month"
            elif maximum is not None and 28 <= maximum <= 31:
                kind = "day"
            elif maximum is not None and maximum >= 1000:
                kind = "year"
        if kind and kind not in positions:
            index = int(item["index"])
            positions[kind] = index
            used_indexes.add(index)

    # React Aria sắp segment theo locale. Nếu build hiện tại không expose
    # data-type/aria-label, suy ra theo đúng thứ tự locale thay vì hardcode M/D/Y.
    locale_order = metadata.get("localeOrder") or []
    if len(items) == 3 and set(locale_order) == {"month", "day", "year"}:
        for item, kind in zip(items, locale_order):
            index = int(item["index"])
            if kind not in positions and index not in used_indexes:
                positions[kind] = index
                used_indexes.add(index)

    if set(positions) != {"month", "day", "year"}:
        raise BrowserPhaseError(
            "không nhận diện đủ birthday segments month/day/year: "
            f"positions={positions}, segments={items}"
        )

    year, month, day = birthdate.split("-")
    values = {
        "month": f"{int(month):02d}",
        "day": f"{int(day):02d}",
        "year": year,
    }
    # Điền năm trước để loại placeholder=current-year, sau đó mới month/day.
    # Click lại từng segment nên không phụ thuộc auto-advance của component.
    for kind in ("year", "month", "day"):
        target = segments.nth(positions[kind])
        await target.click(force=True, timeout=2000)
        await target.press("Control+A", timeout=1000)
        await target.type(values[kind], delay=80, timeout=3000)
        await asyncio.sleep(0.1)

    # Blur để React commit hidden birthday/age trước khi validate và submit.
    await page.keyboard.press("Tab")
    state = {}
    commit_deadline = time.monotonic() + 2.0
    while True:
        state = await page.evaluate("""
            () => {
                const form = document.querySelector('form');
                const birthday = form?.querySelector('input[name="birthday"]');
                const age = form?.querySelector('input[name="age"]');
                return {
                    birthday: birthday?.value ?? null,
                    birthdayValid: birthday?.validity?.valid ?? true,
                    age: age?.value ?? null,
                    ageValid: age?.validity?.valid ?? true,
                };
            }
        """)
        birthday_ready = (
            state.get("birthday") == birthdate and state.get("birthdayValid")
        )
        age_ready = state.get("age") is None or (
            state.get("age") == str(age) and state.get("ageValid")
        )
        if birthday_ready and age_ready:
            break
        if time.monotonic() >= commit_deadline:
            break
        await asyncio.sleep(0.1)
    if state.get("birthday") != birthdate or not state.get("birthdayValid"):
        raise BrowserPhaseError(
            "birthday segments không commit đúng giá trị: "
            f"expected={birthdate!r}, actual={state.get('birthday')!r}"
        )
    if state.get("age") is not None and (
        state.get("age") != str(age) or not state.get("ageValid")
    ):
        raise BrowserPhaseError(
            "birthday segments không đồng bộ age: "
            f"expected={age!r}, actual={state.get('age')!r}"
        )
    log(f"[browser] filled segmented birthday={birthdate} age={age}")
    return True


async def _fill_about_you(page, *, name: str, birthdate: str, timeout_seconds: float, log) -> str:
    """Điền form /about-you (name + age), submit, return callback URL.

    CALLBACK CAPTURE STRATEGY (thay đổi 2026-05):
      - Dùng RESPONSE listener thay vì REQUEST listener để xác nhận
        callback đã thật sự thành công (có Set-Cookie session-token).
      - Lý do: request listener fire NGAY khi request đi ra, chưa biết
        server có response 200/302 hay không, có set cookie hay chưa.
        Đây là root cause của bug "callback URL captured" rồi vẫn
        timeout waiting session-token (page kẹt /about-you).
      - Fail-fast: nếu response status >= 400 → raise (account creation failed).
    """
    log(f"[browser] /about-you: fill name={name!r}")

    # Capture callback URL via RESPONSE listener (xác nhận server đã commit cookie)
    callback_holder: dict[str, Any] = {}

    def _on_resp(response):
        url = response.url
        if "chatgpt.com/api/auth/callback/openai" not in url or "code=" not in url:
            return
        # Đã capture rồi — bỏ qua (chỉ giữ lần đầu)
        if "url" in callback_holder:
            return
        status = response.status
        callback_holder["status"] = status
        # Status 2xx/3xx → callback OK. NextAuth thường trả 302 redirect.
        if 200 <= status < 400:
            callback_holder["url"] = url
            # Probe Set-Cookie từ headers (best-effort, có thể không thấy
            # do Playwright không expose Set-Cookie trên cross-origin redirect).
            try:
                set_cookie = response.headers.get("set-cookie", "")
                has_session = "next-auth.session-token" in set_cookie
                callback_holder["has_session_in_setcookie"] = has_session
                log(
                    f"[browser] callback response OK: HTTP {status} "
                    f"set-cookie-has-session={has_session}"
                )
            except Exception:
                log(f"[browser] callback response OK: HTTP {status}")
        else:
            # 4xx/5xx — log để debug, không raise ngay (background event)
            callback_holder["error_status"] = status
            log(f"[browser] callback response FAILED: HTTP {status}")

    page.on("response", _on_resp)
    try:
        # Name input
        name_input = None
        for sel in ('input[name="name"]', 'input[autocomplete="name"]', 'input[id*="name" i]'):
            try:
                await page.wait_for_selector(sel, state="visible", timeout=5000)
                name_input = sel
                break
            except Exception:
                continue
        if not name_input:
            raise BrowserPhaseError("không tìm thấy name input trên /about-you")

        await page.click(name_input, force=True, timeout=3000)
        await page.fill(name_input, "", timeout=3000)
        await page.type(name_input, name, delay=80)
        actual_name = (await page.locator(name_input).first.input_value(timeout=1000)).strip()
        if actual_name != name:
            raise BrowserPhaseError(
                f"name input không giữ đúng giá trị: expected={name!r}, actual={actual_name!r}"
            )
        await asyncio.sleep(0.2)

        # Age (parse from birthdate)
        try:
            year, month, day = birthdate.split("-")
            today = datetime.utcnow()
            age = today.year - int(year) - ((today.month, today.day) < (int(month), int(day)))
        except ValueError as exc:
            raise BrowserPhaseError(f"birthdate format sai: {birthdate}") from exc

        # Try native date input first, then React-Aria segmented birthday, cuối
        # cùng mới fallback sang age/birthday input thường.
        date_input = None
        try:
            date_input = await page.wait_for_selector('input[type="date"]', state="visible", timeout=1500)
        except Exception:
            pass

        if date_input:
            await page.fill('input[type="date"]', birthdate, timeout=3000)
            actual_birthdate = await page.locator('input[type="date"]').first.input_value(timeout=1000)
            if actual_birthdate != birthdate:
                raise BrowserPhaseError(
                    "birthday input không giữ đúng giá trị: "
                    f"expected={birthdate!r}, actual={actual_birthdate!r}"
                )
            log(f"[browser] filled birthday={birthdate}")
        else:
            segmented_filled = await _fill_segmented_birthdate(
                page,
                birthdate=birthdate,
                age=age,
                log=log,
            )
            profile_input = None
            profile_value = str(age)
            profile_kind = "age"
            # UI /about-you có nhiều biến thể: age number, age text hoặc
            # birthday text (placeholder MM/DD/YYYY). Nhận diện theo semantic
            # attributes trước, không phụ thuộc riêng input[type].
            profile_selectors = (
                ('input[name="age"]', str(age), "age"),
                ('input[name*="age" i]', str(age), "age"),
                ('input[id*="age" i]', str(age), "age"),
                ('input[aria-label*="age" i]', str(age), "age"),
                ('input[placeholder*="age" i]', str(age), "age"),
                ('[role="spinbutton"][data-type="age"]', str(age), "age_spinbutton"),
                ('[role="spinbutton"][aria-label*="age" i]', str(age), "age_spinbutton"),
                ('input[name*="birth" i]', birthdate, "birthday"),
                ('input[id*="birth" i]', birthdate, "birthday"),
                ('input[autocomplete^="bday"]', birthdate, "birthday"),
                ('input[aria-label*="birth" i]', birthdate, "birthday"),
                ('input[placeholder*="birth" i]', birthdate, "birthday"),
                ('input[placeholder*="MM" i][placeholder*="YYYY" i]', birthdate, "birthday"),
                ('input[type="number"]', str(age), "age"),
                ('input[inputmode="numeric"]', str(age), "age"),
            )
            if not segmented_filled:
                for sel, value, kind in profile_selectors:
                    try:
                        target = page.locator(sel).first
                        if not await target.is_visible(timeout=300):
                            continue
                        profile_input = sel
                        profile_value = value
                        profile_kind = kind
                        break
                    except Exception:
                        continue
            if not segmented_filled and profile_input:
                target = page.locator(profile_input).first
                if profile_kind == "age_spinbutton":
                    await target.click(force=True, timeout=3000)
                    await target.press("Control+A", timeout=1000)
                    await target.type(str(age), delay=120, timeout=3000)
                    await page.keyboard.press("Tab")
                    actual_value = ""
                    age_deadline = time.monotonic() + 1.5
                    while time.monotonic() < age_deadline:
                        actual_value = await page.evaluate("""
                            () => String(
                                document.querySelector('form input[name="age"]')?.value ?? ''
                            ).trim()
                        """)
                        if actual_value == str(age):
                            break
                        await asyncio.sleep(0.1)
                    if actual_value != str(age):
                        raise BrowserPhaseError(
                            "age spinbutton không commit đúng giá trị: "
                            f"expected={age!r}, actual={actual_value!r}"
                        )
                    log(f"[browser] typed age spinbutton={age} actual={actual_value!r}")
                else:
                    if profile_kind == "birthday":
                        placeholder = (await target.get_attribute("placeholder") or "").casefold()
                        if "/" in placeholder:
                            profile_value = f"{month}/{day}/{year}"
                    await target.click(force=True, timeout=3000)
                    await target.fill("", timeout=3000)
                    await target.type(profile_value, delay=120)
                    actual_value = (await target.input_value(timeout=1000)).strip()
                    if not actual_value or (
                        profile_kind == "age" and actual_value != str(age)
                    ):
                        raise BrowserPhaseError(
                            f"{profile_kind} input không giữ đúng giá trị: "
                            f"expected={profile_value!r}, actual={actual_value!r}"
                        )
                    log(f"[browser] typed {profile_kind}={profile_value} actual={actual_value!r}")
            elif not segmented_filled:
                # Legacy/custom UI: field age là input text không có semantic
                # attribute. Khôi phục Tab fallback cũ, nhưng chỉ gõ khi phần tử
                # focus thực sự editable để tránh nhập nhầm vào button/link.
                await page.locator(name_input).first.focus(timeout=1000)
                await page.keyboard.press("Tab")
                await asyncio.sleep(0.3)
                active = await page.evaluate("""
                    () => {
                        const el = document.activeElement;
                        if (!el) return null;
                        const tag = (el.tagName || '').toLowerCase();
                        const editable = (tag === 'input' || tag === 'textarea')
                            && el.type !== 'hidden';
                        return {
                            editable,
                            tag,
                            type: el.type || '',
                            name: el.name || '',
                            id: el.id || '',
                            role: el.getAttribute('role') || '',
                            disabled: Boolean(el.disabled),
                            readOnly: Boolean(el.readOnly),
                        };
                    }
                """)
                if not active or not active.get("editable") or active.get("disabled") or active.get("readOnly"):
                    await _log_about_you_dom(page, log=log)
                    raise BrowserPhaseError(
                        f"không tìm thấy age/birthday input editable; active={active}"
                    )
                await page.keyboard.press("Control+A")
                await page.keyboard.type(str(age), delay=120)
                active_value = await page.evaluate("""
                    () => {
                        const el = document.activeElement;
                        return String(el?.value ?? el?.textContent ?? '').trim();
                    }
                """)
                if active_value != str(age):
                    raise BrowserPhaseError(
                        "age fallback không giữ đúng giá trị: "
                        f"expected={age!r}, actual={active_value!r}"
                    )
                log(f"[browser] Tab fallback typed age={age} actual={active_value!r}")

        await asyncio.sleep(0.3)

        # Handle unchecked checkboxes/TOS trước submit — OpenAI có thể thêm field mới
        await _check_about_you_extras(page, log=log)

        # Submit
        await _click_submit_about_you(page, log=log)

        # Đợi callback URL hoặc navigate đến chatgpt.com
        deadline = time.monotonic() + timeout_seconds
        next_retry_at = time.monotonic() + 8.0
        submit_attempts = 1
        max_submit_attempts = 5
        passkey_skip_attempted = False
        dom_logged = False
        while time.monotonic() < deadline:
            # Fail-fast nếu response callback trả error
            if "error_status" in callback_holder and "url" not in callback_holder:
                raise BrowserPhaseError(
                    f"callback /api/auth/callback/openai failed: "
                    f"HTTP {callback_holder['error_status']}"
                )
            if "url" in callback_holder:
                # Sleep ngắn để cookie jar commit (response → cookie store ghi)
                # trước khi return cho caller poll cookies.
                await asyncio.sleep(0.8)
                log(
                    f"[browser] callback URL captured "
                    f"(HTTP {callback_holder.get('status', '?')})"
                )
                return callback_holder["url"]
            cur = page.url
            if "auth/error" in cur:
                raise BrowserPhaseError(f"error page: {cur}")
            # Nếu page đã navigate ra khỏi /about-you → chatgpt.com
            if "chatgpt.com" in cur:
                log("[browser] navigated to chatgpt.com (no explicit callback)")
                return callback_holder.get("url") or cur
            # Detect consent/modal buttons mới
            for accept_btn in (
                'button:has-text("Okay")',
                'button:has-text("I agree")',
                'button:has-text("Accept")',
                'button:has-text("Got it")',
                'button:has-text("Let")',
            ):
                try:
                    btn_el = page.locator(accept_btn).first
                    if await btn_el.is_visible(timeout=200):
                        await btn_el.click(timeout=2000)
                        log(f"[browser] clicked modal button: {accept_btn}")
                        break
                except Exception:
                    continue
            # Passkey enrollment — skip
            if "passkey" in cur.lower():
                if not passkey_skip_attempted:
                    passkey_skip_attempted = True
                    if await _skip_passkey(page, log=log):
                        await asyncio.sleep(1.0)
                        continue
                    log("[browser] passkey skip failed — waiting for natural navigation")
                await asyncio.sleep(1.0)
                continue
            if passkey_skip_attempted and "passkey" not in cur.lower():
                passkey_skip_attempted = False
            # Retry submit nếu vẫn stuck /about-you — mỗi 8s, tối đa max_submit_attempts
            if "about-you" in cur and time.monotonic() > next_retry_at:
                if submit_attempts < max_submit_attempts:
                    submit_attempts += 1
                    # Detect form validation errors trước khi retry
                    form_err = await _detect_about_you_form_error(page)
                    if form_err:
                        log(f"[browser] /about-you form error: {form_err}")
                        # Fatal error_code (user_already_exists, …) → dừng luôn,
                        # KHÔNG retry. Server đã commit kết quả, retry vô ích.
                        err_lower = form_err.lower()
                        for fatal_code in _ABOUT_YOU_FATAL_ERROR_CODES:
                            if fatal_code in err_lower:
                                if fatal_code == "user_already_exists":
                                    raise AccountAlreadyExistsError(
                                        f"/about-you: user_already_exists — "
                                        f"account đã tồn tại, bỏ"
                                    )
                                raise BrowserPhaseError(
                                    f"/about-you fatal error_code: {fatal_code}"
                                )
                    # Re-check extras (checkbox/TOS xuất hiện sau render)
                    await _check_about_you_extras(page, log=log)
                    # Thử submit lại với chiến thuật escalating
                    if submit_attempts <= 3:
                        await _click_submit_about_you(page, log=log)
                    else:
                        # Escalate: Enter key + JS dispatch
                        log(f"[browser] /about-you submit attempt {submit_attempts} — trying Enter + JS")
                        try:
                            await page.keyboard.press("Enter")
                        except Exception:
                            pass
                        await asyncio.sleep(1.0)
                        if "about-you" in page.url:
                            try:
                                await page.evaluate("""
                                    () => {
                                        const form = document.querySelector('form');
                                        if (form) {
                                            form.requestSubmit
                                                ? form.requestSubmit()
                                                : form.submit();
                                        }
                                    }
                                """)
                                log("[browser] JS form.requestSubmit() dispatched")
                            except Exception as exc:
                                log(f"[browser] JS submit failed: {exc}")
                    next_retry_at = time.monotonic() + 8.0
                elif not dom_logged:
                    # Hết retry — log DOM snapshot 1 lần để debug
                    dom_logged = True
                    await _log_about_you_dom(page, log=log)
            await asyncio.sleep(0.5)

        # Fallback: page.url nếu đã navigate qua callback hoặc chatgpt.com
        if "chatgpt.com" in page.url:
            return callback_holder.get("url") or page.url
        if "callback" in page.url and "code=" in page.url:
            return page.url

        raise BrowserPhaseError(f"timeout {timeout_seconds}s waiting callback URL. URL: {page.url}")
    finally:
        try:
            page.remove_listener("response", _on_resp)
        except Exception:
            pass


async def _wait_chatgpt_session(ctx, page, *, timeout_seconds: float, log) -> None:
    """Đợi cookie session-token xuất hiện trên chatgpt.com.

    STRATEGY (thay đổi 2026-05):
      - Yêu cầu cứng: `__Secure-next-auth.session-token` (hoặc chunk .0).
        Đây là cookie DUY NHẤT mà Phase 2 (http_phase) cần.
      - BỎ điều kiện `_account` — cookie này chỉ được set khi browser
        navigate top-level tới chatgpt.com, KHÔNG phải lúc nào cũng tự xảy ra
        sau callback (callback OAuth chạy qua fetch background, page có thể
        vẫn ở auth.openai.com/about-you). Yêu cầu `_account` từng gây
        timeout 60s waiting session-token mặc dù callback đã OK.
      - FALLBACK: sau ~8s không thấy session-token → chủ động
        page.goto("https://chatgpt.com/") để force browser load top-level
        (server sẽ set _account + commit cookies). Chỉ goto 1 lần.
      - Sau khi có session-token → return ngay (Phase 2 self-contained).
    """
    deadline = time.monotonic() + timeout_seconds
    fallback_goto_at = time.monotonic() + 8.0
    fallback_done = False
    last_log_at = 0.0
    while time.monotonic() < deadline:
        cookies = await ctx.cookies("https://chatgpt.com/")
        names = {c["name"] for c in cookies}
        has_session = (
            "__Secure-next-auth.session-token" in names
            or "__Secure-next-auth.session-token.0" in names
        )
        if has_session:
            has_account = "_account" in names
            log(
                f"[browser] chatgpt session ready "
                f"({len(cookies)} cookies, _account={has_account})"
            )
            await asyncio.sleep(0.3)
            return

        # Fallback: force navigate top-level để server commit cookies
        if not fallback_done and time.monotonic() > fallback_goto_at:
            fallback_done = True
            log(
                f"[browser] session-token chưa có sau 8s "
                f"(URL={page.url.split('?')[0]}) — force goto chatgpt.com"
            )
            try:
                await page.goto(
                    "https://chatgpt.com/",
                    wait_until="domcontentloaded",
                    timeout=20_000,
                )
                log(f"[browser] goto chatgpt.com done (URL={page.url.split('?')[0]})")
            except Exception as exc:
                log(
                    f"[browser] goto chatgpt.com failed "
                    f"({type(exc).__name__}: {exc}) — tiếp tục poll cookies"
                )

        # Log progress mỗi 5s để debug (không spam)
        now = time.monotonic()
        if now - last_log_at > 5.0:
            last_log_at = now
            chatgpt_names = sorted(n for n in names if not n.startswith("__cf"))[:8]
            log(
                f"[browser] still waiting session-token "
                f"(URL={page.url.split('?')[0]}, "
                f"{len(cookies)} cookies, top: {chatgpt_names})"
            )

        await asyncio.sleep(0.5)
    raise BrowserPhaseError(f"timeout {timeout_seconds}s waiting session-token. URL: {page.url}")


async def _wait_oai_sc(ctx, *, timeout_seconds: float, log) -> None:
    """Đợi cookie oai-sc (Sentinel SDK fired)."""
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        cookies = await ctx.cookies("https://auth.openai.com/")
        if any(c["name"] == "oai-sc" for c in cookies):
            log("[browser] sentinel cookie oai-sc ready")
            return
        await asyncio.sleep(0.5)
    raise BrowserPhaseError(f"timeout {timeout_seconds}s waiting oai-sc")



def _extract_state_from_authorize(url: str) -> str | None:
    """Parse state query param từ authorize URL."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    return qs["state"][0] if "state" in qs and qs["state"] else None


async def _extract_state_from_url(page, *, log) -> str | None:
    """Lấy state từ navigation history."""
    try:
        entries = await page.evaluate(
            "() => performance.getEntriesByType('navigation').concat(performance.getEntriesByType('resource'))"
            ".map(e => e.name).filter(u => u.includes('state='))"
        )
        for entry in entries or []:
            parsed = urlparse(entry)
            qs = parse_qs(parsed.query)
            if "state" in qs and qs["state"][0]:
                return qs["state"][0]
    except Exception as exc:
        log(f"[browser] state extract failed: {exc}")
    return None


async def _navigate_to_authorize(
    page,
    authorize_url: str,
    *,
    log,
    prefix: str = "[browser]",
) -> None:
    """Navigate to auth.openai.com without failing on a committed slow page.

    OAuth redirect pages sometimes commit the target URL but never emit
    ``DOMContentLoaded`` before Playwright/Camoufox times out. At that point
    the auth state and cookies are already usable, so restarting the browser
    only wastes the valid session. Continue only when the live page is really
    on auth.openai.com; otherwise propagate the navigation error for the
    existing clean-profile retry policy.
    """
    try:
        await page.goto(
            authorize_url,
            wait_until="domcontentloaded",
            timeout=60_000,
        )
    except Exception as exc:
        # Firefox can reject ``goto`` with NS_BINDING_ABORTED just before the
        # redirected URL becomes observable. Give only that narrow condition
        # a short commit window; all other failures keep the immediate check.
        commit_deadline = time.monotonic() + (
            2.0 if _is_navigation_abort_error(exc) else 0.0
        )
        committed = False
        while True:
            current_url = str(getattr(page, "url", "") or "")
            current_host = (urlparse(current_url).hostname or "").casefold()
            try:
                page_open = not page.is_closed()
            except Exception:
                page_open = False
            committed = current_host == "auth.openai.com" and page_open
            if committed or not page_open or time.monotonic() >= commit_deadline:
                break
            await asyncio.sleep(0.1)
        if not committed:
            raise
        log(
            f"{prefix} authorize navigation committed; "
            f"ignore load wait error ({type(exc).__name__})"
        )
    log(f"{prefix} authorize landing ready: {page.url.split('?')[0]}")


_OTP_SEND_URL_MARKERS = (
    "/email-otp/send",
    "/passwordless/send-otp",
    "/email-otp/resend",
)


def _observe_auth_request(
    url: str,
    *,
    callback_holder: dict[str, str],
    on_otp_started,
) -> None:
    """Quan sát auth request mà không chặn hoặc tạo thêm network traffic."""
    if "chatgpt.com/api/auth/callback/openai" in url and "code=" in url:
        callback_holder.setdefault("url", url)

    parsed = urlparse(url)
    host = (parsed.hostname or "").casefold()
    path = parsed.path.rstrip("/").casefold()
    if host == "auth.openai.com" and any(
        path.endswith(marker) for marker in _OTP_SEND_URL_MARKERS
    ):
        # Mark ngay lúc dispatch, không đợi response: server có thể đã nhận và
        # gửi mail dù proxy làm rơi response. Relaunch lúc đó sẽ tạo mã thứ hai.
        on_otp_started()


# ─────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────

async def run_browser_phase(
    *,
    request: SignupRequest,
    settings: Settings,
    mail_provider: MailProvider,
    otp_started_at: datetime,
    log,
    on_checkpoint=None,
) -> tuple[BrowserHandoff, float]:
    """Phase 1: browser signup + set password post-login.

    on_checkpoint: callback(stage:str) — gọi khi đã lấy được OTP để watchdog
        bên ngoài gia hạn deadline (tránh kill job ngay sau khi có OTP).

    Returns: (handoff, otp_seconds).
    """
    if request.tls_insecure:
        from config import warn_insecure_tls
        warn_insecure_tls("browser_phase")
        log("[security] TLS verification DISABLED — debug mode")

    engine_order = _browser_launch_order(settings.browser_engine)
    job_id = f"hybrid_{uuid.uuid4().hex[:10]}"

    profile_dir: Path | None = None
    template_dir: Path | None = None
    current_engine = engine_order[0]
    profile_dirs: list[Path] = []

    def _profile_bundle(browser_engine: str) -> tuple[Path, Path]:
        if browser_engine == "camoufox":
            return (
                settings.profiles_dir / f"camoufox_{job_id}",
                settings.browser_camoufox_profile_dir,
            )
        return (
            settings.profiles_dir / f"{browser_engine}_{job_id}",
            settings.browser_profile_template_dir,
        )

    # HAR capture
    har_kwargs: dict[str, Any] = {}
    if request.har_capture:
        har_dir = settings.runtime_dir / "har_hybrid"
        har_dir.mkdir(parents=True, exist_ok=True)
        har_path = har_dir / f"hybrid-{datetime.now():%Y%m%d-%H%M%S}-{job_id}.har"
        har_kwargs["record_har_path"] = str(har_path)
        har_kwargs["record_har_content"] = "embed"
        har_kwargs["record_har_mode"] = "full"
        log(f"[browser] HAR capture → {har_path}")

    device_id = str(uuid.uuid4())
    logging_id = str(uuid.uuid4())
    log(f"[browser] device_id={device_id} logging_id={logging_id}")

    w, h = settings.browser_viewport_width, settings.browser_viewport_height
    viewport = {"width": w, "height": h}

    proxy_kwargs: dict[str, Any] = {}
    proxy_exit_ip = get_proxy_exit_ip(request.proxy)
    if request.proxy:
        _ensure_geoip_cache(settings.runtime_dir, log=log)

    state_param: str | None = None
    handoff_cookies: list[dict[str, Any]] = []
    authorize_url: str | None = None
    otp_seconds = 0.0
    callback_url: str | None = None

    # Kết quả enroll 2FA inline (page còn sống — CF-clean). Runner ghi vào đây
    # sau khi login OK, trước khi đóng browser. NEVER raise để không phá flow
    # (account đã create — phải trả cookies cho fallback Phase 2).
    mfa_holder: dict[str, Any] = {}

    async def _enroll_2fa_inline(page) -> None:
        """Enroll 2FA bằng page đang login. Ghi kết quả vào mfa_holder, không raise."""
        from mfa_phase import MfaError, _page_access_token, enable_2fa_in_page
        if not getattr(request, "mfa_inline", False):
            # Không có MFA: lấy token đúng một lần trước khi đóng Browser.
            browser_token = await _page_access_token(page, log=log)
            if browser_token:
                mfa_holder["access_token"] = browser_token
            return
        try:
            # enable_2fa_in_page tự lấy token trong cùng page. Không fetch trước
            # ở đây để tránh một /api/auth/session trùng qua proxy.
            mfa_holder["two_factor"] = await enable_2fa_in_page(page, log=log)
            log("[browser] 2FA enrolled inline OK (CF-clean)")
        except MfaError as exc:
            partial = getattr(exc, "partial_state", None)
            if partial and partial.get("secret"):
                mfa_holder["two_factor_partial"] = partial
                log(f"[browser] 2FA inline: enroll OK nhưng activate fail → partial saved: {exc}")
            else:
                log(f"[browser] 2FA inline fail (fallback Phase 2): {exc}")
        except Exception as exc:
            log(f"[browser] 2FA inline lỗi bất ngờ (fallback Phase 2): {exc}")
        finally:
            # Activate có thể rotate/refresh session. Ưu tiên token đọc sau MFA.
            try:
                refreshed_token = await _page_access_token(page, log=log)
                if refreshed_token:
                    mfa_holder["access_token"] = refreshed_token
                else:
                    # Không giữ token lấy trước MFA: activate có thể đã rotate
                    # session. Để Phase 2 curl fallback lấy token fresh.
                    mfa_holder.pop("access_token", None)
                    log("[browser] token sau 2FA chưa fresh — Phase 2 sẽ fallback")
            except Exception as exc:
                mfa_holder.pop("access_token", None)
                log(f"[browser] WARN refresh accessToken sau 2FA lỗi: {exc}")

    # Track từ lúc request gửi OTP thực sự xuất hiện. Sau mốc này, KHÔNG retry
    # kể cả khi driver chết — relaunch có thể gửi OTP lần 2 và làm vô hiệu mã
    # đang trên đường tới mailbox.
    flow_progress = {"otp_started": False}

    def _mark_otp_started() -> None:
        if flow_progress["otp_started"]:
            return
        flow_progress["otp_started"] = True
        log("[browser] OTP send đã bắt đầu — khóa relaunch để tránh gửi mã lần 2")

    # ─── Inner runners (mỗi runner là 1 lần launch + drive flow) ───
    async def _run_camoufox_once() -> tuple[str, float, str, list[dict[str, Any]]]:
        from camoufox.async_api import AsyncCamoufox

        extra_config: dict = {"fonts:spacing_seed": 0} if request.off_font else {}
        screen_kwargs: dict[str, Any] = {}

        if not settings.browser_random_screen:
            from camoufox.utils import Screen as _Screen

            chrome_h = 85
            extra_config["window.innerWidth"] = w
            extra_config["window.innerHeight"] = h
            extra_config["window.outerWidth"] = w
            extra_config["window.outerHeight"] = h + chrome_h
            extra_config["screen.width"] = w
            extra_config["screen.height"] = h + chrome_h
            extra_config["screen.availWidth"] = w
            extra_config["screen.availHeight"] = h + chrome_h
            screen_kwargs["screen"] = _Screen(
                min_width=w, max_width=w, min_height=h + chrome_h, max_height=h + chrome_h
            )
            screen_kwargs["i_know_what_im_doing"] = True

        if request.proxy:
            log("[bandwidth] Camoufox HTTP cache ON — giữ nguyên toàn bộ tài nguyên")
        if proxy_exit_ip:
            log("[bandwidth] tái sử dụng exit IP từ proxy probe cho Camoufox GeoIP")

        cf = AsyncCamoufox(
            headless=request.headless,
            persistent_context=True,
            user_data_dir=str(profile_dir),
            os=list(_CAMOUFOX_OS),
            viewport=viewport,
            locale="en-US",
            ignore_https_errors=request.tls_insecure,
            geoip=proxy_exit_ip or bool(request.proxy),
            enable_cache=bool(request.proxy),
            config=extra_config,
            **screen_kwargs,
            **proxy_kwargs,
            **har_kwargs,
        )
        ctx = await cf.__aenter__()
        completed = False

        callback_holder: dict[str, str] = {}

        def _capture_callback(req) -> None:
            _observe_auth_request(
                req.url,
                callback_holder=callback_holder,
                on_otp_started=_mark_otp_started,
            )

        ctx.on("request", _capture_callback)
        page = None
        try:
            page = ctx.pages[0] if ctx.pages else await ctx.new_page()

            _authorize_url = await _bootstrap_oauth_url(
                page, email=request.email, device_id=device_id, logging_id=logging_id, log=log,
            )
            await _navigate_to_authorize(page, _authorize_url, log=log)
            await asyncio.sleep(1.0)

            _callback_url, _otp_seconds = await _drive_signup_flow(
                ctx=ctx, page=page, request=request,
                mail_provider=mail_provider,
                callback_holder=callback_holder,
                otp_started_at=otp_started_at,
                log=log,
                overall_timeout=request.otp_timeout_seconds + _PRE_OTP_MARGIN_SECONDS,
                on_checkpoint=on_checkpoint,
                on_otp_started=_mark_otp_started,
            )

            _state = (
                _extract_state_from_authorize(_authorize_url)
                or await _extract_state_from_url(page, log=log)
            )
            # 2FA inline TRƯỚC khi đóng browser (page còn login + CF-clean).
            await _enroll_2fa_inline(page)
            # Lấy cookies SAU MFA vì activate có thể rotate session/cookies.
            _cookies = await ctx.cookies()
            completed = True
            return _callback_url, _otp_seconds, _state or "", _cookies
        except BaseException as exc:
            # Plan D: log health snapshot trước khi propagate để debug được
            # lý do page/ctx/browser chết.
            try:
                health = _browser_health(ctx, page) if page is not None else "page=NEVER_CREATED"
            except Exception as health_exc:
                health = f"health-snapshot-failed: {type(health_exc).__name__}: {health_exc}"
            log(
                f"[browser] camoufox runner exception: "
                f"{type(exc).__name__}: {exc} ({health})"
            )
            raise
        finally:
            try:
                ctx.remove_listener("request", _capture_callback)
            except Exception:
                pass
            if completed and request.keep_browser_open and not request.headless:
                log("[browser] debug: giữ browser mở — cancel job để đóng")
            else:
                try:
                    await cf.__aexit__(None, None, None)
                except Exception:
                    pass

    async def _run_chromium_once() -> tuple[str, float, str, list[dict[str, Any]]]:
        from playwright.async_api import async_playwright

        playwright = await async_playwright().start()
        ctx = None
        page = None
        completed = False
        try:
            channel = (
                ((settings.browser_channel or "").strip() or "chrome")
                if current_engine == "chrome"
                else None
            )
            ctx = await playwright.chromium.launch_persistent_context(
                user_data_dir=str(profile_dir),
                headless=request.headless,
                channel=channel,
                viewport=viewport,
                locale="en-US",
                ignore_https_errors=request.tls_insecure,
                **proxy_kwargs,
                **har_kwargs,
            )

            callback_holder: dict[str, str] = {}

            def _capture_callback(req) -> None:
                _observe_auth_request(
                    req.url,
                    callback_holder=callback_holder,
                    on_otp_started=_mark_otp_started,
                )

            ctx.on("request", _capture_callback)

            page = ctx.pages[0] if ctx.pages else await ctx.new_page()
            _authorize_url = await _bootstrap_oauth_url(
                page, email=request.email, device_id=device_id, logging_id=logging_id, log=log,
            )
            await _navigate_to_authorize(page, _authorize_url, log=log)
            await asyncio.sleep(1.0)

            _callback_url, _otp_seconds = await _drive_signup_flow(
                ctx=ctx, page=page, request=request,
                mail_provider=mail_provider,
                callback_holder=callback_holder,
                otp_started_at=otp_started_at,
                log=log,
                overall_timeout=request.otp_timeout_seconds + _PRE_OTP_MARGIN_SECONDS,
                on_checkpoint=on_checkpoint,
                on_otp_started=_mark_otp_started,
            )

            _state = (
                _extract_state_from_authorize(_authorize_url)
                or await _extract_state_from_url(page, log=log)
            )
            # 2FA inline TRƯỚC khi đóng ctx (page còn login + CF-clean).
            await _enroll_2fa_inline(page)
            # Lấy cookies SAU MFA vì activate có thể rotate session/cookies.
            _cookies = await ctx.cookies()

            if not (request.keep_browser_open and not request.headless):
                await ctx.close()
            completed = True
            return _callback_url, _otp_seconds, _state or "", _cookies
        except BaseException as exc:
            # Plan D: log health snapshot trước khi propagate.
            try:
                if ctx is None:
                    health = "ctx=NEVER_CREATED"
                elif page is None:
                    health = "page=NEVER_CREATED"
                else:
                    health = _browser_health(ctx, page)
            except Exception as health_exc:
                health = f"health-snapshot-failed: {type(health_exc).__name__}: {health_exc}"
            log(
                f"[browser] {current_engine} runner exception: "
                f"{type(exc).__name__}: {exc} ({health})"
            )
            raise
        finally:
            if completed and request.keep_browser_open and not request.headless:
                log("[browser] debug: giữ browser mở — cancel job để đóng")
            else:
                await playwright.stop()

    runners = {
        "camoufox": _run_camoufox_once,
        "chromium": _run_chromium_once,
        "chrome": _run_chromium_once,
    }

    async def _run_with_fallback_once() -> tuple[str, float, str, list[dict[str, Any]]]:
        nonlocal profile_dir, template_dir, current_engine
        last_error: BaseException | None = None
        for engine_index, candidate in enumerate(engine_order):
            current_engine = candidate
            profile_dir, template_dir = _profile_bundle(candidate)
            if profile_dir not in profile_dirs:
                profile_dirs.append(profile_dir)
            ensure_runtime_dirs(settings, extra=(profile_dir,))
            shutil.rmtree(profile_dir, ignore_errors=True)
            prepare_profile_dir(
                profile_dir=profile_dir,
                template_dir=template_dir,
                use_template=request.profile_template,
            )
            if engine_index:
                log(f"[browser] fallback launch → {candidate}")
            try:
                return await runners[candidate]()
            except Exception as exc:
                last_error = exc
                retryable = (
                    _is_driver_dead_error(exc)
                    or _is_context_destroyed_error(exc)
                    or _is_network_error(exc)
                    or _is_navigation_timeout(exc)
                    or _is_navigation_abort_error(exc)
                    or _is_browser_launch_error(exc)
                )
                if not retryable or flow_progress["otp_started"]:
                    raise
                if engine_index + 1 < len(engine_order):
                    log(
                        f"[browser] {candidate} failed before OTP — "
                        f"trying {engine_order[engine_index + 1]}"
                    )
        if last_error is not None:
            raise last_error
        raise BrowserPhaseError("browser launch fallback order is empty")

    runner = _run_with_fallback_once

    # Vòng retry: chỉ retry khi bắt được lỗi driver-pipe-dead VÀ flow chưa
    # tới mốc OTP send. Sau OTP send, lỗi driver vẫn fail-fast để tránh
    # spam mã OTP cho user.
    last_exc: BaseException | None = None
    success = False
    proxy_bridge: Socks5HttpBridge | None = None
    # B11 fix: try/finally đảm bảo profile_dir được dọn trên mọi exit path
    # (BrowserPhaseError raise giữa loop, CancelledError, KeyboardInterrupt).
    # Trừ debug mode keep_browser_open + headed (giữ profile để soi).
    try:
        if request.proxy:
            browser_proxy_url = request.proxy
            if needs_socks5_http_bridge(browser_proxy_url):
                proxy_bridge = await Socks5HttpBridge.start(browser_proxy_url, log=log)
                browser_proxy_url = proxy_bridge.proxy_url
            proxy_kwargs["proxy"] = _parse_proxy(browser_proxy_url)

        for attempt in range(1, _LAUNCH_RETRY_MAX + 1):
            flow_progress["otp_started"] = False
            try:
                callback_url, otp_seconds, state_param, handoff_cookies = await runner()
                success = True
                last_exc = None
                break
            except BrowserPhaseError:
                raise
            except Exception as exc:
                last_exc = exc
                retryable = (
                    _is_driver_dead_error(exc)
                    or _is_context_destroyed_error(exc)
                    or _is_network_error(exc)
                    or _is_navigation_timeout(exc)
                    or _is_navigation_abort_error(exc)
                    or _is_browser_launch_error(exc)
                )
                if not retryable:
                    raise BrowserPhaseError(
                        f"browser launch/driver error: {type(exc).__name__}: {exc}"
                    ) from exc
                if flow_progress["otp_started"]:
                    log(
                        f"[browser] lỗi sau khi đã trigger OTP — "
                        f"không retry để tránh gửi OTP lần 2: "
                        f"{type(exc).__name__}: {exc}"
                    )
                    raise BrowserPhaseError(
                        f"lỗi giữa flow (OTP đã gửi, không retry): {exc}"
                    ) from exc
                err_kind = (
                    "network/proxy" if _is_network_error(exc)
                    else "navigation timeout" if _is_navigation_timeout(exc)
                    else "navigation aborted" if _is_navigation_abort_error(exc)
                    else "navigation context" if _is_context_destroyed_error(exc)
                    else "browser launch" if _is_browser_launch_error(exc)
                    else "driver pipe"
                )
                log(
                    f"[browser] {err_kind} error "
                    f"(attempt {attempt}/{_LAUNCH_RETRY_MAX}): "
                    f"{type(exc).__name__}: {exc}"
                )
                if _is_browser_launch_error(exc) or attempt >= _LAUNCH_RETRY_MAX:
                    break
                shutil.rmtree(profile_dir, ignore_errors=True)
                prepare_profile_dir(
                    profile_dir=profile_dir,
                    template_dir=template_dir,
                    use_template=request.profile_template,
                )
                await asyncio.sleep(_LAUNCH_RETRY_BACKOFF)
    finally:
        if proxy_bridge is not None and not (
            success and request.keep_browser_open and not request.headless
        ):
            await proxy_bridge.close()
        if not (request.keep_browser_open and not request.headless):
            for candidate in profile_dirs:
                shutil.rmtree(candidate, ignore_errors=True)

    if not success:
        if last_exc is not None and (
            _is_driver_dead_error(last_exc)
            or _is_context_destroyed_error(last_exc)
            or _is_network_error(last_exc)
            or _is_navigation_timeout(last_exc)
            or _is_navigation_abort_error(last_exc)
            or _is_browser_launch_error(last_exc)
        ):
            raise BrowserPhaseError(
                f"retryable error sau {_LAUNCH_RETRY_MAX} lần thử: {last_exc}"
            ) from last_exc
        # Defensive: không bao giờ xảy ra (đã raise trong loop)
        raise BrowserPhaseError("browser launch failed without specific error")

    if not state_param:
        raise BrowserPhaseError("không lấy được oauth state từ navigation history")

    # Sanity check required cookies
    auth_cookies = {c["name"] for c in handoff_cookies if "openai.com" in (c.get("domain") or "")}
    missing = [c for c in _REQUIRED_AUTH_COOKIES if c not in auth_cookies]
    if missing:
        raise BrowserPhaseError(f"thiếu cookies: {missing}. có: {sorted(auth_cookies)}")

    log(f"[browser] handoff: {len(handoff_cookies)} cookies, state={state_param[:20]}...")
    return (
        BrowserHandoff(
            cookies=handoff_cookies,
            state_param=state_param,
            device_id=device_id,
            auth_session_logging_id=logging_id,
            callback_url=callback_url,
            access_token=mfa_holder.get("access_token"),
            two_factor=mfa_holder.get("two_factor"),
            two_factor_partial=mfa_holder.get("two_factor_partial"),
        ),
        otp_seconds,
    )
