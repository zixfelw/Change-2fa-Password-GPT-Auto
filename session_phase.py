"""Get Session: Login ChatGPT bằng browser + password + 2FA → trả full session JSON.

Dùng browser thật vì auth.openai.com có Cloudflare JS challenge —
curl_cffi không bypass được.

Flow:
    1. Mở chatgpt.com → bootstrap NextAuth (csrf + signin/openai) → authorize URL
    2. Navigate authorize → /log-in/password
    3. Fill password → submit
    4. Nếu MFA → fill TOTP code → submit
    5. Đợi redirect chatgpt.com + session cookies
    6. Gọi /api/auth/session trong page context → return JSON
"""
from __future__ import annotations

import asyncio
import re
import secrets
import shutil
import string
import time
import uuid
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from _browser_retry import (
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
from _nextauth_bootstrap import bootstrap_authorize_url
from config import ensure_runtime_dirs, load_settings, prepare_profile_dir
from totp_helper import generate_code
from user_agent_profile import CAMOUFOX_OS as _CAMOUFOX_OS


LogFn = Callable[[str], None]

_AUTH_SUBMIT_TIMEOUT_MS = 2_000
_POST_PASSWORD_REDIRECT_TIMEOUT_SECONDS = 45.0
_SESSION_COOKIE_TIMEOUT_SECONDS = 60.0


class SessionError(Exception):
    """Login/session fetch failed."""


# Headed sessions used by the QR checkout flow must stay reachable after
# login.  Keep only close callbacks here; page/context objects never leave the
# process and the opaque id is the only value returned to callers.
_HELD_BROWSER_SESSIONS: dict[str, Callable[[], Any]] = {}


def _validate_open_url(value: str | None) -> str | None:
    if value is None:
        return None
    url = value.strip()
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise SessionError("payment link must be an absolute https URL")
    if parsed.username or parsed.password:
        raise SessionError("payment link must not contain embedded credentials")
    if len(url) > 4096:
        raise SessionError("payment link is too long")
    return url


def _register_held_browser(close_callback: Callable[[], Any]) -> str:
    handle_id = uuid.uuid4().hex
    _HELD_BROWSER_SESSIONS[handle_id] = close_callback
    return handle_id


async def close_held_browser(handle_id: str | None) -> bool:
    """Close one headed browser retained for a QR checkout job."""
    if not handle_id:
        return False
    callback = _HELD_BROWSER_SESSIONS.pop(handle_id, None)
    if callback is None:
        return False
    try:
        result = callback()
        if hasattr(result, "__await__"):
            await result
    except Exception:
        # Cleanup is best-effort; the job state remains authoritative.
        return False
    return True


async def _capture_payment_qr(
    page: Any,
    *,
    out_path: Path,
    log: LogFn,
    timeout_seconds: float = 15.0,
    max_loads: int = 3,
) -> Path | None:
    """Capture the QR visibly rendered by a hosted payment page.

    Payment providers render QR as an ``img``, ``canvas``, ``svg``, or a
    QR-named container.  The capture intentionally uses a locator screenshot
    rather than recreating a QR from the URL, so the received Telegram image is
    the exact code the provider currently displays.
    """
    selectors = (
        'img[src*="qr" i]',
        'img[alt*="qr" i]',
        '[data-testid*="qr" i]',
        '[id*="qr" i]',
        '[class*="qr" i]',
        "canvas",
        "svg",
        "img",
    )
    loads = max(1, max_loads)
    for load_number in range(1, loads + 1):
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            candidates: list[tuple[int, float, Any, float, float]] = []
            try:
                surfaces = [page, *list(page.frames)]
            except Exception:
                surfaces = [page]
            for surface in surfaces:
                for selector in selectors:
                    try:
                        locator = surface.locator(selector)
                        count = min(await locator.count(), 24)
                    except Exception:
                        continue
                    for index in range(count):
                        candidate = locator.nth(index)
                        try:
                            if not await candidate.is_visible(timeout=300):
                                continue
                            box = await candidate.bounding_box()
                        except Exception:
                            continue
                        if not box:
                            continue
                        width = float(box.get("width") or 0)
                        height = float(box.get("height") or 0)
                        shortest = min(width, height)
                        longest = max(width, height)
                        if shortest < 140 or longest > 900 or longest / shortest > 1.25:
                            continue
                        try:
                            metadata = await candidate.evaluate(
                                """(element) => [
                                    element.tagName,
                                    element.id,
                                    String(element.className || ''),
                                    element.getAttribute('alt'),
                                    element.getAttribute('src'),
                                    element.getAttribute('aria-label'),
                                    element.getAttribute('data-testid'),
                                ].filter(Boolean).join(' ').toLowerCase()"""
                            )
                        except Exception:
                            metadata = ""
                        score = width * height
                        if isinstance(metadata, str) and any(
                            marker in metadata for marker in ("qr", "qrcode", "barcode")
                        ):
                            score += 1_000_000
                        candidates.append((len(candidates), score, candidate, width, height))

            for _order, _score, candidate, width, height in sorted(
                candidates, key=lambda item: item[1], reverse=True
            ):
                try:
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    out_path.unlink(missing_ok=True)
                    await candidate.screenshot(path=str(out_path), timeout=5_000)
                    if out_path.exists() and out_path.stat().st_size > 1_024:
                        log(
                            "[payment-qr] captured visible provider QR "
                            f"({width:.0f}x{height:.0f})"
                        )
                        return out_path
                except Exception:
                    continue
            await asyncio.sleep(0.5)

        if load_number == loads:
            break
        log(
            "[payment-qr] QR not visible; reloading payment page "
            f"({load_number + 1}/{loads})"
        )
        try:
            await page.reload(wait_until="domcontentloaded", timeout=30_000)
        except Exception as exc:
            log(f"[payment-qr] payment page reload failed: {type(exc).__name__}")
        await asyncio.sleep(1)

    log(f"[payment-qr] QR was not visible after {loads} page loads")
    return None


_PASSWORD_ALPHABET = string.ascii_letters + string.digits + "!@#$%*-_"


def generate_random_password(
    *,
    length: int = 20,
    previous_password: str | None = None,
) -> str:
    """Tạo password mạnh, không chứa ký tự phân tách combo ``|``."""
    if length < 12:
        raise ValueError("password length must be at least 12")

    required = (
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%*-_"),
    )
    for _ in range(8):
        chars = list(required) + [
            secrets.choice(_PASSWORD_ALPHABET)
            for _ in range(length - len(required))
        ]
        secrets.SystemRandom().shuffle(chars)
        candidate = "".join(chars)
        if candidate != previous_password:
            return candidate
    raise SessionError("could not generate a password different from the current one")


def _playwright_password_cookies(raw_cookies: Any) -> list[dict[str, Any]]:
    """Chuẩn hóa cookie export từ Get Session để nạp vào browser direct."""
    if not isinstance(raw_cookies, list):
        return []
    cookies: list[dict[str, Any]] = []
    for raw in raw_cookies:
        if not isinstance(raw, dict):
            continue
        name = raw.get("name")
        value = raw.get("value")
        domain = raw.get("domain")
        if not isinstance(name, str) or not name or not isinstance(value, str):
            continue
        if not isinstance(domain, str) or not domain:
            continue
        cookie: dict[str, Any] = {
            "name": name,
            "value": value,
            "domain": domain,
            "path": raw.get("path") if isinstance(raw.get("path"), str) else "/",
        }
        if isinstance(raw.get("secure"), bool):
            cookie["secure"] = raw["secure"]
        if isinstance(raw.get("httpOnly"), bool):
            cookie["httpOnly"] = raw["httpOnly"]
        expires = raw.get("expires")
        if isinstance(expires, (int, float)) and expires > 0:
            cookie["expires"] = expires
        same_site = raw.get("sameSite")
        if same_site in ("Strict", "Lax", "None"):
            cookie["sameSite"] = same_site
        cookies.append(cookie)
    return cookies


def _account_browser_launch_spec(
    *,
    session_data: dict[str, Any],
    headless: bool,
    profile_prefix: str,
    operation: str,
) -> tuple[list[dict[str, Any]], Path, dict[str, Any]]:
    """Build one isolated direct Camoufox profile for authenticated Account UI."""
    cookies = _playwright_password_cookies(session_data.get("__cookies"))
    if not cookies:
        raise SessionError(f"{operation} requires authenticated session cookies")

    settings = load_settings()
    viewport = {
        "width": settings.browser_viewport_width,
        "height": settings.browser_viewport_height,
    }
    profile_dir = settings.profiles_dir / f"{profile_prefix}_{uuid.uuid4().hex[:10]}"
    ensure_runtime_dirs(settings, extra=(profile_dir,))
    prepare_profile_dir(
        profile_dir=profile_dir,
        template_dir=settings.browser_camoufox_profile_dir,
        use_template=settings.browser_use_profile_template,
    )
    camoufox_config: dict[str, Any] = {}
    screen_kwargs: dict[str, Any] = {}
    if not settings.browser_random_screen:
        from camoufox.utils import Screen as _Screen

        chrome_height = 85
        camoufox_config.update({
            "window.innerWidth": viewport["width"],
            "window.innerHeight": viewport["height"],
            "window.outerWidth": viewport["width"],
            "window.outerHeight": viewport["height"] + chrome_height,
            "screen.width": viewport["width"],
            "screen.height": viewport["height"] + chrome_height,
            "screen.availWidth": viewport["width"],
            "screen.availHeight": viewport["height"] + chrome_height,
        })
        screen_kwargs = {
            "screen": _Screen(
                min_width=viewport["width"],
                max_width=viewport["width"],
                min_height=viewport["height"] + chrome_height,
                max_height=viewport["height"] + chrome_height,
            ),
            "i_know_what_im_doing": True,
        }
    launch_kwargs = {
        "headless": headless,
        "persistent_context": True,
        "user_data_dir": str(profile_dir),
        "os": list(_CAMOUFOX_OS),
        "viewport": viewport,
        "locale": "en-US",
        "geoip": False,
        "config": camoufox_config,
        **screen_kwargs,
    }
    return cookies, profile_dir, launch_kwargs


async def change_password_with_session(
    *,
    session_data: dict[str, Any],
    current_password: str,
    new_password: str,
    secret: str | None = None,
    headless: bool = True,
    log: LogFn = print,
) -> None:
    """Đổi password qua Account UI bằng session hiện có, luôn chạy direct.

    Không dùng private HTTP endpoint để tránh phụ thuộc payload nội bộ. Chỉ trả
    thành công khi browser thấy response cập nhật password thành công.
    """
    if not current_password or not new_password:
        raise SessionError("password change requires current and new passwords")
    if current_password == new_password:
        raise SessionError("new password must differ from the current password")

    from camoufox.async_api import AsyncCamoufox

    cookies, profile_dir, launch_kwargs = _account_browser_launch_spec(
        session_data=session_data,
        headless=headless,
        profile_prefix="password_camoufox",
        operation="password change",
    )

    camoufox = None
    context = None
    try:
        camoufox = AsyncCamoufox(**launch_kwargs)
        context = await camoufox.__aenter__()
        await context.add_cookies(cookies)
        page = context.pages[0] if context.pages else await context.new_page()

        async def _visible_password_fields(
            candidate: Any,
            *,
            minimum: int,
            timeout: float = 12.0,
        ) -> list[Any]:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                locator = candidate.locator('input[type="password"]')
                visible: list[Any] = []
                try:
                    count = await locator.count()
                    for index in range(min(count, 5)):
                        field = locator.nth(index)
                        if await field.is_visible(timeout=300):
                            visible.append(field)
                except Exception:
                    visible = []
                if len(visible) >= minimum:
                    return visible
                await asyncio.sleep(0.25)
            return []

        async def _first_visible(locator: Any) -> Any | None:
            try:
                count = await locator.count()
            except Exception:
                return None
            for index in range(min(count, 6)):
                candidate = locator.nth(index)
                try:
                    if await candidate.is_visible(timeout=300):
                        return candidate
                except Exception:
                    pass
            return None

        async def _is_password_verification_page(candidate: Any) -> bool:
            """Nhận đúng màn hình yêu cầu password hiện tại, không nhầm login."""
            url = candidate.url.lower()
            if "auth.openai.com/log-in/password" not in url:
                return False
            fields = await _visible_password_fields(candidate, minimum=1, timeout=8.0)
            if len(fields) != 1:
                return False
            try:
                text = (await candidate.locator("body").inner_text(timeout=2500)).lower()
            except Exception:
                return False
            verification_markers = (
                "verify it's you",
                "verify your identity",
                "current password",
                "xác minh danh tính",
                "mật khẩu hiện tại",
            )
            return any(marker in text for marker in verification_markers)

        # Đây là URL được mở khi người dùng bấm Password trong Security.
        # Mở thẳng trang này dùng session vừa lấy được, tránh phụ thuộc DOM
        # thường xuyên thay đổi của modal Settings.
        log("[password] opening Account password verification with Camoufox (direct)...")
        direct_verification = False
        try:
            await page.goto(
                "https://auth.openai.com/log-in/password",
                wait_until="domcontentloaded",
                timeout=30000,
            )
            direct_verification = await _is_password_verification_page(page)
        except Exception:
            direct_verification = False

        if not direct_verification:
            log("[password] direct verification unavailable; using Security Settings fallback...")
            await page.goto(
                "https://chatgpt.com/#settings/Security",
                wait_until="domcontentloaded",
                timeout=30000,
            )
            await page.wait_for_timeout(1200)
            previous_pages = set(context.pages)
            password_label = re.compile(r"^(?:password|mật khẩu)\b", re.IGNORECASE)
            password_text = re.compile(r"^\s*(?:password|mật khẩu)\s*$", re.IGNORECASE)

            async def _open_security_password_control() -> bool:
                """Chờ Settings hydrate rồi click hàng Password theo DOM thực tế.

                Hàng này hiện không phải lúc nào cũng có ``button``/``link`` role;
                ở một số bản ChatGPT, handler nằm trên thẻ cha của nhãn Password.
                Vì vậy thử control semantic trước, sau đó đi lên ancestor có thể bấm,
                cuối cùng click trực tiếp nhãn để event bubble đến hàng đó.
                """
                deadline = time.monotonic() + 30.0
                while time.monotonic() < deadline:
                    locators = (
                        page.get_by_role("button", name=password_label),
                        page.get_by_role("link", name=password_label),
                        page.get_by_text(password_text),
                        page.get_by_text("Password", exact=True),
                        page.get_by_text("Mật khẩu", exact=True),
                        page.locator(
                            "[data-testid*='password' i], "
                            "[aria-label*='password' i], "
                            "[id*='password' i]"
                        ),
                    )
                    for locator in locators:
                        label = await _first_visible(locator)
                        if label is None:
                            continue
                        interactive = await _first_visible(
                            label.locator(
                                "xpath=ancestor-or-self::*[self::button or self::a "
                                "or @role='button' or @role='link' or @tabindex='0'][1]"
                            )
                        )
                        for target in (interactive, label):
                            if target is None:
                                continue
                            try:
                                await target.click(timeout=2500)
                                return True
                            except Exception:
                                # Có thể label vừa render lại; poll lại thay vì fail sớm.
                                continue
                    # Some Settings builds attach the click handler to a plain
                    # div, without an ARIA role/tabindex.  Use the exact leaf
                    # label only, then bubble a real DOM click through its
                    # nearest container as the last fallback.
                    try:
                        clicked = await page.evaluate(
                            """
                            () => {
                              const normalized = (value) => (value || '')
                                .replace(/\\s+/g, ' ').trim().toLocaleLowerCase();
                              const labels = Array.from(document.querySelectorAll('*'))
                                .filter((element) => {
                                  const text = normalized(element.textContent);
                                  return (text === 'password' || text === 'mật khẩu')
                                    && !Array.from(element.children).some((child) =>
                                      normalized(child.textContent) === text);
                                });
                              for (const label of labels) {
                                const target = label.closest(
                                  'button,a,[role="button"],[role="link"],[tabindex="0"]'
                                ) || label.parentElement;
                                if (!target) continue;
                                const style = getComputedStyle(target);
                                const rect = target.getBoundingClientRect();
                                if (style.display === 'none' || style.visibility === 'hidden'
                                    || rect.width <= 0 || rect.height <= 0) continue;
                                target.click();
                                return true;
                              }
                              return false;
                            }
                            """
                        )
                        if clicked:
                            return True
                    except Exception:
                        pass
                    await asyncio.sleep(0.25)
                return False

            log("[password] waiting for Security password control...")
            if not await _open_security_password_control():
                raise SessionError("Security settings password control was not found")

            deadline = time.monotonic() + 12.0
            while time.monotonic() < deadline:
                candidates = [item for item in context.pages if item not in previous_pages]
                candidates.append(page)
                target_page = next(
                    (item for item in candidates if "auth.openai.com" in item.url),
                    None,
                )
                if target_page is not None:
                    page = target_page
                    try:
                        await page.wait_for_load_state("domcontentloaded", timeout=5000)
                    except Exception:
                        pass
                    break
                await asyncio.sleep(0.25)

        if "auth.openai.com" not in page.url:
            raise SessionError("password verification page did not open")

        async def _submit_button(candidate: Any) -> Any | None:
            for locator in (
                candidate.get_by_role(
                    "button",
                    name=re.compile(
                        r"^(?:continue|tiếp tục|save|lưu|update password|change password)$",
                        re.IGNORECASE,
                    ),
                ),
                candidate.locator('button[type="submit"]'),
            ):
                button = await _first_visible(locator)
                if button is not None:
                    return button
            return None

        fields = await _visible_password_fields(page, minimum=1)
        if not fields:
            raise SessionError("password verification input was not found")

        if "/log-in/password" in page.url.lower() and len(fields) == 1:
            log("[password] verifying the current password...")
            await fields[0].fill(current_password)
            verify_submit = await _submit_button(page)
            if verify_submit is None:
                raise SessionError("password verification submit button was not found")
            await verify_submit.click(timeout=8000)

            mfa_submitted = False
            deadline = time.monotonic() + 25.0
            fields = []
            while time.monotonic() < deadline:
                fields = await _visible_password_fields(page, minimum=2, timeout=0.5)
                if fields:
                    break
                otp_input = None
                for selector in (
                    'input[autocomplete="one-time-code"]',
                    'input[inputmode="numeric"]',
                    'input[name="code"]',
                ):
                    candidate = await _first_visible(page.locator(selector))
                    if candidate is not None:
                        otp_input = candidate
                        break
                if otp_input is not None and not mfa_submitted:
                    if not secret:
                        raise SessionError("password verification requires a 2FA secret")
                    await otp_input.fill(generate_code(secret))
                    otp_submit = await _submit_button(page)
                    if otp_submit is None:
                        raise SessionError("password verification 2FA submit button was not found")
                    await otp_submit.click(timeout=8000)
                    mfa_submitted = True
                await asyncio.sleep(0.25)
            if not fields:
                raise SessionError("password update form did not appear after verification")

        if len(fields) < 2:
            fields = await _visible_password_fields(page, minimum=2)
        if not fields:
            raise SessionError("password update form was not found")

        async def _field_descriptor(field: Any) -> str:
            values: list[str] = []
            for attr in ("name", "id", "autocomplete", "placeholder", "aria-label"):
                try:
                    value = await field.get_attribute(attr)
                except Exception:
                    value = None
                if value:
                    values.append(value.lower())
            return " ".join(values)

        descriptors = [await _field_descriptor(field) for field in fields]
        current_index = next(
            (index for index, text in enumerate(descriptors) if "current" in text),
            None,
        )
        confirm_index = next(
            (
                index
                for index, text in enumerate(descriptors)
                if "confirm" in text or "repeat" in text
            ),
            None,
        )
        if current_index is None and len(fields) >= 3:
            current_index = 0
        if current_index is not None:
            await fields[current_index].fill(current_password)

        remaining = [index for index in range(len(fields)) if index != current_index]
        new_index = next(
            (
                index
                for index in remaining
                if "new" in descriptors[index] and index != confirm_index
            ),
            remaining[0] if remaining else None,
        )
        if new_index is None:
            raise SessionError("new password input was not found")
        if confirm_index is None:
            confirm_index = next(
                (index for index in remaining if index != new_index),
                None,
            )
        if confirm_index is None:
            raise SessionError("password confirmation input was not found")
        await fields[new_index].fill(new_password)
        await fields[confirm_index].fill(new_password)

        submit = page.get_by_role(
            "button",
            name=re.compile(r"(?:save|update|change|continue).*password|save", re.IGNORECASE),
        )
        try:
            submit_count = await submit.count()
        except Exception:
            submit_count = 0
        if submit_count == 0:
            submit = page.locator('button[type="submit"]')
            submit_count = await submit.count()
        if submit_count == 0:
            raise SessionError("password change submit button was not found")

        password_responses: list[tuple[int, str]] = []

        def _capture_password_response(response: Any) -> None:
            try:
                url = response.url.lower()
                if response.request.method == "POST" and "password" in url:
                    password_responses.append((response.status, url))
            except Exception:
                pass

        page.on("response", _capture_password_response)
        try:
            await submit.first.click(timeout=8000)
            deadline = time.monotonic() + 15.0
            while time.monotonic() < deadline:
                accepted = any(
                    200 <= status < 300 and not url.rstrip("/").endswith("/verify")
                    for status, url in password_responses
                )
                if accepted:
                    log("[password] changed successfully")
                    return
                failed = next(
                    (
                        status
                        for status, url in password_responses
                        if not url.rstrip("/").endswith("/verify") and status >= 400
                    ),
                    None,
                )
                if failed is not None:
                    raise SessionError(f"password change rejected: HTTP {failed}")
                await asyncio.sleep(0.25)
        finally:
            # Playwright Python/Camoufox exposes ``remove_listener`` (không có
            # ``off`` như bản JavaScript). Cleanup không được phép che mất kết
            # quả đổi password đã được server xác nhận.
            page.remove_listener("response", _capture_password_response)
        raise SessionError("password change was not confirmed by the Account page")
    except SessionError:
        raise
    except Exception as exc:
        raise SessionError(f"password change browser error: {type(exc).__name__}") from exc
    finally:
        if camoufox is not None:
            try:
                await camoufox.__aexit__(None, None, None)
            except Exception:
                pass
        shutil.rmtree(profile_dir, ignore_errors=True)


async def logout_all_sessions_with_session(
    *,
    session_data: dict[str, Any],
    headless: bool = True,
    log: LogFn = print,
) -> bool:
    """Open Security settings and revoke every active ChatGPT login session."""
    from camoufox.async_api import AsyncCamoufox

    cookies, profile_dir, launch_kwargs = _account_browser_launch_spec(
        session_data=session_data,
        headless=headless,
        profile_prefix="sessions_camoufox",
        operation="logout all sessions",
    )
    camoufox = None
    page = None
    response_listener = None
    try:
        camoufox = AsyncCamoufox(**launch_kwargs)
        context = await camoufox.__aenter__()
        await context.add_cookies(cookies)
        page = context.pages[0] if context.pages else await context.new_page()

        async def _first_visible(locator: Any, *, limit: int = 8) -> Any | None:
            try:
                count = await locator.count()
            except Exception:
                return None
            for index in range(min(count, limit)):
                candidate = locator.nth(index)
                try:
                    if await candidate.is_visible(timeout=300):
                        return candidate
                except Exception:
                    continue
            return None

        async def _click_settings_control(
            labels: tuple[str, ...],
            pattern: re.Pattern[str],
        ) -> bool:
            deadline = time.monotonic() + 25.0
            while time.monotonic() < deadline:
                locators = [
                    page.get_by_role("button", name=pattern),
                    page.get_by_role("link", name=pattern),
                ]
                locators.extend(page.get_by_text(label, exact=True) for label in labels)
                for locator in locators:
                    label = await _first_visible(locator)
                    if label is None:
                        continue
                    interactive = await _first_visible(
                        label.locator(
                            "xpath=ancestor-or-self::*[self::button or self::a "
                            "or @role='button' or @role='link' or @tabindex='0'][1]"
                        )
                    )
                    for target in (interactive, label):
                        if target is None:
                            continue
                        try:
                            await target.click(timeout=2500)
                            return True
                        except Exception:
                            continue
                try:
                    clicked = await page.evaluate(
                        r"""
                        (labels) => {
                          const normalizedLabels = new Set(labels.map((value) => value
                            .replace(/\s+/g, ' ').trim().toLocaleLowerCase()));
                          const elements = Array.from(document.querySelectorAll('*'));
                          for (const element of elements) {
                            const text = (element.textContent || '')
                              .replace(/\s+/g, ' ').trim().toLocaleLowerCase();
                            if (!normalizedLabels.has(text)) continue;
                            if (Array.from(element.children).some((child) =>
                              normalizedLabels.has((child.textContent || '')
                                .replace(/\s+/g, ' ').trim().toLocaleLowerCase()))) continue;
                            const target = element.closest(
                              'button,a,[role="button"],[role="link"],[tabindex="0"]'
                            ) || element.parentElement;
                            if (!target) continue;
                            const style = getComputedStyle(target);
                            const rect = target.getBoundingClientRect();
                            if (style.display === 'none' || style.visibility === 'hidden'
                                || rect.width <= 0 || rect.height <= 0) continue;
                            target.click();
                            return true;
                          }
                          return false;
                        }
                        """,
                        list(labels),
                    )
                    if clicked:
                        return True
                except Exception:
                    pass
                await asyncio.sleep(0.25)
            return False

        logout_all_pattern = re.compile(
            r"^(?:log\s*out\s*all|logout\s*all|sign\s*out\s*all|đăng\s*xuất\s*tất\s*cả)$",
            re.IGNORECASE,
        )

        async def _logout_all_button(candidate: Any) -> Any | None:
            for locator in (
                candidate.get_by_role("button", name=logout_all_pattern),
                candidate.get_by_text("Log out all", exact=True),
                candidate.get_by_text("Logout all", exact=True),
                candidate.get_by_text("Sign out all", exact=True),
                candidate.get_by_text("Đăng xuất tất cả", exact=True),
            ):
                button = await _first_visible(locator)
                if button is not None:
                    interactive = await _first_visible(
                        button.locator(
                            "xpath=ancestor-or-self::*[self::button or @role='button'][1]"
                        )
                    )
                    return interactive or button
            return None

        log("[sessions] opening Security settings with Camoufox (direct)...")
        await page.goto(
            "https://chatgpt.com/#settings/Security",
            wait_until="domcontentloaded",
            timeout=30000,
        )
        await page.wait_for_timeout(1200)

        logout_button = await _logout_all_button(page)
        if logout_button is None:
            sessions_labels = (
                "Active sessions",
                "Logged in devices",
                "Phiên đăng hoạt động",
                "Phiên đang hoạt động",
                "Phiên đăng nhập",
            )
            sessions_pattern = re.compile(
                r"^(?:active sessions?|logged in devices?|"
                r"phiên đăng hoạt động|phiên đang hoạt động|phiên đăng nhập)$",
                re.IGNORECASE,
            )
            log("[sessions] opening active login sessions...")
            if not await _click_settings_control(sessions_labels, sessions_pattern):
                raise SessionError("active sessions control was not found")

            deadline = time.monotonic() + 20.0
            while time.monotonic() < deadline:
                logout_button = await _logout_all_button(page)
                if logout_button is not None:
                    break
                await asyncio.sleep(0.25)
        if logout_button is None:
            raise SessionError("logout all sessions button was not found")

        session_responses: list[tuple[str, int, str]] = []

        def _capture_session_response(response: Any) -> None:
            try:
                method = response.request.method.upper()
                url = response.url.lower()
                if method not in {"POST", "PUT", "PATCH", "DELETE"}:
                    return
                if any(
                    marker in url
                    for marker in (
                        "logout",
                        "signout",
                        "sign-out",
                        "session",
                        "revoke",
                        "terminate",
                        "device",
                    )
                ):
                    session_responses.append((method, response.status, url))
            except Exception:
                pass

        response_listener = _capture_session_response
        page.on("response", response_listener)

        async def _click_logout_control(target: Any, *, action: str) -> None:
            failures: list[str] = []
            for mode in ("normal", "force", "dom"):
                try:
                    if mode == "normal":
                        await target.scroll_into_view_if_needed(timeout=1500)
                        await target.click(timeout=4000)
                    elif mode == "force":
                        await target.click(timeout=2500, force=True)
                    else:
                        await target.evaluate("(element) => element.click()", timeout=2500)
                    return
                except Exception as exc:
                    failures.append(f"{mode}={type(exc).__name__}")
                    # A click may revoke the current session before Playwright can
                    # observe its actionability result. Do not submit it twice.
                    await asyncio.sleep(0.35)
                    if session_responses:
                        return
                    if mode != "dom":
                        log(f"[sessions] {action} {mode} click failed; trying fallback")
            raise SessionError(
                f"{action} could not be clicked ({', '.join(failures)})"
            )

        log("[sessions] logging out all active sessions...")
        await _click_logout_control(logout_button, action="logout all sessions")

        # Some builds ask for one confirmation in a modal; click only inside
        # that dialog so the original page button cannot be submitted twice.
        confirm_deadline = time.monotonic() + 4.0
        while time.monotonic() < confirm_deadline:
            dialogs = page.locator('[role="dialog"]')
            try:
                dialog_count = await dialogs.count()
            except Exception:
                dialog_count = 0
            confirmed = False
            for index in range(min(dialog_count, 4)):
                dialog = dialogs.nth(index)
                try:
                    if not await dialog.is_visible(timeout=200):
                        continue
                except Exception:
                    continue
                confirm = await _logout_all_button(dialog)
                if confirm is not None:
                    await _click_logout_control(confirm, action="logout confirmation")
                    confirmed = True
                    break
            if confirmed or any(200 <= status < 300 for _, status, _ in session_responses):
                break
            await asyncio.sleep(0.2)

        deadline = time.monotonic() + 18.0
        while time.monotonic() < deadline:
            accepted = any(200 <= status < 300 for _, status, _ in session_responses)
            if accepted:
                log("[sessions] all active sessions logged out")
                return True
            if page.is_closed():
                log("[sessions] all active sessions logged out")
                return True
            failed = next(
                (status for _, status, _ in session_responses if status >= 400),
                None,
            )
            if failed is not None:
                raise SessionError(f"logout all sessions rejected: HTTP {failed}")
            current_url = str(page.url or "").casefold()
            if "auth.openai.com" in current_url or "/auth/login" in current_url:
                log("[sessions] all active sessions logged out")
                return True
            try:
                body_text = (await page.locator("body").inner_text(timeout=1500)).casefold()
            except Exception:
                body_text = ""
            if any(
                marker in body_text
                for marker in (
                    "all sessions have been logged out",
                    "logged out of all sessions",
                    "signed out of all sessions",
                    "đã đăng xuất tất cả",
                    "đã đăng xuất khỏi tất cả",
                    "đăng xuất tất cả thành công",
                )
            ):
                log("[sessions] all active sessions logged out")
                return True
            await asyncio.sleep(0.25)
        log("[sessions] logout submitted but Account page gave no confirmation")
        return False
    except SessionError:
        raise
    except Exception as exc:
        detail = str(exc).strip().replace("\n", " ")[:240]
        suffix = f": {detail}" if detail else ""
        raise SessionError(
            f"logout all sessions browser error: {type(exc).__name__}{suffix}"
        ) from exc
    finally:
        if page is not None and response_listener is not None:
            try:
                page.remove_listener("response", response_listener)
            except Exception:
                pass
        if camoufox is not None:
            try:
                await camoufox.__aexit__(None, None, None)
            except Exception:
                pass
        shutil.rmtree(profile_dir, ignore_errors=True)


# Login errors vĩnh viễn (fatal) — KHÔNG retry để tránh login spam → lockout /
# mail-provider rate-limit. Nguồn chân lý DUY NHẤT (trước đây trùng ở
# web/manager.py + web/upi_runner.py). Dùng cho retry-gate + SessionProvider
# fatal_classifier (xoá record cache khi login fatal).
NON_RETRYABLE_LOGIN_PATTERNS: tuple[str, ...] = (
    "password verify failed",
    "mfa verify failed",
    "no mail_provider available",
    "no secret provided",
    "yêu cầu 2fa nhưng không có",
    "otp polling returned empty",
    "passwordless otp login but no mail_provider",
    "invalid_password",
    "invalid_credential",
    "invalid password",
    "wrong password",
    "sai mật khẩu",
    "2fa_failed",
    "mã 2fa (otp) không đúng",
    "incorrect_code",
    "secret 2fa không hợp lệ",
    "push_auth_required",
    "account restricted",
    "account locked",
    "account suspended",
    "account banned",
)

# Password endpoint có thể trả 409 khi OAuth/login state hết hiệu lực.
# Đây không phải bằng chứng password sai: retry toàn flow sẽ bootstrap
# cookie/state mới. Kiểm tra marker chặt để không retry nhầm lỗi credential.
_TRANSIENT_LOGIN_STATE_PATTERNS: tuple[str, ...] = (
    "your sign-in session is no longer valid",
    "sign-in session is no longer valid",
    "invalid_state",
)

_CLOUDFLARE_CHALLENGE_PATTERNS: tuple[str, ...] = (
    "just a moment",
    "cloudflare challenge",
    "cf-chl-",
    "/cdn-cgi/challenge-platform",
    "cf-ray",
)

_DEACTIVATED_ACCOUNT_PATTERNS: tuple[str, ...] = (
    "account_deactivated",
    "user_deactivated",
    "account deactivated",
    "account has been deactivated",
    "account was deactivated",
    "account is deactivated",
    "account has been disabled",
    "account was disabled",
    "account is disabled",
    "account has been deleted",
    "account was deleted",
)


def is_transient_login_state_error(exc: BaseException | str) -> bool:
    """True cho HTTP 409 do login/OAuth state hết hiệu lực, không phải credential."""
    msg = exc if isinstance(exc, str) else str(exc)
    lower = msg.lower()
    return "http 409" in lower and any(
        marker in lower for marker in _TRANSIENT_LOGIN_STATE_PATTERNS
    )


def is_cloudflare_challenge_error(exc: BaseException | str) -> bool:
    """True khi HTTP 403 là trang Cloudflare challenge, không phải sai mật khẩu."""
    msg = exc if isinstance(exc, str) else str(exc)
    lower = msg.lower()
    return "http 403" in lower and any(
        marker in lower for marker in _CLOUDFLARE_CHALLENGE_PATTERNS
    )


def classify_account_check_error(exc: BaseException | str | None) -> str:
    """Phân loại bảo thủ: chỉ xác nhận dead khi có marker deactivated rõ."""
    if exc is None:
        return "inconclusive"
    msg = exc if isinstance(exc, str) else str(exc)
    lower = msg.lower()
    if any(marker in lower for marker in _DEACTIVATED_ACCOUNT_PATTERNS):
        return "deactivated"
    return "inconclusive"


def is_fatal_login_error(exc: BaseException | str) -> bool:
    """True nếu lỗi login là fatal (không nên retry / nên xoá cache record).

    Nhận Exception hoặc message string. Fail-safe: chỉ True khi match pattern
    fatal rõ ràng — lỗi transient/mạng (không match) trả False.
    """
    msg = exc if isinstance(exc, str) else str(exc)
    lower = msg.lower()
    # Deactivated/disabled/deleted is always terminal.  Check this before the
    # transient HTTP-409 predicate because an upstream response can contain
    # both ``invalid_state`` and an account-deactivation marker.
    if any(marker in lower for marker in _DEACTIVATED_ACCOUNT_PATTERNS):
        return True
    if is_transient_login_state_error(lower) or is_cloudflare_challenge_error(lower):
        return False
    return any(pat in lower for pat in NON_RETRYABLE_LOGIN_PATTERNS)


# JS: fetch /api/auth/session trong page context chatgpt.com
_FETCH_SESSION_JS = r"""
async () => {
    const r = await fetch('/api/auth/session', {credentials: 'include'});
    if (!r.ok) throw new Error('session HTTP ' + r.status);
    return await r.json();
}
"""


async def _get_session_browser(
    *,
    email: str,
    password: str,
    secret: str | None = None,
    headless: bool = True,
    proxy: str | None = None,
    tls_insecure: bool = False,
    keep_browser_open: bool = False,
    open_url_after_login: str | None = None,
    capture_qr_path: str | Path | None = None,
    log: LogFn = print,
) -> dict[str, Any]:
    """Login ChatGPT bằng browser thật → return session JSON.

    Retry: nếu driver pipe đóng sớm TRƯỚC khi submit password → relaunch.
    Sau khi đã submit password thì fail-fast để tránh nhiều lần thử login
    (rủi ro lockout / captcha challenge).

    keep_browser_open=True + headless=False → giữ browser mở sau khi xong
    (debug). User cancel job để đóng. Có tác dụng cả ở exit path lỗi
    sau-submit-password (để soi DOM/network).
    """
    debug_keep = keep_browser_open and not headless
    open_url_after_login = _validate_open_url(open_url_after_login)
    qr_capture_path = Path(capture_qr_path) if capture_qr_path else None
    if tls_insecure:
        from config import warn_insecure_tls
        warn_insecure_tls("session_phase")
        log("[security] TLS verification DISABLED — debug mode")

    settings = load_settings()
    job_id = f"session_{uuid.uuid4().hex[:10]}"
    engine_order = _browser_launch_order(settings.browser_engine)
    w, h = settings.browser_viewport_width, settings.browser_viewport_height
    viewport = {"width": w, "height": h}
    proxy_kwargs: dict[str, Any] = {}
    if proxy:
        proxy_kwargs["proxy"] = _parse_proxy(proxy)
        from browser_phase import _ensure_geoip_cache
        _ensure_geoip_cache(settings.runtime_dir, log=log)

    progress = {"password_submitted": False}

    def _profile_bundle(engine: str) -> tuple[Any, Any]:
        if engine == "camoufox":
            return (
                settings.profiles_dir / f"camoufox_{job_id}",
                settings.browser_camoufox_profile_dir,
            )
        return (
            settings.profiles_dir / f"{engine}_{job_id}",
            settings.browser_profile_template_dir,
        )

    async def _drive_session_flow(ctx: Any, page: Any) -> dict[str, Any]:
        device_id = str(uuid.uuid4())
        logging_id = str(uuid.uuid4())

        async def _submit_auth_form(
            input_locator: Any,
            button_selectors: tuple[str, ...],
            *,
            step: str,
        ) -> None:
            """Submit an auth step, falling back to Enter on the focused input.

            Auth's button markup varies by rollout and locale. In concurrent
            headed runs the old selector-only path waited for redirects that
            could never start when no submit button matched.
            """
            for button_selector in button_selectors:
                try:
                    button = page.locator(button_selector).first
                    if not await button.is_visible(timeout=1_000):
                        continue
                    await button.click(timeout=_AUTH_SUBMIT_TIMEOUT_MS)
                    log(f"[session] submitted {step} ({button_selector})")
                    return
                except Exception:
                    continue
            try:
                await input_locator.press("Enter", timeout=_AUTH_SUBMIT_TIMEOUT_MS)
            except Exception as exc:
                raise SessionError(
                    f"{step} submit failed (button and Enter): {type(exc).__name__}"
                ) from exc
            log(f"[session] submitted {step} (Enter fallback)")

        async def _replace_input_text(locator: Any, value: str, *, delay: int) -> None:
            """Replace text without a pointer click.

            Locator.type() focuses the field itself.  Avoiding a forced click is
            important for concurrent headed browsers: a visible input can still
            have a stalled compositor click while keyboard input remains usable.
            """
            await locator.fill("", timeout=10_000)
            await locator.type(value, delay=delay, timeout=10_000)

        async def _continue_with_password_from_email_verification() -> bool:
            """Leave the email-verification landing page for password login.

            Some password accounts initially land on this page even though they
            do not require an email OTP. The page offers a password path, but
            treating it as an email form made the session flow wait for a
            password input that could never appear.
            """
            if "/email-verification" not in page.url.lower():
                return False

            controls = page.locator('button, a, [role="button"]')
            try:
                count = min(await controls.count(), 32)
            except Exception:
                count = 0

            for index in range(count):
                control = controls.nth(index)
                try:
                    if not await control.is_visible(timeout=500):
                        continue
                    label = (await control.inner_text(timeout=500) or "").strip().lower()
                except Exception:
                    continue
                if not any(
                    phrase in label
                    for phrase in (
                        "continue with password",
                        "sign in with password",
                        "use password",
                    )
                ):
                    continue

                try:
                    await control.click(timeout=_AUTH_SUBMIT_TIMEOUT_MS)
                except Exception:
                    continue
                log("[session] selected password login from email verification")

                deadline = time.monotonic() + 10.0
                while time.monotonic() < deadline:
                    current_url = page.url.lower()
                    if "/log-in/password" in current_url:
                        log("[session] password login page ready")
                        return True
                    if "/create-account/" in current_url:
                        log("[session] email verification led to create-account; stopping")
                        return False
                    await asyncio.sleep(0.25)
                log("[session] password login navigation timed out after email verification")
                return False
            return False

        async def _resolve_email_verification_landing() -> None:
            """Use the safe password route or fail with the actual auth state."""
            if "/email-verification" not in page.url.lower():
                return
            await _continue_with_password_from_email_verification()
            if "/email-verification" in page.url.lower():
                raise SessionError(
                    "email verification requires a code or the password login option "
                    f"is unavailable. URL: {page.url}"
                )
            if "/create-account/" in page.url.lower():
                raise SessionError(
                    f"account reached create-account flow instead of password login. URL: {page.url}"
                )

        # Step 1: bootstrap
        log("[session] bootstrapping NextAuth...")
        authorize_url = await bootstrap_authorize_url(
            page,
            email=email,
            device_id=device_id,
            logging_id=logging_id,
            prepare_page=True,
            log=log,
        )
        log("[session] authorize URL ready")

        # Step 2: navigate authorize → login page
        from browser_phase import _navigate_to_authorize

        await _navigate_to_authorize(
            page,
            authorize_url,
            log=log,
            prefix="[session]",
        )
        await asyncio.sleep(3.0)
        log(f"[session] at: {page.url.split('?')[0]}")

        await _resolve_email_verification_landing()

        # Có thể ở /log-in (email step) → cần fill email trước
        # Hoặc ở /log-in/password → fill password luôn
        if "/log-in/password" not in page.url:
            email_input = None
            for sel in (
                'input[name="email"]',
                'input[type="email"]',
                'input[inputmode="email"]',
            ):
                try:
                    loc = page.locator(sel).first
                    if await loc.is_visible(timeout=8000):
                        email_input = loc
                        break
                except Exception:
                    continue

            if email_input:
                log("[session] filling email...")
                await _replace_input_text(email_input, email, delay=30)
                await asyncio.sleep(0.3)
                await _submit_auth_form(email_input, (
                    'button[type="submit"]',
                    'button:has-text("Continue")',
                ), step="email")
                await asyncio.sleep(3.0)
                log(f"[session] after email: {page.url.split('?')[0]}")
                await _resolve_email_verification_landing()

        # Step 3: fill password
        pwd_input = None
        for sel in ('input[type="password"]', 'input[name="password"]'):
            try:
                loc = page.locator(sel).first
                if await loc.is_visible(timeout=15000):
                    pwd_input = loc
                    break
            except Exception:
                continue

        if not pwd_input:
            raise SessionError(f"password input not found. URL: {page.url}")

        log("[session] filling password...")
        await _replace_input_text(pwd_input, password, delay=40)
        await asyncio.sleep(0.3)

        # Submit password — sau đây không retry để tránh login spam
        await _submit_auth_form(pwd_input, (
            'button[type="submit"]',
            'button:has-text("Continue")',
            'button:has-text("Log in")',
        ), step="password")
        progress["password_submitted"] = True

        # Step 4: poll chờ terminal state sau submit password
        # Terminal states:
        #   - MFA: URL chứa "mfa" hoặc content chứa "mfa"
        #   - Logged in: URL chứa "chatgpt.com" (không còn auth.openai.com)
        #   - Login error: trang vẫn ở /log-in/password + có error message
        _POST_PASSWORD_DEADLINE = _POST_PASSWORD_REDIRECT_TIMEOUT_SECONDS
        _POLL_INTERVAL = 1.0
        poll_end = time.monotonic() + _POST_PASSWORD_DEADLINE
        terminal_state: str | None = None  # "mfa" | "logged_in" | "login_error"

        while time.monotonic() < poll_end:
            await asyncio.sleep(_POLL_INTERVAL)
            current_url = page.url.lower()

            # Terminal: đã redirect về chatgpt.com (no MFA account hoặc MFA đã xong)
            if "chatgpt.com" in current_url and "auth.openai.com" not in current_url:
                terminal_state = "logged_in"
                log(f"[session] after password: redirected to chatgpt.com")
                break

            # Terminal: MFA challenge page
            if "mfa" in current_url:
                terminal_state = "mfa"
                log(f"[session] after password: MFA page detected (URL)")
                break

            # Check content cho trường hợp URL không chứa "mfa" nhưng page content có
            try:
                content_lower = (await page.content()).lower()
                content_snippet = content_lower[:5000]
            except Exception:
                content_lower = ""
                content_snippet = ""

            if any(
                marker in content_lower
                for marker in _DEACTIVATED_ACCOUNT_PATTERNS
            ):
                raise SessionError("account deactivated")

            if "mfa" in content_snippet:
                terminal_state = "mfa"
                log(f"[session] after password: MFA page detected (content)")
                break

            # Terminal: login error (vẫn ở password page + có thông báo lỗi)
            if "/log-in/password" in current_url:
                _error_selectors = (
                    '[data-testid="error-message"]',
                    '.error-message',
                    '[role="alert"]',
                )
                for err_sel in _error_selectors:
                    try:
                        if await page.locator(err_sel).first.is_visible(timeout=300):
                            terminal_state = "login_error"
                            break
                    except Exception:
                        continue
                if terminal_state == "login_error":
                    err_text = ""
                    try:
                        err_text = await page.locator(err_sel).first.inner_text(timeout=1000)
                    except Exception:
                        pass
                    raise SessionError(
                        f"login failed (password error): {err_text or 'unknown'}. "
                        f"URL: {page.url}"
                    )

        if terminal_state is None:
            # Deadline hết mà chưa đạt terminal state → check lần cuối
            current_url = page.url.lower()
            if "mfa" in current_url:
                terminal_state = "mfa"
            elif "chatgpt.com" in current_url and "auth.openai.com" not in current_url:
                terminal_state = "logged_in"
            else:
                raise SessionError(
                    f"timeout waiting for post-password redirect "
                    f"({_POST_PASSWORD_DEADLINE}s). URL: {page.url}"
                )

        log(f"[session] post-password state: {terminal_state}")

        # Handle MFA
        if terminal_state == "mfa":
            if not secret:
                raise SessionError("account yêu cầu 2FA nhưng không có secret")

            log("[session] generating TOTP...")
            code = generate_code(secret)

            otp_input = None
            for sel in (
                'input[name="code"]',
                'input[inputmode="numeric"]',
                'input[autocomplete="one-time-code"]',
                'input[maxlength="6"]',
            ):
                try:
                    loc = page.locator(sel).first
                    if await loc.is_visible(timeout=8000):
                        otp_input = loc
                        break
                except Exception:
                    continue

            if not otp_input:
                raise SessionError(f"TOTP input not found. URL: {page.url}")

            await _replace_input_text(otp_input, code, delay=60)
            log(f"[session] TOTP code entered")
            await asyncio.sleep(0.5)

            await _submit_auth_form(otp_input, (
                'button[type="submit"]',
                'button:has-text("Continue")',
                'button:has-text("Verify")',
            ), step="MFA")

            await asyncio.sleep(3.0)
            log(f"[session] after MFA submit: {page.url.split('?')[0]}")

        # Step 5: đợi redirect về chatgpt.com + session cookies
        deadline = time.monotonic() + _SESSION_COOKIE_TIMEOUT_SECONDS
        session_ready = False
        while time.monotonic() < deadline:
            cookies = await ctx.cookies("https://chatgpt.com/")
            names = {c["name"] for c in cookies}
            has_session = (
                "__Secure-next-auth.session-token" in names
                or "__Secure-next-auth.session-token.0" in names
            )
            if has_session:
                log("[session] session cookies ready")
                session_ready = True
                break
            if "chatgpt.com" in page.url and "auth.openai.com" not in page.url:
                await asyncio.sleep(1.0)
                continue
            await asyncio.sleep(1.0)
        if not session_ready:
            try:
                final_content = (await page.content()).lower()
            except Exception:
                final_content = ""
            if any(marker in final_content for marker in _DEACTIVATED_ACCOUNT_PATTERNS):
                raise SessionError("account deactivated")
            raise SessionError(f"timeout waiting session cookies. URL: {page.url}")

        # Đảm bảo đang ở chatgpt.com
        if "chatgpt.com" not in page.url:
            await page.goto("https://chatgpt.com/", wait_until="domcontentloaded")
            await asyncio.sleep(2.0)

        # Step 6: fetch session JSON
        log("[session] fetching /api/auth/session...")
        session_data = await page.evaluate(_FETCH_SESSION_JS)
        if classify_account_check_error(str(session_data)) == "deactivated":
            raise SessionError("account deactivated")
        if not isinstance(session_data, dict) or not session_data.get("accessToken"):
            raise SessionError(
                f"session response invalid: {str(session_data)[:200]}"
            )

        log(
            f"[session] ✓ done — user: "
            f"{session_data.get('user', {}).get('email', '?')}"
        )

        payment_page = page
        if open_url_after_login:
            log("[session] opening requested payment link in a new browser tab...")
            try:
                payment_page = await ctx.new_page()
                await payment_page.goto(
                    open_url_after_login,
                    wait_until="domcontentloaded",
                    timeout=30000,
                )
            except Exception as exc:
                raise SessionError(
                    f"payment link navigation failed: {type(exc).__name__}"
                ) from exc
            log(
                "[session] payment link opened in a new tab: "
                f"{open_url_after_login.split('?', 1)[0]}"
            )

        if open_url_after_login and qr_capture_path is not None:
            captured_qr = await _capture_payment_qr(
                payment_page,
                out_path=qr_capture_path,
                log=log,
            )
            if captured_qr is not None:
                session_data["__payment_qr_path"] = str(captured_qr)

        # Capture cookies cho session-cookie-cache: gắn __cookies (đồng nhất với
        # get_session_pure_request) để SessionProvider lưu lại tái dùng. Caller
        # PHẢI strip __cookies trước khi broadcast SSE / persist DB.
        try:
            session_data["__cookies"] = await ctx.cookies("https://chatgpt.com/")
        except Exception as exc:
            log(f"[session] cookie export failed: {exc}")
        return session_data

    async def _run_camoufox_once(profile_dir: Any) -> dict[str, Any]:
        from camoufox.async_api import AsyncCamoufox

        extra_config: dict = {}
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
                min_width=w, max_width=w, min_height=h + chrome_h, max_height=h + chrome_h,
            )
            screen_kwargs["i_know_what_im_doing"] = True

        cf = AsyncCamoufox(
            headless=headless,
            persistent_context=True,
            user_data_dir=str(profile_dir),
            os=list(_CAMOUFOX_OS),
            viewport=viewport,
            locale="en-US",
            ignore_https_errors=tls_insecure,
            geoip=bool(proxy),
            config=extra_config,
            **screen_kwargs,
            **proxy_kwargs,
        )
        ctx = await cf.__aenter__()
        completed = False
        try:
            page = ctx.pages[0] if ctx.pages else await ctx.new_page()
            result = await _drive_session_flow(ctx, page)
            completed = True
            if debug_keep and open_url_after_login:
                async def _close_camoufox() -> None:
                    await cf.__aexit__(None, None, None)

                result["__browser_handle_id"] = _register_held_browser(_close_camoufox)
            return result
        finally:
            if debug_keep and completed:
                log("[session] debug: giữ browser mở — cancel job để đóng")
            else:
                try:
                    await cf.__aexit__(None, None, None)
                except Exception:
                    pass

    async def _run_chromium_once(
        profile_dir: Any,
        *,
        channel: str | None,
    ) -> dict[str, Any]:
        from playwright.async_api import async_playwright

        playwright = await async_playwright().start()
        completed = False
        try:
            ctx = await playwright.chromium.launch_persistent_context(
                user_data_dir=str(profile_dir),
                headless=headless,
                channel=channel,
                viewport=viewport,
                locale="en-US",
                ignore_https_errors=tls_insecure,
                **proxy_kwargs,
            )
            try:
                page = ctx.pages[0] if ctx.pages else await ctx.new_page()
                result = await _drive_session_flow(ctx, page)
                completed = True
                if debug_keep and open_url_after_login:
                    async def _close_chromium() -> None:
                        try:
                            await ctx.close()
                        finally:
                            await playwright.stop()

                    result["__browser_handle_id"] = _register_held_browser(_close_chromium)
                return result
            finally:
                if debug_keep and completed:
                    log("[session] debug: giữ browser mở — cancel job để đóng")
                else:
                    try:
                        await ctx.close()
                    except Exception:
                        pass
        finally:
            if not debug_keep or not completed:
                await playwright.stop()

    runners = {
        "camoufox": _run_camoufox_once,
        "chromium": lambda profile_dir: _run_chromium_once(
            profile_dir, channel=None,
        ),
        "chrome": lambda profile_dir: _run_chromium_once(
            profile_dir, channel=(settings.browser_channel or "").strip() or "chrome",
        ),
    }
    last_exc: BaseException | None = None
    try:
        for engine_index, engine in enumerate(engine_order):
            profile_dir, template_dir = _profile_bundle(engine)
            ensure_runtime_dirs(settings, extra=(profile_dir,))
            prepare_profile_dir(
                profile_dir=profile_dir,
                template_dir=template_dir,
                use_template=settings.browser_use_profile_template,
            )
            if engine_index > 0:
                log(f"[session] fallback browser engine: {engine}")

            for attempt in range(1, _LAUNCH_RETRY_MAX + 1):
                progress["password_submitted"] = False
                try:
                    return await runners[engine](profile_dir)
                except SessionError:
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
                        raise SessionError(
                            f"browser launch/driver error: {type(exc).__name__}: {exc}"
                        ) from exc
                    if progress["password_submitted"]:
                        log(
                            f"[session] lỗi sau khi đã submit password — "
                            f"không retry để tránh login spam: "
                            f"{type(exc).__name__}: {exc}"
                        )
                        raise SessionError(
                            f"lỗi sau submit password (không retry): {exc}"
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
                        f"[session] {err_kind} error "
                        f"(attempt {attempt}/{_LAUNCH_RETRY_MAX}): "
                        f"{type(exc).__name__}: {exc}"
                    )
                    if _is_browser_launch_error(exc) or attempt >= _LAUNCH_RETRY_MAX:
                        break
                    shutil.rmtree(profile_dir, ignore_errors=True)
                    prepare_profile_dir(
                        profile_dir=profile_dir,
                        template_dir=template_dir,
                        use_template=settings.browser_use_profile_template,
                    )
                    await asyncio.sleep(_LAUNCH_RETRY_BACKOFF)

            if engine_index + 1 < len(engine_order):
                log(
                    f"[session] {engine} failed before password submit — "
                    f"trying {engine_order[engine_index + 1]}"
                )
                continue

            if last_exc is not None and (
                _is_driver_dead_error(last_exc)
                or _is_context_destroyed_error(last_exc)
                or _is_network_error(last_exc)
                or _is_navigation_timeout(last_exc)
                or _is_navigation_abort_error(last_exc)
                or _is_browser_launch_error(last_exc)
            ):
                raise SessionError(
                    f"retryable error sau {_LAUNCH_RETRY_MAX} lần thử: {last_exc}"
                ) from last_exc

        raise SessionError("browser launch failed without specific error")
    finally:
        # Debug mode + headed → giữ profile để soi (không cleanup).
        # Fail mode (raise) trên 1 engine vẫn cần dọn profile của engine đó
        # nếu không giữ browser mở.
        if not debug_keep:
            for engine in engine_order:
                profile_dir, _ = _profile_bundle(engine)
                shutil.rmtree(profile_dir, ignore_errors=True)


async def get_session(
    *,
    email: str,
    password: str,
    secret: str | None = None,
    headless: bool = True,
    proxy: str | None = None,
    tls_insecure: bool = False,
    keep_browser_open: bool = False,
    open_url_after_login: str | None = None,
    capture_qr_path: str | Path | None = None,
    log: LogFn = print,
) -> dict[str, Any]:
    """Async: login ChatGPT → return full /api/auth/session JSON."""
    return await _get_session_browser(
        email=email,
        password=password,
        secret=secret,
        headless=headless,
        proxy=proxy,
        tls_insecure=tls_insecure,
        keep_browser_open=keep_browser_open,
        open_url_after_login=open_url_after_login,
        capture_qr_path=capture_qr_path,
        log=log,
    )


def get_session_sync(
    *,
    email: str,
    password: str,
    secret: str | None = None,
    headless: bool = True,
    proxy: str | None = None,
    tls_insecure: bool = False,
    keep_browser_open: bool = False,
    open_url_after_login: str | None = None,
    capture_qr_path: str | Path | None = None,
    log: LogFn = print,
) -> dict[str, Any]:
    """Sync wrapper."""
    return asyncio.run(get_session(
        email=email,
        password=password,
        secret=secret,
        headless=headless,
        proxy=proxy,
        tls_insecure=tls_insecure,
        keep_browser_open=keep_browser_open,
        open_url_after_login=open_url_after_login,
        capture_qr_path=capture_qr_path,
        log=log,
    ))


# ─────────────────────────────────────────────────────────────────────
# HTTP-only session fetch (no browser) — dùng khi đã có cookies sẵn từ Phase 2.
# ─────────────────────────────────────────────────────────────────────


def _cookies_to_header(cookies: Any) -> str:
    """Convert cookies (list[dict] | dict | None) → "name=value; name=value" string.

    Hỗ trợ 2 format:
      - list[dict]: Playwright/SignupResult format [{"name":..., "value":..., "domain":...}, ...]
        → chỉ giữ cookies thuộc domain chatgpt.com (hoặc rỗng).
      - dict: {name: value} flat.
    """
    if not cookies:
        return ""
    pairs: list[str] = []
    if isinstance(cookies, list):
        for c in cookies:
            if not isinstance(c, dict):
                continue
            name = c.get("name")
            value = c.get("value")
            if not name or value is None:
                continue
            domain = (c.get("domain") or "").lstrip(".").lower()
            # Chỉ giữ cookies dùng được cho chatgpt.com
            if domain and "chatgpt.com" not in domain:
                continue
            pairs.append(f"{name}={value}")
    elif isinstance(cookies, dict):
        for name, value in cookies.items():
            if value is None:
                continue
            pairs.append(f"{name}={value}")
    return "; ".join(pairs)


async def fetch_session_via_http(
    *,
    cookies: Any,
    proxy: str | None = None,
    timeout: float = 30.0,
    impersonate: str | None = None,
) -> dict[str, Any]:
    """GET https://chatgpt.com/api/auth/session bằng curl_cffi với cookies có sẵn.

    Args:
        cookies: list[dict] (Playwright format) hoặc dict {name: value}.
        proxy: HTTP/HTTPS proxy URL.
        timeout: Request timeout (seconds).
        impersonate: curl_cffi browser impersonation key. None → dùng
            ``CURL_IMPERSONATE_PRIMARY`` từ user_agent_profile (đồng bộ với UA
            persona, tránh mismatch TLS fingerprint).

    Returns:
        Full session JSON (dict) với accessToken không rỗng.

    Raises:
        SessionError: HTTP non-200, JSON parse fail, hoặc accessToken thiếu/rỗng.
    """
    from curl_cffi.requests import AsyncSession
    from user_agent_profile import (
        CURL_IMPERSONATE_PRIMARY,
        SEC_CH_UA,
        SEC_CH_UA_MOBILE,
        SEC_CH_UA_PLATFORM,
        WINDOWS_USER_AGENT,
    )

    if impersonate is None:
        impersonate = CURL_IMPERSONATE_PRIMARY

    cookie_header = _cookies_to_header(cookies)
    if not cookie_header:
        raise SessionError("không có cookie chatgpt.com để fetch session")

    proxies = {"http": proxy, "https": proxy} if proxy else None
    headers = {
        "Cookie": cookie_header,
        "Accept": "application/json",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": "https://chatgpt.com/",
        "User-Agent": WINDOWS_USER_AGENT,
        "sec-ch-ua": SEC_CH_UA,
        "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
    }

    async with AsyncSession(impersonate=impersonate, proxies=proxies) as sess:
        try:
            resp = await sess.get(
                "https://chatgpt.com/api/auth/session",
                headers=headers,
                timeout=timeout,
            )
        except Exception as exc:
            raise SessionError(f"network error: {exc}") from exc

    if resp.status_code != 200:
        full_body = resp.text or ""
        if classify_account_check_error(full_body) == "deactivated":
            raise SessionError("account deactivated")
        body = full_body[:200]
        raise SessionError(f"HTTP {resp.status_code}: {body}")

    try:
        data = resp.json()
    except Exception as exc:
        raise SessionError(f"JSON parse fail: {exc}") from exc

    if not isinstance(data, dict):
        raise SessionError(f"response không phải JSON object: {type(data).__name__}")

    if classify_account_check_error(str(data)) == "deactivated":
        raise SessionError("account deactivated")

    token = data.get("accessToken")
    if not isinstance(token, str) or not token.strip():
        raise SessionError("accessToken thiếu hoặc rỗng")

    return data


# JWT/access-token có prefix "eyJ". Scrub khỏi error message trước khi raise:
# check_plan log lỗi qua _job_log → broadcast SSE tới mọi client, nên token
# tuyệt đối không được lọt vào chuỗi lỗi.
_JWT_TOKEN_RE = re.compile(r"eyJ[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)*")


def _scrub_jwt(text: str) -> str:
    return _JWT_TOKEN_RE.sub("eyJ…[REDACTED]", text)


def _normalize_plan_name(raw: Any) -> str | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    s = raw.strip().lower()
    if s.startswith("chatgpt"):
        s = s[len("chatgpt"):]
    if s.endswith("plan"):
        s = s[:-len("plan")]
    return s or None


def _ensure_ascii_cacert() -> None:
    try:
        import os
        import shutil
        import tempfile
        import certifi

        current_cacert = certifi.where()
        try:
            current_cacert.encode("ascii")
            return
        except UnicodeEncodeError:
            pass

        temp_cacert = os.path.join(tempfile.gettempdir(), "cacert.pem")
        if not os.path.exists(temp_cacert) or os.path.getsize(temp_cacert) != os.path.getsize(current_cacert):
            shutil.copyfile(current_cacert, temp_cacert)
        os.environ["CURL_CA_BUNDLE"] = temp_cacert
        os.environ["SSL_CERT_FILE"] = temp_cacert
        certifi.where = lambda: temp_cacert
    except Exception:
        pass


def _parse_entitlement_plan(data: dict[str, Any]) -> dict[str, Any]:
    """Parse entitlement block từ /backend-api/accounts/check/v4 → plan dict.

    Shape thực tế từ OpenAI API:
        accounts: {
            <account_id>: {
                account: { plan_type: "free"|"plus"|"team", plan_display_name: ... },
                entitlement: { subscription_plan, has_active_subscription, expires_at, ... }
            },
            default: { ... }
        }
        account_ordering: [<primary_account_id>, ...]

    Quy tắc phân loại:
    - Nếu has_active_subscription = True: gói là subscription_plan (e.g. plus/team/pro).
      is_plus = True nếu gói đúng là "plus".
    - Nếu has_active_subscription = False: subscription đã hết hạn hoặc chưa từng mua.
      Gói thực tế hiện tại là "free", is_plus = False.
    - Nếu tài khoản có nhiều account (Personal + Workspace), kiểm tra xem có workspace nào
      đang active không để phản ánh đúng quyền lợi của user.
    """
    blank = {"plan": None, "is_plus": False, "has_active_subscription": False, "expires": None, "is_trial": False}
    if not isinstance(data, dict):
        return blank
    accounts = data.get("accounts")
    if not isinstance(accounts, dict) or not accounts:
        return blank

    acct = None
    ordering = data.get("account_ordering")
    if isinstance(ordering, list) and ordering:
        first_id = ordering[0]
        if first_id in accounts and isinstance(accounts[first_id], dict):
            acct = accounts[first_id]
    if not isinstance(acct, dict):
        acct = accounts.get("default")
    if not isinstance(acct, dict):
        acct = next((v for v in accounts.values() if isinstance(v, dict)), None)
    if not isinstance(acct, dict):
        return blank

    ent = acct.get("entitlement") if isinstance(acct.get("entitlement"), dict) else {}
    account_info = acct.get("account") if isinstance(acct.get("account"), dict) else {}

    raw_sub_plan = ent.get("subscription_plan")
    sub_label = _normalize_plan_name(raw_sub_plan)

    has_active = bool(ent.get("has_active_subscription"))
    expires_at = ent.get("expires_at")
    is_trial = bool(
        account_info.get("is_trial")
        or ent.get("trial")
        or acct.get("is_trial")
        or str(account_info.get("trial_state") or "").strip().lower() in {"active", "in_trial", "true"}
    )

    if has_active:
        plan = sub_label or _normalize_plan_name(account_info.get("plan_type")) or "plus"
        return {
            "plan": plan,
            "is_plus": (plan == "plus"),
            "has_active_subscription": True,
            "expires": expires_at,
            "is_trial": is_trial,
        }

    # Quét các account khác trong accounts (nếu có workspace Team/Plus đang active)
    for acc_id, candidate in accounts.items():
        if candidate is acct or not isinstance(candidate, dict):
            continue
        cand_ent = candidate.get("entitlement")
        if isinstance(cand_ent, dict) and bool(cand_ent.get("has_active_subscription")):
            cand_sub = _normalize_plan_name(cand_ent.get("subscription_plan"))
            cand_acc = candidate.get("account") if isinstance(candidate.get("account"), dict) else {}
            cand_plan = cand_sub or _normalize_plan_name(cand_acc.get("plan_type")) or "plus"
            cand_trial = bool(
                cand_acc.get("is_trial")
                or cand_ent.get("trial")
                or candidate.get("is_trial")
                or str(cand_acc.get("trial_state") or "").strip().lower() in {"active", "in_trial", "true"}
            )
            return {
                "plan": cand_plan,
                "is_plus": (cand_plan == "plus"),
                "has_active_subscription": True,
                "expires": cand_ent.get("expires_at"),
                "is_trial": cand_trial,
            }

    # Không có subscription active → Tài khoản hiện tại là FREE
    return {
        "plan": "free",
        "is_plus": False,
        "has_active_subscription": False,
        "expires": expires_at,
        "is_trial": is_trial,
    }


def _parse_codex_weekly_usage(data: dict[str, Any]) -> dict[str, Any]:
    """Parse the weekly Codex window returned by ``/wham/usage``."""
    if not isinstance(data, dict):
        raise SessionError("usage response is not an object")
    rate_limit = data.get("rate_limit")
    if not isinstance(rate_limit, dict):
        raise SessionError("usage response missing rate_limit")

    weekly = rate_limit.get("secondary_window")
    if not isinstance(weekly, dict):
        weekly = None
    if weekly is None:
        candidates = (
            rate_limit.get("primary_window"),
            rate_limit.get("secondary_window"),
        )
        weekly = next(
            (
                window for window in candidates
                if isinstance(window, dict)
                and isinstance(window.get("limit_window_seconds"), (int, float))
                and not isinstance(window.get("limit_window_seconds"), bool)
                and 6 * 86400 <= float(window["limit_window_seconds"]) <= 8 * 86400
            ),
            None,
        )
    if not isinstance(weekly, dict):
        raise SessionError("weekly usage window is unavailable")

    window_seconds = weekly.get("limit_window_seconds")
    if (
        not isinstance(window_seconds, (int, float))
        or isinstance(window_seconds, bool)
        or not 6 * 86400 <= float(window_seconds) <= 8 * 86400
    ):
        raise SessionError("secondary usage window is not weekly")

    used_percent = weekly.get("used_percent")
    if (
        not isinstance(used_percent, (int, float))
        or isinstance(used_percent, bool)
        or not 0 <= float(used_percent) <= 100
    ):
        raise SessionError("weekly usage percent is invalid")

    used = round(float(used_percent), 2)
    return {
        "used_percent": used,
        "remaining_percent": round(100.0 - used, 2),
        "limit_window_seconds": int(window_seconds),
        "reset_after_seconds": weekly.get("reset_after_seconds"),
        "reset_at": weekly.get("reset_at"),
    }


async def fetch_codex_weekly_usage(
    *,
    access_token: str,
    account_id: str | None = None,
    cookies: Any = None,
    proxy: str | None = None,
    timeout: float = 20.0,
    impersonate: str | None = None,
) -> dict[str, Any]:
    """Fetch the weekly Codex usage window and return used/remaining percent."""
    from curl_cffi.requests import AsyncSession
    from user_agent_profile import (
        CURL_IMPERSONATE_PRIMARY,
        SEC_CH_UA,
        SEC_CH_UA_MOBILE,
        SEC_CH_UA_PLATFORM,
        WINDOWS_USER_AGENT,
    )

    if not isinstance(access_token, str) or not access_token.strip():
        raise SessionError("usage check requires access_token")
    if impersonate is None:
        impersonate = CURL_IMPERSONATE_PRIMARY

    target = "/backend-api/wham/usage"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Origin": "https://chatgpt.com",
        "Referer": "https://chatgpt.com/",
        "User-Agent": WINDOWS_USER_AGENT,
        "sec-ch-ua": SEC_CH_UA,
        "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "x-openai-target-path": target,
        "x-openai-target-route": target,
        "OAI-Language": "en-US",
    }
    if isinstance(account_id, str) and account_id.strip():
        headers["ChatGPT-Account-Id"] = account_id.strip()
    cookie_header = _cookies_to_header(cookies) if cookies else ""
    if cookie_header:
        headers["Cookie"] = cookie_header

    proxies = {"http": proxy, "https": proxy} if proxy else None
    async with AsyncSession(impersonate=impersonate, proxies=proxies) as session:
        try:
            response = await session.get(
                f"https://chatgpt.com{target}",
                headers=headers,
                timeout=timeout,
            )
        except Exception as exc:
            raise SessionError(f"usage network error: {_scrub_jwt(str(exc))}") from exc

    if response.status_code != 200:
        raise SessionError(f"usage check HTTP {response.status_code}")
    try:
        data = response.json()
    except Exception as exc:
        raise SessionError(f"usage JSON parse fail: {_scrub_jwt(str(exc))}") from exc
    return _parse_codex_weekly_usage(data)


def _parse_account_usage(data: dict[str, Any]) -> dict[str, Any]:
    """Parse usage/rate limit block từ /backend-api/wham/usage."""
    if not isinstance(data, dict):
        raise SessionError("usage response is not an object")
    rate_limit = data.get("rate_limit")
    if not isinstance(rate_limit, dict):
        raise SessionError("usage response missing rate_limit")

    allowed = bool(rate_limit.get("allowed", True))
    limit_reached = bool(rate_limit.get("limit_reached", False))

    window = rate_limit.get("secondary_window") or rate_limit.get("primary_window")
    used_percent = 0.0
    if isinstance(window, dict) and "used_percent" in window:
        try:
            val = float(window["used_percent"])
            if not isinstance(window["used_percent"], bool) and 0 <= val <= 100:
                used_percent = round(val, 1)
        except (ValueError, TypeError):
            pass

    remaining_percent = max(0.0, round(100.0 - used_percent, 1))

    if limit_reached or not allowed:
        status_text = "Chạm giới hạn"
    elif used_percent > 0:
        status_text = f"Còn {remaining_percent}%"
    else:
        status_text = "Còn 100%"

    return {
        "allowed": allowed,
        "limit_reached": limit_reached,
        "used_percent": used_percent,
        "remaining_percent": remaining_percent,
        "status_text": status_text,
    }


async def fetch_account_usage(
    *,
    access_token: str,
    account_id: str | None = None,
    cookies: Any = None,
    proxy: str | None = None,
    timeout: float = 15.0,
    impersonate: str | None = None,
) -> dict[str, Any]:
    """Fetch user rate limits & usage quota từ /backend-api/wham/usage."""
    _ensure_ascii_cacert()
    from curl_cffi.requests import AsyncSession
    from user_agent_profile import (
        CURL_IMPERSONATE_PRIMARY,
        SEC_CH_UA,
        SEC_CH_UA_MOBILE,
        SEC_CH_UA_PLATFORM,
        WINDOWS_USER_AGENT,
    )

    if not isinstance(access_token, str) or not access_token.strip():
        raise SessionError("usage check requires access_token")
    if impersonate is None:
        impersonate = CURL_IMPERSONATE_PRIMARY

    target = "/backend-api/wham/usage"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Origin": "https://chatgpt.com",
        "Referer": "https://chatgpt.com/",
        "User-Agent": WINDOWS_USER_AGENT,
        "sec-ch-ua": SEC_CH_UA,
        "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "x-openai-target-path": target,
        "x-openai-target-route": target,
        "OAI-Language": "en-US",
    }
    if isinstance(account_id, str) and account_id.strip():
        headers["ChatGPT-Account-Id"] = account_id.strip()
    cookie_header = _cookies_to_header(cookies) if cookies else ""
    if cookie_header:
        headers["Cookie"] = cookie_header

    proxies = {"http": proxy, "https": proxy} if proxy else None
    async with AsyncSession(impersonate=impersonate, proxies=proxies) as session:
        try:
            response = await session.get(
                f"https://chatgpt.com{target}",
                headers=headers,
                timeout=timeout,
            )
        except Exception as exc:
            raise SessionError(f"usage network error: {_scrub_jwt(str(exc))}") from exc

    if response.status_code != 200:
        raise SessionError(f"usage check HTTP {response.status_code}")
    try:
        data = response.json()
    except Exception as exc:
        raise SessionError(f"usage JSON parse fail: {_scrub_jwt(str(exc))}") from exc
    return _parse_account_usage(data)


async def fetch_account_entitlement(
    *,
    access_token: str,
    cookies: Any = None,
    proxy: str | None = None,
    timeout: float = 20.0,
    impersonate: str | None = None,
) -> dict[str, Any]:
    """GET /backend-api/accounts/check/v4 → đọc entitlement plan LIVE.

    Khác ``fetch_session_via_http`` (đọc ``/api/auth/session`` cache, lag so với
    subscription thật): endpoint này đọc entitlement trực tiếp từ backend nên
    phản ánh upgrade Plus ngay cả khi accessToken được mint *trước* lúc upgrade.

    Auth = Bearer accessToken với **header recipe backend-api đầy đủ** (Origin +
    x-openai-target-path/route + OAI-Language + UA/sec-ch-ua persona). Recipe
    tối giản (chỉ Bearer + UA) bị Cloudflare chặn 403 — đã verify thực tế.

    Args:
        access_token: JWT accessToken (login token đủ để auth Bearer).
        cookies: optional, gắn thêm Cookie header (verify cho thấy KHÔNG cần,
            Bearer-only đã 200; giữ optional để dự phòng).
        proxy: HTTP/HTTPS proxy URL (proxy đã mint token); None = IP trần (đã
            verify no-proxy vẫn 200, không bắt buộc route qua proxy).
        timeout: request timeout (giây). Mặc định 20s (KHÁC ``fetch_session_via_http``
            mặc định 30s — đừng nhầm).
        impersonate: curl_cffi impersonate key. None → persona primary.

    Returns:
        dict ``{plan, is_plus, has_active_subscription, expires}`` qua
        ``_parse_entitlement_plan``.

    Raises:
        SessionError: token rỗng, network error, non-200, hoặc JSON parse fail.
            Error message KHÔNG kèm response body (endpoint identity/oauth có thể
            echo token vào body) và đã scrub mọi chuỗi prefix ``eyJ``.
    """
    _ensure_ascii_cacert()
    from curl_cffi.requests import AsyncSession
    from user_agent_profile import (
        CURL_IMPERSONATE_PRIMARY,
        SEC_CH_UA,
        SEC_CH_UA_MOBILE,
        SEC_CH_UA_PLATFORM,
        WINDOWS_USER_AGENT,
    )

    if not isinstance(access_token, str) or not access_token.strip():
        raise SessionError("access_token thiếu hoặc rỗng")

    if impersonate is None:
        impersonate = CURL_IMPERSONATE_PRIMARY

    url = "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27"
    target = "/backend-api/accounts/check/v4-2023-04-27"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "*/*",
        "Accept-Language": "en-IN,en;q=0.9",
        "Origin": "https://chatgpt.com",
        "Referer": "https://chatgpt.com/",
        "User-Agent": WINDOWS_USER_AGENT,
        "sec-ch-ua": SEC_CH_UA,
        "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
        "x-openai-target-path": target,
        "x-openai-target-route": target,
        "OAI-Language": "en-IN",
    }
    cookie_header = _cookies_to_header(cookies) if cookies else ""
    if cookie_header:
        headers["Cookie"] = cookie_header

    proxies = {"http": proxy, "https": proxy} if proxy else None
    async with AsyncSession(impersonate=impersonate, proxies=proxies) as sess:
        try:
            resp = await sess.get(url, headers=headers, timeout=timeout)
        except Exception as exc:
            raise SessionError(f"network error: {_scrub_jwt(str(exc))}") from exc

    # Chỉ dùng body để phân loại cục bộ; KHÔNG đưa body vào lỗi/log vì endpoint
    # identity/oauth có thể echo token hoặc dữ liệu tài khoản.
    if resp.status_code != 200:
        if classify_account_check_error(resp.text or "") == "deactivated":
            raise SessionError("account deactivated")
        raise SessionError(f"HTTP {resp.status_code}")

    try:
        data = resp.json()
    except Exception as exc:
        raise SessionError(f"JSON parse fail: {_scrub_jwt(str(exc))}") from exc

    if classify_account_check_error(str(data)) == "deactivated":
        raise SessionError("account deactivated")

    return _parse_entitlement_plan(data)


# ─────────────────────────────────────────────────────────────────────
# Pure-request login (no browser) — full protocol for existing accounts
# ─────────────────────────────────────────────────────────────────────


def _resolve_login_flow(explicit: str | None) -> str:
    """Resolve flow login cho ``get_session_pure_request``.

    Ưu tiên: ``explicit`` (caller truyền) > Settings Store ``session.login_flow``
    > default ``"anti409"`` (flow dev — warm + pre-set oai-did +
    auth_session_logging_id + sentinel ``password_verify`` + assume-password,
    chống HTTP 409 invalid_state). DB chưa mở/lỗi → fallback default, KHÔNG raise.

    ``"legacy"`` = flow cũ (``_step_auth_url`` + authorize/continue fallback +
    sentinel ``login``) — dò được passwordless/OTP khi landing không rõ.
    """
    if explicit in ("legacy", "anti409"):
        return explicit
    try:
        from db import get_engine, get_settings_repo
        val = get_settings_repo(get_engine()).get("session.login_flow")
        if val in ("legacy", "anti409"):
            return val
    except Exception:  # noqa: BLE001 — DB chưa sẵn sàng → dùng default
        pass
    return "anti409"


def _cookie_value_for_domains(
    cookies: Any,
    name: str,
    *domains: str,
) -> str | None:
    """Read a named cookie without triggering duplicate-domain conflicts."""
    preferred_domains = tuple(
        domain.lstrip(".").strip().casefold()
        for domain in domains
        if isinstance(domain, str) and domain.strip()
    )
    candidates: list[tuple[str, str, str]] = []
    try:
        cookie_jar = getattr(cookies, "jar", cookies)
        for cookie in cookie_jar:
            cookie_name = str(getattr(cookie, "name", "") or "")
            cookie_value = str(getattr(cookie, "value", "") or "")
            if cookie_name != name or not cookie_value:
                continue
            cookie_domain = str(getattr(cookie, "domain", "") or "")
            cookie_path = str(getattr(cookie, "path", "") or "/")
            candidates.append(
                (cookie_domain.lstrip(".").casefold(), cookie_path, cookie_value)
            )
    except (AttributeError, TypeError):
        return None

    for preferred_domain in preferred_domains:
        for cookie_domain, cookie_path, cookie_value in candidates:
            if cookie_domain == preferred_domain and cookie_path == "/":
                return cookie_value
        for cookie_domain, _cookie_path, cookie_value in candidates:
            if cookie_domain == preferred_domain:
                return cookie_value
    return candidates[0][2] if len(candidates) == 1 else None


def _is_cloudflare_challenge(resp: Any) -> bool:
    """Detect Cloudflare challenge or mitigation block on response."""
    if resp is None:
        return False
    try:
        headers = getattr(resp, "headers", {}) or {}
        cf_mitigated = headers.get("cf-mitigated", "")
        if str(cf_mitigated).strip().casefold() == "challenge":
            return True
        status = getattr(resp, "status_code", 0)
        text = str(getattr(resp, "text", "") or "")[:4096].casefold()
        markers = (
            "cf-chl",
            "/cdn-cgi/challenge",
            "challenge-platform",
            "just a moment",
            "<title>access denied",
            "<title>blocked",
            "attention required",
        )
        if any(m in text for m in markers):
            return True
        if status in (403, 503) and ("cloudflare" in text or "cf-ray" in headers):
            return True
    except Exception:
        pass
    return False


async def get_session_pure_request(
    *,
    email: str,
    password: str,
    secret: str | None = None,
    proxy: str | None = None,
    mail_provider: Any = None,
    login_flow: str | None = None,
    log: LogFn = print,
) -> dict[str, Any]:
    """Login ChatGPT via pure HTTP requests → return /api/auth/session JSON.

    Protocol flow (no browser):
      1. chatgpt.com CSRF + signin/openai → authorize URL
      2. OAuth init → device_id
      3. Sentinel token
      4. authorize/continue (email)
      5. IF passwordless → OTP verify (requires mail_provider)
         IF password → password/verify
      6. MFA verify (if needed, using TOTP secret)
      7. Follow redirect chain → callback
      8. Consume callback → session_token
      9. GET /api/auth/session → full JSON
    """
    flow_mode = _resolve_login_flow(login_flow)
    log(f"[session-req] login_flow={flow_mode}")

    # Primary pure request flow via Chrome 142 macOS profile + pure Sentinel PoW (Tool yunxi / 2026-09 standard)
    if password:
        import logging
        from chatgpt_auth import create_async_client, login_pure_request_with_payload
        from chatgpt_auth.errors import LoginError

        _auth_logger = logging.getLogger("session_phase.chatgpt_login")
        client = create_async_client(proxy=proxy, timeout=30.0)
        try:
            bundle, session_payload = await login_pure_request_with_payload(
                email=email,
                password=password,
                totp_secret=secret,
                http_client=client,
                logger=_auth_logger,
                log_fn=log,
            )
            session_data = dict(session_payload)
            session_data["accessToken"] = bundle.access_token
            session_data["access_token"] = bundle.access_token
            cookies_export: list[dict[str, Any]] = []
            try:
                for ck in client.cookies.jar:
                    cookies_export.append({
                        "name": ck.name,
                        "value": ck.value,
                        "domain": ck.domain,
                        "path": ck.path or "/",
                        "secure": bool(ck.secure),
                        "httpOnly": ck.name.startswith("__Host-") or ck.name.startswith("__Secure-"),
                        "sameSite": "Lax",
                        "expires": ck.expires if ck.expires else -1,
                    })
            except Exception:
                pass
            session_data["__cookies"] = cookies_export
            return session_data
        except LoginError as exc:
            reason = getattr(exc, "reason", "login_failed")
            msg = getattr(exc, "message", None) or str(exc)
            if reason == "account_locked" or "deactivated" in msg.lower():
                raise SessionError(f"account deactivated: {msg}") from exc
            if reason == "invalid_credential":
                raise SessionError(f"invalid_password: {msg}") from exc
            if reason == "push_auth_required":
                raise SessionError("push_auth_required: thiết bị yêu cầu phê duyệt đăng nhập (Push Auth)") from exc
            if reason == "mfa_required":
                raise SessionError(f"2fa_failed: {msg}") from exc
            if "cloudflare" in msg.lower() or (exc.diagnostic and exc.diagnostic.get("cf_mitigated")):
                raise SessionError(f"Cloudflare challenge detected (HTTP 403): {msg}") from exc
            raise SessionError(f"login failed: {msg}") from exc
        finally:
            try:
                await client.close()
            except Exception:
                pass

    from request_phase import (
        _create_session,
        _step_csrf,
        _step_auth_url,
        _get_sentinel_token,
        _common_headers,
        _step_authorize_continue,
        _step_follow_redirects,
        _consume_callback,
        _get_session_tokens,
        _step_resend_otp,
        _step_verify_otp,
        _is_rotatable_error,
        _IMPERSONATE_CANDIDATES,
        RequestPhaseError,
        USER_AGENT,
    )
    from user_agent_profile import (
        SEC_CH_UA as _SEC_CH_UA,
        SEC_CH_UA_MOBILE as _SEC_CH_UA_MOBILE,
        SEC_CH_UA_PLATFORM as _SEC_CH_UA_PLATFORM,
    )
    from totp_helper import generate_code as _generate_totp
    from urllib.parse import urljoin
    import asyncio as _asyncio
    from datetime import datetime, timezone

    def _run_async_poll(provider, recipient, started_at, log) -> str:
        """Poll OTP from async mail provider inside a sync thread (new event loop)."""
        loop = _asyncio.new_event_loop()
        try:
            return loop.run_until_complete(
                provider.poll_otp(
                    recipient=recipient,
                    started_at=started_at,
                    timeout_seconds=180.0,
                    poll_interval_seconds=4.0,
                    log=log,
                )
            )
        finally:
            loop.close()

    def _sync() -> dict[str, Any]:
        flow_mode = _resolve_login_flow(login_flow)
        log(f"[session-req] login_flow={flow_mode}")
        # ─────────────────────────────────────────────────────────────
        # Bootstrap helper: CSRF + signin/openai + GET /authorize.
        # `use_login_hint=True` → server có thể auto-redirect thẳng tới
        # /log-in/password (fast path khi account đã tồn tại + có password).
        # `use_login_hint=False` → state machine ở mức "đợi email submission",
        # cần authorize/continue để rẽ flow (slow path / fallback).
        # ─────────────────────────────────────────────────────────────
        def _do_bootstrap(*, use_login_hint: bool) -> tuple[Any, str, str, str, str]:
            """Returns (session, device_id, session_id, auth_url, landing_url).

            Có TLS fingerprint rotation. Raise nếu bootstrap fail trên mọi
            impersonate candidate.
            """
            last_exc: BaseException | None = None
            for idx, imp in enumerate(_IMPERSONATE_CANDIDATES):
                sess = _create_session(proxy=proxy, impersonate=imp)
                try:
                    if idx > 0:
                        log(f"[session-req] TLS rotation: retrying with impersonate={imp}")
                    did = str(uuid.uuid4())
                    sid = str(uuid.uuid4())
                    if flow_mode == "anti409":
                        # ── Anti-detection & Anti-403 (chatgpt-login-flow-porting-guide) ──
                        # 1. Seed oai-did cookie on .chatgpt.com /
                        try:
                            sess.cookies.set("oai-did", did, domain=".chatgpt.com", path="/")
                        except Exception:
                            try:
                                sess.cookies.set("oai-did", did, domain="chatgpt.com")
                            except Exception:
                                pass

                        # 2. Prime navigation GET https://chatgpt.com/ (clean, no ad-hoc backend-anon calls)
                        # NOTE: warming chatgpt: backend-anon/accounts/check (deprecated — real browsers don't hit this pre-login)
                        prime_headers = {
                            "User-Agent": USER_AGENT,
                            "sec-ch-ua": _SEC_CH_UA,
                            "sec-ch-ua-mobile": _SEC_CH_UA_MOBILE,
                            "sec-ch-ua-platform": _SEC_CH_UA_PLATFORM,
                            "Accept-Language": "en-US,en;q=0.9",
                            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                            "Sec-Fetch-Site": "none",
                            "Sec-Fetch-Mode": "navigate",
                            "Sec-Fetch-User": "?1",
                            "Sec-Fetch-Dest": "document",
                            "Upgrade-Insecure-Requests": "1",
                            "oai-device-id": did,
                        }
                        try:
                            prime_resp = sess.get(
                                "https://chatgpt.com/",
                                headers=prime_headers,
                                timeout=20,
                                allow_redirects=True,
                            )
                            if _is_cloudflare_challenge(prime_resp):
                                raise SessionError(
                                    f"Cloudflare challenge detected at prime (HTTP {prime_resp.status_code})"
                                )
                        except SessionError:
                            raise
                        except Exception as _p_exc:
                            log(f"[session-req] prime non-fatal: {_p_exc}")

                        # Server có thể re-issue oai-did sau warming → đọc lại làm
                        # device_id chuẩn (cookie ↔ ext-oai-did query phải MATCH).
                        did = _cookie_value_for_domains(
                            sess.cookies,
                            "oai-did",
                            "chatgpt.com",
                            "openai.com",
                        ) or did

                        # 3. CSRF with unified device_id and session_id
                        csrf_headers = {
                            "User-Agent": USER_AGENT,
                            "sec-ch-ua": _SEC_CH_UA,
                            "sec-ch-ua-mobile": _SEC_CH_UA_MOBILE,
                            "sec-ch-ua-platform": _SEC_CH_UA_PLATFORM,
                            "Accept-Language": "en-US,en;q=0.9",
                            "Accept": "application/json",
                            "Origin": "https://chatgpt.com",
                            "Referer": "https://chatgpt.com/",
                            "oai-device-id": did,
                            "oai-session-id": sid,
                        }
                        csrf_resp = sess.get(
                            "https://chatgpt.com/api/auth/csrf",
                            headers=csrf_headers,
                            timeout=20,
                        )
                        if _is_cloudflare_challenge(csrf_resp):
                            raise SessionError(
                                f"Cloudflare challenge detected at csrf (HTTP {csrf_resp.status_code})"
                            )
                        if csrf_resp.status_code != 200:
                            raise SessionError(f"csrf fetch failed: HTTP {csrf_resp.status_code}")
                        csrf_json = csrf_resp.json() or {}
                        csrf = str(csrf_json.get("csrfToken") or "").strip()
                        if not csrf:
                            raise SessionError("csrfToken empty or missing in response")

                        # 4. Signin POST https://chatgpt.com/api/auth/signin/openai
                        from urllib.parse import urlencode as _urlencode
                        _au_params = {
                            "prompt": "login",
                            "ext-passkey-client-capabilities": "01001",
                            "ext-oai-did": did,
                            "auth_session_logging_id": sid,
                            "screen_hint": "login_or_signup",
                        }
                        if use_login_hint:
                            _au_params["login_hint"] = email
                        _au_headers = {
                            "User-Agent": USER_AGENT,
                            "sec-ch-ua": _SEC_CH_UA,
                            "sec-ch-ua-mobile": _SEC_CH_UA_MOBILE,
                            "sec-ch-ua-platform": _SEC_CH_UA_PLATFORM,
                            "Accept-Language": "en-US,en;q=0.9",
                            "Accept": "application/json",
                            "Content-Type": "application/x-www-form-urlencoded",
                            "Origin": "https://chatgpt.com",
                            "Referer": "https://chatgpt.com/",
                            "oai-device-id": did,
                            "oai-session-id": sid,
                        }
                        _au_resp = sess.post(
                            "https://chatgpt.com/api/auth/signin/openai?" + _urlencode(_au_params),
                            headers=_au_headers,
                            data={
                                "csrfToken": csrf,
                                "callbackUrl": "https://chatgpt.com/",
                                "json": "true",
                            },
                            timeout=30,
                        )
                        if _is_cloudflare_challenge(_au_resp):
                            raise SessionError(
                                f"Cloudflare challenge detected at signin (HTTP {_au_resp.status_code})"
                            )
                        if _au_resp.status_code != 200:
                            raise SessionError(f"signin/openai failed: HTTP {_au_resp.status_code}")
                        au = (_au_resp.json() or {}).get("url", "")
                        if not au:
                            raise SessionError("signin/openai: no URL in response")
                        parsed_au = urlparse(au)
                        if parsed_au.scheme.lower() != "https" or (parsed_au.hostname or "").lower() != "auth.openai.com":
                            raise SessionError(f"signin/openai returned non-auth domain: {au[:100]}")
                        log(f"[session-req] auth URL: {au[:80]}...")
                    else:
                        # ── Legacy flow main: dùng _step_auth_url helper ──────
                        csrf = _step_csrf(sess, log)
                        au = _step_auth_url(
                            sess, csrf, log,
                            device_id=did,
                            login_hint=email if use_login_hint else "",
                        )
                    # OAuth init: GET authorize MIMIC top-level navigation của browser
                    # (sec-fetch-* + upgrade-insecure-requests + referer chatgpt.com/).
                    # GET authorize KHÔNG có sec-fetch-mode=navigate sẽ bị xử như
                    # XHR và trả thẳng SPA 200 thay vì 302 sang /log-in/password
                    # (xác minh qua HAR thật, RID 424).
                    r = sess.get(
                        au,
                        headers={
                            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                            "Accept-Language": "en-US,en;q=0.9",
                            "Accept-Encoding": "gzip, deflate, br, zstd",
                            "Referer": "https://chatgpt.com/",
                            "Connection": "keep-alive",
                            "Upgrade-Insecure-Requests": "1",
                            "Sec-Fetch-Dest": "document",
                            "Sec-Fetch-Mode": "navigate",
                            "Sec-Fetch-Site": "cross-site",
                            "Sec-Fetch-User": "?1",
                            "User-Agent": USER_AGENT,
                            "sec-ch-ua": _SEC_CH_UA,
                            "sec-ch-ua-mobile": _SEC_CH_UA_MOBILE,
                            "sec-ch-ua-platform": _SEC_CH_UA_PLATFORM,
                            "oai-device-id": did,
                        },
                        timeout=30,
                        allow_redirects=True,
                    )
                    if _is_cloudflare_challenge(r):
                        raise SessionError(f"Cloudflare challenge detected at authorize (HTTP {r.status_code})")
                    land = str(getattr(r, "url", "") or au)
                    did = _cookie_value_for_domains(
                        sess.cookies,
                        "oai-did",
                        "openai.com",
                        "chatgpt.com",
                    ) or did
                    return sess, did, sid, au, land
                except Exception as e:
                    last_exc = e
                    try:
                        sess.close()
                    except Exception:
                        pass
                    # Rotate impersonate khi: TLS handshake fail HOẶC CF 403
                    # flag JA3 (cùng impersonate retry vô ích — phải đổi
                    # fingerprint Chrome trong _IMPERSONATE_CANDIDATES).
                    if _is_rotatable_error(e) and idx < len(_IMPERSONATE_CANDIDATES) - 1:
                        log(
                            f"[session-req] fingerprint rotation: "
                            f"{type(e).__name__} → next impersonate"
                        )
                        continue
                    # Convert RequestPhaseError → SessionError tại boundary để
                    # caller (upi_runner) chỉ cần catch SessionError. Trước fix
                    # này, RequestPhaseError từ _step_auth_url leak qua loop login
                    # retry và thành unhandled exception (không match
                    # `except SessionError`).
                    if isinstance(e, RequestPhaseError):
                        raise SessionError(f"bootstrap failed: {e}") from e
                    raise
            if last_exc:
                if isinstance(last_exc, RequestPhaseError):
                    raise SessionError(f"bootstrap failed: {last_exc}") from last_exc
                raise last_exc
            raise SessionError("bootstrap failed: all impersonate candidates exhausted")

        def _detect_flow_from_landing(land_url: str) -> str:
            """Map landing URL → 'password' | 'otp' | '' (undetermined)."""
            if "/log-in/password" in land_url:
                return "password"
            if "/email-verification" in land_url:
                return "otp"
            # MFA challenge ngụ ý đã qua password (cookie còn sống) → branch password.
            if "/mfa-challenge" in land_url:
                return "password"
            # Passkey enrollment → account đã authed, skip passkey lấy callback.
            if "/login-enroll-passkey" in land_url:
                return "password"
            return ""

        # Fast path: bootstrap WITH login_hint
        session, device_id, session_id, auth_url, landing = _do_bootstrap(use_login_hint=True)
        log(f"[session-req] landing: {landing[:90]!r}")

        page_type = ""
        continue_url = ""
        flow = _detect_flow_from_landing(landing)

        # Fallback: landing không xác định → re-bootstrap KHÔNG login_hint
        if not flow:
            log("[session-req] landing không xác định — re-bootstrap KHÔNG login_hint để gọi authorize/continue clean...")
            try:
                session.close()
            except Exception:
                pass
            session, device_id, session_id, auth_url, landing = _do_bootstrap(use_login_hint=False)
            log(f"[session-req] retry landing: {landing[:90]!r}")
            flow = _detect_flow_from_landing(landing)

        if not flow:
            # State machine giờ clean (no login_hint preset) → authorize/continue
            # an toàn để drive flow. Vẫn catch 409 invalid_state để báo lỗi rõ.
            log("[session-req] resolve qua authorize/continue (no login_hint)...")
            ac_sentinel = _get_sentinel_token(session, device_id, "login", log)
            try:
                ac_data = _step_authorize_continue(
                    session, email, ac_sentinel,
                    screen_hint="login",
                    referer="https://auth.openai.com/log-in",
                    device_id=device_id,
                    log=log,
                )
            except RequestPhaseError as exc:
                msg = str(exc)
                if "HTTP 409" in msg and "invalid_state" in msg:
                    raise SessionError(
                        "authorize/continue bị OpenAI từ chối với HTTP 409 invalid_state. "
                        "State machine không đồng bộ — có thể do proxy chậm khiến state hết hạn "
                        "hoặc account đang ở flow đặc biệt (passwordless/blocked). "
                        f"Detail: {msg}"
                    ) from exc
                raise SessionError(f"authorize/continue failed: {msg}") from exc
            ac_page = ac_data.get("page", {}) if isinstance(ac_data, dict) else {}
            page_type = (ac_page.get("type") or "").strip()
            continue_url = (ac_data.get("continue_url") or "").strip()
            log(f"[session-req] authorize/continue → page_type={page_type!r} continue_url={continue_url[:80]!r}")
            if page_type == "login_password" or "/log-in/password" in continue_url:
                flow = "password"
            elif page_type in ("email_otp_verification", "email_verification") or "/email-verification" in continue_url:
                flow = "otp"
            else:
                raise SessionError(
                    f"unexpected login state: page_type={page_type!r} landing={landing[:80]!r}"
                )

        try:

            # ── Branch A: password login ──
            if flow == "password":
                log("[session-req] password login flow...")
                if flow_mode == "anti409":
                    # Warm sentinel.openai.com sdk.js + frame.html với Referer
                    # /log-in/password → server nhận token là từ password verify
                    # flow (giảm reject token yếu).
                    try:
                        session.get(
                            "https://sentinel.openai.com/backend-api/sentinel/sdk.js",
                            headers={"Referer": "https://auth.openai.com/log-in/password"},
                            timeout=15,
                        )
                        session.get(
                            "https://sentinel.openai.com/backend-api/sentinel/frame.html",
                            params={"sv": "20260219f9f6"},
                            headers={"Referer": "https://auth.openai.com/log-in/password"},
                            timeout=15,
                        )
                    except Exception as _warm_exc:
                        log(f"[session-req] sentinel warming non-fatal: {_warm_exc}")
                headers = _common_headers("https://auth.openai.com/log-in/password")
                headers["Content-Type"] = "application/json"
                if device_id:
                    headers["oai-device-id"] = device_id
                # anti409: sentinel flow="password_verify" (reference) — server map
                # flow → required action; "login" có thể trả token không hợp lệ cho
                # endpoint password/verify. legacy giữ "login".
                _sentinel_flow = "password_verify" if flow_mode == "anti409" else "login"
                sentinel_pw = _get_sentinel_token(session, device_id, _sentinel_flow, log)
                if sentinel_pw:
                    headers["openai-sentinel-token"] = sentinel_pw

                resp = session.post(
                    "https://auth.openai.com/api/accounts/password/verify",
                    headers=headers,
                    json={"password": password},
                    timeout=30,
                )
                if _is_cloudflare_challenge(resp):
                    raise SessionError(
                        f"Cloudflare challenge detected at password/verify (HTTP {resp.status_code})"
                    )
                if resp.status_code != 200:
                    full_body = resp.text or ""
                    if classify_account_check_error(full_body) == "deactivated":
                        raise SessionError("account deactivated")
                    body = full_body[:300]
                    raise SessionError(f"password verify failed: HTTP {resp.status_code} - {body}")
                log("[session-req] password verified")
                pw_data = resp.json() if resp is not None else {}
                if classify_account_check_error(str(pw_data)) == "deactivated":
                    raise SessionError("account deactivated")
                page_type = ((pw_data.get("page") or {}).get("type") or "").strip()
                continue_url = (pw_data.get("continue_url") or "").strip()
                log(f"[session-req] post-password → page_type={page_type!r} continue_url={continue_url[:80]!r}")

                if page_type == "push_auth_verification" or "/push-auth-verification" in (continue_url or ""):
                    raise SessionError("push_auth_required: thiết bị yêu cầu phê duyệt đăng nhập (device approval)")

            # ── Branch B: passwordless OTP login ──
            elif flow == "otp":
                if mail_provider is None:
                    raise SessionError(
                        "account uses passwordless OTP login but no mail_provider available. "
                        "Use an Outlook/mail combo so OTP can be polled, or use browser mode."
                    )
                log("[session-req] passwordless OTP login flow...")
                # Trigger OTP send
                otp_send_headers = _common_headers("https://auth.openai.com/email-verification")
                if device_id:
                    otp_send_headers["oai-device-id"] = device_id
                session.get(
                    "https://auth.openai.com/api/accounts/email-otp/send",
                    headers=otp_send_headers,
                    timeout=30,
                )
                log("[session-req] OTP sent, polling mail provider...")

                # Poll OTP via mail provider (sync bridge)
                otp_started = datetime.now(timezone.utc)
                otp_code = _run_async_poll(
                    mail_provider, email, otp_started, log,
                )
                if not otp_code:
                    raise SessionError("OTP polling returned empty code")

                otp_resp = _step_verify_otp(session, otp_code, device_id, log)
                page_type = ((otp_resp.get("page") or {}).get("type") or "").strip()
                continue_url = (otp_resp.get("continue_url") or "").strip()
                log(f"[session-req] post-OTP → page_type={page_type!r} continue_url={continue_url[:80]!r}")

            # Step 6: MFA (if needed)
            if "mfa" in page_type or "mfa" in (continue_url or ""):
                if not secret:
                    raise SessionError("account requires 2FA but no secret provided")
                log("[session-req] MFA challenge detected...")

                # Extract challenge ID from continue_url
                # e.g. https://auth.openai.com/mfa-challenge/6a2f85296d588191...
                import re as _re
                challenge_id = ""
                _m = _re.search(r"/mfa-challenge/([a-f0-9]+)", continue_url or "")
                if _m:
                    challenge_id = _m.group(1)

                if not challenge_id:
                    raise SessionError(f"MFA challenge ID not found in continue_url: {continue_url[:100]}")

                mfa_headers = _common_headers("https://auth.openai.com/mfa-challenge")
                mfa_headers["Content-Type"] = "application/json"
                if device_id:
                    mfa_headers["oai-device-id"] = device_id

                # Step 6a: Issue challenge
                log("[session-req] issuing MFA challenge...")
                resp = session.post(
                    "https://auth.openai.com/api/accounts/mfa/issue_challenge",
                    headers=mfa_headers,
                    json={"id": challenge_id, "type": "totp", "force_fresh_challenge": False},
                    timeout=30,
                )
                if _is_cloudflare_challenge(resp):
                    raise SessionError(
                        f"Cloudflare challenge detected at mfa/issue_challenge (HTTP {resp.status_code})"
                    )
                if resp.status_code != 200:
                    log(f"[session-req] issue_challenge returned {resp.status_code}: {(resp.text or '')[:200]}")
                    # Non-fatal: some accounts may not need issue_challenge

                # Step 6b: Dedicated Sentinel Token for mfa_verify (Section 7)
                log("[session-req] acquiring fresh Sentinel token for mfa_verify...")
                sentinel_mfa = _get_sentinel_token(session, device_id, "mfa_verify", log)

                # Step 6c: Fresh TOTP code right before verify
                import pyotp
                fresh_totp = pyotp.TOTP(secret).now()
                log(f"[session-req] verifying TOTP code: {fresh_totp[:2]}****...")
                mfa_verify_headers = dict(mfa_headers)
                if sentinel_mfa:
                    mfa_verify_headers["openai-sentinel-token"] = sentinel_mfa

                resp = session.post(
                    "https://auth.openai.com/api/accounts/mfa/verify",
                    headers=mfa_verify_headers,
                    json={"id": challenge_id, "type": "totp", "code": fresh_totp},
                    timeout=30,
                )
                if _is_cloudflare_challenge(resp):
                    raise SessionError(
                        f"Cloudflare challenge detected at mfa/verify (HTTP {resp.status_code})"
                    )
                if resp.status_code != 200:
                    full_body = resp.text or ""
                    if classify_account_check_error(full_body) == "deactivated":
                        raise SessionError("account deactivated")
                    body = full_body[:300]
                    raise SessionError(f"MFA verify failed: HTTP {resp.status_code} - {body}")

                mfa_data = resp.json() if resp is not None else {}
                if classify_account_check_error(str(mfa_data)) == "deactivated":
                    raise SessionError("account deactivated")
                log("[session-req] MFA verified!")
                continue_url = (mfa_data.get("continue_url") or "").strip()

            # Normalize continue_url
            if continue_url and continue_url.startswith("/"):
                continue_url = urljoin("https://auth.openai.com", continue_url)

            # ── Helpers cho callback consume + verify session cookie ──
            # `_consume_callback` của request_phase trả bool (cookie đã set chưa)
            # nhưng caller cũ ignore → khi cookie chưa set kịp do server chậm /
            # callback code đã expire, /api/auth/session sẽ trả response chỉ
            # chứa WARNING_BANNER (unauthenticated). Retry + verify rõ ràng.
            def _has_session_cookie() -> bool:
                """NextAuth session-token có thể bị split thành .0/.1 khi quá dài."""
                for name in (
                    "__Secure-next-auth.session-token",
                    "__Secure-next-auth.session-token.0",
                ):
                    if session.cookies.get(name):
                        return True
                return False

            def _consume_callback_verified(callback_url: str, *, max_attempts: int = 3, delay: float = 1.0) -> bool:
                """Consume callback + verify session-token cookie. Retry nếu chậm."""
                if not callback_url or "code=" not in callback_url:
                    return False
                for attempt in range(1, max_attempts + 1):
                    ok = _consume_callback(session, callback_url, log)
                    if _has_session_cookie():
                        log(f"[session-req] consume_callback verified (attempt {attempt}/{max_attempts}) consumed={ok}")
                        return True
                    if attempt < max_attempts:
                        log(
                            f"[session-req] consume_callback chưa set session cookie "
                            f"(attempt {attempt}/{max_attempts}) — retry sau {delay:g}s..."
                        )
                        time.sleep(delay)
                log(
                    f"[session-req] consume_callback FAIL — session cookie KHÔNG set "
                    f"sau {max_attempts} lần"
                )
                return False

            # Step 7-8: Follow redirects + consume callback
            # If continue_url points to auth.openai.com (not a callback), we need to
            # reauthorize to get the actual callback with code parameter.
            if continue_url and "auth.openai.com" in continue_url and "code=" not in continue_url:
                log("[session-req] continue_url is auth page, attempting reauthorize for callback...")
                try:
                    csrf_reauth_headers = _common_headers("https://chatgpt.com/")
                    if device_id:
                        csrf_reauth_headers["oai-device-id"] = device_id
                    if session_id:
                        csrf_reauth_headers["oai-session-id"] = session_id
                    csrf_resp = session.get(
                        "https://chatgpt.com/api/auth/csrf",
                        headers=csrf_reauth_headers,
                        timeout=20,
                    )
                    csrf2 = str((csrf_resp.json() or {}).get("csrfToken") or "").strip()
                    if csrf2:
                        from urllib.parse import urlencode as _urlencode
                        _reauth_params = {
                            "prompt": "login",
                            "ext-passkey-client-capabilities": "01001",
                            "ext-oai-did": device_id,
                            "auth_session_logging_id": session_id,
                            "screen_hint": "login_or_signup",
                        }
                        _reauth_headers = {
                            "User-Agent": USER_AGENT,
                            "sec-ch-ua": _SEC_CH_UA,
                            "sec-ch-ua-mobile": _SEC_CH_UA_MOBILE,
                            "sec-ch-ua-platform": _SEC_CH_UA_PLATFORM,
                            "Accept-Language": "en-US,en;q=0.9",
                            "Accept": "application/json",
                            "Content-Type": "application/x-www-form-urlencoded",
                            "Origin": "https://chatgpt.com",
                            "Referer": "https://chatgpt.com/",
                            "oai-device-id": device_id,
                            "oai-session-id": session_id,
                        }
                        _reauth_resp = session.post(
                            "https://chatgpt.com/api/auth/signin/openai?" + _urlencode(_reauth_params),
                            headers=_reauth_headers,
                            data={
                                "csrfToken": csrf2,
                                "callbackUrl": "https://chatgpt.com/",
                                "json": "true",
                            },
                            timeout=30,
                        )
                        auth_url2 = str((_reauth_resp.json() or {}).get("url") or "").strip()
                    else:
                        auth_url2 = _step_auth_url(session, csrf2, log)
                    # Follow authorize URL (should redirect to callback since we're now authenticated)
                    if auth_url2:
                        callback_url, _ = _step_follow_redirects(session, auth_url2, log)
                        if callback_url:
                            _consume_callback_verified(callback_url)
                        else:
                            log("[session-req] reauthorize: callback URL KHÔNG tìm thấy trong redirect chain")
                except Exception as e:
                    log(f"[session-req] reauthorize attempt failed: {e}")

            elif continue_url:
                _t_cb = time.monotonic()
                callback_url, final_url = _step_follow_redirects(session, continue_url, log)
                log(
                    f"[session-req] follow_redirects {time.monotonic() - _t_cb:.2f}s "
                    f"callback={'found' if callback_url else 'missing'}"
                )
                if not callback_url:
                    raise SessionError(
                        f"login completed but no callback URL found in redirect chain. "
                        f"final_url={final_url[:120]!r}"
                    )
                _t_cc = time.monotonic()
                if not _consume_callback_verified(callback_url):
                    raise SessionError(
                        "callback consumed nhưng session-token cookie KHÔNG được set. "
                        "Nguyên nhân khả dĩ: callback code đã expire (login tới callback "
                        "quá chậm), Cloudflare reject NextAuth set-cookie, hoặc proxy "
                        "strip cookie. Tăng số lần retry hoặc đổi proxy."
                    )
                log(f"[session-req] consume_callback {time.monotonic() - _t_cc:.2f}s")

            elif not continue_url:
                # Try reauthorize (session cookie may already be set)
                log("[session-req] no continue_url, attempting reauthorize...")
                try:
                    csrf2 = _step_csrf(session, log)
                    auth_url2 = _step_auth_url(session, csrf2, log)
                    resp = session.get(
                        auth_url2,
                        headers={
                            "Accept": "text/html,*/*",
                            "Accept-Language": "en-US,en;q=0.9",
                            "Referer": "https://chatgpt.com/",
                            "User-Agent": USER_AGENT,
                            "sec-ch-ua": _SEC_CH_UA,
                            "sec-ch-ua-mobile": _SEC_CH_UA_MOBILE,
                            "sec-ch-ua-platform": _SEC_CH_UA_PLATFORM,
                        },
                        timeout=30,
                        allow_redirects=False,
                    )
                    loc = (resp.headers.get("Location") or "").strip()
                    if loc:
                        redir_url = loc if loc.startswith("http") else urljoin(auth_url2, loc)
                        callback_url, _ = _step_follow_redirects(session, redir_url, log)
                        if callback_url:
                            _consume_callback_verified(callback_url)
                except Exception as e:
                    log(f"[session-req] reauthorize failed: {e}")

            # Pre-check: nếu session cookie vẫn chưa có ở đây, /api/auth/session
            # CHẮC CHẮN sẽ trả response WARNING_BANNER (unauthenticated). Fail fast
            # với message rõ ràng thay vì để user thấy raw banner JSON.
            if not _has_session_cookie():
                raise SessionError(
                    "login flow completed nhưng cookie __Secure-next-auth.session-token "
                    "không được set. /api/auth/session sẽ trả WARNING_BANNER "
                    "(unauthenticated). Nguyên nhân khả dĩ: callback code expire, "
                    "Cloudflare reject, redirect chain bị cắt, hoặc proxy strip cookie."
                )

            # Step 9: Get FULL /api/auth/session JSON (same as browser mode)
            _t_sess = time.monotonic()
            sess_headers = _common_headers("https://chatgpt.com/")
            if device_id:
                sess_headers["oai-device-id"] = device_id
            if session_id:
                sess_headers["oai-session-id"] = session_id
            sess_resp = session.get(
                "https://chatgpt.com/api/auth/session",
                headers=sess_headers,
                timeout=30,
            )
            log(f"[session-req] GET /api/auth/session {time.monotonic() - _t_sess:.2f}s")
            if _is_cloudflare_challenge(sess_resp):
                raise SessionError(
                    f"Cloudflare challenge detected at /api/auth/session (HTTP {sess_resp.status_code})"
                )
            if sess_resp.status_code != 200:
                full_body = sess_resp.text or ""
                if classify_account_check_error(full_body) == "deactivated":
                    raise SessionError("account deactivated")
                raise SessionError(
                    f"/api/auth/session failed: HTTP {sess_resp.status_code} - {full_body[:200]}"
                )
            try:
                session_data = sess_resp.json()
            except Exception as e:
                raise SessionError(f"/api/auth/session JSON parse failed: {e}")

            if classify_account_check_error(str(session_data)) == "deactivated":
                raise SessionError("account deactivated")

            raw_token = (
                session_data.get("accessToken")
                or (session_data.get("user") or {}).get("accessToken")
                or (session_data.get("user") or {}).get("access_token")
            )
            if not isinstance(raw_token, str) or not raw_token.strip():
                # Detect "warning-only" response: server trả banner cảnh báo
                # nhưng KHÔNG có session payload → user vẫn unauthenticated.
                keys = sorted(session_data.keys()) if isinstance(session_data, dict) else []
                only_warning = (
                    isinstance(session_data, dict)
                    and "WARNING_BANNER" in session_data
                    and not any(k in session_data for k in ("user", "accessToken", "expires"))
                )
                if only_warning:
                    raise SessionError(
                        "login chưa thực sự authenticated — /api/auth/session chỉ trả "
                        "WARNING_BANNER, không có user/accessToken/expires. "
                        "Session cookie đã set nhưng NextAuth không recognize "
                        "(có thể cookie sai domain/path, hoặc Cloudflare strip cookie "
                        "ở request /api/auth/session). "
                        f"keys={keys}"
                    )
                raise SessionError(
                    f"login completed but /api/auth/session has no accessToken: {str(session_data)[:200]}"
                )
            session_data["accessToken"] = raw_token.strip()
            user_email = (session_data.get("user", {}) or {}).get("email", "") or email
            log(f"[session-req] ✓ done — user: {user_email}")
            # Capture cookies cho hybrid flow (caller có thể inject vào browser).
            # curl_cffi expose cookies qua jar (.cookies) — list các Cookie object.
            try:
                cookies_export: list[dict[str, Any]] = []
                for ck in session.cookies.jar:
                    cookies_export.append({
                        "name": ck.name,
                        "value": ck.value,
                        "domain": ck.domain,
                        "path": ck.path or "/",
                        "secure": bool(ck.secure),
                        # httpOnly không lộ qua API curl_cffi → mặc định True cho
                        # cookie auth (an toàn hơn).
                        "httpOnly": ck.name.startswith("__Host-") or ck.name.startswith("__Secure-"),
                        "sameSite": "Lax",
                        "expires": ck.expires if ck.expires else -1,
                    })
                session_data["__cookies"] = cookies_export
            except Exception as exc:
                log(f"[session-req] cookie export failed: {exc}")
            return session_data
        finally:
            try:
                session.close()
            except Exception:
                pass

    return await asyncio.to_thread(_sync)
