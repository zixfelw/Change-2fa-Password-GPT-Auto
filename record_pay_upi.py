"""HYBRID: pure-HTTP login + create checkout → browser navigate + fill + submit.

Flow + cơ chế chuyển đổi điểm áp proxy:
    Step 1 — login pure-HTTP (chatgpt → access_token + cookies)
    Step 2 — POST /backend-api/payments/checkout (HTTP)
    Step 3 — browser launch + verify chatgpt.com (phase A nếu cần split)
    Step 4 — browser navigate checkout URL + Stripe + fill + submit (phase B)

CLI flag `--proxy-from-step N` (1-4) cho phép user thay đổi điểm áp proxy
mà KHÔNG cần sửa code. Mọi step >= N đi qua proxy; step nhỏ hơn đi DIRECT.

Ví dụ:
    --proxy-from-step 1 → toàn bộ via proxy (1 browser context với proxy)
    --proxy-from-step 2 → step 1 (login) DIRECT, step 2-4 via proxy
    --proxy-from-step 3 → step 1-2 DIRECT, step 3-4 via proxy (browser launch via proxy)
    --proxy-from-step 4 → step 1-3 DIRECT, step 4 via proxy (split phase A/B browser)

Khi cần split (from_step == 4): phase A launch browser DIRECT để verify
chatgpt.com → close → phase B relaunch browser cùng `user_data_dir` với
proxy → goto checkout URL + fill + submit. Cookies persist giữa 2 phase.

Chạy:
    python -m gpt_signup_hybrid.record_pay_upi \\
        --combo 'EMAIL|PASS|SECRET' \\
        --vpa 'name@oksbi' \\
        --proxy 'http://user:pass@host:port' \\
        --proxy-from-step 4
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

from pay_upi_http import _ProxyPolicy, _create_chatgpt_checkout
from random_profile import random_india_profile
from session_phase import get_session_pure_request
from user_agent_profile import CURL_IMPERSONATE_PRIMARY as _IMPERSONATE
from web_recorder import (
    ACTION_INIT_SCRIPT,
    RADIX_FONT_FIX_SCRIPT,
    RecorderLog,
    WebRecorderOptions,
    _attach_page,
    _now_label,
    _open_context,
    _safe_email_label,
)

INDIA_LOCALE = ["en-IN", "en"]
INDIA_TIMEZONE = "Asia/Kolkata"
INDIA_GEOLOCATION = (28.6139, 77.2090)


class FlowError(Exception):
    """Hybrid flow failed."""


# ─────────────────────────────────────────────────────────────────────
# Cookie injection
# ─────────────────────────────────────────────────────────────────────


def _normalize_cookies_for_playwright(raw_cookies: list[dict]) -> list[dict]:
    """Convert curl_cffi cookie dict → format Playwright/Camoufox add_cookies.

    Playwright cookie format:
        {name, value, domain, path, expires?, httpOnly?, secure?, sameSite?}
    `sameSite` phải là "Strict"|"Lax"|"None"; `expires` là epoch float.
    """
    out: list[dict] = []
    for ck in raw_cookies or []:
        domain = ck.get("domain") or ""
        if not domain:
            continue
        # Đảm bảo domain bắt đầu bằng "." nếu là wildcard, hoặc giữ nguyên
        normalized: dict[str, Any] = {
            "name": ck["name"],
            "value": ck["value"],
            "domain": domain,
            "path": ck.get("path") or "/",
            "secure": bool(ck.get("secure", True)),
            "httpOnly": bool(ck.get("httpOnly", False)),
            "sameSite": ck.get("sameSite", "Lax"),
        }
        exp = ck.get("expires")
        if exp and exp > 0:
            normalized["expires"] = float(exp)
        out.append(normalized)
    return out


# ─────────────────────────────────────────────────────────────────────
# Browser-side payment
# ─────────────────────────────────────────────────────────────────────


async def _verify_logged_in(page, *, log) -> None:
    """Goto chatgpt.com với cookies đã inject → confirm logged in."""
    log("[3/6] verify session bằng cách load chatgpt.com")
    await page.goto("https://chatgpt.com/", wait_until="domcontentloaded")
    await asyncio.sleep(2.0)
    cur = page.url
    if "auth.openai.com" in cur or "/auth/login" in cur:
        raise FlowError(f"cookie inject thất bại — page redirect login: {cur}")
    log(f"      page={cur[:100]} OK")


async def _open_checkout_url(page, checkout_url: str, *, log) -> None:
    log(f"[4/6] navigate thẳng {checkout_url[:120]}")
    await page.goto(checkout_url, wait_until="domcontentloaded")
    # Đợi frame ELEMENTS-INNER-PAYMENT (frame có DOM thật, không phải controller)
    deadline = time.monotonic() + 30.0
    found_payment = False
    while time.monotonic() < deadline:
        frames = [(fr.url or "") for fr in page.frames]
        if any("elements-inner-payment" in u or "controller-with-preconnect" not in u and "js.stripe.com" in u and "fingerprinted" not in u for u in frames if u):
            # Probe selector để đảm bảo DOM ready
            for fr in page.frames:
                if "js.stripe.com" not in (fr.url or ""):
                    continue
                try:
                    if await fr.locator('button[data-testid="upi"], button[data-testid="card"]').count() > 0:
                        log(f"      Payment Element ready (frame={fr.url[:100]})")
                        found_payment = True
                        break
                except Exception:
                    continue
            if found_payment:
                return
        await asyncio.sleep(0.5)
    log("      WARN: chưa thấy Payment Element DOM sau 30s — tiếp tục best-effort")


async def _find_billing_container(page, *, log, timeout: float = 20.0):
    """Tìm Frame hoặc Page chứa `#billingAddress-nameInput`.

    ChatGPT custom checkout dùng Stripe Elements `addressElement` — có thể
    render trong frame `elements-inner-payment-*` (chung với Payment Element)
    hoặc trong frame riêng. Probe tất cả frames + page để tìm.

    Returns: frame/page object đã có element, hoặc raise FlowError.
    """
    deadline = time.monotonic() + timeout
    last_seen = []
    while time.monotonic() < deadline:
        candidates = [page] + list(page.frames)
        found = []
        for ctx in candidates:
            try:
                cnt = await ctx.locator("#billingAddress-nameInput").count()
                if cnt > 0:
                    found.append(ctx)
            except Exception:
                continue
        if found:
            target = found[0]
            url = getattr(target, "url", "page")
            log(f"       ✓ billing form trong: {str(url)[:100]}")
            return target
        last_seen = [getattr(fr, "url", "") for fr in page.frames]
        await asyncio.sleep(0.6)
    raise FlowError(
        "không thấy #billingAddress-nameInput trong page hoặc bất kỳ frame nào "
        f"sau {timeout}s. frames hiện có: {last_seen[:8]}"
    )


async def _click_subscribe(page, *, log, label: str = "Subscribe") -> None:
    """Click button Subscribe top-level (ngoài iframe Stripe).

    Selector từ DOM thật: button[aria-label="Subscribe"] + type=submit.
    """
    log(f"       click '{label}'")
    selectors = (
        'button[aria-label="Subscribe"]',
        'button.btn-primary:has-text("Subscribe")',
        'button[type="submit"]:has-text("Subscribe")',
        'button:has-text("Subscribe")',
    )
    for sel in selectors:
        try:
            btn = page.locator(sel).first
            if await btn.is_visible(timeout=2000):
                await btn.scroll_into_view_if_needed(timeout=2000)
                await btn.click(timeout=4000)
                log(f"       ✓ clicked {sel}")
                return
        except Exception:
            continue
    raise FlowError(f"không tìm thấy button '{label}'")


async def _wait_billing_form(container, *, log, timeout: float = 15.0) -> None:
    """Đợi billing form render đủ field trong container (page hoặc frame)."""
    log("       đợi billing form render đủ field")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            count = await container.locator(
                "#billingAddress-localityInput, #billingAddress-postalCodeInput, "
                "#billingAddress-administrativeAreaInput"
            ).count()
            if count >= 3:
                log("       ✓ billing form đã render đủ")
                return
        except Exception:
            pass
        await asyncio.sleep(0.5)
    log("       WARN: billing form chưa đủ field sau timeout — fill best-effort")


async def _clear_and_fill(loc, value: str) -> None:
    """Clear input rồi gõ value (giữ nguyên DOM event để React state update)."""
    await loc.click(force=True, timeout=3000)
    # Select all + delete để clear chắc chắn (fill('') có thể không trigger event React)
    await loc.press("Control+a")
    await loc.press("Delete")
    if value:
        await loc.type(value, delay=25)


async def _fill_billing(container, profile: dict, email: str, *, log) -> None:
    """Fill billing fields trong container (page hoặc frame).

    Selectors theo DOM thật của ChatGPT custom checkout (Stripe Elements):
        #billingAddress-nameInput            (input, name='name')
        #billingAddress-countryInput         (select)
        #billingAddress-addressLine1Input    (combobox input)
        #billingAddress-addressLine2Input    (input)
        #billingAddress-localityInput        (input, city)
        #billingAddress-postalCodeInput      (input, PIN)
        #billingAddress-administrativeAreaInput  (select, state full name)
    """
    log("[5/6] fill billing với selector đúng DOM")

    # Country (select) trước — vì state options phụ thuộc country
    try:
        country = container.locator("#billingAddress-countryInput")
        await country.wait_for(state="visible", timeout=8000)
        await country.select_option(value="IN")
        log("       ✓ country = IN")
    except Exception as exc:
        log(f"       ✗ country fail: {exc}")

    await asyncio.sleep(0.6)  # đợi state dropdown re-render với options India

    # Full name
    try:
        loc = container.locator("#billingAddress-nameInput")
        await loc.wait_for(state="visible", timeout=5000)
        await _clear_and_fill(loc, profile["name"])
        log(f"       ✓ name = {profile['name']!r}")
    except Exception as exc:
        log(f"       ✗ name fail: {exc}")

    # Address line 1
    try:
        loc = container.locator("#billingAddress-addressLine1Input")
        await loc.wait_for(state="visible", timeout=5000)
        await _clear_and_fill(loc, profile["address_line1"])
        # Combobox có thể mở suggestion list — đóng bằng Escape
        await loc.press("Escape")
        log(f"       ✓ addressLine1 = {profile['address_line1']!r}")
    except Exception as exc:
        log(f"       ✗ addressLine1 fail: {exc}")

    # Line 2 — để trống
    try:
        loc = container.locator("#billingAddress-addressLine2Input")
        if await loc.is_visible(timeout=1500):
            await _clear_and_fill(loc, "")
            log("       ✓ addressLine2 cleared")
    except Exception:
        pass

    # City
    try:
        loc = container.locator("#billingAddress-localityInput")
        await loc.wait_for(state="visible", timeout=5000)
        await _clear_and_fill(loc, profile["city"])
        log(f"       ✓ locality = {profile['city']!r}")
    except Exception as exc:
        log(f"       ✗ locality fail: {exc}")

    # PIN
    try:
        loc = container.locator("#billingAddress-postalCodeInput")
        await loc.wait_for(state="visible", timeout=5000)
        await _clear_and_fill(loc, profile["postal_code"])
        log(f"       ✓ postalCode = {profile['postal_code']!r}")
    except Exception as exc:
        log(f"       ✗ postalCode fail: {exc}")

    # State (select) — value là full name "Telangana", "Karnataka", ...
    try:
        loc = container.locator("#billingAddress-administrativeAreaInput")
        await loc.wait_for(state="visible", timeout=5000)
        await loc.select_option(value=profile["state"])
        log(f"       ✓ administrativeArea = {profile['state']!r}")
    except Exception as exc:
        log(f"       ✗ state fail: {exc}")


async def _select_upi_and_fill_vpa(page, vpa: str, *, log) -> None:
    """Stripe Payment Element trong iframe: chọn UPI tab + nhập VPA.

    Stripe tạo nhiều iframes:
      - controller-with-preconnect-*.html : controller frame (KHÔNG phải DOM)
      - elements-inner-payment-*.html     : Payment Element DOM (đây)
      - elements-inner-card-*.html        : Card subelement (sau khi chọn card)
      - elements-inner-upi-*.html         : UPI subelement (sau khi chọn UPI)

    Cần tìm frame có DOM thực — dùng selector probe `button[data-testid="upi"]`
    (DOM xác định đã verify từ user) thay vì match URL pattern.
    """
    log("       liệt kê iframes để tìm Payment Element")
    payment_frame = None
    for fr in page.frames:
        url = fr.url or ""
        if not url:
            continue
        log(f"         frame: {url[:120]}")
        if "js.stripe.com" not in url:
            continue
        try:
            # Selector chính xác từ DOM thật: button[data-testid="upi"]
            count = await fr.locator('button[data-testid="upi"], #upi-tab').count()
            if count > 0:
                payment_frame = fr
                log(f"       ✓ payment frame: {url[:120]}")
                break
        except Exception:
            continue

    if not payment_frame:
        # Fallback: thử frame elements-inner-payment
        for fr in page.frames:
            url = fr.url or ""
            if "elements-inner-payment" in url:
                payment_frame = fr
                log(f"       ✓ payment frame (fallback url): {url[:120]}")
                break
    if not payment_frame:
        raise FlowError("không thấy iframe Stripe Payment Element chứa UPI tab")

    # Click UPI tab — selector chính xác
    upi_btn = payment_frame.locator('button[data-testid="upi"]').first
    try:
        await upi_btn.wait_for(state="visible", timeout=10000)
    except Exception as exc:
        raise FlowError(f"UPI tab không visible sau 10s: {exc}") from exc

    # Check trước khi click — có thể đã selected (camoufox geo IN auto-detect)
    try:
        already_selected = (await upi_btn.get_attribute("aria-selected")) == "true"
    except Exception:
        already_selected = False

    if not already_selected:
        try:
            await upi_btn.scroll_into_view_if_needed(timeout=3000)
        except Exception:
            pass
        await upi_btn.click(timeout=4000)
        log("       ✓ clicked UPI tab")
        # Đợi tab transition: aria-selected=true
        try:
            await payment_frame.wait_for_function(
                """() => {
                    const b = document.querySelector('button[data-testid="upi"]');
                    return b && b.getAttribute('aria-selected') === 'true';
                }""",
                timeout=5000,
            )
        except Exception:
            pass
    else:
        log("       UPI tab đã ở trạng thái selected — skip click")

    await asyncio.sleep(0.8)

    # Đợi panel UPI render + VPA input visible
    vpa_loc = None
    vpa_selectors = (
        'input[data-testid="upi-vpa-input"]',
        'input[name="vpa"]',
        'input[id*="vpa" i]',
        'input[placeholder*="VPA" i]',
        'input[placeholder*="UPI" i]',
        '#upi-panel input[type="text"]',
        'div[id="upi-panel"] input',
    )
    for sel in vpa_selectors:
        try:
            loc = payment_frame.locator(sel).first
            if await loc.is_visible(timeout=2500):
                vpa_loc = loc
                log(f"       ✓ VPA input via {sel}")
                break
        except Exception:
            continue
    if not vpa_loc:
        raise FlowError("không thấy VPA input sau khi UPI tab selected")

    await vpa_loc.click(force=True, timeout=3000)
    await vpa_loc.fill("")
    await vpa_loc.type(vpa, delay=40)
    log(f"       ✓ VPA={vpa} filled")


async def _submit_pay_and_wait_approve(page, *, log) -> str:
    """Click Subscribe + listen response /backend-api/payments/checkout/approve.

    Returns: 'approved' | 'blocked' | 'unknown'.
    """
    log("[6/6] click Subscribe (commit) + đợi approve response")
    holder: dict[str, Any] = {}

    async def _on_response(resp) -> None:
        if "/backend-api/payments/checkout/approve" in resp.url:
            try:
                body = await resp.text()
                holder["approve"] = (resp.status, body)
                log(f"       APPROVE → status={resp.status} body={body[:200]}")
            except Exception:
                pass

    page.on("response", _on_response)
    try:
        await _click_subscribe(page, log=log, label="Subscribe (commit)")
        deadline = time.monotonic() + 45.0
        while time.monotonic() < deadline:
            if "approve" in holder:
                break
            await asyncio.sleep(0.5)
    finally:
        try:
            page.remove_listener("response", _on_response)
        except Exception:
            pass

    if "approve" not in holder:
        return "unknown"
    _status, body = holder["approve"]
    try:
        return str(json.loads(body).get("result", "unknown"))
    except Exception:
        return "unknown"


# ─────────────────────────────────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────────────────────────────────


async def run_hybrid(
    *,
    email: str,
    password: str,
    secret: str,
    vpa: str,
    proxy: str | None,
    output_root: Path,
    browser: str,
    headless: bool,
    width: int,
    height: int,
    off_font: bool,
    auto_fill: bool,
    auto_submit: bool,
    proxy_from_step: int = 1,
) -> int:
    label = _safe_email_label(email)
    run_dir = output_root.resolve() / f"pay_upi_{_now_label()}_{label}"
    logger = RecorderLog(run_dir)

    profile = random_india_profile()
    (run_dir / "profile_billing.json").write_text(
        json.dumps(profile, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    # Policy: chuyển đổi điểm áp proxy bằng flag, không sửa code.
    # Step 1 = login HTTP, 2 = create checkout HTTP,
    # 3 = browser phase A (launch + verify chatgpt.com),
    # 4 = browser phase B (navigate checkout URL + Stripe + fill + submit).
    if proxy_from_step < 1 or proxy_from_step > 4:
        raise ValueError(
            f"--proxy-from-step phải trong 1-4 (record_pay_upi), nhận {proxy_from_step}"
        )
    policy = _ProxyPolicy(proxy, from_step=proxy_from_step)
    phaseA_proxy = policy.url_for(3)
    phaseB_proxy = policy.url_for(4)
    need_split_browser = phaseA_proxy != phaseB_proxy

    print(f"[hybrid] output: {run_dir}", flush=True)
    print(f"[hybrid] HAR: {logger.har_path}", flush=True)
    print(f"[hybrid] billing profile: {profile['name']} | {profile['city']} | {profile['phone']}", flush=True)
    if proxy:
        proxied = ", ".join(str(s) for s in range(policy.from_step, 5))
        direct = ", ".join(str(s) for s in range(1, policy.from_step)) or "—"
        print(f"[hybrid] proxy: {proxy[:60]}...", flush=True)
        print(f"[hybrid] policy: from step {policy.from_step} → DIRECT [{direct}], via proxy [{proxied}]", flush=True)
        print(f"[hybrid] browser split needed: {need_split_browser} (phase A={'proxy' if phaseA_proxy else 'direct'}, phase B={'proxy' if phaseB_proxy else 'direct'})", flush=True)
    else:
        print("[hybrid] no proxy — toàn bộ flow đi IP thật", flush=True)

    def _print_artifacts() -> None:
        """In path artifact dir + main files để dễ tìm khi dừng/exit."""
        try:
            har_size = logger.har_path.stat().st_size if logger.har_path.exists() else 0
        except Exception:
            har_size = 0
        print("", flush=True)
        print("─" * 70, flush=True)
        print(f"[hybrid] artifact dir   : {run_dir}", flush=True)
        print(f"         HAR (full)     : {logger.har_path}  ({har_size:,} bytes)", flush=True)
        print(f"         trace.zip      : {logger.trace_path}", flush=True)
        print(f"         actions.jsonl  : {logger.actions_path}", flush=True)
        print(f"         requests.jsonl : {logger.requests_path}", flush=True)
        print(f"         console.jsonl  : {logger.console_path}", flush=True)
        print(f"         screenshots/   : {logger.screenshots_dir}", flush=True)
        print("─" * 70, flush=True)

    rc = 1
    page = None
    ctx: Any = None
    close_ctx: Any = None

    try:
        # ─── STEP 1: pure-HTTP login (proxy theo policy) ───
        def _http_log(msg: str) -> None:
            print(f"[http] {msg}", flush=True)

        login_proxy = policy.url_for(1)
        print(f"[1/6] login pure-HTTP ({'via proxy' if login_proxy else 'DIRECT'}) → access_token + cookies", flush=True)
        session_data = await get_session_pure_request(
            email=email, password=password, secret=secret, proxy=login_proxy, log=_http_log,
        )
        access_token = session_data.get("accessToken")
        if not access_token:
            print("[hybrid] login failed: không có accessToken", file=sys.stderr, flush=True)
            return 1
        raw_cookies = session_data.get("__cookies") or []
        print(f"      ✓ accessToken={access_token[:30]}... cookies={len(raw_cookies)}", flush=True)

        # ─── STEP 2: create checkout HTTP (proxy theo policy) ───
        checkout_proxies = policy.dict_for(2)
        print(f"[2/6] POST /backend-api/payments/checkout ({'via proxy' if checkout_proxies else 'DIRECT'}) → session_id", flush=True)
        from curl_cffi.requests import AsyncSession

        # Session-level proxies=None — dùng per-request proxies kwarg.
        async with AsyncSession(impersonate=_IMPERSONATE) as sess:
            checkout = await _create_chatgpt_checkout(
                sess, access_token=access_token, log=lambda m: print(f"      {m}", flush=True),
                proxies=checkout_proxies,
            )
        session_id = checkout["checkout_session_id"]
        checkout_url = f"https://chatgpt.com/checkout/openai_llc/{session_id}"
        print(f"      ✓ checkout URL: {checkout_url}", flush=True)
        (run_dir / "checkout_url.txt").write_text(checkout_url, encoding="utf-8")
        logger.action("checkout_url", url=checkout_url)
        logger.action("login_combo", email=email)
        logger.action("vpa", vpa=vpa)
        logger.action("profile_billing", **profile)
        logger.action("proxy_policy", from_step=policy.from_step, has_proxy=bool(proxy))

        pw_cookies = _normalize_cookies_for_playwright(raw_cookies)

        # Browser options shared cho cả 2 phase nếu split. Phase A proxy theo
        # policy.url_for(3); phase B theo policy.url_for(4). Khi cùng giá trị
        # → KHÔNG split, dùng 1 context với options_phaseB.
        options_phaseA = WebRecorderOptions(
            url=checkout_url,
            output_root=output_root,
            email=email,
            browser=browser,
            headless=headless,
            locale=INDIA_LOCALE,
            timezone=INDIA_TIMEZONE,
            geolocation=INDIA_GEOLOCATION,
            proxy=phaseA_proxy,
            off_font=off_font,
            viewport=(width, height),
            profile=profile,
        )
        options_phaseB = replace(options_phaseA, proxy=phaseB_proxy)

        # ─── PHASE A (chỉ chạy khi cần split): browser verify session ───
        if need_split_browser:
            print(f"[3/6] [phase A] launch {browser} ({'via proxy' if phaseA_proxy else 'DIRECT'}) — verify session", flush=True)
            ctx_a, close_a = await _open_context(options_phaseA, logger, enable_har=False)
            page_a = None
            try:
                if pw_cookies:
                    try:
                        await ctx_a.add_cookies(pw_cookies)
                        logger.action("cookies_injected_phaseA", count=len(pw_cookies))
                    except Exception as exc:
                        print(f"[hybrid] [A] add_cookies failed: {exc}", file=sys.stderr, flush=True)

                page_a = ctx_a.pages[0] if ctx_a.pages else await ctx_a.new_page()
                await _attach_page(page_a, logger)

                def log_a(msg: str) -> None:
                    print(f"[flow][A] {msg}", flush=True)
                    logger.action("flow_log_phaseA", msg=msg)

                await _verify_logged_in(page_a, log=log_a)
                await logger.screenshot(page_a, "01_verified_phaseA")
                log_a("phase A xong → close để chuyển phase B")
            finally:
                try:
                    await close_a()
                except Exception:
                    pass
            await asyncio.sleep(1.0)

        # ─── PHASE B (hoặc single context): navigate + fill + submit ───
        phase_label = "[phase B]" if need_split_browser else "[single]"
        print(f"[3-4/6] {phase_label} launch {browser} ({'via proxy' if phaseB_proxy else 'DIRECT'}) — navigate + fill + submit", flush=True)
        ctx, close_ctx = await _open_context(options_phaseB, logger, enable_har=True)

        await ctx.expose_binding(
            "__recordAction",
            lambda source, payload: logger.dom_action(
                {**dict(payload), "page_url": source["page"].url if source and source.get("page") else None}
            ),
        )
        await ctx.add_init_script(ACTION_INIT_SCRIPT)
        await ctx.add_init_script(RADIX_FONT_FIX_SCRIPT)

        if getattr(ctx, "tracing", None) is not None:
            await ctx.tracing.start(screenshots=True, snapshots=True, sources=False)
        ctx.on("request", logger.request)
        ctx.on("response", logger.response)
        ctx.on("requestfailed", logger.request_failed)
        ctx.on("page", lambda p: asyncio.create_task(_attach_page(p, logger)))

        # Re-inject cookies từ HTTP login để đảm bảo session — kể cả nếu profile
        # folder chưa flush 100% giữa 2 phase (split case).
        if pw_cookies:
            try:
                await ctx.add_cookies(pw_cookies)
                logger.action("cookies_injected_main", count=len(pw_cookies))
            except Exception as exc:
                print(f"[hybrid] add_cookies failed: {exc}", file=sys.stderr, flush=True)

        page = ctx.pages[0] if ctx.pages else await ctx.new_page()
        await _attach_page(page, logger)

        def log(msg: str) -> None:
            print(f"[flow] {msg}", flush=True)
            logger.action("flow_log", msg=msg)

        # Single-context flow vẫn cần verify chatgpt.com (phase A đã skip).
        if not need_split_browser:
            await _verify_logged_in(page, log=log)
            await logger.screenshot(page, "01_verified_single")

        # Goto checkout URL — proxy theo phaseB_proxy.
        await _open_checkout_url(page, checkout_url, log=log)
        await asyncio.sleep(3.0)
        await logger.screenshot(page, "02_checkout_loaded")

        if auto_fill:
            try:
                # 1. Chọn UPI tab + nhập VPA TRƯỚC (Subscribe sẽ validate UPI)
                await _select_upi_and_fill_vpa(page, vpa, log=log)
                await logger.screenshot(page, "03_upi_filled")

                # 2. Click Subscribe lần 1 → server reveal full billing form
                log("       click Subscribe lần 1 để reveal full billing form")
                try:
                    await _click_subscribe(page, log=log, label="Subscribe (reveal)")
                except FlowError as exc:
                    log(f"       Subscribe reveal warning: {exc} — có thể form đã hiện")
                await logger.screenshot(page, "04_after_first_subscribe")

                # 3. Probe page + frames để tìm container chứa billing form
                billing_ctx = await _find_billing_container(page, log=log, timeout=20.0)

                # 4. Đợi billing form render đủ field
                await _wait_billing_form(billing_ctx, log=log)

                # 5. Fill billing với selectors đúng DOM
                await _fill_billing(billing_ctx, profile, email, log=log)
                await logger.screenshot(page, "05_billing_filled")
                await asyncio.sleep(0.8)

                # 6. Submit thật — confirm + approve qua proxy session-level
                if auto_submit:
                    result = await _submit_pay_and_wait_approve(page, log=log)
                    await logger.screenshot(page, f"06_result_{result}")
                    log(f"FINAL approve.result = {result}")
                    rc = 0 if result == "approved" else 1
                else:
                    log("auto_submit=False → giữ browser cho user click Subscribe thủ công")
                    print("[hybrid] form đã fill xong. Click Subscribe trong browser thủ công.", flush=True)
                    print("[hybrid] Nhấn Enter sau khi xong để dừng...", flush=True)
                    await asyncio.to_thread(input, "")
                    rc = 0
            except FlowError as exc:
                print(f"[hybrid] auto-fill error: {exc}", file=sys.stderr, flush=True)
                print("[hybrid] giữ browser mở để bạn fill thủ công. Enter để stop...", flush=True)
                await asyncio.to_thread(input, "")
                rc = 1
        else:
            print(f"[hybrid] auto_fill=False — checkout URL đã mở: {checkout_url}", flush=True)
            print("[hybrid] hoàn tất thanh toán thủ công, nhấn Enter để stop...", flush=True)
            await asyncio.to_thread(input, "")
            rc = 0

    except KeyboardInterrupt:
        print("\n[hybrid] interrupted (Ctrl+C)", flush=True)
        rc = 130
    except Exception as exc:  # noqa: BLE001
        print(f"[hybrid] unexpected: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        try:
            if page is not None:
                await logger.screenshot(page, "99_error")
        except Exception:
            pass
        rc = 1
    finally:
        try:
            if ctx is not None and getattr(ctx, "tracing", None) is not None:
                await ctx.tracing.stop(path=str(logger.trace_path))
        except Exception:
            pass
        if close_ctx is not None:
            try:
                await close_ctx()
            except Exception:
                pass
        try:
            logger.close()
        except Exception:
            pass
        _print_artifacts()

    return rc


# ─────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────


def _parse_combo(raw: str) -> tuple[str, str, str]:
    parts = raw.split("|")
    if len(parts) < 3:
        raise SystemExit("combo phải là email|password|totp_secret")
    e, p, s = parts[0].strip(), parts[1].strip(), parts[2].strip()
    if not (e and p and s):
        raise SystemExit("combo có field rỗng")
    return e, p, s


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="record_pay_upi",
        description="Hybrid: pure-HTTP login + browser pay UPI.",
    )
    p.add_argument("--combo", required=True, help="email|password|totp_secret")
    p.add_argument("--vpa", required=True, help="UPI VPA, vd 'name@oksbi'")
    p.add_argument("--proxy", default=None)
    p.add_argument(
        "--proxy-from-step", type=int, default=4, choices=tuple(range(1, 5)),
        metavar="N",
        help=(
            "Step bắt đầu áp proxy (1-4, default 4 = chỉ browser navigate "
            "checkout URL trở đi). "
            "1=login HTTP, 2=create checkout HTTP, 3=browser launch+verify, "
            "4=browser navigate checkout URL+fill+submit. "
            "Default 4 → step 1-3 DIRECT, step 4 via proxy (split phase A/B)."
        ),
    )
    p.add_argument("--output-root", default="runtime/research_logs")
    p.add_argument("--browser", default="camoufox", choices=("camoufox", "chrome", "chromium"))
    p.add_argument("--headless", action="store_true")
    p.add_argument("--width", type=int, default=1280)
    p.add_argument("--height", type=int, default=800)
    p.add_argument("--no-off-font", dest="off_font", action="store_false")
    p.set_defaults(off_font=True)
    p.add_argument(
        "--no-auto-fill", dest="auto_fill", action="store_false",
        help="KHÔNG auto fill billing/UPI — chỉ mở URL, user fill tay",
    )
    p.set_defaults(auto_fill=True)
    p.add_argument(
        "--no-auto-submit", dest="auto_submit", action="store_false",
        help="Auto fill xong nhưng không click Subscribe — user click thủ công",
    )
    p.set_defaults(auto_submit=True)
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    email, password, secret = _parse_combo(args.combo)
    return asyncio.run(run_hybrid(
        email=email,
        password=password,
        secret=secret,
        vpa=args.vpa,
        proxy=args.proxy,
        output_root=Path(args.output_root),
        browser=args.browser,
        headless=args.headless,
        width=args.width,
        height=args.height,
        off_font=args.off_font,
        auto_fill=args.auto_fill,
        auto_submit=args.auto_submit,
        proxy_from_step=args.proxy_from_step,
    ))


if __name__ == "__main__":
    raise SystemExit(main())
