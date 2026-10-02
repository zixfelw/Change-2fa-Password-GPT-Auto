"""Manual web recorder: DOM actions + full HAR + trace.

Mục tiêu:
    - Record click / input / change / submit / keydown actions trên page.
    - Ghi full HAR (request + response bodies embed).
    - Cho phép chạy interactive từ CLI root: ``python -m gpt_signup_hybrid record``.
"""
from __future__ import annotations

import asyncio
import json
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx


DEFAULT_START_URL = "https://chatgpt.com/"
DEFAULT_OTP_API_URL = "https://cf-work-get-otp.n5pskgzs9g.workers.dev/api/get-code"
SENSITIVE_MARKERS = (
    "password",
    "passwd",
    "passcode",
    "secret",
    "token",
    "otp",
    "code",
    "mfa",
    "totp",
    "2fa",
)
SENSITIVE_HEADER_NAMES = {"authorization", "cookie", "set-cookie", "x-api-token"}
MAX_LOG_BODY = 4000


ACTION_INIT_SCRIPT = r"""
(() => {
  if (window.__webRecorderInstalled) return;
  window.__webRecorderInstalled = true;

  function cssPath(el) {
    if (!el || el.nodeType !== Node.ELEMENT_NODE) return '';
    if (el.id) return '#' + CSS.escape(el.id);
    const testid = el.getAttribute('data-testid');
    if (testid) return `[data-testid="${testid.replace(/"/g, '\\"')}"]`;
    const name = el.getAttribute('name');
    if (name) return `${el.tagName.toLowerCase()}[name="${name.replace(/"/g, '\\"')}"]`;
    const aria = el.getAttribute('aria-label');
    if (aria) return `${el.tagName.toLowerCase()}[aria-label="${aria.replace(/"/g, '\\"')}"]`;
    const parts = [];
    let cur = el;
    for (let depth = 0; cur && depth < 5 && cur.nodeType === Node.ELEMENT_NODE; depth++) {
      let part = cur.tagName.toLowerCase();
      if (cur.classList && cur.classList.length) {
        part += '.' + Array.from(cur.classList).slice(0, 2).map(c => CSS.escape(c)).join('.');
      }
      const parent = cur.parentElement;
      if (parent) {
        const same = Array.from(parent.children).filter(x => x.tagName === cur.tagName);
        if (same.length > 1) part += `:nth-of-type(${same.indexOf(cur) + 1})`;
      }
      parts.unshift(part);
      cur = parent;
    }
    return parts.join(' > ');
  }

  function payload(type, event) {
    const t = event.target;
    const value = (t && 'value' in t) ? String(t.value || '') : '';
    const text = (t && t.innerText) ? String(t.innerText).trim().slice(0, 200) : '';
    return {
      event_type: type,
      url: location.href,
      tag: t && t.tagName ? t.tagName.toLowerCase() : '',
      target_type: t && t.getAttribute ? (t.getAttribute('type') || '') : '',
      target_name: t && t.getAttribute ? (t.getAttribute('name') || '') : '',
      target_id: t && t.getAttribute ? (t.getAttribute('id') || '') : '',
      target_placeholder: t && t.getAttribute ? (t.getAttribute('placeholder') || '') : '',
      target_aria: t && t.getAttribute ? (t.getAttribute('aria-label') || '') : '',
      target_text: text,
      selector: cssPath(t),
      value,
      value_length: value.length,
      key: event.key || '',
      ts: new Date().toISOString()
    };
  }

  function send(type, event) {
    try {
      window.__recordAction(payload(type, event));
    } catch (_) {}
  }

  document.addEventListener('click', e => send('click', e), true);
  document.addEventListener('input', e => send('input', e), true);
  document.addEventListener('change', e => send('change', e), true);
  document.addEventListener('submit', e => send('submit', e), true);
  document.addEventListener('keydown', e => {
    if (['Enter', 'Tab', 'Escape'].includes(e.key)) send('keydown', e);
  }, true);
})();
"""


# Camoufox custom fontconfig đổi font metrics → phá Radix UI virtual list
# (mọi option dropdown render cùng 1 slot, vd country list ChatGPT toàn
# "United States"). Ép font hệ thống + letter-spacing/font-size chuẩn lên
# Radix popper content để khôi phục metrics đúng. Áp ở context init script
# nên có hiệu lực cho mọi page + mọi navigation.
RADIX_FONT_FIX_SCRIPT = r"""
(() => {
  if (window.__radixFontFixInstalled) return;
  window.__radixFontFixInstalled = true;
  const css = '[data-radix-popper-content-wrapper] *'
    + '{font-family:Arial,Helvetica,sans-serif!important;'
    + 'letter-spacing:normal!important;font-size:14px!important}';
  const inject = () => {
    if (!document.head) return;
    const s = document.createElement('style');
    s.textContent = css;
    document.head.appendChild(s);
  };
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', inject);
  } else {
    inject();
  }
})();
"""


@dataclass(slots=True)
class WebRecorderOptions:
    url: str = DEFAULT_START_URL
    output_root: Path = Path("runtime/research_logs")
    email: str | None = None
    secret: str | None = None
    otp_api_url: str = DEFAULT_OTP_API_URL
    dry_run: bool = False
    headless: bool = False
    browser: str = "camoufox"
    # ── Geo/locale override (opt-in; None = giữ behavior default) ───────
    # Khi set, browser fingerprint sẽ được ép theo region chỉ định
    # (vd India: locale="en-IN", timezone="Asia/Kolkata", geolocation New Delhi).
    locale: str | list[str] | None = None
    timezone: str | None = None
    geolocation: tuple[float, float] | None = None  # (latitude, longitude)
    proxy: str | None = None
    # Profile/billing tĩnh ghi kèm artifact để thao tác viên copy điền form.
    profile: dict | None = None
    # Tắt camoufox font randomization (pin fonts:spacing_seed=0). Cần bật khi
    # ép locale region để country/region dropdown (Radix virtual list) render
    # đúng — font randomization làm lệch font metrics → mọi option render trùng.
    off_font: bool = False
    # Override kích thước viewport (width, height). None = dùng settings.
    # Khi set, cửa sổ camoufox thật được cố định theo size này (không random).
    viewport: tuple[int, int] | None = None


def _json_default(value: Any) -> str:
    return str(value)


def _now_label() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def _accept_language(locales: list[str]) -> str:
    """Build chuỗi Accept-Language với q-values giảm dần từ list locale.

    VD: ["en-IN", "en"] → "en-IN,en;q=0.9".
    """
    parts: list[str] = []
    for idx, loc in enumerate(locales):
        if idx == 0:
            parts.append(loc)
        else:
            q = max(0.1, 1.0 - idx * 0.1)
            parts.append(f"{loc};q={q:.1f}")
    return ",".join(parts)


def _host_camoufox_os() -> str:
    """Map host platform → camoufox OS fingerprint name.

    Headed recording phải khớp OS thật của host (Camoufox mặc định random
    trong ['windows','macos','linux'] gây lệch UA/WebGL/fonts so với cửa sổ
    headed thực → render lỗi). Pin theo host để fingerprint nhất quán.
    """
    platform = sys.platform
    if platform.startswith("darwin"):
        return "macos"
    if platform.startswith("win"):
        return "windows"
    return "linux"


def _safe_email_label(email: str | None) -> str:
    if not email:
        return "manual"
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", email.strip().lower())[:120] or "manual"


def _contains_sensitive_marker(*values: Any) -> bool:
    haystack = " ".join(str(v or "").lower() for v in values)
    return any(marker in haystack for marker in SENSITIVE_MARKERS)


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for key, value in headers.items():
        if key.lower() in SENSITIVE_HEADER_NAMES:
            out[key] = "<redacted>"
        else:
            out[key] = value
    return out


def _redact_body(body: str | None) -> str | None:
    if body is None:
        return None
    lowered = body.lower()
    if any(marker in lowered for marker in SENSITIVE_MARKERS):
        return "<redacted>"
    if len(body) > MAX_LOG_BODY:
        return body[:MAX_LOG_BODY] + "...[truncated]"
    return body


def _redact_action(event: dict[str, Any]) -> dict[str, Any]:
    out = dict(event)
    sensitive = _contains_sensitive_marker(
        out.get("target_name"),
        out.get("target_id"),
        out.get("target_type"),
        out.get("target_placeholder"),
        out.get("target_aria"),
        out.get("selector"),
        out.get("target_text"),
    )
    if sensitive and "value" in out:
        out["value"] = "<redacted>"
        out["redacted"] = True
    return out


class RecorderLog:
    def __init__(self, run_dir: Path) -> None:
        self.run_dir = run_dir
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.screenshots_dir = run_dir / "screenshots"
        self.screenshots_dir.mkdir(exist_ok=True)
        self.har_path = run_dir / "trace.har"
        self.trace_path = run_dir / "trace.zip"
        self.actions_path = run_dir / "actions.jsonl"
        self.requests_path = run_dir / "requests.jsonl"
        self.console_path = run_dir / "console.jsonl"
        self.result_path = run_dir / "result.json"
        self._t0 = time.monotonic()
        self._shot_idx = 0
        self._req_idx = 0
        self._request_ids: dict[Any, int] = {}
        self._actions = self.actions_path.open("w", encoding="utf-8")
        self._requests = self.requests_path.open("w", encoding="utf-8")
        self._console = self.console_path.open("w", encoding="utf-8")

    def elapsed(self) -> float:
        return round(time.monotonic() - self._t0, 3)

    def close(self) -> None:
        for fp in (self._actions, self._requests, self._console):
            try:
                fp.close()
            except Exception:
                pass

    def _write_line(self, fp, record: dict[str, Any]) -> None:
        record.setdefault("t", self.elapsed())
        fp.write(json.dumps(record, ensure_ascii=False, default=_json_default) + "\n")
        fp.flush()

    def action(self, event_type: str, **data: Any) -> None:
        self._write_line(self._actions, {"event_type": event_type, **data})

    def dom_action(self, payload: dict[str, Any]) -> None:
        self._write_line(self._actions, _redact_action(payload))

    def console(self, event_type: str, **data: Any) -> None:
        self._write_line(self._console, {"event_type": event_type, **data})

    def request(self, request) -> None:
        self._req_idx += 1
        rid = self._req_idx
        self._request_ids[request] = rid
        try:
            post_data = request.post_data
        except Exception:
            post_data = None
        self._write_line(
            self._requests,
            {
                "rid": rid,
                "phase": "request",
                "method": request.method,
                "url": request.url,
                "resource_type": request.resource_type,
                "headers": _redact_headers(dict(request.headers)),
                "body": _redact_body(post_data),
            },
        )

    def response(self, response) -> None:
        request = response.request
        rid = self._request_ids.get(request)
        self._write_line(
            self._requests,
            {
                "rid": rid,
                "phase": "response",
                "method": request.method,
                "url": response.url,
                "status": response.status,
                "headers": _redact_headers(dict(response.headers)),
            },
        )

    def request_failed(self, request) -> None:
        failure = None
        try:
            failure = request.failure
        except Exception:
            pass
        self._write_line(
            self._requests,
            {
                "rid": self._request_ids.get(request),
                "phase": "failed",
                "method": request.method,
                "url": request.url,
                "failure": str(failure),
            },
        )

    async def screenshot(self, page, label: str) -> str:
        self._shot_idx += 1
        safe_label = re.sub(r"[^A-Za-z0-9_.-]+", "_", label.strip().lower()) or "shot"
        path = self.screenshots_dir / f"{self._shot_idx:02d}_{safe_label}.png"
        await page.screenshot(path=str(path), full_page=True)
        self.action("screenshot", file=str(path.relative_to(self.run_dir)))
        return str(path)

    def result(self, **data: Any) -> None:
        payload = {"total_seconds": self.elapsed(), **data}
        self.result_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False, default=_json_default),
            encoding="utf-8",
        )


def validate_web_recorder_options(options: WebRecorderOptions) -> None:
    if bool(options.email) != bool(options.secret):
        raise ValueError("--email and --secret must be provided together")
    if options.otp_api_url and not options.otp_api_url.startswith(("http://", "https://")):
        raise ValueError("--otp-api-url must start with http:// or https://")
    if options.url and not options.url.startswith(("http://", "https://")):
        raise ValueError("--url must start with http:// or https://")
    if options.browser not in {"camoufox", "chrome", "chromium"}:
        raise ValueError("--browser must be one of: camoufox, chrome, chromium")
    if options.proxy and not options.proxy.startswith(
        ("http://", "https://", "socks5://", "socks5h://", "socks4://")
    ):
        raise ValueError(
            "--proxy phải bắt đầu bằng http://, https://, socks5://, socks5h://, hoặc socks4://"
        )


async def fetch_otp(*, api_url: str, email: str, secret: str) -> str:
    combo = f"{email.strip()}|{secret.strip()}"
    async with httpx.AsyncClient(timeout=20.0, follow_redirects=True) as client:
        response = await client.post(
            api_url,
            headers={"accept": "*/*", "content-type": "application/json"},
            json={"email_or_url": combo, "mail_secret": ""},
        )
    if response.status_code != 200:
        raise RuntimeError(f"OTP API HTTP {response.status_code}: {response.text[:300]}")
    try:
        data = response.json()
    except ValueError as exc:
        raise RuntimeError("OTP API response is not JSON") from exc
    code = str(data.get("code") or "").strip()
    if data.get("ok") is True and re.fullmatch(r"\d{6}", code):
        return code
    message = data.get("message") or data
    raise RuntimeError(f"OTP API did not return a 6-digit code: {message}")


async def _open_context(
    options: WebRecorderOptions,
    logger: RecorderLog,
    *,
    enable_har: bool = True,
    har_path: Path | None = None,
    user_data_subdir: str = "profile",
):
    """Mở persistent browser context.

    Tham số mở rộng (cho hybrid flow split-proxy):
        enable_har: bật/tắt record HAR. Khi mở 2 context tuần tự cùng profile
            folder, chỉ context đích nên record HAR (tránh ghi đè).
        har_path: override path HAR (default = logger.har_path).
        user_data_subdir: subdirectory dưới run_dir để chứa user profile.
            Mặc định 'profile' — caller có thể đổi để tách profile theo phase.
    """
    from config import load_settings

    settings = load_settings()
    if options.viewport is not None:
        w, h = options.viewport
    else:
        w = settings.browser_viewport_width
        h = settings.browser_viewport_height
    viewport = {"width": w, "height": h}
    # Cố định kích thước screen/window khi caller chỉ định viewport HOẶC khi
    # settings tắt random screen. Tránh camoufox random window → tràn màn hình.
    fixed_screen = options.viewport is not None or not settings.browser_random_screen

    user_data_dir = logger.run_dir / user_data_subdir
    user_data_dir.mkdir(exist_ok=True)
    common: dict[str, Any] = {"user_data_dir": str(user_data_dir)}
    if enable_har:
        common["record_har_path"] = str(har_path or logger.har_path)
        common["record_har_content"] = "embed"
        common["record_har_mode"] = "full"

    # Proxy (opt-in) — parse string → dict cho cả camoufox + playwright.
    proxy_dict: dict[str, str] | None = None
    if options.proxy:
        from _browser_retry import parse_proxy_for_playwright as _parse_proxy

        proxy_dict = _parse_proxy(options.proxy)

    # Geo/locale override config (camoufox `config` dict keys).
    # Set timezone + geolocation rõ ràng để fingerprint nhất quán theo region
    # mà không cần proxy đúng nước. locale truyền qua param `locale` riêng.
    geo_config: dict[str, Any] = {}
    if options.timezone:
        geo_config["timezone"] = options.timezone
    if options.geolocation is not None:
        lat, lon = options.geolocation
        geo_config["geolocation:latitude"] = lat
        geo_config["geolocation:longitude"] = lon
        geo_config["geolocation:accuracy"] = 50.0

    if options.browser == "camoufox":
        from camoufox.async_api import AsyncCamoufox

        # Pin OS theo host + pin screen theo viewport (mirror session_phase /
        # browser_phase) để loại bỏ random OS/UA/screen — nguyên nhân render lỗi
        # khi cửa sổ headed thật không khớp fingerprint.
        host_os = _host_camoufox_os()
        extra_config: dict[str, Any] = {}
        # Pin font spacing seed → tắt randomization. Fix DOM country/region
        # dropdown (Radix virtual list) bị render trùng option khi font metrics
        # bị camoufox randomize. Mirror fork gpt_reg (request.off_font).
        if options.off_font:
            extra_config["fonts:spacing_seed"] = 0
        screen_kwargs: dict[str, Any] = {}
        if fixed_screen:
            from camoufox.utils import Screen as _Screen

            chrome_h = 85  # chiều cao thanh chrome trình duyệt (outer - inner)
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
            # Cố định kích thước cửa sổ THẬT (outer) — nếu không truyền, camoufox
            # tự random window size → tràn/che giao diện web bên dưới.
            screen_kwargs["window"] = (w, h + chrome_h)
            screen_kwargs["i_know_what_im_doing"] = True

        # Merge geo override vào config. Manual geolocation/timezone trigger
        # camoufox LeakWarning → set i_know_what_im_doing=True để tắt cảnh báo
        # (ép India là chủ đích, fingerprint nhất quán).
        if geo_config:
            extra_config.update(geo_config)
            screen_kwargs["i_know_what_im_doing"] = True

        camoufox_kwargs: dict[str, Any] = {}
        if options.locale:
            # KHÔNG dùng camoufox `locale` param: nó gọi handle_locales() set các
            # key `locale:region/language/all` = lớp spoof Intl của camoufox →
            # phá Intl.DisplayNames → country dropdown ChatGPT render mọi option
            # thành cùng 1 nước (bug đã thấy). Thay vào đó set navigator.language
            # + Accept-Language qua config (KHÔNG kích hoạt spoof Intl) để vẫn báo
            # identity en-IN nhưng Intl.DisplayNames chạy native → dropdown đúng.
            locales = (
                [options.locale] if isinstance(options.locale, str) else list(options.locale)
            )
            primary = locales[0]
            extra_config["navigator.language"] = primary
            extra_config["navigator.languages"] = locales
            extra_config["headers.Accept-Language"] = _accept_language(locales)
            screen_kwargs["i_know_what_im_doing"] = True
        if proxy_dict is not None:
            camoufox_kwargs["proxy"] = proxy_dict

        logger.action(
            "camoufox_fingerprint",
            os=host_os,
            viewport=viewport,
            random_screen=settings.browser_random_screen,
            locale=options.locale,
            timezone=options.timezone,
            geolocation=list(options.geolocation) if options.geolocation else None,
            proxy=bool(proxy_dict),
        )
        cf = AsyncCamoufox(
            headless=bool(options.headless),
            persistent_context=True,
            os=host_os,
            viewport=viewport,
            humanize=False,
            config=extra_config,
            # Auto-grant persistent-storage để Firefox không hiện popup "store
            # data" — popup này làm Playwright DOM query treo quá timeout.
            firefox_user_prefs={"permissions.default.persistent-storage": 1},
            **camoufox_kwargs,
            **screen_kwargs,
            **common,
        )
        ctx = await cf.__aenter__()

        async def _close() -> None:
            await cf.__aexit__(None, None, None)

        return ctx, _close

    from playwright.async_api import async_playwright

    playwright = await async_playwright().start()

    # Build playwright context kwargs với geo/locale override (chromium hỗ trợ
    # locale, timezone_id, geolocation, proxy native).
    pw_locale = options.locale if isinstance(options.locale, str) else (
        options.locale[0] if options.locale else "en-US"
    )
    pw_kwargs: dict[str, Any] = {"locale": pw_locale}
    if options.timezone:
        pw_kwargs["timezone_id"] = options.timezone
    if options.geolocation is not None:
        lat, lon = options.geolocation
        pw_kwargs["geolocation"] = {"latitude": lat, "longitude": lon, "accuracy": 50.0}
        pw_kwargs["permissions"] = ["geolocation"]
    if proxy_dict is not None:
        pw_kwargs["proxy"] = proxy_dict

    if options.browser == "chrome":
        try:
            ctx = await playwright.chromium.launch_persistent_context(
                channel="chrome",
                headless=bool(options.headless),
                viewport=viewport,
                **pw_kwargs,
                **common,
            )
        except Exception as exc:
            logger.action("browser_fallback", from_browser="chrome", to_browser="chromium", error=repr(exc))
            print(f"[recorder] Chrome launch failed, fallback Chromium: {exc}")
            ctx = await playwright.chromium.launch_persistent_context(
                headless=bool(options.headless),
                viewport=viewport,
                **pw_kwargs,
                **common,
            )
    else:
        ctx = await playwright.chromium.launch_persistent_context(
            headless=bool(options.headless),
            viewport=viewport,
            **pw_kwargs,
            **common,
        )

    async def _close() -> None:
        try:
            await ctx.close()
        finally:
            await playwright.stop()

    return ctx, _close


async def _attach_page(page, logger: RecorderLog) -> None:
    page.on("console", lambda msg: logger.console("console", type=msg.type, text=msg.text[:1500]))
    page.on("pageerror", lambda err: logger.console("pageerror", text=str(err)[:1500]))
    page.on("close", lambda: logger.action("page_close", url=page.url))


async def run_web_recording(options: WebRecorderOptions) -> int:
    label = _safe_email_label(options.email)
    run_dir = options.output_root.resolve() / f"web_record_{_now_label()}_{label}"
    logger = RecorderLog(run_dir)
    logger.result(status="started", email=options.email, start_url=options.url, dry_run=options.dry_run)

    print(f"[recorder] output: {run_dir}")
    print(f"[recorder] HAR: {logger.har_path}")
    print(f"[recorder] actions: {logger.actions_path}")

    # Ghi profile/billing kèm artifact để thao tác viên copy điền form.
    if options.profile:
        profile_path = run_dir / "profile_billing.json"
        profile_path.write_text(
            json.dumps(options.profile, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.action("profile_billing", **options.profile)
        print(f"[recorder] billing profile: {profile_path}")
        for key, value in options.profile.items():
            print(f"           {key:14s}: {value}")

    if options.dry_run:
        logger.action("dry_run", email=options.email, url=options.url)
        logger.result(
            status="dry_run_ok",
            email=options.email,
            browser=options.browser,
            output=str(run_dir),
        )
        logger.close()
        print("[recorder] dry-run OK")
        return 0

    ctx = None
    close_ctx = None
    try:
        ctx, close_ctx = await _open_context(options, logger)
        await ctx.expose_binding(
            "__recordAction",
            lambda source, payload: logger.dom_action(
                {
                    **dict(payload),
                    "page_url": source["page"].url if source and source.get("page") else None,
                }
            ),
        )
        await ctx.add_init_script(ACTION_INIT_SCRIPT)
        await ctx.add_init_script(RADIX_FONT_FIX_SCRIPT)
        if getattr(ctx, "tracing", None) is not None:
            await ctx.tracing.start(screenshots=True, snapshots=True, sources=False)
        ctx.on("request", logger.request)
        ctx.on("response", logger.response)
        ctx.on("requestfailed", logger.request_failed)
        ctx.on("page", lambda page: asyncio.create_task(_attach_page(page, logger)))

        page = ctx.pages[0] if ctx.pages else await ctx.new_page()
        await _attach_page(page, logger)

        try:
            logger.action("goto", url=options.url)
            await page.goto(options.url, wait_until="domcontentloaded", timeout=60000)
            await logger.screenshot(page, "start")
            print("[recorder] Browser is open.")
            print("[recorder] Commands: Enter=screenshot, otp=fetch OTP, q=stop")

            while True:
                cmd = await asyncio.to_thread(input, "[recorder] > ")
                cmd = cmd.strip().lower()
                if cmd in {"q", "quit", "done", "stop"}:
                    logger.action("operator_stop", url=page.url)
                    break
                if cmd == "otp":
                    if not options.email or not options.secret:
                        print("[recorder] --email and --secret are required for otp")
                        logger.action("otp_fetch_skipped", reason="missing_email_or_secret")
                        continue
                    try:
                        code = await fetch_otp(
                            api_url=options.otp_api_url,
                            email=options.email,
                            secret=options.secret,
                        )
                        print(f"[recorder] OTP: {code}")
                        logger.action("otp_fetch_ok", code_length=len(code))
                    except Exception as exc:  # noqa: BLE001
                        print(f"[recorder] OTP fetch failed: {exc}")
                        logger.action("otp_fetch_failed", error=repr(exc))
                    continue
                label = cmd or "checkpoint"
                try:
                    shot = await logger.screenshot(page, label)
                    print(f"[recorder] screenshot: {shot}")
                except Exception as exc:  # noqa: BLE001
                    print(f"[recorder] screenshot failed: {exc}")
                    logger.action("screenshot_failed", label=label, error=repr(exc))

            final_url = page.url
            await logger.screenshot(page, "stop")
            if getattr(ctx, "tracing", None) is not None:
                await ctx.tracing.stop(path=str(logger.trace_path))
            if close_ctx is not None:
                await close_ctx()
            logger.result(
                status="stopped",
                email=options.email,
                browser=options.browser,
                final_url=final_url,
                output=str(run_dir),
                har=str(logger.har_path),
                trace=str(logger.trace_path),
            )
            print("[recorder] stopped")
            print(f"[recorder] trace: {logger.trace_path}")
            return 0
        except KeyboardInterrupt:
            logger.action("keyboard_interrupt", url=page.url)
            try:
                if getattr(ctx, "tracing", None) is not None:
                    await ctx.tracing.stop(path=str(logger.trace_path))
            except Exception:
                pass
            try:
                if close_ctx is not None:
                    await close_ctx()
            except Exception:
                pass
            logger.result(
                status="interrupted",
                email=options.email,
                browser=options.browser,
                output=str(run_dir),
            )
            print("\n[recorder] interrupted")
            return 130
        except Exception as exc:  # noqa: BLE001
            logger.action("fatal", error=repr(exc))
            try:
                if getattr(ctx, "tracing", None) is not None:
                    await ctx.tracing.stop(path=str(logger.trace_path))
            except Exception:
                pass
            try:
                if close_ctx is not None:
                    await close_ctx()
            except Exception:
                pass
            logger.result(
                status="error",
                email=options.email,
                browser=options.browser,
                error=repr(exc),
                output=str(run_dir),
            )
            print(f"[recorder] error: {exc}", file=sys.stderr)
            return 1
        finally:
            logger.close()
    except Exception as exc:  # noqa: BLE001
        logger.action("fatal_open", error=repr(exc))
        logger.result(
            status="error",
            email=options.email,
            browser=options.browser,
            error=repr(exc),
            output=str(run_dir),
        )
        logger.close()
        print(f"[recorder] error: {exc}", file=sys.stderr)
        return 1
