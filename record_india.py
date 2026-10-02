"""Script: record browser session với identity Ấn Độ + full HAR + actions.

Ép browser fingerprint sang India:
    - locale  : en-IN (Intl API + Accept-Language + navigator.language)
    - timezone: Asia/Kolkata
    - geo     : New Delhi (lat 28.6139, lon 77.2090)
    - billing/profile Ấn Độ random (name, phone +91, address, city, state, PIN)
    - off_font: tắt camoufox font randomization (fonts:spacing_seed=0) để
      country/region dropdown render đúng (mặc định bật; tắt bằng --no-off-font)

Capture (qua web_recorder engine):
    - Full HAR (request + response body embed)  → trace.har
    - DOM actions: click / input / change / submit / keydown  → actions.jsonl
    - Network requests/responses                → requests.jsonl
    - Console + Playwright trace                → console.jsonl, trace.zip
    - Screenshots theo checkpoint

Chạy (phải chạy dạng module để relative import hoạt động):
    python -m gpt_signup_hybrid.record_india
    python -m gpt_signup_hybrid.record_india --url https://chatgpt.com/ --proxy http://user:pass@host:port
    python -m gpt_signup_hybrid.record_india --browser chrome --headless

Lệnh trong recorder: Enter=screenshot, otp=fetch OTP (cần --email/--secret), q=stop.
"""
from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from random_profile import random_india_profile
from web_recorder import (
    DEFAULT_OTP_API_URL,
    DEFAULT_START_URL,
    WebRecorderOptions,
    run_web_recording,
    validate_web_recorder_options,
)

# India geo constants — New Delhi.
INDIA_LOCALE = ["en-IN", "en"]
INDIA_TIMEZONE = "Asia/Kolkata"
INDIA_GEOLOCATION = (28.6139, 77.2090)  # (latitude, longitude)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="record_india",
        description="Record browser (India identity) + full HAR + actions.",
    )
    parser.add_argument("--url", default=DEFAULT_START_URL, help="URL mở lúc start.")
    parser.add_argument(
        "--output-root",
        default="runtime/research_logs",
        help="Thư mục chứa artifact. Default: runtime/research_logs",
    )
    parser.add_argument(
        "--browser",
        default="camoufox",
        choices=("camoufox", "chrome", "chromium"),
        help="Engine browser. Default: camoufox",
    )
    parser.add_argument("--headless", action="store_true", help="Chạy headless.")
    parser.add_argument("--width", type=int, default=1280, help="Chiều rộng viewport. Default: 1280")
    parser.add_argument("--height", type=int, default=800, help="Chiều cao viewport. Default: 800")
    parser.add_argument(
        "--proxy",
        default=None,
        help="Proxy (vd http://user:pass@host:port). Nên dùng proxy IP Ấn Độ.",
    )
    parser.add_argument("--email", default=None, help="Mailbox cho lệnh otp (tuỳ chọn).")
    parser.add_argument("--secret", default=None, help="Secret đi kèm --email (tuỳ chọn).")
    parser.add_argument("--otp-api-url", default=DEFAULT_OTP_API_URL, help="OTP API URL.")
    parser.add_argument(
        "--no-off-font",
        dest="off_font",
        action="store_false",
        help="KHÔNG tắt font randomization (mặc định tắt để dropdown vùng render đúng).",
    )
    parser.set_defaults(off_font=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    profile = random_india_profile()
    options = WebRecorderOptions(
        url=args.url,
        output_root=Path(args.output_root),
        email=args.email,
        secret=args.secret,
        otp_api_url=args.otp_api_url,
        headless=args.headless,
        browser=args.browser,
        locale=INDIA_LOCALE,
        timezone=INDIA_TIMEZONE,
        geolocation=INDIA_GEOLOCATION,
        proxy=args.proxy,
        profile=profile,
        off_font=args.off_font,
        viewport=(args.width, args.height),
    )

    validate_web_recorder_options(options)

    print("[record_india] identity → locale=en-IN timezone=Asia/Kolkata geo=New Delhi")
    if not args.proxy:
        print(
            "[record_india] CẢNH BÁO: không có proxy → IP thật của bạn không phải "
            "Ấn Độ. Fingerprint (locale/tz/geo) là India nhưng IP lệch nước. "
            "Truyền --proxy IP Ấn Độ để nhất quán."
        )
    return asyncio.run(run_web_recording(options))


if __name__ == "__main__":
    raise SystemExit(main())
