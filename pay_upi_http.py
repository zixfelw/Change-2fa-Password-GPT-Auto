"""Pure-HTTP UPI payment flow (best-effort).

KHÔNG dùng browser. Dùng curl_cffi (impersonate Chrome desktop Windows TLS) cho
tất cả request. Login bằng `session_phase.get_session_pure_request`.

Phạm vi proxy:
    ✗ Login chatgpt → DIRECT (không proxy, dùng IP thật để giảm captcha)
    ✓ Step 2+ (checkout, Stripe init/elements, confirm, approve) → via proxy

Phạm vi pure-HTTP:
    ✓  Login chatgpt → access_token + cookies (DIRECT)
    ✓  POST chatgpt.com/backend-api/payments/checkout (custom UI mode)
    ✓  POST api.stripe.com/v1/payment_pages/{id}/init
    ✓  GET  api.stripe.com/v1/elements/sessions
    ✓  POST api.stripe.com/v1/consumers/sessions/lookup (skip OK)
    ⚠  POST api.stripe.com/v1/payment_pages/{id}/confirm
        — Stripe yêu cầu 3 token JS-runtime KHÔNG thể tái tạo ngoài
          browser: `js_checksum`, `rv_timestamp`, `passive_captcha_token`.
          Script vẫn submit best-effort; nếu Stripe reject sẽ log đầy đủ.
    ✓  POST chatgpt.com/backend-api/payments/checkout/approve

UA + TLS persona: import từ ``user_agent_profile`` (Windows Chrome 145) để
đồng bộ với reg flow + sentinel — cùng device persona xuyên suốt 1 account.

Cách chạy:
    python -m gpt_signup_hybrid.pay_upi_http \\
        --combo 'EMAIL|PASS|SECRET' \\
        --vpa 'name@oksbi' \\
        --proxy 'http://user:pass@host:port'
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import time
import uuid
from pathlib import Path
from typing import Any

from random_profile import random_india_profile
from session_phase import get_session_pure_request
from user_agent_profile import (
    CURL_IMPERSONATE_PRIMARY as _UA_IMPERSONATE_PRIMARY,
    SEC_CH_UA as _SEC_CH_UA,
    SEC_CH_UA_MOBILE as _SEC_CH_UA_MOBILE,
    SEC_CH_UA_PLATFORM as _SEC_CH_UA_PLATFORM,
    WINDOWS_USER_AGENT as _WINDOWS_USER_AGENT,
)
from web.proxy_format import mask_proxy as _mask_proxy_url


def _proxy_log_label(proxies: dict | None) -> str:
    """Format proxy cho log step: ``DIRECT`` hoặc ``via ***@host:port``.

    Trước fix dùng chỉ ``yes/no`` → user không biết IP nào đang dùng và khi
    nào silent fallback qua DIRECT. Show masked URL để verify trực quan.
    """
    if not proxies:
        return "DIRECT"
    # _ProxyPolicy.dict_for trả {http, https} cùng URL — lấy 1.
    url = proxies.get("https") or proxies.get("http")
    return f"via {_mask_proxy_url(url)}" if url else "via ?"


# ─────────────────────────────────────────────────────────────────────
# Pretty log helpers — màu ANSI (auto-disable nếu không phải tty)
# ─────────────────────────────────────────────────────────────────────


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not hasattr(sys.stdout, "isatty"):
        return False
    return bool(sys.stdout.isatty())


_USE_COLOR = _supports_color()


def _c(code: str, text: str) -> str:
    return f"\x1b[{code}m{text}\x1b[0m" if _USE_COLOR else text


def _bold(t: str) -> str:    return _c("1", t)
def _dim(t: str) -> str:     return _c("2", t)
def _green(t: str) -> str:   return _c("32", t)
def _red(t: str) -> str:     return _c("31", t)
def _yellow(t: str) -> str:  return _c("33", t)
def _blue(t: str) -> str:    return _c("34", t)
def _cyan(t: str) -> str:    return _c("36", t)
def _gray(t: str) -> str:    return _c("90", t)


def _short(s: str, head: int = 20, tail: int = 16) -> str:
    """Rút gọn chuỗi dài: <head>…<tail>"""
    if not s:
        return s
    if len(s) <= head + tail + 1:
        return s
    return f"{s[:head]}…{s[-tail:]}"


def _short_url(url: str, max_len: int = 90) -> str:
    """Rút gọn URL: domain + path + tail của query nếu quá dài."""
    if len(url) <= max_len:
        return url
    return url[:max_len - 12] + "…"


# ─────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────

_IMPERSONATE = _UA_IMPERSONATE_PRIMARY
_USER_AGENT = _WINDOWS_USER_AGENT
_STRIPE_VERSION = (
    "2025-03-31.basil; checkout_server_update_beta=v1; "
    "checkout_manual_approval_preview=v1"
)
_CHATGPT_CHECKOUT_URL = "https://chatgpt.com/backend-api/payments/checkout"
_CHATGPT_APPROVE_URL = "https://chatgpt.com/backend-api/payments/checkout/approve"
_STRIPE_INIT_URL = "https://api.stripe.com/v1/payment_pages/{id}/init"
_STRIPE_PAGE_URL = "https://api.stripe.com/v1/payment_pages/{id}"
_STRIPE_CONFIRM_URL = "https://api.stripe.com/v1/payment_pages/{id}/confirm"
_STRIPE_ELEMENTS_URL = "https://api.stripe.com/v1/elements/sessions"
_STRIPE_CONSUMER_LOOKUP_URL = "https://api.stripe.com/v1/consumers/sessions/lookup"


# ─────────────────────────────────────────────────────────────────────
# Errors
# ─────────────────────────────────────────────────────────────────────


class PayUpiError(Exception):
    """Pay flow failed."""


# ─────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────


def _uuid4() -> str:
    return str(uuid.uuid4())


def _stripe_guid() -> str:
    """Stripe `guid` cookie format: <uuid>-<10hex>. Sinh ngẫu nhiên."""
    return f"{_uuid4()}{uuid.uuid4().hex[:10]}"


def _flatten(prefix: str, value: Any, out: list[tuple[str, str]]) -> None:
    """Flatten dict/list về form-urlencoded keys (Stripe convention)."""
    if isinstance(value, dict):
        for k, v in value.items():
            _flatten(f"{prefix}[{k}]", v, out)
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            _flatten(f"{prefix}[{i}]", v, out)
    elif value is None:
        return
    elif isinstance(value, bool):
        out.append((prefix, "true" if value else "false"))
    else:
        out.append((prefix, str(value)))


def _to_form(data: dict) -> list[tuple[str, str]]:
    """dict (có thể nested) → list (key, value) cho form-urlencoded."""
    out: list[tuple[str, str]] = []
    for k, v in data.items():
        _flatten(k, v, out)
    return out


def _parse_proxy(proxy: str | None) -> dict | None:
    if not proxy:
        return None
    return {"http": proxy, "https": proxy}


# ─────────────────────────────────────────────────────────────────────
# Proxy policy — chọn step nào áp proxy
# ─────────────────────────────────────────────────────────────────────


# Map step number → tên + mô tả (single source of truth cho CLI help + log).
_STEP_NAMES = {
    1: "login (HTTP login chatgpt → access_token)",
    2: "checkout (POST /backend-api/payments/checkout)",
    3: "stripe_init (POST /v1/payment_pages/{cs}/init)",
    4: "stripe_elements (GET /v1/elements/sessions)",
    5: "token+confirm (extract token + POST /v1/payment_pages/{cs}/confirm)",
    6: "approve (POST /backend-api/payments/checkout/approve)",
}


class _ProxyPolicy:
    """Quyết định mỗi step có đi qua proxy hay không.

    Cấu trúc:
        - `proxy_url`: chuỗi proxy gốc (None = không có proxy).
        - `from_step`: step bắt đầu áp proxy. Mọi step >= from_step đều dùng
          proxy; step nhỏ hơn đi DIRECT.

    Ví dụ:
        from_step=1 → toàn bộ via proxy
        from_step=2 → step 1 (login) DIRECT, step 2-6 via proxy
        from_step=5 → step 1-4 DIRECT, step 5-6 via proxy (token+confirm+approve)
        from_step=6 → step 1-5 DIRECT, step 6 (approve) via proxy

    Caller compute proxies kwarg cho từng request:
        sess.post(url, ..., proxies=policy.dict_for(step))
    """

    def __init__(self, proxy: str | None, from_step: int = 1) -> None:
        if from_step < 1:
            raise ValueError(f"from_step phải >= 1, nhận {from_step}")
        self.proxy_url = proxy
        self.from_step = from_step
        self._proxy_dict = _parse_proxy(proxy)

    def url_for(self, step: int) -> str | None:
        """Trả proxy URL (string) hoặc None — dùng cho function nhận proxy str."""
        return self.proxy_url if (self.proxy_url and step >= self.from_step) else None

    def dict_for(self, step: int) -> dict | None:
        """Trả proxies dict {http,https} hoặc None — dùng cho curl_cffi."""
        return self._proxy_dict if (self._proxy_dict and step >= self.from_step) else None

    def used_at(self, step: int) -> bool:
        return self.dict_for(step) is not None

    def summary(self) -> str:
        if not self.proxy_url:
            return "no proxy — toàn bộ flow DIRECT"
        direct = ", ".join(str(s) for s in range(1, self.from_step))
        proxied = ", ".join(str(s) for s in range(self.from_step, 7))
        return (
            f"proxy from step {self.from_step} → "
            f"DIRECT [{direct or '—'}], via proxy [{proxied}]"
        )


# ─────────────────────────────────────────────────────────────────────
# Retry helper — network/timeout aware
# ─────────────────────────────────────────────────────────────────────


async def _retry_call(
    coro_factory,
    *,
    max_attempts: int,
    backoff: float,
    label: str,
    log,
):
    """Retry async call khi network/timeout error.

    Quy ước:
        - `PayUpiError` (server reject hợp lệ — HTTP non-200 từ Stripe/ChatGPT)
          KHÔNG retry, propagate lên caller.
        - Mọi exception khác (curl_cffi.CurlError timeout, asyncio.TimeoutError,
          OSError, ConnectionError...) → retry với linear backoff (backoff*i).
        - Hết max_attempts → raise last exception (caller bắt + xử lý).

    Args:
        coro_factory: callable trả về coroutine (lambda: foo(...)). Phải tạo
            coroutine MỚI mỗi lần gọi (coroutine cũ đã consumed sau await).
    """
    last_exc: Exception | None = None
    for i in range(1, max_attempts + 1):
        try:
            return await coro_factory()
        except PayUpiError:
            raise  # server reject → không retry
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            log(
                f"        {_yellow('⚠')} {label} attempt {i}/{max_attempts} failed: "
                f"{type(exc).__name__}: {str(exc)[:140]}"
            )
            if i < max_attempts:
                wait = backoff * i
                log(f"        {_dim('└─ retry sau ' + str(wait) + 's…')}")
                await asyncio.sleep(wait)
    assert last_exc is not None
    raise last_exc


# ─────────────────────────────────────────────────────────────────────
# Step 1: ChatGPT checkout (custom UI mode) → session_id + publishable_key
# ─────────────────────────────────────────────────────────────────────


async def _create_chatgpt_checkout(
    sess: Any,
    *,
    access_token: str,
    log,
    proxies: dict | None = None,
) -> dict:
    """POST /backend-api/payments/checkout (custom UI mode) cho India.

    Body khớp với HAR record (web_record_20260616-070836):
        entry_point=all_plans_pricing_modal, plan=chatgptplusplan,
        billing_details.country=IN, currency=INR, checkout_ui_mode=custom.
    """
    body = {
        "entry_point": "all_plans_pricing_modal",
        "plan_name": "chatgptplusplan",
        "billing_details": {"country": "IN", "currency": "INR"},
        "promo_campaign": {
            "promo_campaign_id": "plus-1-month-free",
            "is_coupon_from_query_param": False,
        },
        "checkout_ui_mode": "custom",
    }
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "*/*",
        "Accept-Language": "en-IN,en;q=0.9",
        "Origin": "https://chatgpt.com",
        "Referer": "https://chatgpt.com/?promo_campaign=plus-1-month-free",
        "User-Agent": _USER_AGENT,
        "sec-ch-ua": _SEC_CH_UA,
        "sec-ch-ua-mobile": _SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": _SEC_CH_UA_PLATFORM,
        "x-openai-target-path": "/backend-api/payments/checkout",
        "x-openai-target-route": "/backend-api/payments/checkout",
        "OAI-Language": "en-IN",
    }
    log(f"  {_blue('[2/6]')} POST /backend-api/payments/checkout  {_dim('proxy=' + _proxy_log_label(proxies))}")
    resp = await sess.post(
        _CHATGPT_CHECKOUT_URL, headers=headers, json=body, timeout=30, proxies=proxies,
    )
    if resp.status_code != 200:
        log(f"        {_red('✗')} HTTP {resp.status_code}")
        raise PayUpiError(f"checkout HTTP {resp.status_code}: {resp.text[:300]}")
    data = resp.json()
    needed = ("checkout_session_id", "publishable_key")
    miss = [k for k in needed if not data.get(k)]
    if miss:
        raise PayUpiError(f"checkout response missing {miss}: {data}")
    log(
        f"        {_green('✓')} cs={_short(data['checkout_session_id'], 12, 6)}  "
        f"ui_mode={data.get('checkout_ui_mode')}"
    )
    return data


# ─────────────────────────────────────────────────────────────────────
# Step 2: Stripe init → init_checksum, config_id, etc.
# ─────────────────────────────────────────────────────────────────────


async def _stripe_init(
    sess: Any,
    *,
    session_id: str,
    publishable_key: str,
    stripe_js_id: str,
    log,
    proxies: dict | None = None,
) -> dict:
    url = _STRIPE_INIT_URL.format(id=session_id)
    form = _to_form({
        "browser_locale": "en-IN",
        "browser_timezone": "Asia/Kolkata",
        "elements_session_client": {
            "client_betas": [
                "custom_checkout_server_updates_1",
                "custom_checkout_manual_approval_1",
            ],
            "elements_init_source": "custom_checkout",
            "referrer_host": "chatgpt.com",
            "stripe_js_id": stripe_js_id,
            "locale": "en",
            "is_aggregation_expected": "false",
        },
        "elements_options_client": {
            "saved_payment_method": {
                "enable_save": "auto",
                "enable_redisplay": "auto",
            },
        },
        "key": publishable_key,
        "_stripe_version": _STRIPE_VERSION,
    })
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "Origin": "https://js.stripe.com",
        "Referer": "https://js.stripe.com/",
        "User-Agent": _USER_AGENT,
        "sec-ch-ua": _SEC_CH_UA,
        "sec-ch-ua-mobile": _SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": _SEC_CH_UA_PLATFORM,
        "Accept-Language": "en-IN,en;q=0.9",
    }
    log(f"  {_blue('[3/6]')} POST /v1/payment_pages/{{cs}}/init  {_dim('proxy=' + _proxy_log_label(proxies))}")
    resp = await sess.post(url, headers=headers, data=form, timeout=30, proxies=proxies)
    if resp.status_code != 200:
        log(f"        {_red('✗')} HTTP {resp.status_code}")
        raise PayUpiError(f"stripe init HTTP {resp.status_code}: {resp.text[:300]}")
    data = resp.json()
    init_checksum = data.get("init_checksum")
    config_id = data.get("config_id")
    if not init_checksum or not config_id:
        raise PayUpiError(
            f"stripe init missing init_checksum/config_id: keys={list(data)[:20]}"
        )
    log(f"        {_green('✓')} init_checksum={_short(init_checksum, 12, 6)}  ppage={_short(data.get('id', ''), 12, 6)}")
    return data


# ─────────────────────────────────────────────────────────────────────
# Step 3: Stripe elements/sessions → elements_session_id
# ─────────────────────────────────────────────────────────────────────


async def _stripe_elements_session(
    sess: Any,
    *,
    session_id: str,
    publishable_key: str,
    stripe_js_id: str,
    log,
    proxies: dict | None = None,
) -> dict:
    params = {
        "client_betas[0]": "custom_checkout_server_updates_1",
        "client_betas[1]": "custom_checkout_manual_approval_1",
        "deferred_intent[mode]": "subscription",
        "deferred_intent[amount]": "0",
        "deferred_intent[currency]": "inr",
        "deferred_intent[setup_future_usage]": "off_session",
        "deferred_intent[payment_method_types][0]": "card",
        "deferred_intent[payment_method_types][1]": "link",
        "deferred_intent[payment_method_types][2]": "upi",
        "currency": "inr",
        "key": publishable_key,
        "_stripe_version": _STRIPE_VERSION,
        "elements_init_source": "custom_checkout",
        "referrer_host": "chatgpt.com",
        "stripe_js_id": stripe_js_id,
        "locale": "en",
        "type": "deferred_intent",
        "checkout_session_id": session_id,
    }
    headers = {
        "Accept": "application/json",
        "Origin": "https://js.stripe.com",
        "Referer": "https://js.stripe.com/",
        "User-Agent": _USER_AGENT,
        "sec-ch-ua": _SEC_CH_UA,
        "sec-ch-ua-mobile": _SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": _SEC_CH_UA_PLATFORM,
        "Accept-Language": "en-IN,en;q=0.9",
    }
    log(f"  {_blue('[4/6]')} GET  /v1/elements/sessions  {_dim('proxy=' + _proxy_log_label(proxies))}")
    resp = await sess.get(
        _STRIPE_ELEMENTS_URL, headers=headers, params=params, timeout=30, proxies=proxies,
    )
    if resp.status_code != 200:
        log(f"        {_red('✗')} HTTP {resp.status_code}")
        raise PayUpiError(f"elements/sessions HTTP {resp.status_code}: {resp.text[:300]}")
    data = resp.json()
    sid = data.get("session_id") or ""
    cfg = data.get("config_id") or ""
    if not sid:
        raise PayUpiError(f"elements/sessions missing session_id: keys={list(data)[:20]}")
    log(f"        {_green('✓')} elements_session={_short(sid, 14, 6)}")
    return data


# ─────────────────────────────────────────────────────────────────────
# Step 4: Stripe confirm UPI (best-effort — likely rejected)
# ─────────────────────────────────────────────────────────────────────


async def _stripe_confirm_upi(
    sess: Any,
    *,
    session_id: str,
    publishable_key: str,
    stripe_js_id: str,
    init_data: dict,
    elements_data: dict,
    profile: dict,
    vpa: str,
    email: str,
    log,
    token_config: Any | None = None,
    proxies: dict | None = None,
) -> dict:
    """POST /v1/payment_pages/{id}/confirm với UPI VPA + India billing.

    Khi `token_config` (StripeTokenConfig) cấp:
      - js_checksum + rv_timestamp được compute live qua reverse-engineered
        thuật toán (caesar+xor5+base64). Verified 10/10 PASS với HAR thật.
      - passive_captcha_token vẫn skip (optional trong builder x — Stripe
        accept với risk score cao hơn). Nếu Stripe enforce → log lý do.

    Khi `token_config=None`: fallback rỗng (sẽ bị Stripe reject — chỉ test).
    """
    url = _STRIPE_CONFIRM_URL.format(id=session_id)

    elements_session_id = elements_data.get("session_id")
    elements_session_config_id = elements_data.get("config_id") or ""
    init_config_id = init_data.get("config_id") or ""
    ppage_id = init_data.get("id") or ""
    init_checksum = init_data["init_checksum"]

    client_attribution_metadata = {
        "checkout_config_id": init_config_id,
        "checkout_session_id": session_id,
        "client_session_id": stripe_js_id,
        "elements_session_config_id": elements_session_config_id,
        "elements_session_id": elements_session_id,
        "merchant_integration_additional_elements": [
            "expressCheckout", "payment", "address",
        ],
        "merchant_integration_source": "checkout",
        "merchant_integration_subtype": "payment-element",
        "merchant_integration_version": "custom",
        "payment_intent_creation_flow": "deferred",
        "payment_method_selection_flow": "merchant_specified",
    }

    pmd_client_attribution = dict(client_attribution_metadata)
    pmd_client_attribution["merchant_integration_source"] = "elements"
    pmd_client_attribution["merchant_integration_version"] = "2021"

    # Compute js_checksum + rv_timestamp từ token_config (extract live).
    if token_config is not None:
        import stripe_token as _st
        tokens = _st.build_token_fields(ppage_id=ppage_id, config=token_config)
        js_checksum = tokens["js_checksum"]
        rv_timestamp = tokens["rv_timestamp"]
        log(f"        token: js_checksum={_short(js_checksum, 14, 6)}  rv_ts={_short(rv_timestamp, 14, 6)}")
    else:
        js_checksum = None
        rv_timestamp = None
        log(f"        {_yellow('⚠')} thiếu token_config — submit không có js_checksum")

    form = _to_form({
        "_stripe_version": _STRIPE_VERSION,
        "client_attribution_metadata": client_attribution_metadata,
        "elements_options_client": {
            "saved_payment_method": {
                "enable_redisplay": "auto",
                "enable_save": "auto",
            },
        },
        "elements_session_client": {
            "client_betas": [
                "custom_checkout_server_updates_1",
                "custom_checkout_manual_approval_1",
            ],
            "elements_init_source": "custom_checkout",
            "is_aggregation_expected": "false",
            "locale": "en",
            "referrer_host": "chatgpt.com",
            "session_id": elements_session_id,
            "stripe_js_id": stripe_js_id,
        },
        "expected_amount": 0,
        "expected_payment_method_type": "upi",
        "guid": _stripe_guid(),
        "init_checksum": init_checksum,
        "js_checksum": js_checksum,
        "rv_timestamp": rv_timestamp,
        # passive_captcha_token: optional trong builder — chưa implement,
        # để Stripe trả error rõ nếu enforce.
        "passive_captcha_ekey": None,
        "passive_captcha_token": None,
        "key": publishable_key,
        "muid": _stripe_guid(),
        "sid": _stripe_guid(),
        "payment_method_data": {
            "billing_details": {
                "address": {
                    "city": profile["city"],
                    "country": "IN",
                    "line1": profile["address_line1"],
                    "postal_code": profile["postal_code"],
                    "state": profile["state"],
                },
                "email": email,
                "name": profile["name"],
            },
            "client_attribution_metadata": pmd_client_attribution,
            "payment_user_agent": (
                "stripe.js/e5ebd5e1e6; stripe-js-v3/e5ebd5e1e6; "
                "payment-element; deferred-intent"
            ),
            "referrer": "https://chatgpt.com",
            "time_on_page": int(time.time() * 1000) % 100000,
            "type": "upi",
            "upi": {"vpa": vpa},
        },
        "return_url": (
            f"https://checkout.stripe.com/c/pay/{session_id}"
        ),
        "version": "e5ebd5e1e6",
    })

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "Origin": "https://js.stripe.com",
        "Referer": "https://js.stripe.com/",
        "User-Agent": _USER_AGENT,
        "sec-ch-ua": _SEC_CH_UA,
        "sec-ch-ua-mobile": _SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": _SEC_CH_UA_PLATFORM,
        "Accept-Language": "en-IN,en;q=0.9",
    }
    log(f"  {_blue('[5/6]')} POST /v1/payment_pages/{{cs}}/confirm  {_dim('proxy=' + _proxy_log_label(proxies))}")
    resp = await sess.post(url, headers=headers, data=form, timeout=30, proxies=proxies)
    body_text = resp.text or ""
    try:
        data = resp.json()
    except Exception:
        data = {"_raw": body_text[:1000]}

    if resp.status_code != 200:
        err = data.get("error", {}) if isinstance(data, dict) else {}
        log(
            f"        {_red('✗')} HTTP {resp.status_code} "
            f"code={err.get('code')} param={err.get('param')}"
        )
        raise PayUpiError(
            f"stripe confirm rejected (HTTP {resp.status_code}): "
            f"{json.dumps(err)[:400]}"
        )
    log(f"        {_green('✓')} HTTP 200  confirm OK ({len(data) if isinstance(data, dict) else 0} keys)")
    return data


# ─────────────────────────────────────────────────────────────────────
# Step 5: ChatGPT approve
# ─────────────────────────────────────────────────────────────────────


async def _chatgpt_approve(
    sess: Any,
    *,
    access_token: str,
    session_id: str,
    log,
    proxies: dict | None = None,
) -> dict:
    body = {"checkout_session_id": session_id, "processor_entity": "openai_llc"}
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "*/*",
        "Accept-Language": "en-IN,en;q=0.9",
        "Origin": "https://chatgpt.com",
        "Referer": f"https://chatgpt.com/checkout/openai_llc/{session_id}",
        "User-Agent": _USER_AGENT,
        "sec-ch-ua": _SEC_CH_UA,
        "sec-ch-ua-mobile": _SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": _SEC_CH_UA_PLATFORM,
        "x-openai-target-path": "/backend-api/payments/checkout/approve",
        "x-openai-target-route": "/backend-api/payments/checkout/approve",
        "OAI-Language": "en-IN",
    }
    log(f"  {_blue('[6/6]')} POST /backend-api/payments/checkout/approve  {_dim('proxy=' + _proxy_log_label(proxies))}")
    resp = await sess.post(_CHATGPT_APPROVE_URL, headers=headers, json=body, timeout=30, proxies=proxies)
    body_short = (resp.text or "").strip()[:120]
    if resp.status_code != 200:
        log(f"        {_red('✗')} HTTP {resp.status_code} body={body_short}")
    else:
        try:
            d = resp.json()
            r = d.get("result")
            if r == "approved":
                log(f"        {_green('✓ APPROVED')}")
            elif r == "blocked":
                log(f"        {_red('✗ blocked')}")
            else:
                log(f"        {_yellow('?')} result={r}")
        except Exception:
            log(f"        body={body_short}")
    try:
        return resp.json()
    except Exception:
        return {"_raw": resp.text[:500], "_status": resp.status_code}


# ─────────────────────────────────────────────────────────────────────
# Orchestrator
# ─────────────────────────────────────────────────────────────────────


async def _attempt_subscribe(
    sess: Any,
    *,
    access_token: str,
    session_id: str,
    publishable_key: str,
    stripe_js_id: str,
    init_data: dict,
    elements_data: dict,
    profile: dict,
    vpa: str,
    email: str,
    token_config: Any | None,
    log,
    policy: _ProxyPolicy,
    retry_attempts: int = 3,
    retry_backoff: float = 2.0,
) -> dict:
    """Một lượt confirm + approve. LUÔN trả dict (không raise).

    Mỗi step (confirm, approve) được wrap bằng `_retry_call`:
        - Network/timeout error → retry tối đa `retry_attempts` lần.
        - Hết retry → trả failure dict với stage='*_network'.
        - PayUpiError (server reject) → trả failure dict với stage='stripe_confirm'.

    Caller (spam loop) đọc `attempt['ok']` + `attempt['stage']` để tiếp tục
    iteration tiếp theo, KHÔNG bao giờ crash do exception.
    """
    # ─── CONFIRM ───
    try:
        confirm_data = await _retry_call(
            lambda: _stripe_confirm_upi(
                sess,
                session_id=session_id,
                publishable_key=publishable_key,
                stripe_js_id=stripe_js_id,
                init_data=init_data,
                elements_data=elements_data,
                profile=profile,
                vpa=vpa,
                email=email,
                log=log,
                token_config=token_config,
                proxies=policy.dict_for(5),
            ),
            max_attempts=retry_attempts,
            backoff=retry_backoff,
            label="stripe_confirm",
            log=log,
        )
    except PayUpiError as exc:
        return {
            "ok": False,
            "stage": "stripe_confirm",
            "error": str(exc),
            "result": None,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "ok": False,
            "stage": "stripe_confirm_network",
            "error": f"{type(exc).__name__}: {str(exc)[:200]}",
            "result": None,
        }

    # ─── APPROVE ───
    try:
        approve_data = await _retry_call(
            lambda: _chatgpt_approve(
                sess, access_token=access_token, session_id=session_id, log=log,
                proxies=policy.dict_for(6),
            ),
            max_attempts=retry_attempts,
            backoff=retry_backoff,
            label="approve",
            log=log,
        )
    except Exception as exc:  # noqa: BLE001
        # Approve fail (network) — confirm đã thành công nhưng không xác nhận
        # được result. Coi như attempt fail, để spam loop chạy tiếp.
        return {
            "ok": False,
            "stage": "approve_network",
            "error": f"{type(exc).__name__}: {str(exc)[:200]}",
            "result": None,
            "confirm_keys": list(confirm_data)[:20] if isinstance(confirm_data, dict) else [],
        }
    result = approve_data.get("result") if isinstance(approve_data, dict) else None
    return {
        "ok": result == "approved",
        "stage": "approve",
        "result": result,
        "approve": approve_data,
        "confirm_keys": list(confirm_data)[:20],
    }


async def run_pay_upi(
    *,
    email: str,
    password: str,
    secret: str,
    vpa: str,
    proxy: str | None,
    log,
    sub_count: int = 1,
    sub_delay_min: float = 1.0,
    sub_delay_max: float = 3.0,
    sub_stop_on_approve: bool = True,
    sub_rotate_billing: bool = False,
    sub_rotate_stripe_session: int = 0,
    proxy_from_step: int = 1,
    retry_attempts: int = 3,
    retry_backoff: float = 2.0,
) -> dict:
    """Pure-HTTP pay flow + tùy chọn spam N lần.

    Args:
        proxy_from_step: step bắt đầu áp proxy (1-6, default 1 = toàn bộ via proxy).
            Step 1 login, 2 checkout, 3 stripe_init, 4 elements, 5 token+confirm,
            6 approve. Step < proxy_from_step đi DIRECT.
        sub_count: số lần lặp confirm+approve (1 = single shot).
        sub_delay_min/max: random delay giữa các lần (rate-limit safety).
        sub_stop_on_approve: True → dừng ngay khi gặp approve (default).
        sub_rotate_billing: True → mỗi lần dùng billing IN khác (giảm dup signal).
        sub_rotate_stripe_session: N>0 → cứ N attempt re-init Stripe (làm mới
            init_checksum + elements_session_id, tránh expire). 0 = không rotate.
    """
    import random as _random

    policy = _ProxyPolicy(proxy, from_step=proxy_from_step)
    log(f"\n{_bold(_cyan('▸ PROXY POLICY'))}  {policy.summary()}")

    # Section 1: Login (step 1 — proxy nếu policy cho phép)
    proxy_tag1 = "via proxy" if policy.url_for(1) else "DIRECT"
    log(f"\n{_bold(_cyan('▸ STEP 1'))}  Login pure-HTTP {_dim('(' + proxy_tag1 + ')')}")
    session_data = await get_session_pure_request(
        email=email, password=password, secret=secret, proxy=policy.url_for(1), log=log,
    )
    access_token = session_data.get("accessToken")
    if not isinstance(access_token, str) or not access_token:
        raise PayUpiError("login response missing accessToken")
    user_email = (session_data.get('user') or {}).get('email')
    log(f"        {_green('✓')} user={user_email}  access_token={_short(access_token, 16, 8)}")

    profile = random_india_profile()
    log(
        f"        {_dim('billing IN auto-gen:')} "
        f"{_bold(profile['name'])} | {profile['city']}, {profile['state']} | {profile['phone']}"
    )

    from curl_cffi.requests import AsyncSession
    import stripe_token as _st

    # AsyncSession KHÔNG dùng proxies session-level — mỗi request truyền proxies
    # riêng qua `policy.dict_for(step)` để chuyển đổi điểm áp proxy bằng flag CLI.
    async with AsyncSession(impersonate=_IMPERSONATE) as sess:
        # Section 2-4: Setup checkout (step 2-4 độc lập theo policy)
        log(f"\n{_bold(_cyan('▸ STEP 2-4'))}  Setup checkout session")
        chatgpt = await _create_chatgpt_checkout(
            sess, access_token=access_token, log=log, proxies=policy.dict_for(2),
        )
        session_id = chatgpt["checkout_session_id"]
        publishable_key = chatgpt["publishable_key"]
        stripe_js_id = _uuid4()

        init_data = await _stripe_init(
            sess, session_id=session_id, publishable_key=publishable_key,
            stripe_js_id=stripe_js_id, log=log, proxies=policy.dict_for(3),
        )
        elements_data = await _stripe_elements_session(
            sess, session_id=session_id, publishable_key=publishable_key,
            stripe_js_id=stripe_js_id, log=log, proxies=policy.dict_for(4),
        )

        # Section 5a: Token config (cùng proxy với step 5 confirm)
        proxy_tag5 = "via proxy" if policy.dict_for(5) else "DIRECT"
        log(f"\n{_bold(_cyan('▸ STEP 5a'))}  Stripe token config (auto-fetch + extract) {_dim('(' + proxy_tag5 + ')')}")
        from pathlib import Path as _Path
        fallback_dirs = [
            _Path("runtime/cache/stripe_bundles_default"),
            _Path("/tmp/stripe_har_dump"),
        ]
        fallback_dir = next(
            (
                d for d in fallback_dirs
                if d.is_dir() and any(d.glob("*custom*checkout*.js"))
            ),
            None,
        )
        try:
            token_config = await _st.extract_config_live(
                sess, log=log, use_cache=True, fallback_dir=fallback_dir,
                proxies=policy.dict_for(5),
            )
            log(
                f"        {_green('✓')} shift={token_config.shift}  "
                f"rv={_short(token_config.rv, 8, 4)}  sv={_short(token_config.sv, 8, 4)}"
            )
        except _st.StripeTokenExtractError as exc:
            log(f"        {_red('✗')} extract config FAIL: {exc}")
            log(f"        {_yellow('⚠')} fallback: confirm với token rỗng (Stripe có thể reject)")
            token_config = None

        # Section 5-6: Spam loop (confirm + approve)
        if sub_count > 1:
            log(
                f"\n{_bold(_cyan('▸ STEP 5-6'))}  Spam loop  "
                f"sub={sub_count}  delay={sub_delay_min}-{sub_delay_max}s  "
                f"rotate_billing={sub_rotate_billing}  rotate_stripe={sub_rotate_stripe_session}"
            )
        else:
            log(f"\n{_bold(_cyan('▸ STEP 5-6'))}  Submit confirm + approve")

        history: list[dict] = []
        approved_at: int | None = None
        counts = {"approved": 0, "blocked": 0, "error": 0, "other": 0}

        for i in range(1, sub_count + 1):
            if sub_rotate_billing and i > 1:
                profile = random_india_profile()

            if sub_rotate_stripe_session and i > 1 and (i - 1) % sub_rotate_stripe_session == 0:
                log(f"\n  {_yellow('↻')} re-init Stripe (every {sub_rotate_stripe_session})")
                stripe_js_id = _uuid4()
                init_data = await _stripe_init(
                    sess, session_id=session_id, publishable_key=publishable_key,
                    stripe_js_id=stripe_js_id, log=log, proxies=policy.dict_for(3),
                )
                elements_data = await _stripe_elements_session(
                    sess, session_id=session_id, publishable_key=publishable_key,
                    stripe_js_id=stripe_js_id, log=log, proxies=policy.dict_for(4),
                )

            # Sub header
            if sub_count > 1:
                log(
                    f"\n  {_bold(_blue(f'┌── SUB {i:>3}/{sub_count}'))}  "
                    f"{_dim('billing=')}{profile['name']}"
                )
            t0 = time.monotonic()
            attempt = await _attempt_subscribe(
                sess,
                access_token=access_token,
                session_id=session_id,
                publishable_key=publishable_key,
                stripe_js_id=stripe_js_id,
                init_data=init_data,
                elements_data=elements_data,
                profile=profile,
                vpa=vpa,
                email=email,
                token_config=token_config,
                log=log,
                policy=policy,
                retry_attempts=retry_attempts,
                retry_backoff=retry_backoff,
            )
            elapsed = time.monotonic() - t0
            attempt["sub_index"] = i
            attempt["elapsed_seconds"] = round(elapsed, 2)
            attempt["billing_name"] = profile["name"]
            history.append(attempt)

            result = attempt.get("result")
            stage = attempt.get("stage")
            if stage == "stripe_confirm" and not attempt.get("ok"):
                counts["error"] += 1
                summary = f"  {_red('└─ ERROR')}  confirm fail  {elapsed:.1f}s"
            elif stage == "stripe_confirm_network":
                counts["error"] += 1
                err_short = str(attempt.get('error') or '')[:80]
                summary = f"  {_red('└─ NETWORK ERROR (confirm)')}  {err_short}  {elapsed:.1f}s — tiếp tục loop"
            elif stage == "approve_network":
                counts["error"] += 1
                err_short = str(attempt.get('error') or '')[:80]
                summary = f"  {_red('└─ NETWORK ERROR (approve)')}  {err_short}  {elapsed:.1f}s — tiếp tục loop"
            elif result == "approved":
                counts["approved"] += 1
                if approved_at is None:
                    approved_at = i
                summary = f"  {_green(_bold('└─ ✓ APPROVED'))}  {elapsed:.1f}s"
            elif result == "blocked":
                counts["blocked"] += 1
                _totals = (
                    f"totals: ✓{counts['approved']} "
                    f"✗{counts['blocked']} ⚠{counts['error']}"
                )
                summary = f"  {_red('└─ ✗ BLOCKED')}  {elapsed:.1f}s  {_dim(_totals)}"
            else:
                counts["other"] += 1
                summary = f"  {_yellow('└─ ?')}  result={result}  {elapsed:.1f}s"

            if sub_count > 1:
                log(summary)
            else:
                log(f"\n{_bold('▸ FINAL')}  result={_bold(result or 'unknown')}  {elapsed:.1f}s")

            if result == "approved" and sub_stop_on_approve:
                log(f"\n  {_green('●')} stop_on_approve=True → dừng tại i={i}")
                break

            if i < sub_count:
                delay = _random.uniform(sub_delay_min, sub_delay_max)
                await asyncio.sleep(delay)

        ok = counts["approved"] > 0
        return {
            "ok": ok,
            "stage": "spam_summary" if sub_count > 1 else "approve",
            "result": "approved" if ok else (history[-1].get("result") if history else None),
            "checkout_session_id": session_id,
            "profile": profile,
            "sub_count": sub_count,
            "counts": counts,
            "approved_at": approved_at,
            "history": history,
            "token_config": (
                {
                    "shift": token_config.shift,
                    "rv_ts": token_config.rv_ts,
                    "rv": token_config.rv[:24] + "…",
                    "sv": token_config.sv[:24] + "…",
                    "bundle_hash": token_config.bundle_hash[:16] + "…",
                }
                if token_config else None
            ),
        }


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
        prog="pay_upi_http",
        description="Pure-HTTP UPI payment flow (best-effort).",
    )
    p.add_argument("--combo", required=True, help="email|password|totp_secret")
    p.add_argument("--vpa", required=True, help="UPI VPA, vd 'name@oksbi'")
    p.add_argument("--proxy", default=None, help="proxy URL (khuyến nghị IN residential)")
    p.add_argument(
        "--proxy-from-step", type=int, default=3, choices=tuple(range(1, 7)),
        metavar="N",
        help=(
            "Step bắt đầu áp proxy (1-6, default 3 = từ khi bắt đầu request "
            "đến checkout session cs_live_xxx). Step nhỏ hơn N đi DIRECT. "
            "1=login, 2=checkout, 3=stripe_init, 4=elements, "
            "5=token+confirm, 6=approve. "
            "Default 3 → step 1-2 DIRECT (login + tạo checkout chưa có cs_live_), "
            "step 3-6 via proxy (mọi request đến cs_live_xxx)."
        ),
    )
    p.add_argument(
        "--retry-attempts", type=int, default=3, metavar="N",
        help=(
            "Số lần retry mỗi step (confirm + approve) khi network/timeout "
            "error (default 3). Lỗi server reject (HTTP 4xx/5xx) KHÔNG retry. "
            "Hết retry → attempt được đánh dấu network_error, spam loop tiếp tục."
        ),
    )
    p.add_argument(
        "--retry-backoff", type=float, default=2.0, metavar="SEC",
        help="Backoff giữa các retry (linear: backoff*i). Default 2.0s.",
    )
    p.add_argument("--output", default=None, help="ghi result JSON ra file")
    # Spam loop
    p.add_argument(
        "--sub", type=int, default=1, metavar="N",
        help="số lần spam confirm+approve (default 1). Login + Stripe init chạy 1 lần, "
        "chỉ confirm+approve lặp.",
    )
    p.add_argument(
        "--sub-delay-min", type=float, default=1.0,
        help="delay tối thiểu giữa các attempt (giây, default 1.0)",
    )
    p.add_argument(
        "--sub-delay-max", type=float, default=3.0,
        help="delay tối đa giữa các attempt (giây, default 3.0)",
    )
    p.add_argument(
        "--sub-no-stop-on-approve", dest="sub_stop_on_approve", action="store_false",
        help="KHÔNG dừng khi gặp approve — chạy đủ N lần",
    )
    p.set_defaults(sub_stop_on_approve=True)
    p.add_argument(
        "--sub-rotate-billing", action="store_true",
        help="mỗi attempt random billing IN khác (giảm dup signal). Default: cùng billing.",
    )
    p.add_argument(
        "--sub-rotate-stripe", type=int, default=0, metavar="N",
        help="mỗi N attempt → re-init Stripe (làm mới init_checksum). 0 = không rotate.",
    )
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    email, password, secret = _parse_combo(args.combo)

    def log(msg: str) -> None:
        print(msg, flush=True)

    if args.sub < 1:
        print("--sub phải >= 1", file=sys.stderr, flush=True)
        return 2
    if args.sub_delay_min < 0 or args.sub_delay_max < args.sub_delay_min:
        print("--sub-delay-min/max không hợp lệ", file=sys.stderr, flush=True)
        return 2

    print("", flush=True)
    print(_bold(_cyan("═" * 70)), flush=True)
    print(_bold(_cyan("  pay_upi_http — Pure-HTTP UPI Payment")), flush=True)
    print(_bold(_cyan("═" * 70)), flush=True)
    print(f"  email     : {_bold(email)}", flush=True)
    print(f"  vpa       : {args.vpa}", flush=True)
    if args.proxy:
        print(
            f"  proxy     : {_green('yes')}  "
            f"{_dim('from step ' + str(args.proxy_from_step) + ' (' + _STEP_NAMES.get(args.proxy_from_step, '') + ')')}",
            flush=True,
        )
    else:
        print(f"  proxy     : {_red('no')}", flush=True)
    print(
        f"  sub       : {_bold(str(args.sub))}  "
        f"delay={args.sub_delay_min}-{args.sub_delay_max}s  "
        f"rotate_billing={args.sub_rotate_billing}  "
        f"rotate_stripe={args.sub_rotate_stripe}  "
        f"stop_on_approve={args.sub_stop_on_approve}",
        flush=True,
    )
    print(_bold(_cyan("═" * 70)), flush=True)
    if not args.proxy:
        print(_yellow("  ⚠ không có proxy → toàn bộ flow đi IP thật"), flush=True)

    try:
        result = asyncio.run(run_pay_upi(
            email=email, password=password, secret=secret,
            vpa=args.vpa, proxy=args.proxy, log=log,
            sub_count=args.sub,
            sub_delay_min=args.sub_delay_min,
            sub_delay_max=args.sub_delay_max,
            sub_stop_on_approve=args.sub_stop_on_approve,
            sub_rotate_billing=args.sub_rotate_billing,
            sub_rotate_stripe_session=args.sub_rotate_stripe,
            proxy_from_step=args.proxy_from_step,
            retry_attempts=args.retry_attempts,
            retry_backoff=args.retry_backoff,
        ))
    except Exception as exc:
        print(f"\n{_red(_bold('✗ FATAL'))}: {type(exc).__name__}: {exc}", file=sys.stderr, flush=True)
        return 1

    if args.output:
        Path(args.output).write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\n  {_green('●')} result → {args.output}", flush=True)

    # Summary
    print("", flush=True)
    print(_bold(_cyan("═" * 70)), flush=True)
    if result.get("sub_count", 1) > 1:
        c = result["counts"]
        ok_count = c["approved"]
        bad_count = c["blocked"] + c["error"] + c["other"]
        bar_w = 50
        ok_w = int(bar_w * ok_count / max(1, ok_count + bad_count))
        bar = _green("█" * ok_w) + _red("█" * (bar_w - ok_w))
        print(f"  {_bold('SPAM SUMMARY')}  total={result['sub_count']}", flush=True)
        print(f"  {bar}", flush=True)
        print(
            f"    {_green('✓ approved')} = {c['approved']:>3}    "
            f"{_red('✗ blocked')} = {c['blocked']:>3}    "
            f"{_red('⚠ error')} = {c['error']:>3}    "
            f"{_yellow('? other')} = {c['other']:>3}",
            flush=True,
        )
        if result.get("approved_at"):
            print(f"  {_green('●')} approved at attempt #{result['approved_at']}", flush=True)
    else:
        r = result.get("result")
        ok = result.get("ok")
        if ok:
            print(f"  {_green(_bold('✓ APPROVED'))}", flush=True)
        else:
            print(f"  {_red(_bold('✗ NOT APPROVED'))}  result={r}", flush=True)
        if result.get("stage") == "stripe_confirm" and result.get("error"):
            print(f"  {_dim('error:')} {result['error'][:200]}", flush=True)
    print(_bold(_cyan("═" * 70)), flush=True)

    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
