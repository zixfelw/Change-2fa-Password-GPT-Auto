"""Payment Link: lấy checkout URL pay.openai.com từ ChatGPT + Stripe API.

Flow:
    1. POST chatgpt.com/backend-api/payments/checkout (hosted mode)
       → CheckoutResponse (session_id, publishable_key, optional url)
    2. Nếu response có url chứa checkout.stripe.com/c/pay/ → replace host → return
    3. Nếu không → POST api.stripe.com/v1/payment_pages/{session_id}/init
       → stripe_hosted_url → replace host → return

UA + TLS persona: import từ ``user_agent_profile`` (Windows Chrome 145) — đồng
bộ với reg + UPI flow để cùng device persona xuyên suốt 1 account.
"""
from __future__ import annotations

import asyncio
import json
import re
import uuid
from dataclasses import dataclass
from typing import Callable
from urllib.parse import quote, unquote, urlparse, urlunparse

from curl_cffi.requests import AsyncSession

from user_agent_profile import (
    CURL_IMPERSONATE_PRIMARY as _UA_IMPERSONATE_PRIMARY,
    SEC_CH_UA as _SEC_CH_UA,
    SEC_CH_UA_MOBILE as _SEC_CH_UA_MOBILE,
    SEC_CH_UA_PLATFORM as _SEC_CH_UA_PLATFORM,
    WINDOWS_USER_AGENT as _WINDOWS_USER_AGENT,
)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class PaymentLinkError(Exception):
    """Base error for payment link operations."""
    pass


class SessionExpiredError(PaymentLinkError):
    """HTTP 401 from Checkout API — access token expired/revoked."""
    pass


class CloudflareBlockedError(PaymentLinkError):
    """HTTP 403 with Cloudflare challenge markers."""
    pass


class StripeInitError(PaymentLinkError):
    """Stripe init API failed or missing hosted_url."""
    pass


class OfferProbeError(PaymentLinkError):
    """Safe staged failure for the Get Session offer probe."""

    def __init__(self, stage: str, reason: str) -> None:
        self.stage = stage
        self.reason = reason
        super().__init__(f"{stage}:{reason}")


class GopayLinkError(PaymentLinkError):
    """Failed to obtain Midtrans GoPay redirect URL from Stripe checkout."""
    pass


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------


@dataclass
class CheckoutResponse:
    """Parsed response from chatgpt.com/backend-api/payments/checkout."""

    checkout_session_id: str
    publishable_key: str
    client_secret: str | None = None
    url: str | None = None
    checkout_ui_mode: str | None = None
    checkout_state_amount: int | None = None
    checkout_state_currency: str | None = None
    checkout_state_has_gcash: bool = False
    checkout_state_gcash_state: str = "unknown"
    checkout_state_has_momo: bool = False
    checkout_state_momo_state: str = "unknown"
    processor_entity: str | None = None
    plan_name: str | None = None
    raw_data: dict[str, object] | None = None


@dataclass
class GopayCheckoutContext:
    """Stripe init metadata required to confirm one GoPay checkout."""

    payment_url: str
    checkout_session_id: str
    publishable_key: str
    config_id: str
    init_checksum: str
    eid: str
    expected_amount: str


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_CHECKOUT_URL = "https://chatgpt.com/backend-api/payments/checkout"
_ACCOUNTS_CHECK_URL = "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27"
_STRIPE_INIT_URL_TPL = "https://api.stripe.com/v1/payment_pages/{session_id}/init"
_STRIPE_JS_URL = "https://js.stripe.com/clover/stripe.js"
_BROWSER_CHECKOUT_HOSTS = frozenset({
    "chatgpt.com",
    "checkout.stripe.com",
    "pay.openai.com",
})
_CF_MARKERS = ("cf-chl", "just a moment", "cloudflare")
_DEACTIVATED_MARKERS = (
    "account_deactivated",
    "user_deactivated",
    "account deactivated",
    "account has been deactivated",
    "account is deactivated",
    "account has been disabled",
    "account is disabled",
    "account has been deleted",
)
_IMPERSONATE = _UA_IMPERSONATE_PRIMARY
_CHECKOUT_MAX_ATTEMPTS = 3
_CHECKOUT_RETRY_DELAY_SECONDS = 0.5

# Payment-section audit is used for the optional PH GCash and VN MoMo checks. Reuse
# one browser process so Multi 30 does not launch 30 Chromium processes at
# once; every audit still creates a fresh isolated browser context.
_GCASH_AUDIT_BROWSER = None
_GCASH_AUDIT_PLAYWRIGHT = None
_GCASH_AUDIT_LOCK = None
_GCASH_AUDIT_LOOP = None

# The Get Session offer probe intentionally uses one fixed campaign/region.
# Keep these values separate from ``DEFAULT_REGION``: the latter is the
# caller-facing default for normal payment links, whereas this probe must be
# comparable across accounts and must not silently fall back to VN billing.
_PLUS_OFFER_REGION = "IN"
_PLUS_OFFER_CAMPAIGN = "plus-1-month-free"

_GCASH_CHECKOUT_UPDATE_PATH = "/backend-api/payments/checkout/update"
_GCASH_CHECKOUT_TAXES_PATH = "/backend-api/payments/checkout/taxes"
_GCASH_CHECK_BILLING = {
    "name": "Juan Dela Cruz",
    "line1": "Col. Bonny Serrano Avenue",
    "city": "Quezon City",
    "state": "Metro Manila",
    "postal_code": "1500",
}

# Region → billing_details mapping
REGION_BILLING: dict[str, dict[str, str]] = {
    "VN": {"country": "VN", "currency": "VND"},
    "ID": {"country": "ID", "currency": "IDR"},
    "IN": {"country": "IN", "currency": "INR"},
    "PH": {"country": "PH", "currency": "PHP"},
    "US": {"country": "US", "currency": "USD"},
}
DEFAULT_REGION = "VN"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _replace_stripe_host(url: str) -> str:
    """Replace checkout.stripe.com → pay.openai.com, preserve path/query."""
    parsed = urlparse(url)
    if parsed.hostname == "checkout.stripe.com":
        replaced = parsed._replace(netloc="pay.openai.com")
        return urlunparse(replaced)
    return url


def _generate_stripe_js_id() -> str:
    """UUID v4 string for stripe_js_id parameter."""
    return str(uuid.uuid4())


def _chatgpt_cookie_header(cookies: object) -> str:
    """Serialize ChatGPT cookies for checkout without logging their values."""
    pairs: list[str] = []
    if isinstance(cookies, list):
        for item in cookies:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            value = item.get("value")
            domain = str(item.get("domain") or "").lstrip(".").lower()
            if not name or value is None or (domain and "chatgpt.com" not in domain):
                continue
            pairs.append(f"{name}={value}")
    elif isinstance(cookies, dict):
        for name, value in cookies.items():
            if name and value is not None:
                pairs.append(f"{name}={value}")
    return "; ".join(pairs)


def _chatgpt_cookie_map(cookies: object) -> dict[str, str]:
    """Return non-sensitive cookie mapping suitable for curl_cffi's jar."""
    result: dict[str, str] = {}
    if isinstance(cookies, list):
        for item in cookies:
            if not isinstance(item, dict):
                continue
            name = item.get("name")
            value = item.get("value")
            domain = str(item.get("domain") or "").lstrip(".").lower()
            if not isinstance(name, str) or not name or value is None:
                continue
            if domain and "chatgpt.com" not in domain:
                continue
            result[name] = str(value)
    elif isinstance(cookies, dict):
        for name, value in cookies.items():
            if isinstance(name, str) and name and value is not None:
                result[name] = str(value)
    return result


def _offer_failure_reason(exc: BaseException) -> str:
    """Reduce a payment exception to a safe, actionable diagnostic code."""
    if isinstance(exc, SessionExpiredError):
        return "session_expired"
    if isinstance(exc, CloudflareBlockedError):
        return "cloudflare_blocked"
    text = str(exc).casefold()
    if any(marker in text for marker in _DEACTIVATED_MARKERS):
        return "account_deactivated"
    match = re.search(r"http\s+(\d{3})", text)
    if match:
        status = match.group(1)
        if (
            status == "400"
            and "billing country must match request country" in text
        ):
            return "http_400_billing_country_mismatch"
        code_match = re.search(
            r"[\"'](?:code|error_code)[\"']\s*:\s*[\"']([a-z0-9_-]{1,48})",
            text,
        )
        code = f"_{code_match.group(1)}" if code_match else ""
        return f"http_{status}{code}"
    if "missing required fields" in text:
        return "response_shape"
    if "json parse" in text:
        return "invalid_json"
    if "missing trusted amount" in text:
        return "amount_missing"
    if "amount mismatch" in text:
        return "amount_mismatch"
    if "request failed" in text or "network" in text:
        return "network"
    return "rejected"


def _account_id_from_access_token(access_token: str) -> str | None:
    """Read the account context claim locally; never verifies or logs the token."""
    try:
        from codex_auth.oauth import extract_account_id

        return extract_account_id(access_token)
    except Exception:
        return None


def _checkout_state_total_summary(value: object) -> dict[str, object] | None:
    """Read the server-calculated total from ChatGPT's current checkout shape.

    New OpenAI-managed checkout IDs use the ``oaics_*`` namespace instead of a
    Stripe ``cs_*`` resource.  Their authoritative amount is already present at
    ``checkout_state.total.total.minorUnitsAmount``.  Return ``None`` for older
    response shapes so existing Stripe checkout flows remain untouched.
    """
    if not isinstance(value, dict):
        return None
    totals = value.get("total")
    if not isinstance(totals, dict):
        return None
    total = totals.get("total")
    if not isinstance(total, dict):
        return None
    amount = total.get("minorUnitsAmount")
    if isinstance(amount, bool) or not isinstance(amount, int) or amount < 0:
        return None
    currency = value.get("currency")
    if not isinstance(currency, str) or not currency.strip():
        currency = total.get("currency")
    return {
        "amount": amount,
        "currency": currency.casefold() if isinstance(currency, str) else None,
    }


def _normalize_audited_payment_method(value: object) -> str:
    method = str(value or "").strip().casefold()
    if method not in {"gcash", "momo"}:
        raise ValueError("payment method audit supports only gcash or momo")
    return method


def _checkout_payload_has_payment_method(value: object, payment_method: str) -> bool:
    """Return whether this checkout itself exposes the requested method.

    Only the checkout/Stripe-init payload is inspected, never the billing
    country alone.  The response is not logged or persisted; the caller gets a
    boolean so account/session secrets cannot leak into UI or SQLite.
    """
    method = _normalize_audited_payment_method(payment_method)
    try:
        serialized = json.dumps(value, ensure_ascii=False).casefold()
    except (TypeError, ValueError):
        return False
    return re.search(
        rf"(?<![a-z0-9]){re.escape(method)}(?![a-z0-9])",
        serialized,
    ) is not None


def _checkout_payload_has_gcash(value: object) -> bool:
    """Backward-compatible GCash payload marker helper."""
    return _checkout_payload_has_payment_method(value, "gcash")


def _checkout_payload_has_momo(value: object) -> bool:
    """Return whether checkout metadata contains an explicit MoMo marker."""
    return _checkout_payload_has_payment_method(value, "momo")


def _checkout_payload_payment_method_state(value: object, payment_method: str) -> str:
    """Return available/unavailable/unknown from explicit payment metadata.

    A missing method marker is never enough to deny the method because some
    checkout responses omit methods or expose wallets only after the hosted
    payment section hydrates.  This metadata is therefore a positive fast
    path only; negative values remain diagnostic evidence for the UI audit.
    """
    method = _normalize_audited_payment_method(payment_method)
    explicit_method_keys = {
        "paymentmethodtypes",
        "paymentmethods",
        "paymentmethodsavailable",
        "availablepaymentmethods",
        "supportedpaymentmethods",
    }

    # Checkout metadata is not stable across hosted/custom responses: method
    # lists may live under ``checkout_state``, ``payment_method_configuration``
    # or another nested object. Walk containers instead of only the top level,
    # while treating empty lists as "not loaded" rather than "no GCash".
    if not isinstance(value, (dict, list, tuple, set)):
        return "unknown"
    stack: list[object] = [value]
    seen: set[int] = set()
    explicit_states: list[str] = []
    while stack:
        current = stack.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, dict):
            entries = current.items()
        elif isinstance(current, (list, tuple, set)):
            stack.extend(current)
            continue
        else:
            continue
        for key, item in entries:
            normalized_key = re.sub(r"[^a-z0-9]", "", str(key).casefold())
            if normalized_key in {
                f"{method}available",
                f"{method}enabled",
                f"is{method}available",
            } and isinstance(item, bool):
                # A positive boolean is a safe fast path. A negative flag can
                # be emitted before the hosted payment methods hydrate, so it
                # must not suppress the browser audit by itself.
                if item:
                    explicit_states.append("available")
            elif normalized_key in explicit_method_keys:
                has_items = isinstance(item, str) and bool(item.strip())
                has_items = has_items or (
                    isinstance(item, (list, tuple, set, dict)) and bool(item)
                )
                if has_items:
                    explicit_states.append(
                        "available"
                        if _checkout_payload_has_payment_method(item, method)
                        else "unavailable"
                    )
            if isinstance(item, (dict, list, tuple, set)):
                stack.append(item)

    if "available" in explicit_states:
        return "available"
    if explicit_states:
        return "unavailable"

    # A free-form marker (for example a description or an embedded label) is
    # not authoritative: some checkout responses include stale/hidden methods.
    # Leave those responses for the bounded hosted-page audit instead of
    # short-circuiting to a false positive.
    return "unknown"


def _checkout_payload_gcash_state(value: object) -> str:
    """Backward-compatible GCash metadata state helper."""
    return _checkout_payload_payment_method_state(value, "gcash")


def _custom_payment_methods_gcash_selection(
    value: object,
) -> tuple[str, str | None]:
    """Return the GCash state and selected OpenAI custom-method ID."""
    if not isinstance(value, dict) or "custom_payment_methods" not in value:
        return "unknown", None
    methods = value.get("custom_payment_methods")
    if not isinstance(methods, list):
        return "unknown", None
    if not methods:
        return "unavailable", None

    explicit_ids: list[str] = []
    generic_ids: list[str] = []
    explicit_marker_without_id = False
    for method in methods:
        if not isinstance(method, dict):
            continue
        method_id = method.get("id")
        if isinstance(method_id, str) and method_id.startswith("cpmt_"):
            generic_ids.append(method_id)
            if "gcash" in json.dumps(method, ensure_ascii=False).casefold():
                explicit_ids.append(method_id)
        elif "gcash" in json.dumps(method, ensure_ascii=False).casefold():
            explicit_marker_without_id = True

    if explicit_ids:
        return "available", explicit_ids[0]
    unique_generic_ids = list(dict.fromkeys(generic_ids))
    if len(unique_generic_ids) == 1:
        return "available", unique_generic_ids[0]
    if unique_generic_ids or explicit_marker_without_id:
        return "unknown", None
    return "unavailable", None


def _custom_payment_methods_gcash_state(value: object) -> str:
    """Read the oaicss custom-method list used by the PH GCash checkout."""
    state, _method_id = _custom_payment_methods_gcash_selection(value)
    return state


def _checkout_payload_momo_state(value: object) -> str:
    """Return MoMo state from explicit checkout payment metadata."""
    return _checkout_payload_payment_method_state(value, "momo")


def _stripe_init_payment_method_state(
    response_body: object,
    payment_method: str,
) -> str:
    """Extract a method state from the live hosted-checkout Stripe init body.

    This is intentionally separate from the OpenAI checkout response: only a
    successfully parsed Stripe init response belongs to the payment section
    currently rendered in the browser and can provide a conclusive negative.
    """
    if not isinstance(response_body, str):
        return "unknown"
    try:
        payload = json.loads(response_body)
    except (TypeError, ValueError):
        return "unknown"
    return _checkout_payload_payment_method_state(payload, payment_method)


def _stripe_init_gcash_state(response_body: object) -> str:
    """Backward-compatible GCash Stripe-init helper."""
    return _stripe_init_payment_method_state(response_body, "gcash")


def _stripe_init_momo_state(response_body: object) -> str:
    """Return MoMo state from a live hosted-checkout Stripe init body."""
    return _stripe_init_payment_method_state(response_body, "momo")


def _check_response_error(status_code: int, body: str) -> None:
    """Raise appropriate error based on HTTP status code and body content.

    - 401 → SessionExpiredError
    - 403 + CF markers → CloudflareBlockedError
    - Other non-2xx → PaymentLinkError with status + first 300 chars body
    """
    if 200 <= status_code < 300:
        return

    if any(marker in body.casefold() for marker in _DEACTIVATED_MARKERS):
        # Preserve the classification while never including the response body.
        raise PaymentLinkError("account deactivated")

    if status_code == 401:
        raise SessionExpiredError(f"HTTP 401: session expired — {body[:300]}")

    if status_code == 403:
        body_lower = body.lower()
        if any(marker in body_lower for marker in _CF_MARKERS):
            raise CloudflareBlockedError(
                f"HTTP 403: Cloudflare block detected — {body[:300]}"
            )

    raise PaymentLinkError(f"HTTP {status_code}: {body[:300]}")


# ---------------------------------------------------------------------------
# Internal API calls
# ---------------------------------------------------------------------------


async def _call_chatgpt_checkout(
    session: AsyncSession,
    access_token: str,
    *,
    region: str = DEFAULT_REGION,
    promo_campaign: bool = True,
    timeout: float = 30.0,
    cookies: object = None,
    checkout_ui_mode: str = "hosted",
    max_attempts: int = _CHECKOUT_MAX_ATTEMPTS,
    india_recipe: bool = False,
    promo_from_query_param: bool = False,
    account_id: str | None = None,
) -> CheckoutResponse:
    """POST ChatGPT checkout with a browser-compatible request recipe."""
    billing = REGION_BILLING.get(region, REGION_BILLING[DEFAULT_REGION])
    if checkout_ui_mode not in ("hosted", "custom"):
        raise ValueError("checkout_ui_mode must be hosted or custom")
    if max_attempts < 1:
        raise ValueError("max_attempts must be at least 1")

    referer = "https://chatgpt.com"
    payload = {
        "entry_point": "all_plans_pricing_modal",
        "plan_name": "chatgptplusplan",
        "billing_details": {
            "country": billing["country"],
            "currency": billing["currency"],
        },
        "checkout_ui_mode": checkout_ui_mode,
    }
    if promo_campaign:
        referer += "/?promo_campaign=plus-1-month-free"
        payload["promo_campaign"] = {
            "promo_campaign_id": "plus-1-month-free",
            "is_coupon_from_query_param": bool(promo_from_query_param),
        }

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "*/*",
        "Origin": "https://chatgpt.com",
        "Referer": referer,
        "x-openai-target-path": "/backend-api/payments/checkout",
        "x-openai-target-route": "/backend-api/payments/checkout",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "same-origin",
        "Priority": "u=1, i",
    }
    cookie_header = _chatgpt_cookie_header(cookies)
    if cookie_header:
        headers["Cookie"] = cookie_header
    cookie_map = _chatgpt_cookie_map(cookies)
    device_id = cookie_map.get("oai-did")
    if device_id:
        headers["oai-device-id"] = device_id
    if isinstance(account_id, str) and account_id.strip():
        headers["ChatGPT-Account-Id"] = account_id.strip()
    if india_recipe:
        language = (
            "en-IN,en;q=0.9" if region == "IN"
            else "en-PH,en;q=0.9" if region == "PH"
            else "en-US,en;q=0.9"
        )
        headers.update({
            "Accept-Language": language,
            "OAI-Language": (
                "en-IN" if region == "IN"
                else "en-PH" if region == "PH"
                else "en-US"
            ),
            "User-Agent": _WINDOWS_USER_AGENT,
            "sec-ch-ua": _SEC_CH_UA,
            "sec-ch-ua-mobile": _SEC_CH_UA_MOBILE,
            "sec-ch-ua-platform": _SEC_CH_UA_PLATFORM,
        })

    last_error: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            resp = await session.post(
                _CHECKOUT_URL,
                headers=headers,
                json=payload,
                timeout=timeout,
            )
        except Exception as exc:
            last_error = exc
            if attempt < max_attempts:
                await asyncio.sleep(_CHECKOUT_RETRY_DELAY_SECONDS * attempt)
                continue
            raise PaymentLinkError(f"checkout request failed: {exc}") from exc

        body = resp.text
        if resp.status_code >= 500 and attempt < max_attempts:
            await asyncio.sleep(_CHECKOUT_RETRY_DELAY_SECONDS * attempt)
            continue
        break
    else:
        raise PaymentLinkError(f"checkout request failed: {last_error}")

    _check_response_error(resp.status_code, body)

    try:
        data = resp.json()
    except Exception as exc:
        raise PaymentLinkError(f"checkout JSON parse failed: {exc} — body: {body[:300]}") from exc

    data_text = json.dumps(data, ensure_ascii=False).casefold()
    if any(marker in data_text for marker in _DEACTIVATED_MARKERS):
        raise PaymentLinkError("account deactivated")

    session_id = data.get("checkout_session_id")
    pub_key = data.get("publishable_key")
    if not session_id or not pub_key:
        raise PaymentLinkError(
            f"checkout response missing required fields — "
            f"checkout_session_id={session_id!r}, publishable_key={pub_key!r}"
        )

    checkout_summary = _checkout_state_total_summary(data.get("checkout_state"))
    gcash_state = _checkout_payload_gcash_state(data)
    momo_state = _checkout_payload_momo_state(data)
    return CheckoutResponse(
        checkout_session_id=session_id,
        publishable_key=pub_key,
        client_secret=data.get("client_secret"),
        url=data.get("url"),
        checkout_ui_mode=data.get("checkout_ui_mode"),
        checkout_state_amount=(
            int(checkout_summary["amount"]) if checkout_summary is not None else None
        ),
        checkout_state_currency=(
            checkout_summary.get("currency") if checkout_summary is not None else None
        ),
        checkout_state_has_gcash=_checkout_payload_has_gcash(data),
        checkout_state_gcash_state=gcash_state,
        checkout_state_has_momo=_checkout_payload_has_momo(data),
        checkout_state_momo_state=momo_state,
        processor_entity=(
            str(data.get("processor_entity"))
            if data.get("processor_entity")
            else None
        ),
        plan_name=(str(data.get("plan_name")) if data.get("plan_name") else None),
        raw_data=data,
    )


async def _call_stripe_init_data(
    session: AsyncSession,
    checkout_session_id: str,
    publishable_key: str,
    *,
    timeout: float = 30.0,
    india_recipe: bool = False,
    region: str | None = None,
) -> dict:
    """POST api.stripe.com/v1/payment_pages/{session_id}/init → response data.

    Uses form-encoded data as Stripe expects.
    """
    url = _STRIPE_INIT_URL_TPL.format(session_id=checkout_session_id)
    stripe_js_id = _generate_stripe_js_id()

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
        "Origin": "https://js.stripe.com",
        "Referer": "https://js.stripe.com/",
    }
    use_india_locale = india_recipe and region == "IN"
    use_ph_locale = india_recipe and region == "PH"
    if india_recipe:
        headers.update({
            "Accept-Language": (
                "en-IN,en;q=0.9" if use_india_locale
                else "en-PH,en;q=0.9" if use_ph_locale
                else "en-US,en;q=0.9"
            ),
            "User-Agent": _WINDOWS_USER_AGENT,
            "sec-ch-ua": _SEC_CH_UA,
            "sec-ch-ua-mobile": _SEC_CH_UA_MOBILE,
            "sec-ch-ua-platform": _SEC_CH_UA_PLATFORM,
        })
    # Form data y hệt Rust checkout.rs (urlencoded vẫn dùng được dict)
    form_data = {
        "browser_locale": (
            "en-IN" if use_india_locale
            else "en-PH" if use_ph_locale
            else "en-US"
        ),
        "browser_timezone": (
            "Asia/Kolkata" if use_india_locale
            else "Asia/Manila" if use_ph_locale
            else "Asia/Saigon"
        ),
        "elements_session_client[client_betas][0]": "custom_checkout_server_updates_1",
        "elements_session_client[client_betas][1]": "custom_checkout_manual_approval_1",
        "elements_session_client[elements_init_source]": "custom_checkout",
        "elements_session_client[referrer_host]": "chatgpt.com",
        "elements_session_client[stripe_js_id]": stripe_js_id,
        "elements_session_client[locale]": "en" if (use_india_locale or use_ph_locale) else "en-US",
        "elements_session_client[is_aggregation_expected]": "false",
        "elements_options_client[saved_payment_method][enable_save]": (
            "auto" if india_recipe else "never"
        ),
        "elements_options_client[saved_payment_method][enable_redisplay]": (
            "auto" if india_recipe else "never"
        ),
        "key": publishable_key,
        "_stripe_version": "2025-03-31.basil; checkout_server_update_beta=v1; checkout_manual_approval_preview=v1",
    }

    try:
        resp = await session.post(
            url,
            headers=headers,
            data=form_data,
            timeout=timeout,
        )
    except Exception as exc:
        raise PaymentLinkError(f"stripe init request failed: {exc}") from exc

    body = resp.text
    _check_response_error(resp.status_code, body)

    try:
        data = resp.json()
    except Exception as exc:
        raise StripeInitError(
            f"stripe init JSON parse failed: {exc} — body: {body[:300]}"
        ) from exc

    data_text = json.dumps(data, ensure_ascii=False).casefold()
    if any(marker in data_text for marker in _DEACTIVATED_MARKERS):
        raise PaymentLinkError("account deactivated")

    return data


_MISSING = object()


def _strict_stripe_amount(value: object, *, field: str) -> int:
    """Validate one Stripe amount field without coercing untrusted values."""
    # ``bool`` is an ``int`` subclass, but accepting True/False here would turn
    # malformed JSON into a seemingly valid amount.  Stripe amounts are
    # non-negative integer minor units.
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StripeInitError(f"stripe init invalid {field}")
    return value


def _parse_stripe_init_amount(init_data: object) -> int:
    """Return a trusted Stripe init amount, or raise when it is ambiguous.

    Stripe emits different shapes for hosted/custom checkout.  Read the first
    trustworthy tier below and reject disagreements inside that tier.  Lower
    tiers are summaries of a different lifecycle point, so they are not used
    to invalidate a higher-priority amount.
    """
    if not isinstance(init_data, dict):
        raise StripeInitError("stripe init response is not an object")

    tiers = (
        (("elements_options", "amount"),),
        (("total_summary", "due"), ("invoice", "amount_due"), (None, "amount_due")),
        (("total_summary", "total"), ("invoice", "total"), (None, "amount_total")),
    )
    for tier in tiers:
        values: list[tuple[str, int]] = []
        for container_key, field in tier:
            if container_key is None:
                value = init_data.get(field, _MISSING)
                label = field
            else:
                container = init_data.get(container_key, _MISSING)
                if container is _MISSING:
                    continue
                if not isinstance(container, dict):
                    raise StripeInitError(f"stripe init invalid {container_key}")
                value = container.get(field, _MISSING)
                label = f"{container_key}.{field}"
            if value is _MISSING:
                continue
            values.append((label, _strict_stripe_amount(value, field=label)))
        if not values:
            continue
        amount = values[0][1]
        if any(value != amount for _label, value in values[1:]):
            labels = ", ".join(label for label, _value in values)
            raise StripeInitError(f"stripe init amount mismatch within tier: {labels}")
        return amount

    raise StripeInitError("stripe init missing trusted amount field")


def parse_stripe_init_amount(init_data: object) -> int:
    """Public strict wrapper for parsing a Stripe init amount.

    Raises :class:`StripeInitError` for missing, malformed, negative, or
    contradictory same-priority amount fields.  ``check_plus_offer`` deliberately
    propagates those errors so its caller can represent the result as ``unknown``.
    """
    return _parse_stripe_init_amount(init_data)


async def check_plus_offer(
    access_token: str,
    *,
    proxy: str | None = None,
    timeout: float = 30.0,
    region: str = _PLUS_OFFER_REGION,
    cookies: object = None,
    checkout_ui_mode: str = "hosted",
    checkout_attempts: int = 1,
    promo_from_query_param: bool = False,
    account_id: str | None = None,
) -> dict[str, object]:
    """Probe the one-month-free Plus campaign without charging the account.

    The probe creates a checkout and reads its server-calculated total.  Current
    ``oaics_*`` checkouts expose that total in ``checkout_state``; legacy Stripe
    sessions fall back to payment-page init.  It never confirms a payment or
    calls an approval endpoint.  A zero amount is the only positive signal.
    """
    if not isinstance(access_token, str) or not access_token.strip():
        raise PaymentLinkError("access_token thiếu hoặc rỗng")
    if region not in REGION_BILLING:
        raise ValueError(f"unsupported offer region: {region}")
    if not isinstance(timeout, (int, float)) or timeout <= 0:
        raise ValueError("timeout phải lớn hơn 0")

    proxies = {"http": proxy, "https": proxy} if proxy else None
    cookie_map = _chatgpt_cookie_map(cookies)
    resolved_account_id = account_id or _account_id_from_access_token(access_token)
    async with AsyncSession(
        impersonate=_IMPERSONATE,
        proxies=proxies,
        trust_env=False,
    ) as session:
        # Domain-pin auth cookies so they can never be attached to Stripe.
        for name, value in cookie_map.items():
            session.cookies.set(name, value, domain=".chatgpt.com", path="/")
        # Warm the same origin first so response Set-Cookie/device context matches
        # what the pricing page establishes before its checkout fetch.
        warm_headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": (
                "en-IN,en;q=0.9" if region == "IN"
                else "en-PH,en;q=0.9" if region == "PH"
                else "en-US,en;q=0.9"
            ),
            "Referer": "https://chatgpt.com/",
            "User-Agent": _WINDOWS_USER_AGENT,
            "sec-ch-ua": _SEC_CH_UA,
            "sec-ch-ua-mobile": _SEC_CH_UA_MOBILE,
            "sec-ch-ua-platform": _SEC_CH_UA_PLATFORM,
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "same-origin",
        }
        try:
            warm = await session.get(
                "https://chatgpt.com/?promo_campaign=plus-1-month-free",
                headers=warm_headers,
                timeout=float(timeout),
            )
            if any(
                marker in (warm.text or "").casefold()
                for marker in _DEACTIVATED_MARKERS
            ):
                raise PaymentLinkError("account deactivated")
        except PaymentLinkError:
            raise
        except Exception:
            # Warm-up is compatibility context, not an eligibility signal.
            pass

        try:
            checkout = await _call_chatgpt_checkout(
                session,
                access_token,
                region=region,
                promo_campaign=True,
                timeout=float(timeout),
                cookies=cookies,
                checkout_ui_mode=checkout_ui_mode,
                max_attempts=checkout_attempts,
                india_recipe=True,
                promo_from_query_param=promo_from_query_param,
                account_id=resolved_account_id,
            )
        except PaymentLinkError as exc:
            if "deactivated" in str(exc).casefold():
                raise
            raise OfferProbeError("checkout", _offer_failure_reason(exc)) from exc

        amount = checkout.checkout_state_amount
        currency: object = checkout.checkout_state_currency
        gcash_state = checkout.checkout_state_gcash_state
        momo_state = checkout.checkout_state_momo_state
        source = "chatgpt_checkout_state"
        if amount is None:
            try:
                init_data = await _call_stripe_init_data(
                    session,
                    checkout.checkout_session_id,
                    checkout.publishable_key,
                    timeout=float(timeout),
                    india_recipe=True,
                    region=region,
                )
                amount = parse_stripe_init_amount(init_data)
            except PaymentLinkError as exc:
                if "deactivated" in str(exc).casefold():
                    raise
                raise OfferProbeError("stripe_init", _offer_failure_reason(exc)) from exc
            currency = init_data.get("currency")
            init_gcash_state = _checkout_payload_gcash_state(init_data)
            if init_gcash_state == "available" or gcash_state == "unknown":
                gcash_state = init_gcash_state
            init_momo_state = _checkout_payload_momo_state(init_data)
            if init_momo_state == "available" or momo_state == "unknown":
                momo_state = init_momo_state
            if not isinstance(currency, str) or not currency.strip():
                options = init_data.get("elements_options")
                if isinstance(options, dict):
                    currency = options.get("currency")
            source = "stripe_init"
    if not isinstance(currency, str) or not currency.strip():
        currency = REGION_BILLING[region]["currency"].lower()
    state = "available" if amount == 0 else "unavailable"
    return {
        "state": state,
        "status": state,
        "available": amount == 0,
        "amount": amount,
        "currency": currency.lower(),
        "region": region,
        "campaign": _PLUS_OFFER_CAMPAIGN,
        "source": source,
        "gcash_available": gcash_state == "available",
        "gcash_metadata_state": gcash_state,
        "momo_available": momo_state == "available",
        "momo_metadata_state": momo_state,
    }


def _dual_proxy_headers(
    access_token: str,
    path: str,
    *,
    device_id: str | None,
    account_id: str | None = None,
    referer: str = "https://chatgpt.com/",
) -> dict[str, str]:
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "*/*",
        "Accept-Language": "fil,fil-PH;q=0.9,tl;q=0.8,en-US;q=0.7,en;q=0.6",
        "OAI-Language": "en-US",
        "Origin": "https://chatgpt.com",
        "Referer": referer,
        "User-Agent": _WINDOWS_USER_AGENT,
        "sec-ch-ua": _SEC_CH_UA,
        "sec-ch-ua-mobile": _SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": _SEC_CH_UA_PLATFORM,
        "x-openai-target-path": path,
        "x-openai-target-route": path,
    }
    if device_id:
        headers["oai-device-id"] = device_id
    if account_id:
        headers["ChatGPT-Account-Id"] = account_id
    return headers


async def _warm_dual_proxy_session(
    session: AsyncSession,
    *,
    timeout: float,
) -> None:
    try:
        response = await session.get(
            "https://chatgpt.com/",
            headers={
                "Accept": "text/html,application/xhtml+xml",
                "Accept-Language": "fil,fil-PH;q=0.9,tl;q=0.8,en-US;q=0.7,en;q=0.6",
                "User-Agent": _WINDOWS_USER_AGENT,
            },
            timeout=timeout,
        )
    except Exception:
        return
    if any(marker in (response.text or "").casefold() for marker in _DEACTIVATED_MARKERS):
        raise PaymentLinkError("account deactivated")


async def _resolve_dual_proxy_account_id(
    session: AsyncSession,
    access_token: str,
    *,
    device_id: str | None,
    fallback_account_id: str | None,
    timeout: float,
) -> str:
    path = "/backend-api/accounts/check/v4-2023-04-27"
    response = await session.get(
        _ACCOUNTS_CHECK_URL,
        params={"timezone_offset_min": -420},
        headers=_dual_proxy_headers(
            access_token,
            path,
            device_id=device_id,
        ),
        timeout=timeout,
    )
    _check_response_error(response.status_code, response.text)
    try:
        payload = response.json()
    except Exception as exc:
        raise PaymentLinkError("accounts/check returned invalid JSON") from exc
    accounts = payload.get("accounts") if isinstance(payload, dict) else None
    if not isinstance(accounts, dict) or not accounts:
        if fallback_account_id:
            return fallback_account_id
        raise PaymentLinkError("accounts/check returned no account")
    ordering = payload.get("account_ordering")
    if isinstance(ordering, list):
        for candidate in ordering:
            if isinstance(candidate, str) and candidate in accounts:
                return candidate
    return next(iter(accounts))


def _gcash_checkout_email(value: object) -> str | None:
    """Read the checkout email required by the native taxes endpoint."""
    if not isinstance(value, dict):
        return None
    candidates: list[object] = [value.get("email"), value.get("checkout_email")]
    for key in ("checkout_state", "checkout_session"):
        nested = value.get(key)
        if isinstance(nested, dict):
            candidates.extend(
                (nested.get("email"), nested.get("checkout_email"), nested.get("customer_email"))
            )
    for candidate in candidates:
        if isinstance(candidate, str) and "@" in candidate and candidate.strip():
            return candidate.strip()
    return None


def _gcash_checkout_page_url(session_id: str, processor_entity: str) -> str:
    entity = processor_entity.strip() or "openai_llc"
    return (
        "https://chatgpt.com/checkout/"
        f"{quote(entity, safe='')}/{quote(session_id, safe='')}"
    )


async def _post_gcash_checkout_action(
    session: AsyncSession,
    access_token: str,
    *,
    path: str,
    session_id: str,
    processor_entity: str,
    device_id: str | None,
    account_id: str,
    payload: dict[str, object],
    timeout: float,
) -> dict[str, object]:
    response = await session.post(
        f"https://chatgpt.com{path}",
        headers=_dual_proxy_headers(
            access_token,
            path,
            device_id=device_id,
            account_id=account_id,
            referer=_gcash_checkout_page_url(session_id, processor_entity),
        ),
        json=payload,
        timeout=timeout,
    )
    _check_response_error(response.status_code, response.text)
    try:
        data = response.json()
    except Exception as exc:
        raise PaymentLinkError(f"{path} JSON parse failed") from exc
    if not isinstance(data, dict):
        raise PaymentLinkError(f"{path} returned invalid response shape")
    return data


async def _submit_gcash_checkout_taxes(
    session: AsyncSession,
    access_token: str,
    *,
    session_id: str,
    processor_entity: str,
    checkout_email: str,
    device_id: str | None,
    account_id: str,
    timeout: float,
) -> dict[str, object]:
    return await _post_gcash_checkout_action(
        session,
        access_token,
        path=_GCASH_CHECKOUT_TAXES_PATH,
        session_id=session_id,
        processor_entity=processor_entity,
        device_id=device_id,
        account_id=account_id,
        payload={
            "checkout_session_id": session_id,
            "checkout_email": checkout_email,
            "billing_country": "PH",
            "billing_name": _GCASH_CHECK_BILLING["name"],
            "currency": "php",
            "processor_entity": processor_entity,
            "billing_address": {
                "line1": _GCASH_CHECK_BILLING["line1"],
                "city": _GCASH_CHECK_BILLING["city"],
                "country": "PH",
                "postal_code": _GCASH_CHECK_BILLING["postal_code"],
                "state": _GCASH_CHECK_BILLING["state"],
            },
        },
        timeout=timeout,
    )


async def _apply_gcash_checkout_promo(
    session: AsyncSession,
    access_token: str,
    *,
    session_id: str,
    processor_entity: str,
    device_id: str | None,
    account_id: str,
    timeout: float,
) -> dict[str, object]:
    return await _post_gcash_checkout_action(
        session,
        access_token,
        path=_GCASH_CHECKOUT_UPDATE_PATH,
        session_id=session_id,
        processor_entity=processor_entity,
        device_id=device_id,
        account_id=account_id,
        payload={
            "checkout_session_id": session_id,
            "processor_entity": processor_entity,
            "plan_name": "chatgptplusplan",
            "price_interval": "month",
            "seat_quantity": 1,
            "promo_campaign": {
                "promo_campaign_id": _PLUS_OFFER_CAMPAIGN,
                "is_coupon_from_query_param": False,
            },
        },
        timeout=timeout,
    )


def _gcash_taxes_total(value: object) -> tuple[int | None, str | None]:
    """Extract the server-calculated PHP total without inventing defaults."""
    if not isinstance(value, dict):
        return None, None
    checkout = value.get("checkout_session")
    if not isinstance(checkout, dict):
        return None, None

    amount: int | None = None
    raw_amount = checkout.get("amount_total")
    if isinstance(raw_amount, int) and not isinstance(raw_amount, bool) and raw_amount >= 0:
        amount = raw_amount
    elif isinstance(raw_amount, str) and raw_amount.strip().isdigit():
        amount = int(raw_amount.strip())

    if amount is None:
        summary = _checkout_state_total_summary(
            checkout.get("checkout_state") if isinstance(checkout, dict) else None
        )
        if summary is not None:
            amount = int(summary["amount"])

    if amount is None:
        for key in ("total_summary", "totals", "pricing", "invoice"):
            nested = checkout.get(key)
            if not isinstance(nested, dict):
                continue
            for amount_key in ("amount_total", "total", "due", "amount_due"):
                raw_nested = nested.get(amount_key)
                if (
                    isinstance(raw_nested, int)
                    and not isinstance(raw_nested, bool)
                    and raw_nested >= 0
                ):
                    amount = raw_nested
                    break
                if isinstance(raw_nested, str) and raw_nested.strip().isdigit():
                    amount = int(raw_nested.strip())
                    break
            if amount is not None:
                break

    currency = checkout.get("currency")
    normalized_currency = (
        currency.strip().casefold()
        if isinstance(currency, str) and currency.strip()
        else None
    )
    return amount, normalized_currency


async def check_gcash_dual_proxy(
    access_token: str,
    *,
    cookies: object,
    proxy_a: str,
    proxy_b: str | None = None,
    account_id: str | None = None,
    checkout_email: str | None = None,
    timeout: float = 30.0,
) -> dict[str, object]:
    """Run the GCash QR flow through its money gate, then stop before confirm."""
    if not isinstance(access_token, str) or not access_token.strip():
        raise PaymentLinkError("access_token missing")
    if not isinstance(proxy_a, str) or not proxy_a.strip():
        raise ValueError("GCash proxy A is required")
    normalized_proxy_b = proxy_b.strip() if isinstance(proxy_b, str) else ""

    cookie_map = _chatgpt_cookie_map(cookies)
    device_id = cookie_map.get("oai-did")
    session_options = {
        "impersonate": _IMPERSONATE,
        "trust_env": False,
    }
    session_b_options = dict(session_options)
    if normalized_proxy_b:
        session_b_options["proxies"] = {
            "http": normalized_proxy_b,
            "https": normalized_proxy_b,
        }
    async with AsyncSession(
        proxies={"http": proxy_a, "https": proxy_a},
        **session_options,
    ) as session_a, AsyncSession(
        **session_b_options,
    ) as session_b:
        for session in (session_a, session_b):
            for name, value in cookie_map.items():
                session.cookies.set(name, value, domain=".chatgpt.com", path="/")

        try:
            await _warm_dual_proxy_session(session_a, timeout=timeout)
        except Exception as exc:
            raise OfferProbeError(
                "gcash_warm_a", _offer_failure_reason(exc)
            ) from exc
        try:
            await _warm_dual_proxy_session(session_b, timeout=timeout)
        except Exception as exc:
            raise OfferProbeError(
                "gcash_warm_b", _offer_failure_reason(exc)
            ) from exc
        try:
            resolved_account_id = await _resolve_dual_proxy_account_id(
                session_a,
                access_token,
                device_id=device_id,
                fallback_account_id=(
                    account_id or _account_id_from_access_token(access_token)
                ),
                timeout=timeout,
            )
        except Exception as exc:
            raise OfferProbeError(
                "gcash_accounts_check", _offer_failure_reason(exc)
            ) from exc
        try:
            checkout = await _call_chatgpt_checkout(
                session_b,
                access_token,
                region="PH",
                promo_campaign=False,
                timeout=timeout,
                cookies=cookies,
                checkout_ui_mode="custom",
                max_attempts=1,
                india_recipe=True,
                account_id=resolved_account_id,
            )
        except Exception as exc:
            raise OfferProbeError(
                "gcash_bare_checkout", _offer_failure_reason(exc)
            ) from exc
        bare_payload = checkout.raw_data or {}
        bare_state, custom_method_id = _custom_payment_methods_gcash_selection(
            bare_payload
        )
        if bare_state == "unavailable":
            return {
                "gcash_available": False,
                "gcash_state": "unavailable",
                "source": "dual_proxy_ph_bare_checkout",
                "checkout_session_id": checkout.checkout_session_id,
            }
        if bare_state != "available" or custom_method_id is None:
            raise OfferProbeError(
                "gcash_bare_checkout", "payment_method_inconclusive"
            )

        resolved_checkout_email = (
            checkout_email.strip()
            if isinstance(checkout_email, str) and "@" in checkout_email
            else _gcash_checkout_email(bare_payload)
        )
        if resolved_checkout_email is None:
            raise OfferProbeError("gcash_bare_checkout", "checkout_email_missing")
        processor_entity = checkout.processor_entity or "openai_llc"

        try:
            bare_taxes = await _submit_gcash_checkout_taxes(
                session_b,
                access_token,
                session_id=checkout.checkout_session_id,
                processor_entity=processor_entity,
                checkout_email=resolved_checkout_email,
                device_id=device_id,
                account_id=resolved_account_id,
                timeout=timeout,
            )
        except Exception as exc:
            raise OfferProbeError(
                "gcash_taxes_bare", _offer_failure_reason(exc)
            ) from exc
        bare_amount, bare_currency = _gcash_taxes_total(bare_taxes)
        if bare_amount is None:
            raise OfferProbeError("gcash_taxes_bare", "amount_missing")
        if bare_currency not in (None, "php"):
            raise OfferProbeError("gcash_taxes_bare", "currency_mismatch")

        try:
            promo_result = await _apply_gcash_checkout_promo(
                session_a,
                access_token,
                session_id=checkout.checkout_session_id,
                processor_entity=processor_entity,
                device_id=device_id,
                account_id=resolved_account_id,
                timeout=timeout,
            )
        except Exception as exc:
            raise OfferProbeError(
                "gcash_promo_update", _offer_failure_reason(exc)
            ) from exc
        promo_state, promoted_method_id = _custom_payment_methods_gcash_selection(
            promo_result
        )
        if promo_state == "unavailable":
            return {
                "gcash_available": False,
                "gcash_state": "unavailable",
                "source": "dual_proxy_ph_promo_update",
                "checkout_session_id": checkout.checkout_session_id,
            }
        if promo_state == "available" and promoted_method_id is not None:
            custom_method_id = promoted_method_id

        try:
            final_taxes = await _submit_gcash_checkout_taxes(
                session_b,
                access_token,
                session_id=checkout.checkout_session_id,
                processor_entity=processor_entity,
                checkout_email=resolved_checkout_email,
                device_id=device_id,
                account_id=resolved_account_id,
                timeout=timeout,
            )
        except Exception as exc:
            raise OfferProbeError(
                "gcash_taxes_final", _offer_failure_reason(exc)
            ) from exc
        final_amount, final_currency = _gcash_taxes_total(final_taxes)
        if final_amount is None:
            raise OfferProbeError("gcash_taxes_final", "amount_missing")
        if final_currency not in (None, "php"):
            raise OfferProbeError("gcash_taxes_final", "currency_mismatch")

        return {
            "gcash_available": True,
            "gcash_state": "available",
            "offer_state": "available" if final_amount == 0 else "unavailable",
            "state": "available" if final_amount == 0 else "unavailable",
            "campaign": _PLUS_OFFER_CAMPAIGN,
            "region": "PH",
            "source": "dual_proxy_ph_check_only",
            "checkout_session_id": checkout.checkout_session_id,
            "custom_payment_method_type_id": custom_method_id,
            "amount": final_amount,
            "currency": final_currency or "php",
        }


def _playwright_chatgpt_cookies(cookies: object) -> list[dict[str, object]]:
    """Convert persisted ChatGPT cookies to Playwright's strict cookie shape."""
    source: list[dict[str, object]] = []
    if isinstance(cookies, list):
        source = [item for item in cookies if isinstance(item, dict)]
    elif isinstance(cookies, dict):
        source = [
            {"name": name, "value": value}
            for name, value in cookies.items()
            if isinstance(name, str) and name and value is not None
        ]

    result: list[dict[str, object]] = []
    for item in source:
        name = item.get("name")
        value = item.get("value")
        if not isinstance(name, str) or not name or value is None:
            continue
        domain = str(item.get("domain") or ".chatgpt.com").casefold()
        if "chatgpt.com" not in domain:
            continue
        converted: dict[str, object] = {
            "name": name,
            "value": str(value),
            "domain": domain,
            "path": str(item.get("path") or "/"),
            "secure": bool(item.get("secure", True)),
            "httpOnly": bool(item.get("httpOnly", False)),
        }
        expires = item.get("expires")
        if isinstance(expires, (int, float)) and not isinstance(expires, bool) and expires > 0:
            converted["expires"] = float(expires)
        same_site = str(item.get("sameSite") or "").casefold()
        if same_site in ("strict", "lax", "none"):
            converted["sameSite"] = same_site.title()
        result.append(converted)
    return result


def _browser_checkout_target(checkout_data: dict[str, object], session_id: str) -> str:
    """Return a trusted hosted-checkout URL without exposing its secret fragment."""
    candidate = checkout_data.get("url")
    if isinstance(candidate, str) and candidate.strip():
        parsed = urlparse(candidate.strip())
        if (
            parsed.scheme == "https"
            and (parsed.hostname or "").casefold() in _BROWSER_CHECKOUT_HOSTS
        ):
            return candidate.strip()
    return (
        "https://chatgpt.com/checkout/openai_llc/"
        f"{quote(session_id, safe='')}"
    )


def _is_browser_stripe_init_response(url: str, session_id: str) -> bool:
    """Match only this checkout's Stripe payment-page init response."""
    parsed = urlparse(url)
    if (
        parsed.scheme != "https"
        or (parsed.hostname or "").casefold() != "api.stripe.com"
    ):
        return False
    path = unquote(parsed.path)
    return (
        path.startswith("/v1/payment_pages/")
        and path.endswith("/init")
        and f"/{session_id}/" in path
    )


def _safe_browser_probe_code(value: object, *, fallback: str) -> str:
    """Normalize a browser-side Stripe error without leaking messages or secrets."""
    code = re.sub(r"[^a-z0-9_-]+", "_", str(value or "").casefold()).strip("_")
    return code[:64] or fallback


async def _read_custom_checkout_summary_in_browser(
    page: object,
    *,
    publishable_key: str,
    client_secret: str,
) -> dict[str, object]:
    """Read a custom Checkout Session total through the supported Stripe.js API."""
    await page.add_script_tag(url=_STRIPE_JS_URL)
    result = await page.evaluate(
        """
        async ({publishableKey, clientSecret}) => {
          const safeCode = (error, fallback) => {
            const raw = error && (error.code || error.type || error.name);
            return typeof raw === 'string' && raw ? raw.slice(0, 64) : fallback;
          };
          try {
            if (typeof window.Stripe !== 'function') {
              return {ok: false, error: 'stripe_js_missing'};
            }
            const stripe = window.Stripe(publishableKey);
            const checkout = await Promise.resolve(stripe.initCheckout({clientSecret}));
            if (!checkout || typeof checkout.loadActions !== 'function') {
              return {ok: false, error: 'load_actions_missing'};
            }
            const loaded = await checkout.loadActions();
            if (!loaded || loaded.type !== 'success' || !loaded.actions) {
              return {ok: false, error: safeCode(loaded && loaded.error, 'load_actions_failed')};
            }
            const session = loaded.actions.getSession();
            const totalBlock = session && session.total;
            const total = totalBlock && (totalBlock.total || totalBlock);
            const amount = total && total.amount;
            const currency = total && total.currency;
            if (!Number.isSafeInteger(amount) || amount < 0) {
              return {ok: false, error: 'amount_invalid'};
            }
            return {
              ok: true,
              amount,
              currency: typeof currency === 'string' ? currency : null,
            };
          } catch (error) {
            return {ok: false, error: safeCode(error, 'stripe_js_exception')};
          }
        }
        """,
        {"publishableKey": publishable_key, "clientSecret": client_secret},
    )
    if not isinstance(result, dict) or result.get("ok") is not True:
        code = _safe_browser_probe_code(
            result.get("error") if isinstance(result, dict) else None,
            fallback="response_shape",
        )
        raise OfferProbeError("browser_stripe_js", code)
    amount = _strict_stripe_amount(result.get("amount"), field="stripe_js.total")
    currency = result.get("currency")
    return {
        "amount": amount,
        "currency": currency.casefold() if isinstance(currency, str) else None,
    }


async def _read_hosted_checkout_init_in_browser(
    page: object,
    checkout_data: dict[str, object],
    *,
    session_id: str,
    timeout: float,
) -> dict[str, object]:
    """Let the hosted page issue Stripe init and capture its authoritative JSON."""
    timeout_ms = max(1_000, int(float(timeout) * 1_000))
    target = _browser_checkout_target(checkout_data, session_id)
    async with page.expect_response(
        lambda response: _is_browser_stripe_init_response(response.url, session_id),
        timeout=timeout_ms,
    ) as pending_response:
        await page.goto(
            target,
            wait_until="domcontentloaded",
            timeout=timeout_ms,
        )
    response = await pending_response.value
    body = await response.text()
    _check_response_error(int(response.status), body)
    try:
        data = json.loads(body)
    except Exception as exc:
        raise StripeInitError("browser stripe init returned invalid JSON") from exc
    if not isinstance(data, dict):
        raise StripeInitError("browser stripe init response is not an object")
    return data


async def _shared_gcash_audit_browser() -> tuple[object, object]:
    """Return one live Playwright/Chromium pair for PH payment audits."""
    global _GCASH_AUDIT_BROWSER, _GCASH_AUDIT_LOCK, _GCASH_AUDIT_LOOP
    global _GCASH_AUDIT_PLAYWRIGHT

    loop = asyncio.get_running_loop()
    if _GCASH_AUDIT_LOOP is not loop:
        _GCASH_AUDIT_BROWSER = None
        _GCASH_AUDIT_PLAYWRIGHT = None
        _GCASH_AUDIT_LOCK = asyncio.Lock()
        _GCASH_AUDIT_LOOP = loop
    if _GCASH_AUDIT_LOCK is None:
        _GCASH_AUDIT_LOCK = asyncio.Lock()

    async with _GCASH_AUDIT_LOCK:
        browser = _GCASH_AUDIT_BROWSER
        try:
            connected = browser is not None and browser.is_connected()
        except Exception:
            connected = False
        if connected and _GCASH_AUDIT_PLAYWRIGHT is not None:
            return _GCASH_AUDIT_PLAYWRIGHT, browser

        from playwright.async_api import async_playwright

        playwright = await async_playwright().start()
        try:
            browser = await playwright.chromium.launch(headless=True)
        except Exception:
            await playwright.stop()
            raise
        _GCASH_AUDIT_PLAYWRIGHT = playwright
        _GCASH_AUDIT_BROWSER = browser
        return playwright, browser


async def _open_hosted_checkout_for_payment_audit(
    page: object,
    checkout_data: dict[str, object],
    *,
    session_id: str,
    timeout: float,
) -> None:
    """Open the hosted checkout UI without submitting any payment action."""
    timeout_ms = max(1_000, int(min(float(timeout), 8.0) * 1_000))
    await page.goto(
        _browser_checkout_target(checkout_data, session_id),
        wait_until="domcontentloaded",
        timeout=timeout_ms,
    )


async def _browser_payment_section_has_payment_method(
    page: object,
    *,
    payment_method: str,
    timeout: float,
) -> bool:
    """Detect a visible wallet choice in the real hosted checkout UI.

    ``inner_text`` alone misses controls rendered inside an open shadow root,
    which is how a number of checkout payment pickers are mounted.  Playwright
    role/text locators pierce open shadow DOM, so use those first and retain
    the text scan for cross-origin iframe content that exposes no useful role.
    """
    method = _normalize_audited_payment_method(payment_method)
    deadline = asyncio.get_running_loop().time() + max(1.0, min(float(timeout), 12.0))
    method_pattern = re.compile(
        rf"(?<![a-z0-9]){re.escape(method)}(?![a-z0-9])",
        re.IGNORECASE,
    )
    javascript_pattern = re.escape(method)
    visible_dom_probe = """
      () => {
        const pattern = /(?<![a-z0-9])__PAYMENT_METHOD__(?![a-z0-9])/i;
        const isVisible = (node) => {
          if (!(node instanceof Element)) return false;
          const style = getComputedStyle(node);
          if (style.display === 'none' || style.visibility === 'hidden'
              || style.opacity === '0') return false;
          const rect = node.getBoundingClientRect();
          return rect.width > 0 && rect.height > 0;
        };
        const walk = (root) => {
          if (!root) return false;
          const elements = root.querySelectorAll
            ? Array.from(root.querySelectorAll('*')) : [];
          for (const element of elements) {
            const label = [
              element.getAttribute('aria-label') || '',
              element.getAttribute('data-testid') || '',
              element.getAttribute('data-value') || '',
              element.getAttribute('title') || '',
              element.getAttribute('name') || '',
              element.getAttribute('value') || '',
              element.getAttribute('alt') || '',
              element.getAttribute('src') || '',
              element.textContent || '',
            ].join(' ');
            if (pattern.test(label) && isVisible(element)) return true;
            if (element.shadowRoot && walk(element.shadowRoot)) return true;
          }
          return false;
        };
        return walk(document);
      }
    """.replace("__PAYMENT_METHOD__", javascript_pattern)
    selector = ", ".join(
        f"[{attribute}*='{method}' i]"
        for attribute in (
            "aria-label",
            "data-testid",
            "data-value",
            "title",
            "name",
            "value",
            "alt",
            "src",
            "id",
        )
    )
    while asyncio.get_running_loop().time() < deadline:
        try:
            if await page.evaluate(visible_dom_probe):
                return True
        except Exception:
            pass
        try:
            frames = list(page.frames)
        except Exception:
            frames = []
        for frame in frames:
            # These locators intentionally inspect only elements that the
            # checkout actually exposes to the user; no payment is submitted.
            for locator_factory in (
                lambda: frame.get_by_text(method_pattern),
                lambda: frame.get_by_role("button", name=method_pattern),
                lambda: frame.get_by_role("radio", name=method_pattern),
                lambda: frame.get_by_role("option", name=method_pattern),
                lambda: frame.get_by_label(method_pattern),
                lambda: frame.locator(selector),
            ):
                try:
                    locator = locator_factory()
                    count = min(await locator.count(), 12)
                    for index in range(count):
                        if await locator.nth(index).is_visible(timeout=500):
                            return True
                except Exception:
                    continue
            try:
                text = await frame.locator("body").inner_text(timeout=1_500)
            except Exception:
                continue
            if method_pattern.search(text):
                return True
        await asyncio.sleep(0.25)
    return False


async def _browser_payment_section_has_gcash(
    page: object,
    *,
    timeout: float,
) -> bool:
    """Backward-compatible GCash hosted-checkout UI helper."""
    return await _browser_payment_section_has_payment_method(
        page,
        payment_method="gcash",
        timeout=timeout,
    )


async def _browser_payment_section_has_momo(
    page: object,
    *,
    timeout: float,
) -> bool:
    """Detect a visible MoMo choice in the Vietnamese hosted checkout UI."""
    return await _browser_payment_section_has_payment_method(
        page,
        payment_method="momo",
        timeout=timeout,
    )


async def _click_gcash_payment_option(
    page: object,
    *,
    timeout: float,
    log: Callable[[str], None],
) -> bool:
    """Select the visible GCash method without scanning or authorizing a QR."""
    deadline = asyncio.get_running_loop().time() + max(3.0, min(float(timeout), 20.0))
    pattern = re.compile(r"(?<![a-z0-9])gcash(?![a-z0-9])", re.IGNORECASE)
    while asyncio.get_running_loop().time() < deadline:
        try:
            frames = list(page.frames)
        except Exception:
            frames = [page]
        for frame in frames:
            for locator_factory in (
                lambda: frame.get_by_role("radio", name=pattern),
                lambda: frame.get_by_role("button", name=pattern),
                lambda: frame.get_by_label(pattern),
                lambda: frame.get_by_text(pattern),
                lambda: frame.locator(
                    "[aria-label*='gcash' i], [data-testid*='gcash' i], "
                    "[data-value*='gcash' i], [name*='gcash' i], [value*='gcash' i]"
                ),
            ):
                try:
                    locator = locator_factory()
                    count = min(await locator.count(), 12)
                except Exception:
                    continue
                for index in range(count):
                    candidate = locator.nth(index)
                    try:
                        if not await candidate.is_visible(timeout=500):
                            continue
                        if not await candidate.is_enabled(timeout=500):
                            continue
                        await candidate.click(timeout=3_000)
                    except Exception:
                        continue
                    log("[gcash] selected payment method")
                    return True
        await asyncio.sleep(0.25)
    return False


async def _submit_gcash_checkout(
    page: object,
    *,
    timeout: float,
    log: Callable[[str], None],
) -> bool:
    """Submit the already-selected GCash method to open its provider QR.

    This starts a provider checkout only. It never scans the QR, signs into a
    GCash account, or authorizes the payment in the GCash app.
    """
    deadline = asyncio.get_running_loop().time() + max(2.0, min(float(timeout), 12.0))
    while asyncio.get_running_loop().time() < deadline:
        try:
            frames = list(page.frames)
        except Exception:
            frames = [page]
        for frame in frames:
            try:
                buttons = frame.locator('button[type="submit"], input[type="submit"]')
                count = min(await buttons.count(), 8)
            except Exception:
                continue
            for index in range(count):
                button = buttons.nth(index)
                try:
                    if not await button.is_visible(timeout=500):
                        continue
                    if not await button.is_enabled(timeout=500):
                        continue
                    await button.click(timeout=3_000)
                except Exception:
                    continue
                log("[gcash] submitted selected method; waiting for provider QR")
                return True
        await asyncio.sleep(0.25)
    return False


async def _wait_for_gcash_provider_page(page: object, *, timeout: float) -> object:
    """Prefer a redirected/popup GCash page; otherwise retain the checkout page."""
    deadline = asyncio.get_running_loop().time() + max(2.0, min(float(timeout), 15.0))
    while asyncio.get_running_loop().time() < deadline:
        try:
            pages = list(page.context.pages)
        except Exception:
            pages = [page]
        for candidate in reversed(pages):
            try:
                if candidate.is_closed():
                    continue
                host = (urlparse(str(candidate.url)).hostname or "").casefold()
            except Exception:
                continue
            if host == "gcash.com" or host.endswith(".gcash.com"):
                return candidate
        await asyncio.sleep(0.25)
    return page


async def open_gcash_qr_in_browser(
    page: object,
    *,
    access_token: str,
    cookies: object,
    timeout: float = 30.0,
    log: Callable[[str], None] = print,
) -> tuple[object, str]:
    """Create a Philippine hosted checkout and open the GCash QR in-browser.

    The caller owns the authenticated browser context. This function only
    selects GCash and starts its checkout so the provider can display a QR;
    payment authorization remains a manual action in the GCash application.
    """
    if not isinstance(access_token, str) or not access_token.strip():
        raise PaymentLinkError("browser checkout requires an access token")

    timeout_ms = max(5_000, int(min(float(timeout), 60.0) * 1_000))
    billing = REGION_BILLING["PH"]
    payload = {
        "entry_point": "all_plans_pricing_modal",
        "plan_name": "chatgptplusplan",
        "billing_details": {
            "country": billing["country"],
            "currency": billing["currency"],
        },
        "checkout_ui_mode": "hosted",
        "promo_campaign": {
            "promo_campaign_id": _PLUS_OFFER_CAMPAIGN,
            "is_coupon_from_query_param": True,
        },
    }
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "*/*",
        "OAI-Language": "en-PH",
        "x-openai-target-path": "/backend-api/payments/checkout",
        "x-openai-target-route": "/backend-api/payments/checkout",
    }
    cookie_map = _chatgpt_cookie_map(cookies)
    if cookie_map.get("oai-did"):
        headers["oai-device-id"] = cookie_map["oai-did"]
    account_id = _account_id_from_access_token(access_token)
    if account_id:
        headers["ChatGPT-Account-Id"] = account_id

    try:
        response_data = await page.evaluate(
            """
            async ({payload, headers, timeoutMs}) => {
              const controller = new AbortController();
              const timer = setTimeout(() => controller.abort(), timeoutMs);
              try {
                const response = await fetch('/backend-api/payments/checkout', {
                  method: 'POST',
                  credentials: 'include',
                  headers,
                  body: JSON.stringify(payload),
                  signal: controller.signal,
                });
                return {status: response.status, body: await response.text()};
              } finally {
                clearTimeout(timer);
              }
            }
            """,
            {"payload": payload, "headers": headers, "timeoutMs": timeout_ms},
        )
    except Exception as exc:
        raise PaymentLinkError(
            f"browser GCash checkout request failed: {type(exc).__name__}"
        ) from exc
    if not isinstance(response_data, dict):
        raise PaymentLinkError("browser GCash checkout returned an invalid response")
    body = str(response_data.get("body") or "")
    _check_response_error(int(response_data.get("status") or 0), body)
    try:
        checkout_data = json.loads(body)
    except (TypeError, ValueError) as exc:
        raise PaymentLinkError("browser GCash checkout returned invalid JSON") from exc
    if not isinstance(checkout_data, dict):
        raise PaymentLinkError("browser GCash checkout response is not an object")
    session_id = checkout_data.get("checkout_session_id")
    if not isinstance(session_id, str) or not session_id:
        raise PaymentLinkError("browser GCash checkout is missing its session id")

    target = _browser_checkout_target(checkout_data, session_id)
    try:
        await page.goto(target, wait_until="domcontentloaded", timeout=timeout_ms)
    except Exception as exc:
        raise PaymentLinkError(
            f"browser GCash checkout navigation failed: {type(exc).__name__}"
        ) from exc
    log("[gcash] hosted checkout opened")
    if not await _click_gcash_payment_option(page, timeout=timeout, log=log):
        raise PaymentLinkError("GCash payment method was not visible in the checkout")
    if not await _submit_gcash_checkout(page, timeout=timeout, log=log):
        raise PaymentLinkError("GCash checkout submit button was not available")
    provider_page = await _wait_for_gcash_provider_page(page, timeout=timeout)
    log("[gcash] provider page ready for QR capture")
    return provider_page, session_id


async def check_plus_offer_browser_context(
    access_token: str,
    *,
    cookies: object,
    timeout: float = 30.0,
    region: str = _PLUS_OFFER_REGION,
    checkout_ui_mode: str = "custom",
    account_id: str | None = None,
    inspect_gcash_payment_section: bool = False,
    inspect_momo_payment_section: bool = False,
    checkout_attempts: int = _CHECKOUT_MAX_ATTEMPTS,
    use_promo_campaign: bool = True,
) -> dict[str, object]:
    """Create checkout in Chromium and read its total through Stripe.js.

    This transport is intentionally independent from ``_call_stripe_init_data``:
    custom checkout uses the returned client secret with Stripe's supported
    ``initCheckout`` API, while hosted checkout lets the real page issue init.
    Payment-method audits may use a standard paid Plus checkout without the
    promo campaign. No payment confirmation or approval endpoint is called.
    """
    if not isinstance(access_token, str) or not access_token.strip():
        raise OfferProbeError("browser_checkout", "access_token_missing")
    if region not in REGION_BILLING:
        raise ValueError(f"unsupported offer region: {region}")
    if checkout_ui_mode not in ("hosted", "custom"):
        raise ValueError("checkout_ui_mode must be hosted or custom")
    audit_methods = [
        method
        for method, enabled in (
            ("gcash", inspect_gcash_payment_section),
            ("momo", inspect_momo_payment_section),
        )
        if enabled
    ]
    if len(audit_methods) > 1:
        raise ValueError("payment methods must be audited one at a time")
    audited_payment_method = audit_methods[0] if audit_methods else None
    if audited_payment_method and checkout_ui_mode != "hosted":
        raise ValueError("payment-section audit requires hosted checkout")
    try:
        browser_checkout_attempts = int(checkout_attempts)
    except (TypeError, ValueError) as exc:
        raise ValueError("checkout_attempts must be an integer") from exc
    browser_checkout_attempts = max(
        1,
        min(browser_checkout_attempts, _CHECKOUT_MAX_ATTEMPTS),
    )

    billing = REGION_BILLING[region]
    payload = {
        "entry_point": "all_plans_pricing_modal",
        "plan_name": "chatgptplusplan",
        "billing_details": {
            "country": billing["country"],
            "currency": billing["currency"],
        },
        "checkout_ui_mode": checkout_ui_mode,
    }
    if use_promo_campaign:
        payload["promo_campaign"] = {
            "promo_campaign_id": _PLUS_OFFER_CAMPAIGN,
            "is_coupon_from_query_param": True,
        }
    cookie_map = _chatgpt_cookie_map(cookies)
    resolved_account_id = account_id or _account_id_from_access_token(access_token)
    browser_locale = (
        "en-PH" if region == "PH"
        else "en-IN" if region == "IN"
        else "vi-VN" if region == "VN"
        else "en-US"
    )
    fetch_headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
        "Accept": "*/*",
        "OAI-Language": browser_locale,
        "x-openai-target-path": "/backend-api/payments/checkout",
        "x-openai-target-route": "/backend-api/payments/checkout",
    }
    device_id = cookie_map.get("oai-did")
    if device_id:
        fetch_headers["oai-device-id"] = device_id
    if resolved_account_id:
        fetch_headers["ChatGPT-Account-Id"] = resolved_account_id

    playwright = None
    browser = None
    context = None
    page = None
    payment_response_listener = None
    using_shared_audit_browser = audited_payment_method is not None
    try:
        if using_shared_audit_browser:
            playwright, browser = await _shared_gcash_audit_browser()
        else:
            from playwright.async_api import async_playwright

            playwright = await async_playwright().start()
            browser = await playwright.chromium.launch(headless=True)
        context_options = {
            "locale": browser_locale,
            "user_agent": _WINDOWS_USER_AGENT,
            "bypass_csp": True,
            "extra_http_headers": {
                "Accept-Language": (
                    "en-PH,en;q=0.9" if region == "PH"
                    else "en-IN,en;q=0.9" if region == "IN"
                    else "vi-VN,vi;q=0.9,en;q=0.8" if region == "VN"
                    else "en-US,en;q=0.9"
                ),
            },
        }
        if region == "PH":
            # Payment-method availability is locale-sensitive.  Match the
            # Philippine checkout context instead of an en-US browser.
            context_options["timezone_id"] = "Asia/Manila"
        elif region == "VN":
            context_options["timezone_id"] = "Asia/Ho_Chi_Minh"
        context = await browser.new_context(**context_options)
        browser_cookies = _playwright_chatgpt_cookies(cookies)
        if browser_cookies:
            await context.add_cookies(browser_cookies)
        page = await context.new_page()
        start_url = "https://chatgpt.com/"
        if use_promo_campaign:
            start_url = (
                f"{start_url}?promo_campaign={_PLUS_OFFER_CAMPAIGN}"
            )
        await page.goto(
            start_url,
            wait_until="domcontentloaded",
            timeout=int(float(timeout) * 1000),
        )
        page_html = (await page.content()).casefold()
        page_title = (await page.title()).casefold()
        if any(marker in page_html for marker in _DEACTIVATED_MARKERS):
            raise PaymentLinkError("account deactivated")
        if (
            "just a moment" in page_title
            or "cf-chl" in page_html
            or "/cdn-cgi/challenge" in page_html
        ):
            raise CloudflareBlockedError("HTTP 403: browser Cloudflare challenge")

        response_data: dict[str, object] | None = None
        for attempt in range(1, browser_checkout_attempts + 1):
            response_data = await page.evaluate(
                """
                async ({payload, headers, timeoutMs}) => {
                  const controller = new AbortController();
                  const timer = setTimeout(() => controller.abort(), timeoutMs);
                  try {
                    const response = await fetch('/backend-api/payments/checkout', {
                      method: 'POST',
                      credentials: 'include',
                      headers,
                      body: JSON.stringify(payload),
                      signal: controller.signal,
                    });
                    return {status: response.status, body: await response.text()};
                  } finally {
                    clearTimeout(timer);
                  }
                }
                """,
                {
                    "payload": payload,
                    "headers": fetch_headers,
                    "timeoutMs": int(float(timeout) * 1000),
                },
            )
            status = int(response_data.get("status") or 0)
            if status < 500 or attempt >= browser_checkout_attempts:
                break
            await asyncio.sleep(_CHECKOUT_RETRY_DELAY_SECONDS * attempt)

        if not isinstance(response_data, dict):
            raise OfferProbeError("browser_checkout", "response_shape")
        status = int(response_data.get("status") or 0)
        body = str(response_data.get("body") or "")
        try:
            _check_response_error(status, body)
            checkout_data = json.loads(body)
            if not isinstance(checkout_data, dict):
                raise PaymentLinkError("browser checkout response is not an object")
            session_id = checkout_data.get("checkout_session_id")
            publishable_key = checkout_data.get("publishable_key")
            if not isinstance(session_id, str) or not isinstance(publishable_key, str):
                raise PaymentLinkError("browser checkout response missing required fields")
        except PaymentLinkError as exc:
            if "deactivated" in str(exc).casefold():
                raise
            raise OfferProbeError("browser_checkout", _offer_failure_reason(exc)) from exc
        except Exception as exc:
            raise OfferProbeError("browser_checkout", _offer_failure_reason(exc)) from exc

        checkout_summary = _checkout_state_total_summary(
            checkout_data.get("checkout_state")
        )
        payment_metadata_states = {
            "gcash": _checkout_payload_gcash_state(checkout_data),
            "momo": _checkout_payload_momo_state(checkout_data),
        }
        client_secret = checkout_data.get("client_secret")
        currency: object = None
        source = "browser_checkout_page"
        if checkout_summary is not None:
            amount = int(checkout_summary["amount"])
            currency = checkout_summary.get("currency")
            source = "browser_checkout_state"
        elif isinstance(client_secret, str) and client_secret.strip():
            summary = await _read_custom_checkout_summary_in_browser(
                page,
                publishable_key=publishable_key,
                client_secret=client_secret,
            )
            amount = int(summary["amount"])
            currency = summary.get("currency")
            source = "browser_stripe_js"
        else:
            try:
                init_data = await _read_hosted_checkout_init_in_browser(
                    page,
                    checkout_data,
                    session_id=session_id,
                    timeout=float(timeout),
                )
                amount = parse_stripe_init_amount(init_data)
                for method in ("gcash", "momo"):
                    init_method_state = _checkout_payload_payment_method_state(
                        init_data,
                        method,
                    )
                    if (
                        init_method_state == "available"
                        or payment_metadata_states[method] == "unknown"
                    ):
                        payment_metadata_states[method] = init_method_state
            except PaymentLinkError as exc:
                raise OfferProbeError(
                    "browser_stripe_init",
                    _offer_failure_reason(exc),
                ) from exc
            currency = init_data.get("currency")
            if not isinstance(currency, str) or not currency.strip():
                options = init_data.get("elements_options")
                currency = options.get("currency") if isinstance(options, dict) else None

        if not isinstance(currency, str) or not currency.strip():
            currency = billing["currency"].lower()
        state = "available" if amount == 0 else "unavailable"
        payment_sections = {"gcash": False, "momo": False}
        payment_sources = {"gcash": "none", "momo": "none"}
        payment_conclusive = {"gcash": False, "momo": False}
        payment_network_signal: dict[str, object] = {
            "found": False,
            "found_source": "network",
            "stripe_init_state": "unknown",
        }
        if audited_payment_method:
            if payment_metadata_states[audited_payment_method] == "available":
                # The checkout response contains an explicit wallet method;
                # avoid the expensive hosted-page audit.
                payment_sections[audited_payment_method] = True
                payment_sources[audited_payment_method] = "checkout_metadata"
                payment_conclusive[audited_payment_method] = True
            else:
                # Negative metadata is not authoritative: wallet methods can
                # appear after the hosted payment section hydrates. Verify
                # both "unknown" and "unavailable" in the browser.
                try:
                    async def _capture_payment_response(response: object) -> None:
                        response_url = str(getattr(response, "url", "") or "")
                        parsed_response = urlparse(response_url)
                        response_host = (parsed_response.hostname or "").casefold()
                        if response_host not in {
                            "chatgpt.com",
                            "checkout.stripe.com",
                            "pay.openai.com",
                            "api.stripe.com",
                        }:
                            return
                        response_path = parsed_response.path.casefold()
                        if not any(
                            marker in response_path
                            for marker in ("checkout", "payment", "stripe", "elements")
                        ):
                            return
                        try:
                            response_body = await response.text()
                        except Exception:
                            return
                        if (
                            response_host == "api.stripe.com"
                            and _is_browser_stripe_init_response(
                                response_url,
                                session_id,
                            )
                        ):
                            stripe_init_state = _stripe_init_payment_method_state(
                                response_body,
                                audited_payment_method,
                            )
                            if stripe_init_state != "unknown":
                                payment_network_signal["stripe_init_state"] = (
                                    stripe_init_state
                                )
                            if stripe_init_state == "available":
                                payment_network_signal["found"] = True
                                payment_network_signal["found_source"] = "stripe_init"
                        if _checkout_payload_has_payment_method(
                            response_body,
                            audited_payment_method,
                        ):
                            payment_network_signal["found"] = True

                    payment_response_listener = _capture_payment_response
                    page.on("response", payment_response_listener)
                    await _open_hosted_checkout_for_payment_audit(
                        page,
                        checkout_data,
                        session_id=session_id,
                        timeout=float(timeout),
                    )
                    # Payment choices are hydrated after the initial document;
                    # give the hosted checkout one short render turn before
                    # reading its Stripe init metadata or scanning the UI.
                    await page.wait_for_timeout(750)
                    stripe_init_state = str(
                        payment_network_signal["stripe_init_state"]
                    ).casefold()
                    if bool(payment_network_signal["found"]):
                        payment_sections[audited_payment_method] = True
                        payment_sources[audited_payment_method] = str(
                            payment_network_signal["found_source"]
                        )
                        payment_conclusive[audited_payment_method] = True
                    elif stripe_init_state == "unavailable":
                        # This is the real hosted checkout's server payload,
                        # not the earlier OpenAI checkout metadata. It makes
                        # a negative result fast without masking wallets that
                        # appear only after the hosted page hydrates.
                        payment_sources[audited_payment_method] = "stripe_init"
                        payment_conclusive[audited_payment_method] = True
                    else:
                        payment_sections[audited_payment_method] = (
                            await _browser_payment_section_has_payment_method(
                                page,
                                payment_method=audited_payment_method,
                                timeout=float(timeout),
                            )
                        )
                        if payment_sections[audited_payment_method]:
                            payment_sources[audited_payment_method] = "checkout_ui"
                except Exception as exc:
                    raise OfferProbeError(
                        "browser_payment_section",
                        _offer_failure_reason(exc),
                    ) from exc
        return {
            "state": state,
            "status": state,
            "available": amount == 0,
            "amount": amount,
            "currency": currency.lower(),
            "region": region,
            "campaign": _PLUS_OFFER_CAMPAIGN if use_promo_campaign else None,
            "source": source,
            "gcash_payment_section": payment_sections["gcash"],
            "gcash_payment_section_source": payment_sources["gcash"],
            "gcash_payment_section_conclusive": payment_conclusive["gcash"],
            "gcash_metadata_state": payment_metadata_states["gcash"],
            "momo_payment_section": payment_sections["momo"],
            "momo_payment_section_source": payment_sources["momo"],
            "momo_payment_section_conclusive": payment_conclusive["momo"],
            "momo_metadata_state": payment_metadata_states["momo"],
        }
    except PaymentLinkError:
        raise
    except Exception as exc:
        raise OfferProbeError("browser_checkout", _offer_failure_reason(exc)) from exc
    finally:
        if context is not None and payment_response_listener is not None:
            try:
                page.remove_listener("response", payment_response_listener)
            except Exception:
                pass
        if context is not None:
            try:
                await context.close()
            except Exception:
                pass
        if browser is not None and not using_shared_audit_browser:
            try:
                await browser.close()
            except Exception:
                pass
        if playwright is not None and not using_shared_audit_browser:
            try:
                await playwright.stop()
            except Exception:
                pass


async def _call_stripe_init(
    session: AsyncSession,
    checkout_session_id: str,
    publishable_key: str,
    *,
    timeout: float = 30.0,
) -> str:
    """POST Stripe init and return the hosted checkout URL."""
    data = await _call_stripe_init_data(
        session,
        checkout_session_id,
        publishable_key,
        timeout=timeout,
    )
    hosted_url = data.get("stripe_hosted_url")
    if not hosted_url:
        raise StripeInitError(
            f"stripe init response missing stripe_hosted_url — keys: {list(data.keys())}"
        )

    return hosted_url


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def _get_checkout_url(
    session: AsyncSession,
    access_token: str,
    *,
    timeout: float,
    region: str,
    promo_campaign: bool,
) -> tuple[str, str]:
    """Return the hosted checkout URL together with its live publishable key."""
    checkout = await _call_chatgpt_checkout(
        session,
        access_token,
        region=region,
        promo_campaign=promo_campaign,
        timeout=timeout,
    )

    if checkout.url:
        replaced = _replace_stripe_host(checkout.url)
        parsed = urlparse(replaced)
        if "/c/pay/" in (parsed.path or ""):
            return replaced, checkout.publishable_key

    hosted_url = await _call_stripe_init(
        session,
        checkout.checkout_session_id,
        checkout.publishable_key,
        timeout=timeout,
    )
    return _replace_stripe_host(hosted_url), checkout.publishable_key


def _validate_trial_init_data(init_data: dict) -> None:
    """Fail fast unless Stripe init proves this checkout is the IDR 0 trial."""
    payment_method_types = init_data.get("payment_method_types")
    if not isinstance(payment_method_types, list) or "gopay" not in payment_method_types:
        raise GopayLinkError("trial checkout does not expose the gopay payment method")

    elements_options = init_data.get("elements_options")
    amount = elements_options.get("amount") if isinstance(elements_options, dict) else None
    if amount != 0:
        raise GopayLinkError(f"trial checkout expected amount 0, got {amount!r}")

    invoice = init_data.get("invoice")
    invoice_total = invoice.get("total") if isinstance(invoice, dict) else None
    invoice_amount_due = invoice.get("amount_due") if isinstance(invoice, dict) else None
    if invoice_total != 0 or invoice_amount_due != 0:
        raise GopayLinkError(
            "trial invoice expected total=0 and amount_due=0, "
            f"got total={invoice_total!r} amount_due={invoice_amount_due!r}"
        )


async def _get_trial_checkout(
    session: AsyncSession,
    access_token: str,
    *,
    timeout: float,
) -> tuple[str, str]:
    """Return a validated one-month-free ID checkout URL and publishable key."""
    checkout = await _call_chatgpt_checkout(
        session,
        access_token,
        region="ID",
        promo_campaign=True,
        timeout=timeout,
    )
    init_data = await _call_stripe_init_data(
        session,
        checkout.checkout_session_id,
        checkout.publishable_key,
        timeout=timeout,
    )
    _validate_trial_init_data(init_data)

    hosted_url = init_data.get("stripe_hosted_url") or init_data.get("url")
    if not isinstance(hosted_url, str) or not hosted_url:
        raise StripeInitError(
            f"stripe init response missing stripe_hosted_url — keys: {list(init_data.keys())}"
        )
    return _replace_stripe_host(hosted_url), checkout.publishable_key


async def _get_trial_checkout_url(
    session: AsyncSession,
    access_token: str,
    *,
    timeout: float,
) -> str:
    """Return only a validated one-month-free ID checkout URL."""
    payment_url, _publishable_key = await _get_trial_checkout(
        session,
        access_token,
        timeout=timeout,
    )
    return payment_url


async def get_checkout_url(
    access_token: str,
    *,
    proxy: str | None = None,
    timeout: float = 30.0,
    region: str = DEFAULT_REGION,
    promo_campaign: bool = True,
) -> str:
    """Main entry: access_token → pay.openai.com URL.

    Flow:
        1. POST checkout API → CheckoutResponse
        2. If response.url has checkout.stripe.com/c/pay/ → replace host → return
        3. Otherwise POST stripe init → get hosted_url → replace host → return

    Args:
        access_token: Bearer JWT from ChatGPT session.
        proxy: HTTP/HTTPS proxy URL (optional).
        timeout: Per-request timeout in seconds (default 30s).
        region: Region code (VN, ID, IN, US). Determines country + currency.
        promo_campaign: Apply the one-month-free campaign.

    Returns:
        Payment URL with pay.openai.com host.

    Raises:
        SessionExpiredError: HTTP 401
        CloudflareBlockedError: HTTP 403 + CF markers
        PaymentLinkError: other HTTP errors, timeout, parse errors
        StripeInitError: Stripe init failed or missing hosted_url
    """
    proxies = {"http": proxy, "https": proxy} if proxy else None

    async with AsyncSession(impersonate=_IMPERSONATE, proxies=proxies) as session:
        payment_url, _publishable_key = await _get_checkout_url(
            session,
            access_token,
            timeout=timeout,
            region=region,
            promo_campaign=promo_campaign,
        )
        return payment_url


# ---------------------------------------------------------------------------
# GoPay / Midtrans link extraction (Indonesia region)
# ---------------------------------------------------------------------------

_STRIPE_VERSION_GOPAY = "2020-08-27;custom_checkout_beta=v1"
_STRIPE_PM_URL = "https://api.stripe.com/v1/payment_methods"
_STRIPE_CONFIRM_URL_TPL = "https://api.stripe.com/v1/payment_pages/{session_id}/confirm"

# Billing info dùng cho tạo payment method GoPay.
_GOPAY_BILLING = {
    "name": "Mia Henderson",
    "email": "user@example.com",
    "country": "ID",
    "line1": "Jl Sudirman No 1",
    "city": "Jakarta",
    "postal_code": "10220",
    "state": "DKI Jakarta",
}


def _extract_cs_session_id(payment_url: str) -> str | None:
    """Extract cs_live_... or cs_test_... from pay.openai.com URL."""
    # URL format: https://pay.openai.com/c/pay/cs_live_xxxxx#...
    match = re.search(r'(cs_(?:live|test)_[A-Za-z0-9]+)', payment_url)
    return match.group(1) if match else None


def _extract_publishable_key(payment_url: str) -> str:
    """Return the legacy Stripe public-key fallback for URL-only callers."""
    return "pk_live_51HOrSwC6h1nxGoI3lTAgRjYVrz4dU3fVOabyCcKR3pbEJguCVAlqCxdxCUvoRh1XWwRacViovU3kLKvpkjh7IqkW00iXQsjo3n"


def _is_midtrans_url(value: str) -> bool:
    """Return True only for HTTPS URLs hosted by Midtrans."""
    try:
        parsed = urlparse(value)
    except ValueError:
        return False
    host = parsed.hostname
    return (
        parsed.scheme == "https"
        and host is not None
        and (host == "midtrans.com" or host.endswith(".midtrans.com"))
    )


def _build_gopay_checkout_context(
    payment_url: str,
    publishable_key: str,
    init_data: dict,
) -> GopayCheckoutContext:
    """Validate live Stripe init metadata before creating a GoPay method."""
    checkout_session_id = _extract_cs_session_id(payment_url)
    if not checkout_session_id:
        raise GopayLinkError(
            f"cannot extract checkout session ID from URL: {payment_url[:100]}"
        )

    payment_method_types = init_data.get("payment_method_types")
    if not isinstance(payment_method_types, list) or "gopay" not in payment_method_types:
        raise GopayLinkError("Stripe checkout does not expose the gopay payment method")

    elements_options = init_data.get("elements_options")
    amount = elements_options.get("amount") if isinstance(elements_options, dict) else None
    if not isinstance(amount, int):
        raise GopayLinkError("Stripe init response missing elements_options.amount")
    required = {}
    for key in ("config_id", "init_checksum", "eid"):
        value = init_data.get(key)
        if not isinstance(value, str) or not value:
            raise GopayLinkError(f"Stripe init response missing {key}")
        required[key] = value

    return GopayCheckoutContext(
        payment_url=payment_url,
        checkout_session_id=checkout_session_id,
        publishable_key=publishable_key,
        config_id=required["config_id"],
        init_checksum=required["init_checksum"],
        eid=required["eid"],
        expected_amount=str(amount),
    )


def _gopay_attribution_data(
    context: GopayCheckoutContext,
    *,
    client_session_id: str,
) -> dict[str, str]:
    return {
        "client_attribution_metadata[client_session_id]": client_session_id,
        "client_attribution_metadata[checkout_session_id]": context.checkout_session_id,
        "client_attribution_metadata[merchant_integration_source]": "checkout",
        "client_attribution_metadata[merchant_integration_version]": "hosted_checkout",
        "client_attribution_metadata[payment_method_selection_flow]": "automatic",
        "client_attribution_metadata[checkout_config_id]": context.config_id,
    }


def _build_gopay_payment_method_data(
    context: GopayCheckoutContext,
    *,
    guid: str,
    muid: str,
    sid: str,
    client_session_id: str,
) -> dict[str, str]:
    return {
        "type": "gopay",
        "billing_details[name]": _GOPAY_BILLING["name"],
        "billing_details[email]": _GOPAY_BILLING["email"],
        "billing_details[address][country]": _GOPAY_BILLING["country"],
        "billing_details[address][line1]": _GOPAY_BILLING["line1"],
        "billing_details[address][city]": _GOPAY_BILLING["city"],
        "billing_details[address][postal_code]": _GOPAY_BILLING["postal_code"],
        "billing_details[address][state]": _GOPAY_BILLING["state"],
        "guid": guid,
        "muid": muid,
        "sid": sid,
        "_stripe_version": _STRIPE_VERSION_GOPAY,
        "key": context.publishable_key,
        "payment_user_agent": "stripe.js/922d612e68; stripe-js-v3/922d612e68; checkout",
        **_gopay_attribution_data(context, client_session_id=client_session_id),
    }


def _build_gopay_confirm_data(
    context: GopayCheckoutContext,
    *,
    payment_method_id: str,
    guid: str,
    muid: str,
    sid: str,
    client_session_id: str,
) -> dict[str, str]:
    return_url = (
        f"https://pay.openai.com/c/pay/{context.checkout_session_id}"
        f"?redirect_pm_type=gopay&lid={uuid.uuid4()}&ui_mode=hosted"
    )
    return {
        "eid": context.eid,
        "payment_method": payment_method_id,
        "expected_amount": context.expected_amount,
        "consent[terms_of_service]": "accepted",
        "expected_payment_method_type": "gopay",
        "return_url": return_url,
        "_stripe_version": _STRIPE_VERSION_GOPAY,
        "guid": guid,
        "muid": muid,
        "sid": sid,
        "key": context.publishable_key,
        "version": "922d612e68",
        "init_checksum": context.init_checksum,
        **_gopay_attribution_data(context, client_session_id=client_session_id),
        "link_brand": "link",
    }


def _summarize_stripe_error(body: str) -> str:
    """Trích các field chẩn đoán quan trọng từ Stripe error response.

    Stripe nhét lý do thật vào nhiều chỗ lồng nhau (error.decline_code,
    error.advice_code, error.payment_method.*, last_setup_error...). Code cũ chỉ
    in 300 ký tự đầu nên thường cắt mất phần này. Hàm này parse JSON và gom các
    field hữu ích thành 1 dòng ngắn gọn; nếu không parse được thì trả raw body
    (cắt 600 ký tự thay vì 300 để giữ thêm ngữ cảnh).

    Returns:
        Chuỗi summary dạng "code=... decline_code=... message=...".
    """
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, TypeError, ValueError):
        return body[:600]

    err = data.get("error") if isinstance(data, dict) else None
    if not isinstance(err, dict):
        return body[:600]

    parts: list[str] = []
    for key in ("type", "code", "decline_code", "advice_code", "doc_url"):
        val = err.get(key)
        if val:
            parts.append(f"{key}={val}")

    msg = err.get("message")
    if msg:
        parts.append(f"message={msg!r}")

    # last_setup_error / last_payment_error thường chứa lý do GoPay/Midtrans thật.
    for nested_key in ("last_setup_error", "last_payment_error"):
        nested = err.get(nested_key)
        if isinstance(nested, dict):
            sub = {
                k: nested.get(k)
                for k in ("code", "decline_code", "message", "type")
                if nested.get(k)
            }
            if sub:
                parts.append(f"{nested_key}={sub}")

    return " ".join(parts) if parts else body[:600]


async def get_gopay_midtrans_url(
    payment_url: str,
    *,
    proxy: str | None = None,
    timeout: float = 30.0,
    publishable_key: str | None = None,
) -> str:
    """Lấy Midtrans GoPay redirect URL từ Stripe checkout session URL.

    billing_details cố định (generic), KHÔNG nhận email/name từ caller.

    Flow:
        1. Extract cs_live_... từ payment_url
        2. POST /v1/payment_pages/{cs}/init → live confirm metadata
        3. POST /v1/payment_methods (type=gopay) → pm_...
        4. POST /v1/payment_pages/{cs}/confirm → redirect URL (pm-redirects.stripe.com)
        5. GET redirect URL (no follow) → 302 Location → Midtrans URL

    Args:
        payment_url: Stripe checkout URL (pay.openai.com/c/pay/cs_live_...)
        proxy: HTTP/HTTPS proxy URL (optional)
        timeout: Per-request timeout
        publishable_key: Live key returned with the checkout session. URL-only
            legacy callers omit this and use the public-key fallback.

    Returns:
        Midtrans snap URL: https://app.midtrans.com/snap/v4/redirection/{token}...

    Raises:
        GopayLinkError: any step fails
    """
    cs_session = _extract_cs_session_id(payment_url)
    if not cs_session:
        raise GopayLinkError(f"cannot extract checkout session ID from URL: {payment_url[:100]}")

    pk_live = publishable_key or _extract_publishable_key(payment_url)
    guid = uuid.uuid4().hex + "b41d9b"
    muid = uuid.uuid4().hex + "f10cae"
    sid = uuid.uuid4().hex + "6babdc"
    client_session_id = str(uuid.uuid4())

    headers = {
        "Accept": "application/json",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Language": "en-US,en;q=0.9",
        "Origin": "https://pay.openai.com",
        "Referer": "https://pay.openai.com/",
        "User-Agent": _WINDOWS_USER_AGENT,
        "sec-ch-ua": _SEC_CH_UA,
        "sec-ch-ua-mobile": _SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": _SEC_CH_UA_PLATFORM,
    }

    proxies = {"http": proxy, "https": proxy} if proxy else None

    async with AsyncSession(impersonate=_IMPERSONATE, proxies=proxies) as session:
        # Step 1: Load the live Stripe Checkout contract.  The config id,
        # checksum, eid and amount are session-specific and must not be guessed.
        try:
            init_data = await _call_stripe_init_data(
                session,
                cs_session,
                pk_live,
                timeout=timeout,
            )
        except PaymentLinkError as exc:
            raise GopayLinkError(f"stripe init failed: {exc}") from exc
        context = _build_gopay_checkout_context(payment_url, pk_live, init_data)

        # Step 2: Create payment method (type=gopay)
        pm_data = _build_gopay_payment_method_data(
            context,
            guid=guid,
            muid=muid,
            sid=sid,
            client_session_id=client_session_id,
        )

        try:
            resp = await session.post(
                _STRIPE_PM_URL, headers=headers, data=pm_data, timeout=timeout,
            )
        except Exception as exc:
            raise GopayLinkError(f"create payment_method failed: {exc}") from exc

        if resp.status_code != 200:
            raise GopayLinkError(f"create payment_method HTTP {resp.status_code}: {resp.text[:300]}")

        try:
            pm_result = resp.json()
        except Exception as exc:
            raise GopayLinkError(f"payment_method JSON parse failed: {exc}") from exc

        pm_id = pm_result.get("id")
        if not pm_id:
            raise GopayLinkError(f"payment_method response missing id: {list(pm_result.keys())}")

        # Step 3: Confirm payment using only live init metadata.
        confirm_data = _build_gopay_confirm_data(
            context,
            payment_method_id=pm_id,
            guid=guid,
            muid=muid,
            sid=sid,
            client_session_id=client_session_id,
        )

        confirm_url = _STRIPE_CONFIRM_URL_TPL.format(session_id=cs_session)
        try:
            resp = await session.post(
                confirm_url, headers=headers, data=confirm_data, timeout=timeout,
            )
        except Exception as exc:
            raise GopayLinkError(f"confirm request failed: {exc}") from exc

        if resp.status_code != 200:
            raise GopayLinkError(
                f"confirm HTTP {resp.status_code}: {_summarize_stripe_error(resp.text)}"
            )

        try:
            confirm_result = resp.json()
        except Exception as exc:
            raise GopayLinkError(f"confirm JSON parse failed: {exc}") from exc

        # Stripe có thể trả HTTP 200 nhưng body chứa error object (setup decline).
        # Phải fail-fast với lý do đầy đủ, không để rơi xuống nhánh "missing
        # pm-redirects URL" gây hiểu nhầm.
        if isinstance(confirm_result, dict) and confirm_result.get("error"):
            raise GopayLinkError(
                f"confirm declined: {_summarize_stripe_error(resp.text)}"
            )

        # Extract pm-redirects URL from response
        redirect_url: str | None = None
        confirm_str = resp.text
        match = re.search(r'https://pm-redirects\.stripe\.com/[^"\\]+', confirm_str)
        if match:
            redirect_url = match.group(0)

        if not redirect_url:
            raise GopayLinkError(
                f"confirm response missing pm-redirects URL — keys: {list(confirm_result.keys())[:10]}"
            )

        # Step 3: Follow redirect to get Midtrans URL
        try:
            resp = await session.get(
                redirect_url,
                headers={"User-Agent": headers["User-Agent"]},
                allow_redirects=False,
                timeout=timeout,
            )
        except Exception as exc:
            raise GopayLinkError(f"follow redirect failed: {exc}") from exc

        if resp.status_code in (301, 302, 303, 307, 308):
            midtrans_url = resp.headers.get("Location") or resp.headers.get("location")
            if midtrans_url and _is_midtrans_url(midtrans_url):
                return midtrans_url
            raise GopayLinkError(
                f"redirect Location not Midtrans: {midtrans_url}"
            )

        # Fallback: parse body for midtrans URL
        body = resp.text[:3000]
        match = re.search(r'https://app\.midtrans\.com/snap/v[^\s"\'<>]+', body)
        if match:
            return match.group(0)

        raise GopayLinkError(
            f"cannot extract Midtrans URL from redirect response (status={resp.status_code})"
        )


async def get_gopay_url_from_access_token(
    access_token: str,
    *,
    proxy: str | None = None,
    timeout: float = 30.0,
) -> tuple[str, str | None]:
    """Return a validated promo trial URL plus a separate GoPay URL.

    The returned ``payment_url`` is always a validated amount=0 trial checkout.
    Do not confirm GoPay against that checkout here: Stripe rejects zero-amount
    GoPay setup for this flow.  The Midtrans ``gopay_url`` is created from a
    separate non-promo ID checkout first, then a fresh trial checkout is created
    last so the returned trial URL remains active.
    """
    proxies = {"http": proxy, "https": proxy} if proxy else None
    async with AsyncSession(impersonate=_IMPERSONATE, proxies=proxies) as session:
        paid_payment_url, paid_publishable_key = await _get_checkout_url(
            session,
            access_token,
            timeout=timeout,
            region="ID",
            promo_campaign=False,
        )

    gopay_url = await get_gopay_midtrans_url(
        paid_payment_url,
        proxy=proxy,
        timeout=timeout,
        publishable_key=paid_publishable_key,
    )

    async with AsyncSession(impersonate=_IMPERSONATE, proxies=proxies) as session:
        payment_url, _trial_publishable_key = await _get_trial_checkout(
            session,
            access_token,
            timeout=timeout,
        )
    return payment_url, gopay_url
