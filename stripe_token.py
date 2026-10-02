"""Stripe `js_checksum` + `rv_timestamp` token generator (pure Python).

Anti-fragile design — KHÔNG hardcode module ID, var name, salt values, shift.
Mỗi run extract live từ Stripe `custom_checkout.js` bundle bằng pattern match
(ổn định với obfuscation thay đổi). Cache extracted config theo bundle hash.

Thuật toán đã reverse-engineer (verified 10/10 PASS với HAR sample
runtime/research_logs/web_record_20260616-070836):

    Caesar shift (function `b` trong bundle):
        b(s, n) = ''.join(chr((ord(c) - 32 + n) % 95 + 32) for c in s)

    Stripe encode (module 9107 P.l):
        r(s) = ''.join(chr(5 ^ ord(c)) for c in s)        # XOR-5
        l(s) = url_encode(base64(r(s + ' '*(3 - len(s) % 3))))

    js_checksum  = b(l(JSON.stringify({id: ppage_id})), 11)
    rv_timestamp = b(l(JSON.stringify({rvTs, rv, sv})), 11)

Constants per build (module 114):
    rvTs (sK) — version date, vd "2024-01-01 00:00:00 -0000"
    rv (dG)   — build hash, vd "e5ebd5e1e6...3"
    sv (QJ)   — build salt, vd "3c7ef39815...69"

Inputs runtime:
    ppage_id (`id` field từ response /v1/payment_pages/{cs}/init).
    Reuse cùng `js_checksum` cho mọi confirm trong cùng checkout session.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any


# ─────────────────────────────────────────────────────────────────────
# Pure-Python primitives (verified 10/10 PASS với HAR thật)
# ─────────────────────────────────────────────────────────────────────


def caesar_shift(s: str, n: int) -> str:
    """JS: function(e, n) {
        for (var t=[],a=0; a<e.length; a++)
          t.push(String.fromCharCode((e.charCodeAt(a)-32+n)%95+32));
        return t.join("");
    }"""
    return "".join(chr((ord(c) - 32 + n) % 95 + 32) for c in s)


def stripe_encode(s: str) -> str:
    """Stripe module 9107 P.l(s).

    Lưu ý quirk: `pad = 3 - len(s) % 3` (KHÔNG modulo lại) — luôn pad 1..3 spaces,
    kể cả khi `len(s) % 3 == 0` (pad 3 spaces). XOR-5 mỗi byte trước khi base64.
    """
    pad = 3 - len(s) % 3
    padded = s + " " * pad
    xored = bytes(5 ^ ord(c) for c in padded)
    return urllib.parse.quote(
        base64.b64encode(xored).decode("ascii"),
        safe="-_.!~*'()",
    )


def _js_stringify(obj: dict[str, Any]) -> str:
    """JS JSON.stringify default — keys insertion order, no spaces."""
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


# ─────────────────────────────────────────────────────────────────────
# Config extraction (anti-fragile — pattern match, không hardcode ID)
# ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class StripeTokenConfig:
    """Config extract từ Stripe bundle. Tất cả values cần để compute token.

    Thay đổi mỗi build → cần re-extract khi bundle hash thay đổi.
    """
    bundle_hash: str       # SHA256 hash của bundle source — invalidate cache
    shift: int             # Caesar shift (verified hiện tại = 11)
    rv_ts: str             # constants module 114 sK
    rv: str                # constants module 114 dG
    sv: str                # constants module 114 QJ

    def __repr__(self) -> str:
        return (
            f"StripeTokenConfig(bundle_hash={self.bundle_hash[:12]}…, "
            f"shift={self.shift}, "
            f"rv_ts={self.rv_ts!r}, rv={self.rv[:12]}…, sv={self.sv[:12]}…)"
        )


class StripeTokenExtractError(Exception):
    """Không extract được config từ bundle — Stripe có thể đã đổi obfuscation."""


# Pattern matchers — bám vào THUẬT TOÁN, không bám vào tên var/ID:
#   - Caesar shift: `charCodeAt(...)-32+...)%95+32`
#   - js_checksum builder: `<fn>((0,<P>.<l>)(JSON.stringify({id:<var>})),<shift>)`
#   - Module require: `<lhs>=<t>(<id>)`
_CAESAR_FN_RE = re.compile(
    r"\b[a-zA-Z_$][\w$]{0,3}\s*=\s*function\s*\(\s*"
    r"[a-zA-Z_$][\w$]{0,3}\s*,\s*"
    r"[a-zA-Z_$][\w$]{0,3}\s*\)\s*\{"
    r"[^{}]*?charCodeAt\([^)]*?\)\s*-\s*32\s*\+\s*[a-zA-Z_$][\w$]{0,3}\s*\)\s*%\s*95\s*\+\s*32"
    r"[^{}]*?\}"
)

_JS_CHECKSUM_RE = re.compile(
    r"\b(?P<fn>[a-zA-Z_$][\w$]{0,3})\s*\(\s*"
    r"\(\s*0\s*,\s*(?P<encmod>[a-zA-Z_$][\w$]{0,3})\s*\.\s*(?P<encfn>[a-zA-Z_$][\w$]{0,3})\s*\)"
    r"\s*\(\s*JSON\s*\.\s*stringify\s*\(\s*\{\s*id\s*:\s*[a-zA-Z_$][\w$]*\s*\}\s*\)\s*\)"
    r"\s*,\s*(?P<shift>\d+)\s*\)"
)

_RV_TIMESTAMP_RE = re.compile(
    r"rv_timestamp\s*:\s*[a-zA-Z_$][\w$]{0,3}"
    r"\s*\(\s*\(\s*0\s*,\s*[a-zA-Z_$][\w$]{0,3}\s*\.\s*[a-zA-Z_$][\w$]{0,3}\s*\)"
    r"\s*\(\s*JSON\s*\.\s*stringify\s*\(\s*\{(?P<keys>[^}]+)\}\s*\)\s*\)"
    r"\s*,\s*(?P<shift>\d+)\s*\)"
)

_WEBPACK_REQUIRE_RE = re.compile(
    r"\b(?P<lhs>[a-zA-Z_$][\w$]{0,3})\s*=\s*[a-zA-Z_$][\w$]{0,3}\s*\(\s*(?P<id>\d+)\s*\)"
)


def _balanced_brace(body: str, open_pos: int) -> int:
    depth = 0
    in_str = False
    ch_str = ""
    i = open_pos
    while i < len(body):
        c = body[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == ch_str:
                in_str = False
        else:
            if c in ("'", '"', "`"):
                in_str = True
                ch_str = c
            elif c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth == 0:
                    return i
        i += 1
    return -1


def _extract_webpack_module(body: str, mod_id: int) -> str:
    """Extract body của webpack module ID — pattern: `<id>:function(...){...}`."""
    pattern = re.compile(rf"[\s,{{(]{mod_id}\s*:\s*", re.MULTILINE)
    for m in pattern.finditer(body):
        rest = body[m.end():m.end() + 200]
        sig = re.match(
            r"\s*(?:function\s*\([^)]*\)|\([^)]*\)\s*=>|[a-zA-Z_$][\w$]*\s*=>)\s*\{",
            rest,
        )
        if not sig:
            continue
        brace_open = m.end() + sig.end() - 1
        brace_close = _balanced_brace(body, brace_open)
        if brace_close < 0:
            continue
        return body[m.start():brace_close + 1]
    return ""


def _extract_constants_from_module_114_body(mod_body: str) -> dict[str, str]:
    """Extract `sK/dG/QJ` từ module body. Format webpack:
        n.d(t, { QJ: () => a, dG: () => o, sK: () => r });
        var r = "...",
            o = /*! STRIPE_JS_BUILD_SALT */"...",
            a = /*! STRIPE_JS_BUILD_SALT */"...";

    Trả map: {"sK": value, "dG": value, "QJ": value}
    """
    # Map exported name → local var (`QJ` → `a`)
    export_map: dict[str, str] = {}
    for m in re.finditer(
        r"([a-zA-Z_$][\w$]{0,3})\s*:\s*function\s*\(\s*\)\s*\{\s*return\s+([a-zA-Z_$][\w$]{0,3})\s*\}",
        mod_body,
    ):
        export_map[m.group(1)] = m.group(2)
    # Bắt local var assignments: `<var>=<optional_comment>"<string>"` (cho phép
    # /*! ... */ block comment chèn giữa `=` và string literal).
    var_values: dict[str, str] = {}
    for m in re.finditer(
        r'\b([a-zA-Z_$][\w$]{0,3})\s*=\s*(?:/\*[^*]*(?:\*(?!/)[^*]*)*\*/\s*)?"([^"]*)"',
        mod_body,
    ):
        var_values.setdefault(m.group(1), m.group(2))

    out: dict[str, str] = {}
    for export_name, local_name in export_map.items():
        if local_name in var_values:
            out[export_name] = var_values[local_name]
    return out


def extract_config(
    bundle_source: str,
    *,
    fallback_sources: list[str] | None = None,
) -> StripeTokenConfig:
    """Parse Stripe bundle (custom_checkout.js) + optional fallback bundles để
    extract toàn bộ config cần compute token.

    Anti-fragile: pattern match thuật toán, không bám tên/ID. Fail-fast nếu
    không match — log rõ để biết Stripe đã đổi obfuscation.
    """
    bundle_hash = hashlib.sha256(bundle_source.encode("utf-8")).hexdigest()

    # 1. Caesar shift function — verify pattern tồn tại (chỉ assert, không cần value)
    if not _CAESAR_FN_RE.search(bundle_source):
        raise StripeTokenExtractError(
            "Caesar shift function pattern không tìm thấy — "
            "Stripe có thể đã đổi thuật toán encode."
        )

    # 2. js_checksum builder → extract shift
    js_match = _JS_CHECKSUM_RE.search(bundle_source)
    if not js_match:
        raise StripeTokenExtractError(
            "js_checksum builder pattern không tìm thấy — "
            "Stripe có thể đã đổi cấu trúc payload."
        )
    shift = int(js_match.group("shift"))
    encmod_local = js_match.group("encmod")  # vd 'P'

    # 3. rv_timestamp — extract module local cho constants ('C')
    rv_match = _RV_TIMESTAMP_RE.search(bundle_source)
    if not rv_match:
        raise StripeTokenExtractError(
            "rv_timestamp builder pattern không tìm thấy."
        )
    keys_literal = rv_match.group("keys")
    if int(rv_match.group("shift")) != shift:
        raise StripeTokenExtractError(
            f"shift mismatch js_checksum={shift} vs rv_timestamp={rv_match.group('shift')} "
            "— builder có thể đã tách ra dùng shift khác."
        )

    # Map rv/sv/rvTs key trong JSON.stringify → module member
    member_refs = re.findall(
        r"(\w+)\s*:\s*([a-zA-Z_$][\w$]*)\s*\.\s*([a-zA-Z_$][\w$]*)",
        keys_literal,
    )
    if len(member_refs) != 3:
        raise StripeTokenExtractError(
            f"rv_timestamp keys layout đã đổi — expect 3 refs, got {member_refs}"
        )

    # 4. Resolve module ID cho `C` (constants) và `P` (encoder) trong scope
    rv_scope_start = max(0, rv_match.start() - 4000)
    rv_scope_end = min(len(bundle_source), rv_match.start() + 4000)
    rv_scope = bundle_source[rv_scope_start:rv_scope_end]
    constants_module_local = member_refs[0][1]  # vd 'C'

    constants_module_id: int | None = None
    for rm in _WEBPACK_REQUIRE_RE.finditer(rv_scope):
        if rm.group("lhs") == constants_module_local:
            constants_module_id = int(rm.group("id"))
            break
    if constants_module_id is None:
        raise StripeTokenExtractError(
            f"không resolve được module ID cho constants local {constants_module_local!r}"
        )

    # 5. Extract module body — try bundle chính trước, fallback các bundle khác
    mod_body = _extract_webpack_module(bundle_source, constants_module_id)
    if not mod_body:
        for fb in fallback_sources or []:
            mod_body = _extract_webpack_module(fb, constants_module_id)
            if mod_body:
                break
    if not mod_body:
        raise StripeTokenExtractError(
            f"không tìm thấy body module {constants_module_id} trong bundle chính "
            f"hoặc {len(fallback_sources or [])} fallback bundle"
        )

    # 6. Extract constants {sK, dG, QJ} từ module body
    constants = _extract_constants_from_module_114_body(mod_body)
    expected_keys = {ref[2] for ref in member_refs}  # ('sK', 'dG', 'QJ')
    missing = expected_keys - set(constants)
    if missing:
        raise StripeTokenExtractError(
            f"constants module {constants_module_id} thiếu keys {missing}; "
            f"got {list(constants)}"
        )

    # Map key (rvTs/rv/sv) → constant member name
    key_to_member = {ref[0]: ref[2] for ref in member_refs}
    rv_ts = constants[key_to_member["rvTs"]]
    rv = constants[key_to_member["rv"]]
    sv = constants[key_to_member["sv"]]

    return StripeTokenConfig(
        bundle_hash=bundle_hash,
        shift=shift,
        rv_ts=rv_ts,
        rv=rv,
        sv=sv,
    )


def extract_config_from_paths(
    custom_checkout_path: Path,
    *,
    controller_path: Path | None = None,
    extra_bundles: list[Path] | None = None,
) -> StripeTokenConfig:
    """Convenience: load bundles từ disk + extract.

    Auto-scan: nếu không pass `controller_path`, tự tìm các `*.js` cùng thư
    mục với `custom_checkout_path` và dùng làm fallback source cho module
    constants. Robust với mọi bundle dump.
    """
    custom_checkout_path = Path(custom_checkout_path)
    bundle = custom_checkout_path.read_text(encoding="utf-8")

    fallback_sources: list[str] = []
    if controller_path:
        fallback_sources.append(Path(controller_path).read_text(encoding="utf-8"))
    if extra_bundles:
        for p in extra_bundles:
            fallback_sources.append(Path(p).read_text(encoding="utf-8"))

    # Auto-scan láng giềng nếu chưa có fallback
    if not fallback_sources:
        for sibling in custom_checkout_path.parent.glob("*.js"):
            if sibling.resolve() == custom_checkout_path.resolve():
                continue
            try:
                if sibling.stat().st_size < 200_000:
                    continue  # skip file nhỏ — module constants thường trong bundle lớn
                fallback_sources.append(sibling.read_text(encoding="utf-8"))
            except Exception:
                continue

    return extract_config(bundle, fallback_sources=fallback_sources)


# ─────────────────────────────────────────────────────────────────────
# Live bundle fetch (auto, không phụ thuộc HAR cache)
# ─────────────────────────────────────────────────────────────────────


from user_agent_profile import (
    SEC_CH_UA as _SEC_CH_UA,
    SEC_CH_UA_MOBILE as _SEC_CH_UA_MOBILE,
    SEC_CH_UA_PLATFORM as _SEC_CH_UA_PLATFORM,
    WINDOWS_USER_AGENT as _USER_AGENT,
)
_CACHE_ROOT = Path("runtime/cache/stripe_bundles")


def _cache_path(key: str) -> Path:
    p = _CACHE_ROOT / key[:16]
    p.mkdir(parents=True, exist_ok=True)
    return p


async def fetch_bundles_live(
    sess: Any,
    *,
    log,
    use_cache: bool = True,
    proxies: dict | None = None,
) -> tuple[str, str]:
    """Fetch (custom_checkout, entry_stripe) live từ Stripe qua curl_cffi.

    Strategy ĐÚNG (phát hiện qua reverse webpack):
        1. GET https://js.stripe.com/v3/ (entry script) → set cookies + entry source
        2. Parse webpack chunk map từ entry:
              - `e.u = e => "fingerprinted/js/" + {chunkId: name}[e] + ...`
              - hash table `{chunkId: hash}`
              → resolve URL fingerprinted của `custom-checkout` chunk
        3. GET https://js.stripe.com/v3/fingerprinted/js/custom-checkout-<hash>.js
           với Sec-Fetch-Site=same-origin → 200

    Module 114 (constants `rv_ts/rv/sv`) NẰM TRONG ENTRY stripe.js — không
    cần fetch thêm controller bundle riêng.

    Cache disk theo SHA256 entry source.

    Returns: (cc_src, entry_src). entry_src dùng làm fallback module 114.
    """
    common_headers = {
        "User-Agent": _USER_AGENT,
        "sec-ch-ua": _SEC_CH_UA,
        "sec-ch-ua-mobile": _SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": _SEC_CH_UA_PLATFORM,
        "Accept": "*/*",
        "Accept-Language": "en-IN,en;q=0.9",
    }

    log(f"        │ fetch entry https://js.stripe.com/v3/")
    r_entry = await sess.get(
        "https://js.stripe.com/v3/",
        headers={**common_headers, "Referer": "https://chatgpt.com/"},
        timeout=30,
        proxies=proxies,
    )
    if r_entry.status_code != 200:
        raise StripeTokenExtractError(
            f"entry HTTP {r_entry.status_code}: {(r_entry.text or '')[:200]}"
        )
    entry = r_entry.text or ""
    entry_hash = hashlib.sha256(entry.encode("utf-8")).hexdigest()
    log(f"        │ entry hash={entry_hash[:16]} size={len(entry)}")

    if use_cache:
        cdir = _cache_path(entry_hash)
        cc_cache = cdir / "custom_checkout.js"
        entry_cache = cdir / "entry.js"
        if cc_cache.exists() and entry_cache.exists():
            log(f"        │ cache hit → {cdir}")
            return (
                cc_cache.read_text(encoding="utf-8"),
                entry_cache.read_text(encoding="utf-8"),
            )

    # Parse webpack chunk maps
    chunk_names: dict[int, str] = {}
    chunk_hashes: dict[int, str] = {}

    # Map chunkId → name (loose: tìm map trong block sau "fingerprinted/js/")
    name_map_match = re.search(
        r'"fingerprinted/js/"[^}]*?\{([^}]+)\}', entry,
    )
    if name_map_match:
        for em in re.finditer(r'(\d+):"([a-z][a-zA-Z0-9_-]+)"', name_map_match.group(1)):
            chunk_names[int(em.group(1))] = em.group(2)

    # Map chunkId → hash (numeric chunkId → hex string ≥20 chars)
    for m in re.finditer(r'\{(\d+:"[a-f0-9]{20,}",?){3,40}\}', entry):
        for em in re.finditer(r'(\d+):"([a-f0-9]{20,})"', m.group(0)):
            chunk_hashes[int(em.group(1))] = em.group(2)
        if chunk_hashes:
            break

    if not chunk_names or not chunk_hashes:
        raise StripeTokenExtractError(
            f"không parse được webpack chunk map (names={len(chunk_names)}, "
            f"hashes={len(chunk_hashes)}) — Stripe có thể đã đổi format webpack"
        )

    cc_id = next((cid for cid, n in chunk_names.items() if n == "custom-checkout"), None)
    if cc_id is None:
        raise StripeTokenExtractError(
            f"không thấy chunk 'custom-checkout' trong map: {list(chunk_names.values())}"
        )
    cc_hash = chunk_hashes.get(cc_id)
    if not cc_hash:
        raise StripeTokenExtractError(
            f"không có hash cho chunk {cc_id} (custom-checkout)"
        )
    cc_url = f"https://js.stripe.com/v3/fingerprinted/js/custom-checkout-{cc_hash}.js"
    log(f"        │ resolved custom-checkout → chunkId={cc_id} hash={cc_hash[:12]}…")

    sub_headers = {
        **common_headers,
        "Referer": "https://js.stripe.com/v3/",
        "Sec-Fetch-Dest": "script",
        "Sec-Fetch-Mode": "no-cors",
        "Sec-Fetch-Site": "same-origin",
    }

    log(f"        │ fetch {cc_url.rsplit('/', 1)[-1]}")
    r_cc = await sess.get(cc_url, headers=sub_headers, timeout=60, proxies=proxies)
    if r_cc.status_code != 200:
        raise StripeTokenExtractError(
            f"custom_checkout fingerprinted HTTP {r_cc.status_code}: "
            f"{(r_cc.text or '')[:200]}"
        )
    cc_src = r_cc.text or ""
    log(f"        │ custom_checkout size={len(cc_src)}")

    if use_cache:
        cdir = _cache_path(entry_hash)
        (cdir / "custom_checkout.js").write_text(cc_src, encoding="utf-8")
        (cdir / "entry.js").write_text(entry, encoding="utf-8")
        log(f"        │ cached → {cdir}")

    return cc_src, entry


async def extract_config_live(
    sess: Any,
    *,
    log,
    use_cache: bool = True,
    fallback_dir: Path | None = None,
    proxies: dict | None = None,
) -> StripeTokenConfig:
    """Combo: fetch bundles live + extract config. Idempotent qua cache.

    Fallback chain:
        1. Cache live (entry_hash hit) → instant
        2. Fetch live qua sess (đòi proxy stable)
        3. Nếu live fail + `fallback_dir` cấp → đọc bundle từ disk
           (vd HAR dump cũ) → vẫn extract được, log cảnh báo bundle có thể lỗi thời.
    """
    try:
        cc_src, entry_src = await fetch_bundles_live(
            sess, log=log, use_cache=use_cache, proxies=proxies,
        )
    except (StripeTokenExtractError, Exception) as exc:  # noqa: BLE001
        if fallback_dir is None:
            raise
        log(f"        │ live fetch FAIL ({type(exc).__name__}: {exc})")
        log(f"        │ fallback → đọc bundle từ {fallback_dir}")
        cc_path = next(fallback_dir.glob("custom-checkout-*.js"), None) \
            or fallback_dir / "custom_checkout.js"
        if not cc_path.exists():
            raise StripeTokenExtractError(
                f"fallback dir {fallback_dir} không có custom_checkout bundle"
            ) from exc
        cc_src = cc_path.read_text(encoding="utf-8")
        # Module 114 (constants) thường nằm trong ENTRY stripe.js hoặc shared
        # bundle. Glob có thể trả nhiều file — chọn file lớn nhất (entry/shared
        # đều >900KB; stripe-cookies-* nhỏ ~66KB cần tránh).
        entry_candidates: list[Path] = []
        for pat in ("stripe.js", "stripe-*.js", "shared-*.js", "entry.js"):
            entry_candidates.extend(fallback_dir.glob(pat))
        entry_candidates = [
            p for p in entry_candidates
            if "stripe-cookies" not in p.name and p.stat().st_size > 200_000
        ]
        entry_path = (
            max(entry_candidates, key=lambda p: p.stat().st_size)
            if entry_candidates else None
        )
        entry_src = entry_path.read_text(encoding="utf-8") if entry_path else ""
        log(
            f"[stripe_token] fallback OK: cc={cc_path.name}, "
            f"entry={entry_path.name if entry_path else '(none)'}"
        )

    fallback_sources = [entry_src] if entry_src else []
    cfg = extract_config(cc_src, fallback_sources=fallback_sources)
    log(f"        │ config ready: {cfg}")
    return cfg


# ─────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────


def compute_js_checksum(ppage_id: str, *, shift: int = 11) -> str:
    """Compute js_checksum cho 1 ppage_id (id từ /v1/payment_pages/{cs}/init).

    Reuse cùng giá trị cho mọi confirm trong cùng checkout session (cùng ppage).
    """
    payload = _js_stringify({"id": ppage_id})
    return caesar_shift(stripe_encode(payload), shift)


def compute_rv_timestamp(config: StripeTokenConfig) -> str:
    """Compute rv_timestamp từ constants config (extract live từ bundle)."""
    payload = _js_stringify({
        "rvTs": config.rv_ts,
        "rv": config.rv,
        "sv": config.sv,
    })
    return caesar_shift(stripe_encode(payload), config.shift)


def build_token_fields(
    *,
    ppage_id: str,
    config: StripeTokenConfig,
) -> dict[str, str]:
    """Build dict các field token để inject vào confirm payload.

    Returns:
        {"js_checksum": "...", "rv_timestamp": "..."}

    Lưu ý:
        `passive_captcha_token`, `passive_captcha_ekey` là OPTIONAL (truthy
        check `t ? {...} : {}` trong builder x). Pure-HTTP có thể bỏ qua,
        Stripe accept với risk score cao hơn — vẫn thử trước.
    """
    return {
        "js_checksum": compute_js_checksum(ppage_id, shift=config.shift),
        "rv_timestamp": compute_rv_timestamp(config),
    }
