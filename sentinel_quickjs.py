"""QuickJS-driven Sentinel token generator.

Runs OpenAI's real sdk.js inside a Node subprocess to produce tokens that pass
deep server-side verification (required for OTP dispatch to actually send emails).

Adapted from https://github.com/Regert888/gpt-outlook-register (sentinel_quickjs.py)
and https://github.com/zc-zhangchen/any-auto-register (MIT License).

Two passes:
  1. action=requirements → request_p (fingerprint token)
  2. POST /sentinel/req with request_p → challenge (server token + PoW params)
  3. action=solve with challenge → final_p + t (solved enforcement token)
  4. Assemble {p: final_p, t, c: server_token, id: device_id, flow} → JSON string

Public API:
    get_sentinel_token_via_quickjs(session, device_id, flow, ...) -> str | None
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Optional

from user_agent_profile import sentinel_navigator_payload as _navigator_payload

logger = logging.getLogger(__name__)

SENTINEL_VERSION = "20260219f9f6"
SENTINEL_SDK_URL = f"https://sentinel.openai.com/sentinel/{SENTINEL_VERSION}/sdk.js"
SENTINEL_REQ_URL = "https://sentinel.openai.com/backend-api/sentinel/req"

# TLS-library recovery (mirror sentinel_pow): curl_cffi/BoringSSL có thể corrupt
# state khi đổi host (login → sentinel.openai.com) hoặc chạy concurrent. Retry
# trên Session tươi thay vì raise → fallback PoW (vốn cũng dùng session corrupt).
_TLS_RETRY_MAX = 2


def _is_tls_library_error(exc: BaseException) -> bool:
    msg = str(exc).lower()
    markers = (
        "invalid library", "openssl_internal", "tls connect error",
        "curl: (35)", "curl: (56)", "curl: (7)", "sslerror", "handshake",
    )
    return any(m in msg for m in markers)


def _make_fresh_session(template_session: Any) -> Any:
    """Session curl_cffi tươi (clear corrupt BoringSSL), copy proxy từ session gốc."""
    from curl_cffi import requests as _curl_requests
    from user_agent_profile import CURL_IMPERSONATE_PRIMARY as _IMPERSONATE

    fresh = _curl_requests.Session(impersonate=_IMPERSONATE)
    fresh.trust_env = False
    try:
        proxies = getattr(template_session, "proxies", None)
        if proxies:
            fresh.proxies = dict(proxies)
    except Exception:  # noqa: BLE001
        pass
    return fresh


def _resolve_node_binary() -> str:
    return (os.getenv("OPENAI_SENTINEL_NODE_PATH", "") or "").strip() or "node"


def _quickjs_script_path() -> Path:
    return Path(__file__).resolve().parent / "openai_sentinel_quickjs.js"


def _ensure_sdk_file(session: Any, timeout_ms: int) -> Path:
    """Download OpenAI's sdk.js to /tmp cache (one-shot per version)."""
    cache_dir = Path(tempfile.gettempdir()) / "openai-sentinel-demo" / SENTINEL_VERSION
    cache_dir.mkdir(parents=True, exist_ok=True)
    sdk_file = cache_dir / "sdk.js"
    if sdk_file.exists() and sdk_file.stat().st_size > 0:
        return sdk_file

    from user_agent_profile import (
        SEC_CH_UA,
        SEC_CH_UA_MOBILE,
        SEC_CH_UA_PLATFORM,
        WINDOWS_USER_AGENT,
    )

    resp = session.get(
        SENTINEL_SDK_URL,
        headers={
            "accept": "*/*",
            "accept-language": "en-US,en;q=0.9",
            "referer": "https://auth.openai.com/",
            "user-agent": WINDOWS_USER_AGENT,
            "sec-ch-ua": SEC_CH_UA,
            "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
            "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
            "sec-fetch-dest": "script",
            "sec-fetch-mode": "no-cors",
            "sec-fetch-site": "same-site",
        },
        timeout=max(10, int(timeout_ms / 1000)),
    )
    if getattr(resp, "status_code", 0) != 200:
        raise RuntimeError(f"Download sdk.js failed: HTTP {resp.status_code}")
    content = getattr(resp, "content", b"") or (resp.text or "").encode()
    if not content:
        raise RuntimeError("Download sdk.js failed: empty response")
    sdk_file.write_bytes(content)
    return sdk_file


_WRAPPER_JS = """
const fs = require('fs');
const timeoutMs = Number(process.env.OPENAI_SENTINEL_VM_TIMEOUT_MS || '10000');
const sdkFile = process.env.OPENAI_SENTINEL_SDK_FILE;
const scriptFile = process.env.OPENAI_SENTINEL_QUICKJS_SCRIPT;

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { input += chunk; });
process.stdin.on('end', async () => {
  try {
    const payload = JSON.parse(input || '{}');
    globalThis.__payload_json = JSON.stringify(payload);
    globalThis.__sdk_source = fs.readFileSync(sdkFile, 'utf8');
    globalThis.__vm_done = false;
    globalThis.__vm_output_json = '';
    globalThis.__vm_error = '';
    const script = fs.readFileSync(scriptFile, 'utf8');
    eval(script);

    const started = Date.now();
    while (!globalThis.__vm_done) {
      if ((Date.now() - started) > timeoutMs) {
        throw new Error('QuickJS script timeout');
      }
      await new Promise((resolve) => setTimeout(resolve, 1));
    }

    if (String(globalThis.__vm_error || '').trim()) {
      throw new Error(String(globalThis.__vm_error));
    }

    process.stdout.write(String(globalThis.__vm_output_json || ''));
  } catch (err) {
    const msg = err && err.stack ? String(err.stack) : String(err);
    process.stderr.write(msg);
    process.exit(1);
  }
});
""".strip()


# ─── Persistent Node worker (warm process — tránh cold-start V8 mỗi action) ──

# Wrapper loop: đọc từng dòng JSON {id, action, sdk_file, script_file, payload,
# timeout_ms} từ stdin, xử lý y hệt _WRAPPER_JS (set globals → eval script →
# poll __vm_done), ghi 1 dòng JSON {id, ok, output|error} ra stdout. Tái dùng
# 1 Node process cho nhiều action → tiết kiệm V8/Node startup (~150-300ms/lần).
_WORKER_BOOTSTRAP_JS = r"""
const fs = require('fs');
const readline = require('readline');

// Giữ reference setTimeout GỐC trước khi sdk/installRuntime override nó thành
// synchronous — wrapper loop phải dùng timer thật để không kẹt event loop.
const _origSetTimeout = setTimeout;

// sdk source cache theo path (đọc 1 lần / version).
const _sdkCache = new Map();
function _loadSdk(file) {
  if (_sdkCache.has(file)) return _sdkCache.get(file);
  const src = fs.readFileSync(file, 'utf8');
  _sdkCache.set(file, src);
  return src;
}

// Chuyển mọi console.* sang stderr để stdout chỉ chứa protocol JSON.
const _toErr = (...a) => { try { process.stderr.write(a.map(String).join(' ') + '\n'); } catch (e) {} };
console.log = _toErr; console.info = _toErr; console.warn = _toErr;
console.error = _toErr; console.debug = _toErr;

const rl = readline.createInterface({ input: process.stdin });

rl.on('line', async (line) => {
  const trimmed = (line || '').trim();
  if (!trimmed) return;
  let job;
  try { job = JSON.parse(trimmed); } catch (e) { return; }
  const id = job.id;
  const timeoutMs = Number(job.timeout_ms || 10000);
  try {
    const sdkSource = _loadSdk(job.sdk_file);
    const scriptSource = fs.readFileSync(job.script_file, 'utf8');
    const payload = job.payload || {};
    payload.action = job.action;

    globalThis.__payload_json = JSON.stringify(payload);
    globalThis.__sdk_source = sdkSource;
    globalThis.__vm_done = false;
    globalThis.__vm_output_json = '';
    globalThis.__vm_error = '';

    eval(scriptSource);

    const started = Date.now();
    while (!globalThis.__vm_done) {
      if ((Date.now() - started) > timeoutMs) throw new Error('QuickJS script timeout');
      await new Promise((resolve) => _origSetTimeout(resolve, 1));
    }
    if (String(globalThis.__vm_error || '').trim()) {
      throw new Error(String(globalThis.__vm_error));
    }
    process.stdout.write(JSON.stringify({ id: id, ok: true, output: String(globalThis.__vm_output_json || '') }) + '\n');
  } catch (err) {
    const msg = err && err.stack ? String(err.stack) : String(err);
    process.stdout.write(JSON.stringify({ id: id, ok: false, error: msg }) + '\n');
  }
});
""".strip()


class SentinelNodeWorker:
    """Persistent Node process cho sentinel — tái dùng qua nhiều action.

    Giao tiếp line-protocol qua stdin/stdout (1 dòng JSON/request, 1 dòng
    JSON/response). Tuần tự hóa bằng lock vì 1 reg có thể gọi từ thread chính
    (sentinel #1) và thread pre-compute (sentinel #2) — tuy không overlap nhưng
    lock đảm bảo an toàn. Tự respawn nếu process chết.
    """

    def __init__(self, *, node_path: str, script_file: Path, log: Callable[[str], None]) -> None:
        self._node = node_path
        self._script = str(script_file)
        self._log = log
        self._proc: Optional[subprocess.Popen] = None
        self._lock = threading.Lock()
        self._counter = 0

    def _ensure_proc(self) -> None:
        if self._proc is not None and self._proc.poll() is None:
            return
        self._proc = subprocess.Popen(
            [self._node, "-e", _WORKER_BOOTSTRAP_JS],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,  # tránh deadlock khi stderr buffer đầy
            text=True,
            bufsize=1,
            env={**os.environ},
        )

    def run_action(
        self,
        *,
        action: str,
        sdk_file: Path,
        payload: dict,
        timeout_ms: int,
    ) -> dict:
        with self._lock:
            self._ensure_proc()
            proc = self._proc
            assert proc is not None and proc.stdin is not None and proc.stdout is not None

            self._counter += 1
            req_id = self._counter
            job = {
                "id": req_id,
                "action": action,
                "sdk_file": str(sdk_file),
                "script_file": self._script,
                "payload": dict(payload),
                "timeout_ms": min(timeout_ms, 30000),
            }
            try:
                proc.stdin.write(json.dumps(job, ensure_ascii=False) + "\n")
                proc.stdin.flush()
            except (BrokenPipeError, ValueError) as exc:
                raise RuntimeError(f"sentinel worker stdin write failed: {exc}") from exc

            deadline = time.monotonic() + max(10.0, timeout_ms / 1000 + 5)
            while time.monotonic() < deadline:
                out = proc.stdout.readline()
                if not out:
                    raise RuntimeError("sentinel worker stdout closed (process died)")
                out = out.strip()
                if not out:
                    continue
                try:
                    resp = json.loads(out)
                except Exception:
                    continue  # bỏ qua dòng noise không phải protocol
                if not isinstance(resp, dict) or resp.get("id") != req_id:
                    continue
                if not resp.get("ok"):
                    raise RuntimeError(
                        f"sentinel worker action={action} failed: "
                        f"{str(resp.get('error'))[:300]}"
                    )
                data = json.loads(resp.get("output") or "{}")
                if not isinstance(data, dict):
                    raise RuntimeError("sentinel worker output is not a JSON object")
                return data
            raise RuntimeError(f"sentinel worker timeout (action={action})")

    def close(self) -> None:
        with self._lock:
            proc = self._proc
            self._proc = None
        if proc is None:
            return
        try:
            if proc.stdin:
                proc.stdin.close()
        except Exception:
            pass
        try:
            proc.terminate()
            proc.wait(timeout=3)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


def create_worker(log: Optional[Callable[[str], None]] = None) -> Optional["SentinelNodeWorker"]:
    """Tạo persistent Node worker. None nếu script không tồn tại."""
    log = log or (lambda m: logger.info(m))
    script = _quickjs_script_path()
    if not script.exists():
        return None
    return SentinelNodeWorker(
        node_path=_resolve_node_binary(),
        script_file=script,
        log=log,
    )


def _run_quickjs_action(
    *,
    action: str,
    sdk_file: Path,
    quickjs_script: Path,
    payload: dict,
    timeout_ms: int,
) -> dict:
    body = dict(payload)
    body["action"] = action
    proc = subprocess.run(
        [_resolve_node_binary(), "-e", _WRAPPER_JS],
        input=json.dumps(body, ensure_ascii=False),
        text=True,
        capture_output=True,
        timeout=max(10, int(timeout_ms / 1000) + 5),
        env={
            **os.environ,
            "OPENAI_SENTINEL_SDK_FILE": str(sdk_file),
            "OPENAI_SENTINEL_QUICKJS_SCRIPT": str(quickjs_script),
            "OPENAI_SENTINEL_VM_TIMEOUT_MS": str(min(timeout_ms, 30000)),
        },
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"QuickJS failed: {(proc.stderr or proc.stdout or 'unknown').strip()[:300]}"
        )
    out = (proc.stdout or "").strip()
    if not out:
        raise RuntimeError("QuickJS returned empty output")
    data = json.loads(out)
    if not isinstance(data, dict):
        raise RuntimeError("QuickJS output is not a JSON object")
    return data


def _fetch_sentinel_challenge(
    session: Any,
    *,
    device_id: str,
    flow: str,
    request_p: str,
    timeout_ms: int,
) -> dict:
    from user_agent_profile import (
        SEC_CH_UA,
        SEC_CH_UA_MOBILE,
        SEC_CH_UA_PLATFORM,
        WINDOWS_USER_AGENT,
    )

    body = {"p": request_p, "id": device_id, "flow": flow}
    _headers = {
        "origin": "https://sentinel.openai.com",
        "referer": (
            f"https://sentinel.openai.com/backend-api/sentinel/frame.html"
            f"?sv={SENTINEL_VERSION}"
        ),
        "content-type": "text/plain;charset=UTF-8",
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "en-US,en;q=0.9",
        "user-agent": WINDOWS_USER_AGENT,
        "sec-ch-ua": SEC_CH_UA,
        "sec-ch-ua-mobile": SEC_CH_UA_MOBILE,
        "sec-ch-ua-platform": SEC_CH_UA_PLATFORM,
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
    }
    _data = json.dumps(body, separators=(",", ":"))
    _timeout = max(10, int(timeout_ms / 1000))

    # Attempt trên session gốc; nếu TLS-library corruption → retry fresh session.
    # Lỗi khác (HTTP, JSON) propagate như cũ (RuntimeError ở dưới / caller catch).
    resp = None
    for attempt in range(_TLS_RETRY_MAX + 1):
        active = session if attempt == 0 else _make_fresh_session(session)
        try:
            resp = active.post(SENTINEL_REQ_URL, data=_data, headers=_headers, timeout=_timeout)
            break
        except Exception as exc:  # noqa: BLE001
            if not _is_tls_library_error(exc) or attempt >= _TLS_RETRY_MAX:
                raise
            logger.warning(
                "QuickJS /sentinel/req TLS-library error (retry %d/%d) → fresh session: %s",
                attempt + 1, _TLS_RETRY_MAX, exc,
            )
        finally:
            if attempt > 0 and active is not session:
                try:
                    active.close()
                except Exception:  # noqa: BLE001
                    pass
    if getattr(resp, "status_code", 0) != 200:
        raise RuntimeError(f"/sentinel/req HTTP {resp.status_code}")
    payload = resp.json()
    if not isinstance(payload, dict):
        raise RuntimeError("Sentinel challenge response is not a JSON object")
    return payload


def get_sentinel_token_via_quickjs(
    session: Any,
    device_id: str,
    *,
    flow: str = "authorize_continue",
    timeout_ms: int = 45000,
    log: Optional[Callable[[str], None]] = None,
    worker: Optional["SentinelNodeWorker"] = None,
) -> Optional[str]:
    """Run QuickJS sentinel path. Returns JSON string on success, None on failure.

    Caller should fall back to sentinel_pow.get_sentinel_token() on None.

    Nếu ``worker`` được truyền → chạy action qua persistent Node process (warm,
    tránh cold-start). Nếu None → spawn Node one-shot mỗi action (hành vi cũ).
    """
    log = log or (lambda m: logger.info(m))
    quickjs_script = _quickjs_script_path()
    if not quickjs_script.exists():
        log(f"[sentinel] QuickJS script not found: {quickjs_script}")
        return None

    def _action(action: str, payload: dict) -> dict:
        if worker is not None:
            return worker.run_action(
                action=action,
                sdk_file=sdk_file,
                payload=payload,
                timeout_ms=timeout_ms,
            )
        return _run_quickjs_action(
            action=action,
            sdk_file=sdk_file,
            quickjs_script=quickjs_script,
            payload=payload,
            timeout_ms=timeout_ms,
        )

    did = str(device_id or uuid.uuid4())
    # Navigator persona (UA + language + hardware) — phải pass vào sdk.js để
    # navigator.userAgent khớp Windows Chrome thực tế. Trước refactor không pass
    # → sdk.js thấy navigator.userAgent="Mozilla/5.0" (default trong JS) →
    # fingerprint cực kỳ generic, deep verification fail.
    nav_payload = _navigator_payload()
    try:
        sdk_file = _ensure_sdk_file(session, timeout_ms)

        # Pass 1: generate requirements token (fingerprint)
        requirements = _action(
            "requirements",
            {"device_id": did, **nav_payload},
        )
        request_p = str(requirements.get("request_p") or "").strip()
        if not request_p:
            log("[sentinel] QuickJS requirements did not return request_p")
            return None

        # Pass 2: fetch challenge from server
        challenge = _fetch_sentinel_challenge(
            session, device_id=did, flow=flow, request_p=request_p, timeout_ms=timeout_ms,
        )
        c_value = str(challenge.get("token") or "").strip()
        if not c_value:
            log("[sentinel] Challenge token is empty")
            return None

        # Pass 3: solve challenge
        solved = _action(
            "solve",
            {
                "device_id": did,
                "request_p": request_p,
                "challenge": challenge,
                **nav_payload,
            },
        )
        final_p = str(solved.get("final_p") or solved.get("p") or "").strip()
        if not final_p:
            log("[sentinel] QuickJS solve did not return final_p")
            return None

        t_raw = solved.get("t")
        t_value = "" if t_raw is None else str(t_raw).strip()
        if not t_value:
            log("[sentinel] QuickJS solve did not return valid t")
            return None

        token = json.dumps(
            {"p": final_p, "t": t_value, "c": c_value, "id": did, "flow": flow},
            separators=(",", ":"),
            ensure_ascii=False,
        )
        log(f"[sentinel] QuickJS OK (p={len(final_p)} t={len(t_value)} c={len(c_value)})")
        return token
    except Exception as e:
        log(f"[sentinel] QuickJS error: {e}")
        return None
