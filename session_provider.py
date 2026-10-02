"""SessionProvider — điều phối tái dùng session/cookie cho mọi flow login.

Luồng ``acquire``:
    1. (nếu bật reuse + không force_fresh) load record → revalidate cookie qua
       HTTP (mint access_token tươi, không mở browser) → REUSE nếu 200.
    2. miss/fail/tắt → ``login_fn()`` (Full_Login per-flow) → lưu record.

Trả FULL session (còn ``__cookies``) — flow tự strip trước khi broadcast/persist
(UPI cần ``__cookies`` để fill auth_sink/check_plan).

Phụ thuộc: session_store (leaf) + session_phase (fetch_session_via_http, ...).
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Awaitable, Callable

from session_phase import (
    SessionError,
    _scrub_jwt,
    fetch_session_via_http,
    is_fatal_login_error,
)
from session_store import (
    SessionStore,
    has_session_token,
    now_iso,
    session_token_from_cookies,
)


LogFn = Callable[[str], None]
LoginFn = Callable[[], Awaitable[dict[str, Any]]]


@dataclass
class SessionRecord:
    """Shape chuẩn của 1 record cache (chống phân mảnh logic chuyển đổi)."""

    email: str
    cookies: list[dict[str, Any]]
    access_token: str | None
    session_token: str | None
    two_factor: dict[str, Any] | None
    proxy: str | None
    created_at: str
    last_validated_at: str | None

    @classmethod
    def from_session_json(cls, email: str, data: dict[str, Any], proxy: str | None) -> "SessionRecord":
        """Nguồn: get_session_pure_request / get_session(browser) / upi → session JSON + __cookies."""
        cookies = data.get("__cookies") or []
        ts = now_iso()
        return cls(
            email=email,
            cookies=cookies,
            access_token=data.get("accessToken"),
            session_token=session_token_from_cookies(cookies),
            two_factor=None,
            proxy=proxy,
            created_at=ts,
            last_validated_at=ts,
        )

    @classmethod
    def from_signup_result(cls, result: Any, proxy: str | None) -> "SessionRecord":
        """Nguồn: reg flow (SignupResult) — save-only, không qua acquire."""
        ts = now_iso()
        return cls(
            email=getattr(result, "email"),
            cookies=getattr(result, "cookies", None) or [],
            access_token=getattr(result, "access_token", None),
            session_token=getattr(result, "session_token", None),
            two_factor=getattr(result, "two_factor", None),
            proxy=proxy,
            created_at=ts,
            last_validated_at=ts,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "email": self.email,
            "cookies": self.cookies,
            "access_token": self.access_token,
            "session_token": self.session_token,
            "two_factor": self.two_factor,
            "proxy": self.proxy,
            "created_at": self.created_at,
            "last_validated_at": self.last_validated_at,
        }


@dataclass(frozen=True)
class _CacheCfg:
    reuse_enabled: bool
    revalidate_http: bool
    cookie_max_age_hours: int


def strip_cookies(session: dict[str, Any]) -> dict[str, Any]:
    """Bản copy bỏ key ``__cookies`` — flow gọi TRƯỚC khi broadcast SSE / persist
    DB jobs (R4.5). KHÔNG gọi trong acquire (UPI cần __cookies)."""
    if not isinstance(session, dict) or "__cookies" not in session:
        return session
    return {k: v for k, v in session.items() if k != "__cookies"}


class SessionProvider:
    def __init__(self, store: SessionStore, settings_repo: Any = None) -> None:
        self._store = store
        self._settings_repo = settings_repo

    @property
    def store(self) -> SessionStore:
        return self._store

    # ── config ────────────────────────────────────────────────────────
    def _read_cfg(self) -> _CacheCfg:
        repo = self._settings_repo
        if repo is None:
            return _CacheCfg(True, True, 24)

        def _get(key: str, default: Any) -> Any:
            try:
                val = repo.get(key)
            except Exception:
                return default
            return default if val is None else val

        hours = _get("session.cookie_max_age_hours", 24)
        try:
            hours = int(hours)
        except (TypeError, ValueError):
            hours = 24
        return _CacheCfg(
            reuse_enabled=bool(_get("session.reuse_enabled", True)),
            revalidate_http=bool(_get("session.revalidate_http", True)),
            cookie_max_age_hours=hours if hours >= 1 else 24,
        )

    # ── public ────────────────────────────────────────────────────────
    async def acquire(
        self,
        *,
        email: str,
        proxy: str | None,
        login_fn: LoginFn,
        log: LogFn = print,
        force_fresh: bool = False,
        fatal_classifier: Callable[[BaseException], bool] | None = None,
    ) -> dict[str, Any]:
        """Trả session (session-JSON shape, còn ``__cookies``). Reuse nếu được,
        else Full_Login qua ``login_fn``."""
        cfg = self._read_cfg()
        classify = fatal_classifier or is_fatal_login_error
        async with self._store.lock_for(email):
            if cfg.reuse_enabled and not force_fresh:
                reused = await self._try_reuse(self._store.load(email), proxy, cfg, log)
                if reused is not None:
                    log("[session-cache] reuse hit — bỏ qua login")
                    return reused
            try:
                session = await login_fn()
            except BaseException as exc:  # noqa: BLE001 — phân loại rồi re-raise
                if classify(exc):
                    self._store.delete(email)  # GAP 5: chỉ xoá khi fatal
                raise
            try:
                self._store.save(email, SessionRecord.from_session_json(email, session, proxy).to_dict())
            except Exception as exc:  # noqa: BLE001 — cache best-effort, không fail job
                log(f"[session-cache] save fail: {type(exc).__name__}: {exc}")
            return session

    def save_login_result(self, result: Any, proxy: str | None, log: LogFn = print) -> None:
        """Reg flow (save-only): lưu record từ SignupResult, KHÔNG reuse.
        Best-effort — lỗi cache không làm fail job."""
        try:
            self._store.save(
                getattr(result, "email"),
                SessionRecord.from_signup_result(result, proxy).to_dict(),
            )
        except Exception as exc:  # noqa: BLE001
            log(f"[session-cache] save (reg) fail: {type(exc).__name__}: {exc}")

    # ── internal ──────────────────────────────────────────────────────
    async def _try_reuse(
        self,
        rec: dict[str, Any] | None,
        proxy: str | None,
        cfg: _CacheCfg,
        log: LogFn,
    ) -> dict[str, Any] | None:
        if not rec or not has_session_token(rec.get("cookies") or []):
            return None  # R2.6: cookie rỗng/không có session-token → không reuse

        if not cfg.revalidate_http:
            # Cheap mode (opt-in): tin cookie còn hạn theo TTL, KHÔNG gọi network.
            # access_token lưu có thể đã hết hạn → caller chịu rủi ro (spec R7.2).
            if not _within_ttl(rec, cfg.cookie_max_age_hours):
                return None
            # Trả ĐÚNG shape session-JSON (key "accessToken", không phải "access_token")
            # để khớp caller (get-session/link/upi đều đọc data.get("accessToken")).
            return {
                "accessToken": rec.get("access_token"),
                "__cookies": rec.get("cookies") or [],
            }

        rec_proxy = rec.get("proxy")
        try:
            data = await fetch_session_via_http(cookies=rec["cookies"], proxy=rec_proxy or proxy)
        except SessionError as exc:
            if is_fatal_login_error(exc):
                self._store.delete(rec["email"])
                raise
            # GAP 9: proxy lưu có thể chết/xoay SID → thử lại 1 lần với proxy runtime.
            if rec_proxy and proxy and rec_proxy != proxy:
                try:
                    data = await fetch_session_via_http(cookies=rec["cookies"], proxy=proxy)
                except SessionError as exc2:
                    if is_fatal_login_error(exc2):
                        self._store.delete(rec["email"])
                        raise
                    log(f"[session-cache] revalidate fail (cả 2 proxy): {_scrub_jwt(str(exc2))}")
                    return None
            else:
                log(f"[session-cache] revalidate fail: {_scrub_jwt(str(exc))}")
                return None

        # Reuse OK: cập nhật token tươi + last_validated_at, đính __cookies cho caller.
        try:
            self._store.save(rec["email"], {
                **rec,
                "access_token": data.get("accessToken"),
                "last_validated_at": now_iso(),
            })
        except Exception as exc:  # noqa: BLE001
            log(f"[session-cache] update-after-reuse fail: {type(exc).__name__}: {exc}")
        data["__cookies"] = rec["cookies"]
        return data


def _within_ttl(rec: dict[str, Any], max_age_hours: int) -> bool:
    """True nếu record còn trong ngưỡng tuổi (dùng khi tắt revalidate_http)."""
    ts = rec.get("last_validated_at") or rec.get("created_at")
    if not ts:
        return False
    try:
        # fromisoformat (py3.11+) parse cả 'YYYY-MM-DD hh:mm:ss' lẫn ISO 'T'.
        dt = datetime.fromisoformat(str(ts))
    except ValueError:
        return False
    age_hours = (datetime.now() - dt).total_seconds() / 3600.0
    return age_hours <= max_age_hours


def seed_from_session_results(store: SessionStore, session_repo: Any, log: LogFn = print) -> int:
    """Seed cache một lần từ bảng session_results (R11).

    - Chỉ row có cookie chứa session-token (reuse-được); bỏ cookie rỗng.
    - Dedupe theo email (list_all đã ORDER BY created_at DESC → lần gặp đầu là mới nhất).
    - Idempotent: KHÔNG clobber record runtime đã có (skip nếu file tồn tại).
    - proxy=null (DB không lưu proxy); last_validated_at=null → lần acquire đầu HTTP-revalidate.
    - Best-effort: lỗi 1 row không dừng cả seed.
    """
    n = 0
    seen: set[str] = set()
    try:
        rows = session_repo.list_all()
    except Exception as exc:  # noqa: BLE001
        log(f"[session-cache] seed bỏ qua (đọc session_results lỗi): {exc}")
        return 0
    for row in rows:
        email = row.get("email")
        if not email or email in seen:
            continue
        seen.add(email)
        try:
            cookies_raw = row.get("cookies")
            cookies = json.loads(cookies_raw) if cookies_raw else []
            if not has_session_token(cookies):
                continue
            if store.load(email) is not None:   # R11.5: không clobber record đã có
                continue
            tf_raw = row.get("two_factor")
            two_factor = json.loads(tf_raw) if tf_raw else None
            store.save(email, {
                "email": email,
                "cookies": cookies,
                "access_token": row.get("access_token"),
                "session_token": row.get("session_token"),
                "two_factor": two_factor,
                "proxy": None,
                "created_at": row.get("created_at"),
                "last_validated_at": None,
            })
            n += 1
        except Exception as exc:  # noqa: BLE001 — best-effort per row
            log(f"[session-cache] seed skip {email}: {type(exc).__name__}: {exc}")
    log(f"[session-cache] seed {n} record từ session_results")
    return n


# ── Singleton (set bởi web/server startup; managers/runner đọc) ───────
_provider_singleton: SessionProvider | None = None


def set_session_provider(provider: SessionProvider | None) -> None:
    global _provider_singleton  # noqa: PLW0603
    _provider_singleton = provider


def get_session_provider() -> SessionProvider | None:
    """Trả SessionProvider singleton, hoặc None nếu chưa init (caller fallback
    login trực tiếp — feature degrade an toàn, không crash)."""
    return _provider_singleton


def get_session_store() -> SessionStore:
    """Trả SessionStore của provider singleton (single source, đúng instance_id
    đã inject lúc startup). Fallback SessionStore() default nếu chưa init."""
    if _provider_singleton is not None:
        return _provider_singleton.store
    return SessionStore()
