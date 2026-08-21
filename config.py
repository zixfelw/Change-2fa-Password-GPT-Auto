"""Config + utilities — self-contained (không import signup_runner)."""
from __future__ import annotations

import os
import shutil
import sys
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional


_RUNTIME_BROWSER_SETTINGS: dict[str, str] = {}


def apply_runtime_settings(
    settings: dict[str, object],
    *,
    replace: bool = False,
) -> None:
    """Overlay browser settings loaded from the SQLite Settings Store."""
    if replace:
        for key in ("browser.engine", "browser.channel"):
            _RUNTIME_BROWSER_SETTINGS.pop(key, None)
    for key in ("browser.engine", "browser.channel"):
        if key not in settings:
            continue
        value = settings[key]
        if value is None:
            _RUNTIME_BROWSER_SETTINGS.pop(key, None)
        elif isinstance(value, str) and value.strip():
            _RUNTIME_BROWSER_SETTINGS[key] = value.strip()
        else:
            raise ValueError(f"Invalid runtime browser setting {key}: {value!r}")


# ─── Env parsing helpers ──────────────────────────────────────────────


def _load_env_file(path: Path) -> dict[str, str]:
    """Parse .env file đơn giản (KEY=VALUE, bỏ comment #)."""
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, val = line.partition("=")
        key = key.strip()
        val = val.strip().strip("'\"")
        values[key] = val
    return values


def _lookup(env: dict[str, str], key: str, default: str) -> str:
    return os.environ.get(key) or env.get(key) or default


def _parse_bool(val: str, *, default: bool) -> bool:
    if not val:
        return default
    return val.lower() in ("1", "true", "yes", "on")


def _parse_int(val: str, *, default: int) -> int:
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def _parse_float(val: str, *, default: float) -> float:
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


def _lookup_optional(env: dict[str, str], key: str) -> Optional[str]:
    """Trả raw value cho env key. None nếu không set hoặc empty string."""
    raw = os.environ.get(key)
    if raw is None:
        raw = env.get(key)
    if raw is None:
        return None
    raw = raw.strip()
    return raw or None


def _parse_optional_int(val: Optional[str]) -> Optional[int]:
    """Parse int, trả None nếu val là None hoặc parse fail."""
    if val is None:
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None


def _parse_positive_int(val: str, *, default: int, field_name: str) -> int:
    """Parse int yêu cầu > 0. Raise ValueError nếu val parse được nhưng <= 0
    (fail-fast theo project-rules — không silent fallback default).
    """
    try:
        parsed = int(val)
    except (ValueError, TypeError):
        return default
    if parsed <= 0:
        raise ValueError(
            f"{field_name} must be > 0 (got {parsed!r}); "
            f"set env to a positive integer or unset to use default {default}"
        )
    return parsed


def _parse_int_with_min(
    raw: Optional[str],
    *,
    default: int,
    min_value: int,
    field_name: str,
) -> int:
    """Parse int env value với fail-fast min validation.

    Trả default khi raw là None hoặc empty string (key vắng / chưa set).
    Raise ValueError nếu raw không parse được hoặc parsed < min_value
    (fail-fast — không trả Settings nếu config sai).
    """
    if raw is None:
        return default
    stripped = raw.strip()
    if stripped == "":
        return default
    try:
        parsed = int(stripped)
    except (ValueError, TypeError) as exc:
        raise ValueError(
            f"{field_name} must be an integer (got {raw!r})"
        ) from exc
    if parsed < min_value:
        raise ValueError(
            f"{field_name} must be >= {min_value} (got {parsed})"
        )
    return parsed


def _resolve_add_profile_timeout_sec(env: dict[str, str]) -> int:
    """Resolve Add_Profile session timeout từ 2 env tương đương.

    Canonical (R14.8, R14.16): ``ICLOUD_ADD_PROFILE_TIMEOUT_SEC`` (giây).
    Alias backward-compat (R14.7): ``ICLOUD_ADD_PROFILE_TTL_MINUTES`` (phút,
    sẽ nhân 60 để ra giây). Cả 2 cùng cấu hình hard timeout cho 1 session
    Add_Profile, default 1800s = 30 phút.

    Rules (fail-fast — không silent fallback):
    - Cả 2 set → raise ``ValueError`` (tránh ambiguity về precedence).
    - Chỉ ``TTL_MINUTES`` set → return ``ttl * 60``.
    - Chỉ ``TIMEOUT_SEC`` set → return giá trị đó.
    - Cả 2 unset → 1800.
    - Bất kỳ giá trị nào parse fail hoặc ≤ 0 → raise ``ValueError``.
    """
    ttl_raw = _lookup_optional(env, "ICLOUD_ADD_PROFILE_TTL_MINUTES")
    sec_raw = _lookup_optional(env, "ICLOUD_ADD_PROFILE_TIMEOUT_SEC")
    if ttl_raw is not None and sec_raw is not None:
        raise ValueError(
            "Set only one of ICLOUD_ADD_PROFILE_TTL_MINUTES or "
            "ICLOUD_ADD_PROFILE_TIMEOUT_SEC (both configure the same "
            "Add_Profile session timeout); unset one to disambiguate"
        )
    if ttl_raw is not None:
        ttl_minutes = _parse_int_with_min(
            ttl_raw,
            default=30,
            min_value=1,
            field_name="ICLOUD_ADD_PROFILE_TTL_MINUTES",
        )
        return ttl_minutes * 60
    return _parse_int_with_min(
        sec_raw,
        default=1800,
        min_value=1,
        field_name="ICLOUD_ADD_PROFILE_TIMEOUT_SEC",
    )


# ─── Settings ─────────────────────────────────────────────────────────


@dataclass
class Settings:
    root_dir: Path
    runtime_dir: Path
    browser_engine: str = "camoufox"
    browser_channel: str = "chrome"
    browser_headless: bool = False
    browser_viewport_width: int = 1440
    browser_viewport_height: int = 800
    browser_use_profile_template: bool = True
    browser_profile_template_dir: Path = Path("runtime/profiles/template")
    browser_camoufox_profile_dir: Path = Path("runtime/profiles/camoufox_template")
    browser_random_screen: bool = False

    # ── iCloud HME pool (feature: icloud-hme-pool) ─────────────────────
    # Pool / profile lifecycle (R2)
    icloud_limited_ttl_hours: int = 24            # R2.9
    icloud_quota_retry_minutes: int = 15          # R2.13
    icloud_hme_quota_limit: int = 700             # R2.14
    # Generator / HME client (R3, R11)
    icloud_hme_profile_parallelism: int = 1       # R3.17
    icloud_hme_http_timeout_sec: int = 30         # R11.7
    icloud_hme_race_retry_max: int = 3            # R3.14
    icloud_infinite_wait_max_sec: int = 86400     # R3.23
    # Recording / audit retention (R1, R6)
    icloud_recording_retention_days: Optional[int] = None  # R1.8 (None = giữ vô hạn)
    icloud_audit_retention_days: Optional[int] = None      # R6.5 (None = giữ vô hạn)
    # Job runner (R13)
    icloud_job_max_parallel: int = 1              # R13.9
    icloud_job_log_retention_days: int = 30       # R13.12
    # Web API auth (R10) — None khi unset; Web_API startup tự raise theo R10.10a.
    icloud_api_auth_token: Optional[str] = None   # R10.10a
    # Add_Profile_Flow web extension (R14)
    # Canonical: ICLOUD_ADD_PROFILE_TIMEOUT_SEC (R14.8, R14.16). Alias
    # backward-compat: ICLOUD_ADD_PROFILE_TTL_MINUTES (R14.7) → giây = phút*60.
    icloud_add_profile_timeout_sec: int = 1800    # R14.7, R14.8, R14.16
    # Open_Profile_Flow web extension (R15)
    icloud_open_profile_timeout_sec: int = 1800   # R15.9, R15.16
    # Runner loop (feature: icloud-runner-loop, R7)
    icloud_retry_interval: int = 900              # R7.1, R7.2 (min 10)
    icloud_max_errors_per_cycle: int = 0          # R7.4, R7.5 (min 0; 0 = không cap)

    @property
    def profiles_dir(self) -> Path:
        return self.runtime_dir / "profiles"

    def profile_dir_for(self, job_id: str) -> Path:
        return self.profiles_dir / job_id

    @classmethod
    def from_env(cls, env: dict[str, str]) -> "Settings":
        """Build Settings từ env mapping (không đọc file).

        Wire toàn bộ field ``icloud_*`` từ env. Trước May 2026 method này
        chỉ wire 2 field (R7) gây config drift im lặng — env như
        ``ICLOUD_HME_QUOTA_LIMIT`` set trong .env nhưng CLI runner không
        nhận. Bug A1 (refactor B review) — fix bằng cách wire đầy đủ
        giống ``load_settings`` (chỉ khác ở chỗ KHÔNG tự load .env file —
        caller chịu trách nhiệm pass env dict, thường là ``os.environ``).
        """
        root = Path(
            env.get("GPT_REG_ROOT")
            or os.environ.get("GPT_REG_ROOT")
            or Path.cwd()
        ).resolve()
        runtime_dir = Path(env.get("RUNTIME_DIR") or "runtime")
        if not runtime_dir.is_absolute():
            runtime_dir = root / runtime_dir

        return cls(
            root_dir=root,
            runtime_dir=runtime_dir,
            browser_engine=(
                _RUNTIME_BROWSER_SETTINGS.get("browser.engine")
                or _lookup(env, "BROWSER_ENGINE", "camoufox")
            ),
            browser_channel=(
                _RUNTIME_BROWSER_SETTINGS.get("browser.channel")
                or _lookup(env, "BROWSER_CHANNEL", "chrome")
            ),
            # ── iCloud HME pool ─────────────────────────────────────────
            icloud_limited_ttl_hours=_parse_int(
                _lookup(env, "ICLOUD_LIMITED_TTL_HOURS", "24"), default=24,
            ),
            icloud_quota_retry_minutes=_parse_int(
                _lookup(env, "ICLOUD_QUOTA_RETRY_MINUTES", "15"), default=15,
            ),
            icloud_hme_quota_limit=_parse_int(
                _lookup(env, "ICLOUD_HME_QUOTA_LIMIT", "700"), default=700,
            ),
            icloud_hme_profile_parallelism=_parse_int(
                _lookup(env, "ICLOUD_HME_PROFILE_PARALLELISM", "1"), default=1,
            ),
            icloud_hme_http_timeout_sec=_parse_int(
                _lookup(env, "ICLOUD_HME_HTTP_TIMEOUT_SEC", "30"), default=30,
            ),
            icloud_hme_race_retry_max=_parse_int(
                _lookup(env, "ICLOUD_HME_RACE_RETRY_MAX", "3"), default=3,
            ),
            icloud_infinite_wait_max_sec=_parse_int(
                _lookup(env, "ICLOUD_INFINITE_WAIT_MAX_SEC", "86400"),
                default=86400,
            ),
            icloud_recording_retention_days=_parse_optional_int(
                _lookup_optional(env, "ICLOUD_RECORDING_RETENTION_DAYS"),
            ),
            icloud_audit_retention_days=_parse_optional_int(
                _lookup_optional(env, "ICLOUD_AUDIT_RETENTION_DAYS"),
            ),
            icloud_job_max_parallel=_parse_int(
                _lookup(env, "ICLOUD_JOB_MAX_PARALLEL", "1"), default=1,
            ),
            icloud_job_log_retention_days=_parse_int(
                _lookup(env, "ICLOUD_JOB_LOG_RETENTION_DAYS", "30"), default=30,
            ),
            icloud_api_auth_token=_lookup_optional(env, "ICLOUD_API_AUTH_TOKEN"),
            icloud_add_profile_timeout_sec=_resolve_add_profile_timeout_sec(env),
            icloud_open_profile_timeout_sec=_parse_positive_int(
                _lookup(env, "ICLOUD_OPEN_PROFILE_TIMEOUT_SEC", "1800"),
                default=1800,
                field_name="ICLOUD_OPEN_PROFILE_TIMEOUT_SEC",
            ),
            # ── Runner loop (R7) ────────────────────────────────────────
            icloud_retry_interval=_parse_int_with_min(
                _lookup_optional(env, "ICLOUD_RETRY_INTERVAL"),
                default=900,
                min_value=10,
                field_name="ICLOUD_RETRY_INTERVAL",
            ),
            icloud_max_errors_per_cycle=_parse_int_with_min(
                _lookup_optional(env, "ICLOUD_MAX_ERRORS_PER_CYCLE"),
                default=0,
                min_value=0,
                field_name="ICLOUD_MAX_ERRORS_PER_CYCLE",
            ),
        )


def load_settings(root_dir: Path | None = None, env_file: str | Path = ".env") -> Settings:
    root = Path(root_dir or os.environ.get("GPT_REG_ROOT") or Path.cwd()).resolve()
    env_path = Path(env_file)
    if not env_path.is_absolute():
        env_path = root / env_path
    env = _load_env_file(env_path)

    runtime_dir = Path(_lookup(env, "RUNTIME_DIR", "runtime"))
    if not runtime_dir.is_absolute():
        runtime_dir = root / runtime_dir

    profile_template_dir = Path(_lookup(env, "BROWSER_PROFILE_TEMPLATE_DIR", "runtime/profiles/template"))
    if not profile_template_dir.is_absolute():
        profile_template_dir = root / profile_template_dir

    camoufox_profile_dir = Path(_lookup(env, "BROWSER_CAMOUFOX_PROFILE_DIR", "runtime/profiles/camoufox_template"))
    if not camoufox_profile_dir.is_absolute():
        camoufox_profile_dir = root / camoufox_profile_dir

    return Settings(
        root_dir=root,
        runtime_dir=runtime_dir,
        browser_engine=(
            _RUNTIME_BROWSER_SETTINGS.get("browser.engine")
            or _lookup(env, "BROWSER_ENGINE", "camoufox")
        ),
        browser_channel=(
            _RUNTIME_BROWSER_SETTINGS.get("browser.channel")
            or _lookup(env, "BROWSER_CHANNEL", "chrome")
        ),
        browser_headless=_parse_bool(_lookup(env, "BROWSER_HEADLESS", "false"), default=False),
        browser_viewport_width=_parse_int(_lookup(env, "BROWSER_VIEWPORT_WIDTH", "1440"), default=1440),
        browser_viewport_height=_parse_int(_lookup(env, "BROWSER_VIEWPORT_HEIGHT", "800"), default=800),
        browser_use_profile_template=_parse_bool(
            _lookup(env, "BROWSER_USE_PROFILE_TEMPLATE", "true"), default=True,
        ),
        browser_profile_template_dir=profile_template_dir,
        browser_camoufox_profile_dir=camoufox_profile_dir,
        browser_random_screen=_parse_bool(
            _lookup(env, "BROWSER_RANDOM_SCREEN", "false"), default=False,
        ),
        # ── iCloud HME pool ─────────────────────────────────────────────
        icloud_limited_ttl_hours=_parse_int(
            _lookup(env, "ICLOUD_LIMITED_TTL_HOURS", "24"), default=24,
        ),
        icloud_quota_retry_minutes=_parse_int(
            _lookup(env, "ICLOUD_QUOTA_RETRY_MINUTES", "15"), default=15,
        ),
        icloud_hme_quota_limit=_parse_int(
            _lookup(env, "ICLOUD_HME_QUOTA_LIMIT", "700"), default=700,
        ),
        icloud_hme_profile_parallelism=_parse_int(
            _lookup(env, "ICLOUD_HME_PROFILE_PARALLELISM", "1"), default=1,
        ),
        icloud_hme_http_timeout_sec=_parse_int(
            _lookup(env, "ICLOUD_HME_HTTP_TIMEOUT_SEC", "30"), default=30,
        ),
        icloud_hme_race_retry_max=_parse_int(
            _lookup(env, "ICLOUD_HME_RACE_RETRY_MAX", "3"), default=3,
        ),
        icloud_infinite_wait_max_sec=_parse_int(
            _lookup(env, "ICLOUD_INFINITE_WAIT_MAX_SEC", "86400"), default=86400,
        ),
        icloud_recording_retention_days=_parse_optional_int(
            _lookup_optional(env, "ICLOUD_RECORDING_RETENTION_DAYS"),
        ),
        icloud_audit_retention_days=_parse_optional_int(
            _lookup_optional(env, "ICLOUD_AUDIT_RETENTION_DAYS"),
        ),
        icloud_job_max_parallel=_parse_int(
            _lookup(env, "ICLOUD_JOB_MAX_PARALLEL", "1"), default=1,
        ),
        icloud_job_log_retention_days=_parse_int(
            _lookup(env, "ICLOUD_JOB_LOG_RETENTION_DAYS", "30"), default=30,
        ),
        icloud_api_auth_token=_lookup_optional(env, "ICLOUD_API_AUTH_TOKEN"),
        icloud_add_profile_timeout_sec=_resolve_add_profile_timeout_sec(env),
        icloud_open_profile_timeout_sec=_parse_positive_int(
            _lookup(env, "ICLOUD_OPEN_PROFILE_TIMEOUT_SEC", "1800"),
            default=1800,
            field_name="ICLOUD_OPEN_PROFILE_TIMEOUT_SEC",
        ),
        icloud_retry_interval=_parse_int_with_min(
            _lookup_optional(env, "ICLOUD_RETRY_INTERVAL"),
            default=900,
            min_value=10,
            field_name="ICLOUD_RETRY_INTERVAL",
        ),
        icloud_max_errors_per_cycle=_parse_int_with_min(
            _lookup_optional(env, "ICLOUD_MAX_ERRORS_PER_CYCLE"),
            default=0,
            min_value=0,
            field_name="ICLOUD_MAX_ERRORS_PER_CYCLE",
        ),
    )


def ensure_runtime_dirs(settings: Settings, extra: Iterable[Path] = ()) -> None:
    for path in (
        settings.profiles_dir,
        settings.browser_profile_template_dir,
        settings.browser_camoufox_profile_dir,
        *extra,
    ):
        path.mkdir(parents=True, exist_ok=True)


def runtime_session_dir(settings: Settings) -> Path:
    out = settings.runtime_dir / "sessions"
    out.mkdir(parents=True, exist_ok=True)
    return out


# ─── Proxy health/acquire knobs (.env layer) ─────────────────────────
# 6 knob cho SID-rotation + health-check. Default value canonical ở
# web/proxy_health._DEFAULT_KNOBS; .env CHỈ override khi set. Settings store
# (UI) ưu tiên cao hơn .env (xem proxy_health._load_proxy_knobs).
_PROXY_ENV_TO_KEY: dict[str, str] = {
    "PROXY_PROBE_ENDPOINT": "proxy.probe_endpoint",
    "PROXY_PROBE_TIMEOUT": "proxy.probe_timeout",
    "PROXY_MAX_TRIES": "proxy.max_tries",
    "PROXY_SID_LEN": "proxy.sid_len",
    "PROXY_SID_RETRY_PER_LINE": "proxy.sid_retry_per_line",
    "PROXY_PROBE_CONCURRENCY": "proxy.probe_concurrency",
}


def proxy_env_defaults(root_dir: Path | None = None, env_file: str | Path = ".env") -> dict[str, str]:
    """Trả raw value (store-key format) cho 6 proxy knob có set trong .env/env.

    Sparse: key không set → bỏ qua (proxy_health dùng hardcoded default). Mọi
    value đi qua validator của ``_load_proxy_knobs`` (reject→default) → .env sai
    range KHÔNG làm crash, chỉ fallback default + warning.
    """
    root = Path(root_dir or os.environ.get("GPT_REG_ROOT") or Path.cwd()).resolve()
    env = _load_env_file(root / env_file)
    out: dict[str, str] = {}
    for env_key, store_key in _PROXY_ENV_TO_KEY.items():
        raw = _lookup_optional(env, env_key)
        if raw is not None:
            out[store_key] = raw
    return out


# ─── Profile dir management ──────────────────────────────────────────


_PROFILE_COPY_IGNORE = (
    "BrowserMetrics",
    "Crashpad",
    "DevToolsActivePort",
    "LOCK",
    "RunningChromeVersion",
    "SingletonLock",
    "SingletonCookie",
    "SingletonSocket",
)


def _directory_has_contents(path: Path) -> bool:
    try:
        next(path.iterdir())
        return True
    except (FileNotFoundError, StopIteration):
        return False


def prepare_profile_dir(*, profile_dir: Path, template_dir: Path, use_template: bool) -> bool:
    """Clone profile template → profile_dir. Return True nếu đã clone."""
    if profile_dir.resolve() == template_dir.resolve():
        raise ValueError("Run profile clone path must be different from template profile path")
    if profile_dir.exists():
        shutil.rmtree(profile_dir, ignore_errors=True)
    profile_dir.parent.mkdir(parents=True, exist_ok=True)
    if use_template and _directory_has_contents(template_dir):
        shutil.copytree(
            template_dir,
            profile_dir,
            ignore=shutil.ignore_patterns(*_PROFILE_COPY_IGNORE),
        )
        return True
    profile_dir.mkdir(parents=True, exist_ok=True)
    return False


# ─── TLS security helpers ────────────────────────────────────────────


_INSECURE_TLS_ENV = "GPT_SIGNUP_INSECURE_TLS"
_warned_scopes: set[str] = set()


def env_insecure_tls() -> bool:
    """Đọc env GPT_SIGNUP_INSECURE_TLS → bool. Default False (secure).

    Bật qua env (1/true/yes/on) hoặc CLI flag truyền tay. Không có default
    insecure ở bất cứ đâu — chỉ opt-in.
    """
    raw = os.environ.get(_INSECURE_TLS_ENV, "").strip().lower()
    return raw in ("1", "true", "yes", "on")


def warn_insecure_tls(scope: str) -> None:
    """In cảnh báo loud khi 1 phase đang chạy với TLS verify off.

    Idempotent per-process per-scope: chỉ log lần đầu mỗi scope để không spam.
    """
    if scope in _warned_scopes:
        return
    _warned_scopes.add(scope)
    msg = (
        f"[security] TLS verification DISABLED for {scope!r} — "
        f"debug/local-dev only. Set {_INSECURE_TLS_ENV}=0 or remove --insecure-tls "
        f"to restore secure default."
    )
    print(msg, file=sys.stderr)
    warnings.warn(msg, RuntimeWarning, stacklevel=2)
