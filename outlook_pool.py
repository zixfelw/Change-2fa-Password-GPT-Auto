"""Pool combo Outlook/Hotmail.

Format pool file (1 dòng = 1 combo):
    email|password|refresh_token|client_id
    email|password|refresh_token|client_id
    ...

Pool tracker:
    runtime/outlook_state/<email>.json giờ thêm field:
        used_for_signup: true|false      — true = đã signup ChatGPT thành công, skip
        last_used_at:    ISO timestamp   — lần cuối thử
        last_error:      str | null      — lý do skip nếu fail (e.g. registration_disallowed)

Selection strategy:
    1. Đọc pool file.
    2. Loop từng combo, check state:
       - used_for_signup == true → skip.
       - last_error == 'registration_disallowed' → skip (combo bị OpenAI block, không retry).
       - last_error == 'invalid_grant' → skip (combo expire token).
       - Otherwise → return combo này.
    3. Hết pool mà không có combo dùng được → raise.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

from mail_providers import OutlookCombo, OutlookComboError

if TYPE_CHECKING:
    from db.repositories import ComboRepository

from db.repositories import TERMINAL_ERROR_SUBSTRINGS

# Alias cho backward compat internal usage
_TERMINAL_ERRORS = tuple(TERMINAL_ERROR_SUBSTRINGS)


class OutlookPoolError(Exception):
    """Pool fail."""


def _state_file(state_dir: Path, email: str) -> Path:
    safe = email.replace("/", "_")
    return state_dir / f"{safe}.json"


def _read_state(state_dir: Path, email: str) -> dict:
    path = _state_file(state_dir, email)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _write_state(state_dir: Path, email: str, state: dict) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    path = _state_file(state_dir, email)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    tmp.replace(path)


def parse_pool_file(path: Path) -> list[OutlookCombo]:
    """Đọc pool file, return list combo. Skip dòng trống / comment (#)."""
    if not path.exists():
        raise OutlookPoolError(f"pool file không tồn tại: {path}")
    combos: list[OutlookCombo] = []
    seen_emails: set[str] = set()
    for line_num, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            combo = OutlookCombo.parse(line)
        except OutlookComboError as exc:
            raise OutlookPoolError(f"pool file dòng {line_num}: {exc}") from exc
        if combo.email.lower() in seen_emails:
            raise OutlookPoolError(f"pool file dòng {line_num}: email trùng {combo.email}")
        seen_emails.add(combo.email.lower())
        combos.append(combo)
    if not combos:
        raise OutlookPoolError(f"pool file rỗng: {path}")
    return combos


def iter_available(
    pool: list[OutlookCombo], *, state_dir: Path, log,
) -> Iterator[OutlookCombo]:
    """Yield combo còn dùng được, theo thứ tự pool file."""
    for combo in pool:
        state = _read_state(state_dir, combo.email)
        if state.get("used_for_signup"):
            log(f"[pool] skip {combo.email} — đã signup ChatGPT (used_for_signup=true)")
            continue
        last_error = state.get("last_error")
        if last_error and any(err in last_error for err in _TERMINAL_ERRORS):
            log(f"[pool] skip {combo.email} — terminal error: {last_error[:80]}")
            continue
        # Hydrate refresh_token mới nếu state có
        latest = state.get("refresh_token")
        if isinstance(latest, str) and latest.startswith("M.C"):
            combo.refresh_token = latest
        yield combo


def pick_first_available(
    pool: list[OutlookCombo],
    *,
    state_dir: Path,
    log,
    combo_repo: "ComboRepository | None" = None,
) -> OutlookCombo:
    """Pick combo đầu tiên còn dùng được — chỉ trong phạm vi pool hiện tại.

    Nếu combo_repo được cung cấp: check từng email trong pool qua SQLite.
    Nếu không: fallback về JSON state files (backward compat).
    """
    if combo_repo is not None:
        pool_emails = {c.email.lower() for c in pool}
        for combo in pool:
            row = combo_repo.get_by_email(combo.email)
            if row is None:
                # Chưa có trong DB → available (sẽ được upsert trước khi chạy)
                log(f"[pool] picked combo {combo.email} (not yet in db)")
                return combo
            if row.get("used_for_signup"):
                log(f"[pool] skip {combo.email} — đã signup (used_for_signup=true)")
                continue
            last_error = row.get("last_error") or ""
            if last_error and any(err in last_error for err in _TERMINAL_ERRORS):
                log(f"[pool] skip {combo.email} — terminal error: {last_error[:80]}")
                continue
            # Available — hydrate refresh_token mới từ DB nếu có
            if row.get("refresh_token") and row["refresh_token"].startswith("M.C"):
                combo.refresh_token = row["refresh_token"]
            log(f"[pool] picked combo {combo.email}")
            return combo
        raise OutlookPoolError(
            f"hết combo khả dụng trong pool ({len(pool)} combo total). "
            "Tất cả đã used_for_signup hoặc terminal error."
        )

    # Fallback: JSON state files
    for combo in iter_available(pool, state_dir=state_dir, log=log):
        log(f"[pool] picked combo {combo.email}")
        return combo
    raise OutlookPoolError(
        f"hết combo khả dụng trong pool ({len(pool)} combo total). "
        "Tất cả đã used_for_signup hoặc terminal error."
    )


def mark_signup_success(
    *,
    state_dir: Path,
    email: str,
    combo_repo: "ComboRepository | None" = None,
) -> None:
    """Đánh dấu combo đã signup thành công.

    Nếu combo_repo được cung cấp: delegate sang SQLite.
    Nếu không: fallback về JSON state files (backward compat).
    """
    if combo_repo is not None:
        combo_repo.mark_success(email)
        return

    # Fallback: JSON state files
    state = _read_state(state_dir, email)
    state["used_for_signup"] = True
    state["used_at"] = datetime.now(timezone.utc).isoformat()
    state.pop("last_error", None)
    _write_state(state_dir, email, state)


def mark_signup_failure(
    *,
    state_dir: Path,
    email: str,
    error: str,
    combo_repo: "ComboRepository | None" = None,
) -> None:
    """Đánh dấu combo fail. Nếu lỗi thuộc terminal, sẽ bị skip lần sau.

    Nếu combo_repo được cung cấp: delegate sang SQLite.
    Nếu không: fallback về JSON state files (backward compat).
    """
    if combo_repo is not None:
        combo_repo.mark_failure(email, error)
        return

    # Fallback: JSON state files
    state = _read_state(state_dir, email)
    state["last_error"] = error
    state["last_failed_at"] = datetime.now(timezone.utc).isoformat()
    _write_state(state_dir, email, state)


def status_summary(
    pool: list[OutlookCombo],
    *,
    state_dir: Path,
    combo_repo: "ComboRepository | None" = None,
) -> dict:
    """Tổng kết pool: bao nhiêu used / available / failed.

    Nếu combo_repo available: dùng SQLite (single source of truth).
    Ngược lại: fallback sang JSON state files.
    """
    if combo_repo is not None:
        used = available = terminal = 0
        for combo in pool:
            row = combo_repo.get_by_email(combo.email)
            if row is None:
                available += 1
                continue
            if row.get("used_for_signup"):
                used += 1
                continue
            last_error = row.get("last_error") or ""
            if last_error and any(err in last_error for err in _TERMINAL_ERRORS):
                terminal += 1
                continue
            available += 1
        return {
            "total": len(pool),
            "used_for_signup": used,
            "available": available,
            "terminal_error": terminal,
        }

    # Fallback: JSON state files
    used = available = terminal = unknown = 0
    for combo in pool:
        state = _read_state(state_dir, combo.email)
        if state.get("used_for_signup"):
            used += 1
            continue
        last_error = state.get("last_error", "")
        if last_error and any(err in last_error for err in _TERMINAL_ERRORS):
            terminal += 1
            continue
        if state:
            available += 1
        else:
            unknown += 1
    return {
        "total": len(pool),
        "used_for_signup": used,
        "available": available + unknown,
        "terminal_error": terminal,
    }
