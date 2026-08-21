"""Migration Tool — Chuyển dữ liệu JSON → SQLite + import pool files.

MigrationTool đọc outlook_state JSON files và session result JSON files,
insert vào SQLite database qua repository layer.
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .engine import DatabaseEngine
    from .repositories import ComboRepository, SessionResultRepository

logger = logging.getLogger(__name__)


@dataclass
class MigrationSummary:
    """Kết quả migration cho 1 entity type."""

    entity_type: str
    total_files: int
    inserted: int
    skipped_duplicate: int
    skipped_error: int
    errors: list[str] = field(default_factory=list)


@dataclass
class ImportSummary:
    """Kết quả import pool file."""

    total_lines: int
    inserted: int
    updated: int
    skipped: int
    errors: list[str] = field(default_factory=list)


class MigrationTool:
    """Chuyển dữ liệu JSON → SQLite + import pool files."""

    def __init__(
        self,
        engine: "DatabaseEngine",
        combo_repo: "ComboRepository",
        session_repo: "SessionResultRepository",
    ) -> None:
        self._engine = engine
        self._combo_repo = combo_repo
        self._session_repo = session_repo

    def migrate_outlook_state(self, state_dir: Path) -> MigrationSummary:
        """Đọc runtime/outlook_state/*.json, insert vào outlook_combos.

        - Email lấy từ filename (strip .json suffix).
        - password: lấy từ JSON content nếu có, ngược lại dùng "".
        - Skip duplicate (email đã tồn tại trong DB).
        - Invalid JSON → log error + skip.
        - Directory không tồn tại → report 0 records.

        Args:
            state_dir: Path tới thư mục outlook_state.

        Returns:
            MigrationSummary cho entity type "outlook_combos".
        """
        summary = MigrationSummary(
            entity_type="outlook_combos",
            total_files=0,
            inserted=0,
            skipped_duplicate=0,
            skipped_error=0,
        )

        if not state_dir.exists() or not state_dir.is_dir():
            logger.warning("outlook_state directory không tồn tại: %s", state_dir)
            return summary

        json_files = sorted(state_dir.glob("*.json"))
        summary.total_files = len(json_files)

        if not json_files:
            return summary

        with self._engine.get_connection() as conn:
            for filepath in json_files:
                email = filepath.stem  # filename without .json

                # Parse JSON content
                try:
                    content = json.loads(filepath.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError) as exc:
                    error_msg = f"{filepath.name}: invalid JSON — {exc}"
                    logger.error(error_msg)
                    summary.errors.append(error_msg)
                    summary.skipped_error += 1
                    continue

                if not isinstance(content, dict):
                    error_msg = f"{filepath.name}: JSON content is not a dict"
                    logger.error(error_msg)
                    summary.errors.append(error_msg)
                    summary.skipped_error += 1
                    continue

                # Check duplicate — email đã tồn tại trong DB
                existing = conn.execute(
                    "SELECT email FROM outlook_combos WHERE email = ?", (email,)
                ).fetchone()
                if existing:
                    logger.warning(
                        "skip duplicate combo: email=%s from file=%s (already exists in DB)",
                        email, filepath.name,
                    )
                    summary.skipped_duplicate += 1
                    continue

                # Extract fields
                refresh_token = content.get("refresh_token", "")
                client_id = content.get("client_id", "")
                password = content.get("password", "")

                # Validate required fields
                if not refresh_token or not client_id:
                    error_msg = (
                        f"{filepath.name}: missing required fields "
                        f"(refresh_token={bool(refresh_token)}, client_id={bool(client_id)})"
                    )
                    logger.error(error_msg)
                    summary.errors.append(error_msg)
                    summary.skipped_error += 1
                    continue

                # Insert vào DB
                conn.execute(
                    """
                    INSERT INTO outlook_combos
                        (email, password, refresh_token, client_id,
                         used_for_signup, last_error, last_failed_at, used_at, last_refresh_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        email,
                        password,
                        refresh_token,
                        client_id,
                        1 if content.get("used_for_signup") else 0,
                        content.get("last_error"),
                        content.get("last_failed_at"),
                        content.get("used_at"),
                        content.get("last_refresh_at"),
                    ),
                )
                summary.inserted += 1

        return summary

    def migrate_sessions(self, sessions_dir: Path) -> MigrationSummary:
        """Đọc runtime/sessions/signup-*.json (exclude *.2fa.json), insert vào session_results.

        - Skip duplicate (email + created_at combination đã tồn tại).
        - Invalid JSON → log error + skip.
        - Directory không tồn tại → report 0 records.

        Args:
            sessions_dir: Path tới thư mục sessions.

        Returns:
            MigrationSummary cho entity type "session_results".
        """
        summary = MigrationSummary(
            entity_type="session_results",
            total_files=0,
            inserted=0,
            skipped_duplicate=0,
            skipped_error=0,
        )

        if not sessions_dir.exists() or not sessions_dir.is_dir():
            logger.warning("sessions directory không tồn tại: %s", sessions_dir)
            return summary

        # Match signup-*.json but exclude *.2fa.json
        json_files = sorted(
            f for f in sessions_dir.glob("signup-*.json")
            if not f.name.endswith(".2fa.json")
        )
        summary.total_files = len(json_files)

        if not json_files:
            return summary

        with self._engine.get_connection() as conn:
            for filepath in json_files:
                # Parse JSON content
                try:
                    content = json.loads(filepath.read_text(encoding="utf-8"))
                except (json.JSONDecodeError, OSError) as exc:
                    error_msg = f"{filepath.name}: invalid JSON — {exc}"
                    logger.error(error_msg)
                    summary.errors.append(error_msg)
                    summary.skipped_error += 1
                    continue

                if not isinstance(content, dict):
                    error_msg = f"{filepath.name}: JSON content is not a dict"
                    logger.error(error_msg)
                    summary.errors.append(error_msg)
                    summary.skipped_error += 1
                    continue

                email = content.get("email")
                if not email:
                    error_msg = f"{filepath.name}: missing 'email' field"
                    logger.error(error_msg)
                    summary.errors.append(error_msg)
                    summary.skipped_error += 1
                    continue

                # Extract created_at from filename: signup-YYYYMMDD-HHMMSS-...
                created_at = self._parse_created_at_from_filename(filepath.name)

                # Check duplicate — email + created_at (normalize: both T and space separators)
                existing = conn.execute(
                    """SELECT id FROM session_results
                    WHERE email = ?
                      AND (created_at = ? OR created_at = ?)""",
                    (email, created_at, created_at.replace("T", " ")),
                ).fetchone()
                if existing:
                    logger.warning(
                        "skip duplicate session: email=%s @ %s from file=%s (already exists in DB)",
                        email, created_at, filepath.name,
                    )
                    summary.skipped_duplicate += 1
                    continue

                # Serialize JSON fields
                cookies_raw = content.get("cookies")
                cookies_json = json.dumps(cookies_raw) if cookies_raw is not None else None

                two_factor_raw = content.get("two_factor")
                two_factor_json = json.dumps(two_factor_raw) if two_factor_raw is not None else None

                # Insert
                conn.execute(
                    """
                    INSERT INTO session_results
                        (email, password, name, age, user_id, account_id,
                         session_token, access_token, cookies, two_factor,
                         phase1_seconds, phase2_seconds, otp_seconds, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        email,
                        content.get("password"),
                        content.get("name"),
                        content.get("age"),
                        content.get("user_id"),
                        content.get("account_id"),
                        content.get("session_token"),
                        content.get("access_token"),
                        cookies_json,
                        two_factor_json,
                        content.get("phase1_seconds"),
                        content.get("phase2_seconds"),
                        content.get("otp_seconds"),
                        created_at,
                    ),
                )
                summary.inserted += 1

        return summary

    def import_pool_file(self, pool_path: Path) -> ImportSummary:
        """Import pool file vào outlook_combos table.

        Format per line: email|password|refresh_token|client_id
        - Skip blank lines và lines bắt đầu bằng '#'
        - Upsert: existing email → preserve used_for_signup, used_at, last_error,
          last_failed_at; overwrite password, refresh_token, client_id
        - Parse error → print to stderr với line number, continue
        - File không tồn tại → print error to stderr, raise SystemExit(1)
        - All successful upserts trong single transaction

        Args:
            pool_path: Path tới pool file.

        Returns:
            ImportSummary với total_lines, inserted, updated, skipped, errors.

        Raises:
            SystemExit: Nếu file không tồn tại.
        """
        if not pool_path.exists():
            print(f"Error: pool file not found: {pool_path}", file=sys.stderr)
            raise SystemExit(1)

        # Check file readability
        try:
            lines = pool_path.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            print(f"Error: cannot read pool file: {pool_path}: {exc}", file=sys.stderr)
            raise SystemExit(1)

        summary = ImportSummary(
            total_lines=0,
            inserted=0,
            updated=0,
            skipped=0,
        )

        # Parse all lines first, collect valid entries
        valid_entries: list[tuple[str, str, str, str]] = []  # (email, password, refresh_token, client_id)

        for line_num, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()

            # Skip blank lines and comments
            if not line or line.startswith("#"):
                continue

            summary.total_lines += 1

            # Parse format: email|password|refresh_token|client_id
            parts = line.split("|")
            if len(parts) != 4:
                error_msg = (
                    f"line {line_num}: expected 4 fields (email|password|refresh_token|client_id), "
                    f"got {len(parts)}"
                )
                print(error_msg, file=sys.stderr)
                summary.errors.append(error_msg)
                summary.skipped += 1
                continue

            email, password, refresh_token, client_id = (p.strip() for p in parts)

            # Validate: all fields must be non-empty
            if not email or not password or not refresh_token or not client_id:
                empty_fields = []
                if not email:
                    empty_fields.append("email")
                if not password:
                    empty_fields.append("password")
                if not refresh_token:
                    empty_fields.append("refresh_token")
                if not client_id:
                    empty_fields.append("client_id")
                error_msg = f"line {line_num}: empty field(s): {', '.join(empty_fields)}"
                print(error_msg, file=sys.stderr)
                summary.errors.append(error_msg)
                summary.skipped += 1
                continue

            # Validate refresh_token prefix (Microsoft format: M.C...)
            if not refresh_token.startswith("M.C"):
                error_msg = (
                    f"line {line_num}: refresh_token must start with 'M.C' "
                    f"(got: {refresh_token[:10]!r}...)"
                )
                print(error_msg, file=sys.stderr)
                summary.errors.append(error_msg)
                summary.skipped += 1
                continue

            valid_entries.append((email, password, refresh_token, client_id))

        # Upsert all valid entries in a single transaction
        if valid_entries:
            with self._engine.get_connection() as conn:
                for email, password, refresh_token, client_id in valid_entries:
                    # Check if email exists to distinguish insert vs update
                    existing = conn.execute(
                        "SELECT email FROM outlook_combos WHERE email = ?",
                        (email,),
                    ).fetchone()

                    conn.execute(
                        """
                        INSERT INTO outlook_combos (email, password, refresh_token, client_id)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(email) DO UPDATE SET
                            password = excluded.password,
                            refresh_token = excluded.refresh_token,
                            client_id = excluded.client_id
                        """,
                        (email, password, refresh_token, client_id),
                    )

                    if existing:
                        summary.updated += 1
                    else:
                        summary.inserted += 1

        return summary

    @staticmethod
    def _parse_created_at_from_filename(filename: str) -> str:
        """Parse timestamp từ filename format: signup-YYYYMMDD-HHMMSS-<email>.json.

        Returns ISO 8601 string: YYYY-MM-DDTHH:MM:SS.
        Nếu parse fail → dùng filename as-is (fallback).
        """
        # filename: signup-20260520-213236-pmexzwe2616_at_hotmail.com.json
        parts = filename.split("-", 3)  # ['signup', '20260520', '213236', 'rest...']
        if len(parts) >= 3:
            date_str = parts[1]  # 20260520
            time_str = parts[2]  # 213236
            if len(date_str) == 8 and len(time_str) == 6:
                try:
                    formatted = (
                        f"{date_str[:4]}-{date_str[4:6]}-{date_str[6:8]}"
                        f"T{time_str[:2]}:{time_str[2:4]}:{time_str[4:6]}"
                    )
                    return formatted
                except (IndexError, ValueError):
                    pass
        # Fallback: return filename without extension
        return filename.replace(".json", "")
