"""Schema definitions — DDL strings và version management cho SQLite persistence layer."""

# Schema version hiện tại. Tăng khi có thay đổi DDL.
CURRENT_VERSION = 13

# --- DDL: Schema version tracking ---

DDL_SCHEMA_VERSION = """\
CREATE TABLE IF NOT EXISTS _schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (datetime('now')),
    description TEXT
);
"""

# --- DDL: Outlook combo state ---

DDL_OUTLOOK_COMBOS = """\
CREATE TABLE IF NOT EXISTS outlook_combos (
    email TEXT PRIMARY KEY,
    password TEXT NOT NULL,
    refresh_token TEXT NOT NULL,
    client_id TEXT NOT NULL,
    used_for_signup INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    last_failed_at TEXT,
    used_at TEXT,
    last_refresh_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

# --- DDL: Jobs (web UI) ---

DDL_JOBS = """\
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    combo TEXT NOT NULL,
    mail_mode TEXT NOT NULL DEFAULT 'outlook',
    status TEXT NOT NULL DEFAULT 'queued'
        CHECK(status IN ('queued', 'running', 'success', 'error', 'cancelled')),
    error TEXT,
    password TEXT,
    secret TEXT,
    first_code TEXT,
    user_id TEXT,
    session_path TEXT,
    payment_link TEXT,
    session_data TEXT,
    account_check TEXT,
    region TEXT,
    mail_account_id TEXT,
    created_at REAL NOT NULL,
    started_at REAL,
    finished_at REAL,
    job_type TEXT NOT NULL DEFAULT 'signup'
);
"""

DDL_JOBS_INDEXES = """\
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_email ON jobs(email);
"""

# --- DDL: Job logs ---

DDL_JOB_LOGS = """\
CREATE TABLE IF NOT EXISTS job_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    line TEXT NOT NULL,
    created_at REAL NOT NULL DEFAULT (unixepoch('subsec'))
);
"""

DDL_JOB_LOGS_INDEXES = """\
CREATE INDEX IF NOT EXISTS idx_job_logs_job_id ON job_logs(job_id);
"""

# --- DDL: Session results ---

DDL_SESSION_RESULTS = """\
CREATE TABLE IF NOT EXISTS session_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    password TEXT,
    name TEXT,
    age INTEGER,
    user_id TEXT,
    account_id TEXT,
    session_token TEXT,
    access_token TEXT,
    cookies TEXT,
    two_factor TEXT,
    mfa_pending TEXT,
    phase1_seconds REAL,
    phase2_seconds REAL,
    otp_seconds REAL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

DDL_SESSION_RESULTS_INDEXES = """\
CREATE INDEX IF NOT EXISTS idx_session_results_email ON session_results(email);
"""

# --- DDL: iCloud Hide My Email — accounts pool ---

DDL_ICLOUD_ACCOUNTS = """\
CREATE TABLE IF NOT EXISTS icloud_accounts (
    apple_id TEXT PRIMARY KEY,
    profile_dir TEXT,
    hme_count INTEGER NOT NULL DEFAULT 0,
    disabled INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    last_used_at TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    status TEXT NOT NULL DEFAULT 'active',
    limited_until TEXT,
    quota_retry_until TEXT
);
"""

# --- DDL: iCloud HME — generated emails (v6) ---
# CHECK enum mở rộng: 7 trạng thái lifecycle (R8.1, R9.x).
# 4 cột timestamp lifecycle mới: deactivated_at / reactivated_at / deleted_at / last_sync_at.
# Default timestamp dùng strftime ISO 8601 UTC với millisecond + suffix Z (Timestamp_Format, P30).

DDL_ICLOUD_EMAILS = """\
CREATE TABLE IF NOT EXISTS icloud_emails (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    apple_id TEXT NOT NULL REFERENCES icloud_accounts(apple_id),
    label TEXT,
    note TEXT,
    hme_id TEXT,
    status TEXT NOT NULL DEFAULT 'created'
        CHECK(status IN ('created','reconciled','deactivated','revoked',
                          'deleted','disabled','used_for_chatgpt')),
    used_for_email TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    used_at TEXT,
    deactivated_at TEXT,
    reactivated_at TEXT,
    deleted_at TEXT,
    last_sync_at TEXT
);
"""

DDL_ICLOUD_EMAILS_INDEXES = """\
CREATE INDEX IF NOT EXISTS idx_icloud_emails_status ON icloud_emails(status);
CREATE INDEX IF NOT EXISTS idx_icloud_emails_apple_id ON icloud_emails(apple_id);
CREATE INDEX IF NOT EXISTS idx_icloud_emails_label ON icloud_emails(label);
CREATE INDEX IF NOT EXISTS idx_icloud_emails_last_sync_at ON icloud_emails(last_sync_at);
"""

# --- DDL: iCloud HME — audit log (v6, R6.1, R6.2) ---
# event_type cố tình KHÔNG có CHECK — set giá trị quá lớn (35+ event), giữ enum
# trong code (Audit_Log Repository) làm single source. timestamp_iso dùng strftime
# format ISO 8601 UTC với millisecond + suffix Z (Timestamp_Format, Property 30).

DDL_ICLOUD_AUDIT_LOG = """\
CREATE TABLE IF NOT EXISTS icloud_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_iso TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    event_type TEXT NOT NULL,
    apple_id TEXT,
    payload_json TEXT NOT NULL DEFAULT '{}',
    error TEXT
);
"""

DDL_ICLOUD_AUDIT_LOG_INDEXES = """\
CREATE INDEX IF NOT EXISTS idx_icloud_audit_log_apple_id_ts
    ON icloud_audit_log(apple_id, timestamp_iso DESC);
CREATE INDEX IF NOT EXISTS idx_icloud_audit_log_event_type_ts
    ON icloud_audit_log(event_type, timestamp_iso DESC);
"""

# --- DDL: iCloud HME — pool_state (v6, R7.3) ---
# Persistent key/value store. Giá trị đầu tiên: key='round_robin_cursor' → apple_id
# được pick gần nhất (Pool_Manager round-robin coverage, Property 2 / R2.3).

DDL_POOL_STATE = """\
CREATE TABLE IF NOT EXISTS pool_state (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

# --- DDL: iCloud HME — jobs (v6, R13.1, R13.2, R13.3) ---
# Bảng riêng cho HME job lifecycle (tách khỏi `jobs` cũ vì schema + lifecycle
# 6-state khác hotmail flow 5-state). PK = uuid4 string.

DDL_ICLOUD_JOBS = """\
CREATE TABLE IF NOT EXISTS icloud_jobs (
    job_id TEXT PRIMARY KEY,
    kind TEXT NOT NULL CHECK(kind IN (
        'generate','deactivate_bulk','reactivate_bulk','delete_bulk',
        'list_sync','bootstrap','check_all','update_meta_bulk','export'
    )),
    status TEXT NOT NULL DEFAULT 'queued' CHECK(status IN (
        'queued','running','paused','completed','failed','cancelled'
    )),
    progress_done INTEGER NOT NULL DEFAULT 0,
    progress_total INTEGER NOT NULL DEFAULT 0,
    params_json TEXT NOT NULL DEFAULT '{}',
    result_json TEXT,
    apple_id_filter TEXT,
    label_filter TEXT,
    parent_job_id TEXT,
    started_at TEXT,
    ended_at TEXT,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
"""

DDL_ICLOUD_JOBS_INDEXES = """\
CREATE INDEX IF NOT EXISTS idx_icloud_jobs_status_updated
    ON icloud_jobs(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_icloud_jobs_kind_status
    ON icloud_jobs(kind, status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_icloud_jobs_apple_id
    ON icloud_jobs(apple_id_filter, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_icloud_jobs_label
    ON icloud_jobs(label_filter, updated_at DESC);
"""

# --- DDL: ChatGPT accounts (v9) ---

DDL_CHATGPT_ACCOUNTS = """\
CREATE TABLE IF NOT EXISTS chatgpt_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    secret_2fa TEXT,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
"""

DDL_CHATGPT_ACCOUNTS_INDEXES = """\
CREATE INDEX IF NOT EXISTS idx_chatgpt_accounts_email ON chatgpt_accounts(email);
"""

# --- DDL: Settings key-value store (v10) ---

DDL_SETTINGS = """\
CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL UNIQUE,
    value TEXT,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
"""

DDL_SETTINGS_INDEXES = """\
CREATE INDEX IF NOT EXISTS idx_settings_key ON settings(key);
"""

# --- Ordered list tất cả DDL statements cho migration ---

ALL_DDL: list[str] = [
    DDL_SCHEMA_VERSION,
    DDL_OUTLOOK_COMBOS,
    DDL_JOBS,
    DDL_JOBS_INDEXES,
    DDL_JOB_LOGS,
    DDL_JOB_LOGS_INDEXES,
    DDL_SESSION_RESULTS,
    DDL_SESSION_RESULTS_INDEXES,
    DDL_ICLOUD_ACCOUNTS,
    DDL_ICLOUD_EMAILS,
    DDL_ICLOUD_EMAILS_INDEXES,
    # --- v6: iCloud HME pool extension ---
    DDL_ICLOUD_AUDIT_LOG,
    DDL_ICLOUD_AUDIT_LOG_INDEXES,
    DDL_POOL_STATE,
    # NOTE: DDL_ICLOUD_JOBS / DDL_ICLOUD_JOBS_INDEXES cố tình KHÔNG nằm trong ALL_DDL
    # sau v7 (icloud-runner-loop spec, R12.4). Constants vẫn giữ định nghĩa vì
    # MIGRATIONS[6] còn reference (cần tạo bảng để DB v5 pass qua v6 trước khi v7
    # drop). DB mới khởi tạo từ ALL_DDL → không có bảng icloud_jobs → v7 DROP IF
    # EXISTS chạy no-op an toàn (R12.6).
    # --- v9: ChatGPT accounts ---
    DDL_CHATGPT_ACCOUNTS,
    DDL_CHATGPT_ACCOUNTS_INDEXES,
    # --- v10: Settings key-value store ---
    DDL_SETTINGS,
    DDL_SETTINGS_INDEXES,
]
"""Danh sách DDL theo thứ tự thực thi. Engine sẽ chạy lần lượt trong 1 transaction."""

# --- Incremental migrations (version → SQL list) ---
# Dùng khi DB đã tồn tại ở version cũ. CREATE TABLE IF NOT EXISTS sẽ skip
# existing tables, nhưng ALTER TABLE ADD COLUMN cần chạy riêng.

MIGRATIONS: dict[int, list[str]] = {
    2: [
        "ALTER TABLE jobs ADD COLUMN session_data TEXT;",
    ],
    # v3: gỡ CHECK constraint trên mail_mode để cho phép giá trị mới (vd 'dongvanfb')
    # mà không phải sửa schema mỗi lần thêm provider. Application validate qua
    # mail_modes registry — schema không cần biết enum.
    # SQLite không hỗ trợ ALTER TABLE DROP CONSTRAINT → phải rebuild table.
    # Pattern: backup logs → drop+rebuild jobs → restore logs.
    # Note: PRAGMA legacy_alter_table không hoạt động trong transaction. Cách an toàn
    # nhất là rebuild jobs table + đồng thời rebuild job_logs để FK mới trỏ đúng.
    3: [
        # 1. Backup job_logs (không có FK ràng buộc)
        """CREATE TABLE job_logs_backup AS SELECT * FROM job_logs;""",
        # 2. Drop job_logs (để có thể drop jobs mà không vướng FK)
        "DROP TABLE job_logs;",
        # 3. Tạo bảng jobs mới (no CHECK trên mail_mode)
        """CREATE TABLE jobs_new (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL,
            combo TEXT NOT NULL,
            mail_mode TEXT NOT NULL DEFAULT 'outlook',
            status TEXT NOT NULL DEFAULT 'queued'
                CHECK(status IN ('queued', 'running', 'success', 'error', 'cancelled')),
            error TEXT,
            password TEXT,
            secret TEXT,
            first_code TEXT,
            user_id TEXT,
            session_path TEXT,
            payment_link TEXT,
            session_data TEXT,
            created_at REAL NOT NULL,
            started_at REAL,
            finished_at REAL,
            job_type TEXT NOT NULL DEFAULT 'signup'
        );""",
        # 4. Copy data jobs cũ qua bảng mới
        """INSERT INTO jobs_new SELECT
            id, email, combo, mail_mode, status, error, password, secret, first_code,
            user_id, session_path, payment_link, session_data, created_at, started_at,
            finished_at, job_type
        FROM jobs;""",
        # 5. Drop bảng jobs cũ + rename bảng mới
        "DROP TABLE jobs;",
        "ALTER TABLE jobs_new RENAME TO jobs;",
        # 6. Re-create job_logs với FK trỏ tới jobs mới
        """CREATE TABLE job_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
            line TEXT NOT NULL,
            created_at REAL NOT NULL DEFAULT (unixepoch('subsec'))
        );""",
        # 7. Restore logs từ backup
        """INSERT INTO job_logs (id, job_id, line, created_at)
           SELECT id, job_id, line, created_at FROM job_logs_backup;""",
        # 8. Drop backup
        "DROP TABLE job_logs_backup;",
        # 9. Re-create indexes
        "CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);",
        "CREATE INDEX IF NOT EXISTS idx_jobs_email ON jobs(email);",
        "CREATE INDEX IF NOT EXISTS idx_job_logs_job_id ON job_logs(job_id);",
    ],
    # v4: thêm cột region để lưu region per-job (tab Reg + tab Link).
    # NULL = legacy job hoặc Reg job không bật post_reg_get_link với region cụ thể.
    4: [
        "ALTER TABLE jobs ADD COLUMN region TEXT;",
    ],
    # v5: iCloud Hide My Email pool — 2 bảng mới.
    # MIGRATIONS[v] PHẢI self-contained — KHÔNG phụ thuộc ALL_DDL chạy trước.
    # CREATE TABLE IF NOT EXISTS đảm bảo idempotent (nếu DDL pass đầu đã tạo, skip).
    5: [
        # icloud_accounts (v5 schema — KHÔNG có status / limited_until / quota_retry_until,
        # những cột này được thêm ở MIGRATIONS[6]).
        "CREATE TABLE IF NOT EXISTS icloud_accounts (\n"
        "    apple_id TEXT PRIMARY KEY,\n"
        "    profile_dir TEXT NOT NULL,\n"
        "    hme_count INTEGER NOT NULL DEFAULT 0,\n"
        "    disabled INTEGER NOT NULL DEFAULT 0,\n"
        "    last_error TEXT,\n"
        "    last_used_at TEXT,\n"
        "    created_at TEXT NOT NULL DEFAULT (datetime('now'))\n"
        ");",
        # icloud_emails (v5 schema — CHECK enum 4 trạng thái cũ, KHÔNG có 4 timestamp
        # lifecycle. Rebuild sang v6 schema thực hiện ở MIGRATIONS[6]).
        "CREATE TABLE IF NOT EXISTS icloud_emails (\n"
        "    id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
        "    email TEXT NOT NULL UNIQUE,\n"
        "    apple_id TEXT NOT NULL REFERENCES icloud_accounts(apple_id),\n"
        "    label TEXT,\n"
        "    note TEXT,\n"
        "    hme_id TEXT,\n"
        "    status TEXT NOT NULL DEFAULT 'created'\n"
        "        CHECK(status IN ('created','used','revoked','disabled')),\n"
        "    used_for_email TEXT,\n"
        "    created_at TEXT NOT NULL DEFAULT (datetime('now')),\n"
        "    used_at TEXT\n"
        ");",
        "CREATE INDEX IF NOT EXISTS idx_icloud_emails_status ON icloud_emails(status);",
        "CREATE INDEX IF NOT EXISTS idx_icloud_emails_apple_id ON icloud_emails(apple_id);",
    ],
    # v6: iCloud HME pool extension — full lifecycle + audit + jobs (R6.1, R7.3, R13.1).
    #
    # Sequence:
    #   1. icloud_accounts: ADD COLUMN status / limited_until / quota_retry_until
    #      + backfill UPDATE từ disabled=1 sang status='disabled'.
    #   2. icloud_emails: rebuild bảng để mở rộng CHECK enum + thêm 4 cột timestamp
    #      lifecycle (deactivated_at, reactivated_at, deleted_at, last_sync_at).
    #      SQLite không hỗ trợ ALTER CHECK → phải rebuild qua pattern <table>_new.
    #      → THÊM Ở TASK 3.2 (xem tasks.md task 3.2).
    #   3. CREATE 3 bảng mới (icloud_audit_log, pool_state, icloud_jobs) + index.
    #
    # _migrate() execute từng phần tử qua conn.execute(stmt) (single-statement only),
    # nên multi-CREATE INDEX block phải tách thành từng statement riêng ở đây.
    # DDL_*_INDEXES dạng string vẫn giữ multi-statement vì ALL_DDL đi qua _split_statements().
    6: [
        # --- icloud_accounts: thêm enum status + 2 timestamp TTL ---
        "ALTER TABLE icloud_accounts ADD COLUMN status TEXT NOT NULL DEFAULT 'active';",
        "ALTER TABLE icloud_accounts ADD COLUMN limited_until TEXT;",
        "ALTER TABLE icloud_accounts ADD COLUMN quota_retry_until TEXT;",
        # Backfill: row có disabled=1 → status='disabled' (giữ disabled cho backward compat)
        "UPDATE icloud_accounts SET status='disabled' WHERE disabled=1 AND status='active';",

        # --- icloud_emails rebuild (CHECK enum + 4 timestamp lifecycle): TASK 3.2 ---
        # SQLite không hỗ trợ ALTER CHECK constraint (chỉ ADD/RENAME COLUMN, không
        # đổi được CHECK). Phải rebuild bảng theo pattern <table>_new (giống v3 jobs):
        #   CREATE icloud_emails_new → INSERT SELECT (map cột) → DROP cũ → RENAME → recreate index.
        #
        # Mapping data v5 → v6:
        #   - id, email, apple_id, label, note, hme_id, used_for_email, created_at, used_at:
        #     copy nguyên (cùng kiểu, cùng semantics).
        #   - status: enum v5 ('created','used','revoked','disabled') → enum v6
        #     ('created','reconciled','deactivated','revoked','deleted','disabled','used_for_chatgpt').
        #     Giá trị cũ 'used' KHÔNG còn trong enum v6 → map 'used' → 'used_for_chatgpt'
        #     (theo bảng Action→Status, R9.19: mark_used = DB-only, lifecycle terminal cho
        #     ChatGPT signup). Các giá trị 'created','revoked','disabled' giữ nguyên.
        #   - 4 cột mới (deactivated_at, reactivated_at, deleted_at, last_sync_at) = NULL
        #     cho row legacy (v5 không track lifecycle Apple-side timestamp).
        #   - revoked_at cũ: v5 schema KHÔNG có cột này (chỉ có used_at) → không INSERT cột nguồn.
        #     Nếu instance nào có cột revoked_at do migration thủ công, hỗ trợ qua subquery
        #     ngoài là không khả thi vì SELECT ngoài table sẽ raise no such column. Giữ
        #     NULL cho deactivated_at là an toàn theo hiện trạng v5 chính thức của repo.
        "CREATE TABLE icloud_emails_new (\n"
        "    id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
        "    email TEXT NOT NULL UNIQUE,\n"
        "    apple_id TEXT NOT NULL REFERENCES icloud_accounts(apple_id),\n"
        "    label TEXT,\n"
        "    note TEXT,\n"
        "    hme_id TEXT,\n"
        "    status TEXT NOT NULL DEFAULT 'created'\n"
        "        CHECK(status IN ('created','reconciled','deactivated','revoked',\n"
        "                          'deleted','disabled','used_for_chatgpt')),\n"
        "    used_for_email TEXT,\n"
        "    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),\n"
        "    used_at TEXT,\n"
        "    deactivated_at TEXT,\n"
        "    reactivated_at TEXT,\n"
        "    deleted_at TEXT,\n"
        "    last_sync_at TEXT\n"
        ");",
        # Copy data: map status 'used' → 'used_for_chatgpt'; các status khác giữ nguyên.
        # 4 cột timestamp lifecycle mới = NULL cho row legacy.
        "INSERT INTO icloud_emails_new ("
        "id, email, apple_id, label, note, hme_id, status, "
        "used_for_email, created_at, used_at"
        ") SELECT "
        "id, email, apple_id, label, note, hme_id, "
        "CASE status WHEN 'used' THEN 'used_for_chatgpt' ELSE status END, "
        "used_for_email, created_at, used_at "
        "FROM icloud_emails;",
        "DROP TABLE icloud_emails;",
        "ALTER TABLE icloud_emails_new RENAME TO icloud_emails;",
        # Recreate index: 2 cũ (status, apple_id) + 2 mới (label, last_sync_at).
        "CREATE INDEX IF NOT EXISTS idx_icloud_emails_status ON icloud_emails(status);",
        "CREATE INDEX IF NOT EXISTS idx_icloud_emails_apple_id ON icloud_emails(apple_id);",
        "CREATE INDEX IF NOT EXISTS idx_icloud_emails_label ON icloud_emails(label);",
        "CREATE INDEX IF NOT EXISTS idx_icloud_emails_last_sync_at "
        "ON icloud_emails(last_sync_at);",

        # --- icloud_audit_log: bảng + 2 index (apple_id|event_type, timestamp_iso DESC) ---
        DDL_ICLOUD_AUDIT_LOG,
        "CREATE INDEX IF NOT EXISTS idx_icloud_audit_log_apple_id_ts "
        "ON icloud_audit_log(apple_id, timestamp_iso DESC);",
        "CREATE INDEX IF NOT EXISTS idx_icloud_audit_log_event_type_ts "
        "ON icloud_audit_log(event_type, timestamp_iso DESC);",

        # --- pool_state: key/value persistent store cho round-robin cursor ---
        DDL_POOL_STATE,

        # --- icloud_jobs: bảng + 4 index (status / kind+status / apple_id_filter / label_filter) ---
        DDL_ICLOUD_JOBS,
        "CREATE INDEX IF NOT EXISTS idx_icloud_jobs_status_updated "
        "ON icloud_jobs(status, updated_at DESC);",
        "CREATE INDEX IF NOT EXISTS idx_icloud_jobs_kind_status "
        "ON icloud_jobs(kind, status, updated_at DESC);",
        "CREATE INDEX IF NOT EXISTS idx_icloud_jobs_apple_id "
        "ON icloud_jobs(apple_id_filter, updated_at DESC);",
        "CREATE INDEX IF NOT EXISTS idx_icloud_jobs_label "
        "ON icloud_jobs(label_filter, updated_at DESC);",
    ],
    # v7: Job layer removal — drop bảng icloud_jobs sau khi refactor sang HmeRunner
    # (icloud-runner-loop spec, R12.1–12.6).
    #
    # Idempotent với mọi DB state:
    #   - DB ở v6 đã có bảng icloud_jobs (có data) → DROP TABLE thực hiện thành công.
    #   - DB mới khởi tạo từ ALL_DDL hiện hành (không có DDL_ICLOUD_JOBS) → bảng không
    #     tồn tại → IF EXISTS no-op an toàn.
    #
    # MIGRATIONS[6] giữ nguyên (kể cả DDL_ICLOUD_JOBS bên trong) để DB version ≤ 5
    # vẫn pass qua step 6 (tạo bảng) trước khi v7 drop nó. Upgrade path v5 → v7:
    #   v5 → v6 (tạo icloud_jobs) → v7 (drop icloud_jobs).
    7: [
        "DROP TABLE IF EXISTS icloud_jobs;",
    ],
    # v8: ``mfa_pending`` cho session_results — persist enrollment state sau
    # khi /mfa/enroll OK nhưng activate chưa OK. Cho phép retry-2fa tái dùng
    # secret thay vì enroll lại (server đã có active factor → conflict loop).
    # Format JSON: {"secret": "...", "factor_id": "...", "session_id": "...",
    #               "status": "enrolled"}.
    # Sau khi activate OK → repository.clear_mfa_pending() set NULL.
    8: [
        "ALTER TABLE session_results ADD COLUMN mfa_pending TEXT;",
    ],
    # v9: ChatGPT accounts — bảng lưu tài khoản ChatGPT đã đăng ký thành công
    # qua AutoRegRunner (auto-reg-gpt spec, R5.1–R5.3).
    9: [
        "CREATE TABLE IF NOT EXISTS chatgpt_accounts (\n"
        "    id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
        "    email TEXT NOT NULL UNIQUE,\n"
        "    password TEXT NOT NULL,\n"
        "    secret_2fa TEXT,\n"
        "    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))\n"
        ");",
        "CREATE INDEX IF NOT EXISTS idx_chatgpt_accounts_email ON chatgpt_accounts(email);",
    ],
    # v10: Settings key-value store — unified runtime configuration
    # (unified-settings-store spec, R1.1–R1.5).
    10: [
        "CREATE TABLE IF NOT EXISTS settings (\n"
        "    id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
        "    key TEXT NOT NULL UNIQUE,\n"
        "    value TEXT,\n"
        "    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))\n"
        ");",
        "CREATE INDEX IF NOT EXISTS idx_settings_key ON settings(key);",
    ],
    # v11: icloud_accounts — bỏ NOT NULL trên profile_dir.
    #
    # delete_profile() (R5) cần SET profile_dir=NULL khi status='deleted'.
    # DDL latest (ALL_DDL) đã đúng (TEXT nullable) nhưng DB đi qua migration v5
    # vẫn giữ NOT NULL → IntegrityError khi delete. SQLite không hỗ trợ
    # ALTER COLUMN DROP NOT NULL → rebuild table.
    #
    # Pattern: backup → create new (nullable) → copy data → drop old → rename.
    # Giữ mọi cột, index, data nguyên vẹn. FK từ icloud_emails → apple_id vẫn OK
    # vì SQLite FK check dựa trên row tồn tại (không validate nullable schema).
    11: [
        # 1. Tạo bảng mới với profile_dir nullable (khớp DDL_ICLOUD_ACCOUNTS latest)
        "CREATE TABLE icloud_accounts_new (\n"
        "    apple_id TEXT PRIMARY KEY,\n"
        "    profile_dir TEXT,\n"
        "    hme_count INTEGER NOT NULL DEFAULT 0,\n"
        "    disabled INTEGER NOT NULL DEFAULT 0,\n"
        "    last_error TEXT,\n"
        "    last_used_at TEXT,\n"
        "    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),\n"
        "    status TEXT NOT NULL DEFAULT 'active',\n"
        "    limited_until TEXT,\n"
        "    quota_retry_until TEXT\n"
        ");",
        # 2. Copy toàn bộ data
        "INSERT INTO icloud_accounts_new "
        "(apple_id, profile_dir, hme_count, disabled, last_error, "
        "last_used_at, created_at, status, limited_until, quota_retry_until) "
        "SELECT apple_id, profile_dir, hme_count, disabled, last_error, "
        "last_used_at, created_at, status, limited_until, quota_retry_until "
        "FROM icloud_accounts;",
        # 3. Drop bảng cũ
        "DROP TABLE icloud_accounts;",
        # 4. Rename
        "ALTER TABLE icloud_accounts_new RENAME TO icloud_accounts;",
    ],
    # v12: persist Get Session account/offer classification separately from the
    # raw /api/auth/session payload. This keeps downloaded session JSON clean
    # while preserving the Plus/free-offer result across process restarts.
    12: [
        "ALTER TABLE jobs ADD COLUMN account_check TEXT;",
    ],
    # v13: persist the iCloud IMAP account selected for each signup job so
    # recovery/retry/readmail keep using the original mailbox.
    13: [
        "ALTER TABLE jobs ADD COLUMN mail_account_id TEXT;",
    ],
}
