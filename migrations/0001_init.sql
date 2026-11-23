-- Smart Door Access Backend Schema (SQLite WAL, Lock -> Adapter Layered Abstraction)

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    sso_subject TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    groups_json TEXT NOT NULL DEFAULT '[]',
    role TEXT NOT NULL CHECK (role IN ('user', 'admin')) DEFAULT 'user',
    status TEXT NOT NULL CHECK (status IN ('active', 'disabled')) DEFAULT 'active',
    created_at INTEGER NOT NULL,
    last_login_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_devices (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    device_name TEXT NOT NULL,
    sso_sid TEXT,
    refresh_token_hash TEXT NOT NULL,
    refresh_family_id TEXT NOT NULL,
    last_ip TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL CHECK (status IN ('online', 'kicked', 'logged_out', 'expired')) DEFAULT 'online',
    created_at INTEGER NOT NULL,
    last_active_at INTEGER NOT NULL,
    kicked_at INTEGER
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_user_devices_online_unique
    ON user_devices(user_id, device_id)
    WHERE status = 'online';

CREATE INDEX IF NOT EXISTS idx_user_devices_user_status
    ON user_devices(user_id, status, last_active_at);

CREATE INDEX IF NOT EXISTS idx_user_devices_sid
    ON user_devices(user_id, sso_sid)
    WHERE sso_sid IS NOT NULL AND status = 'online';

CREATE INDEX IF NOT EXISTS idx_user_devices_refresh_hash
    ON user_devices(refresh_token_hash);

CREATE TABLE IF NOT EXISTS adapters (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    approval_status TEXT NOT NULL CHECK (approval_status IN ('pending', 'approved', 'rejected', 'revoked')) DEFAULT 'pending',
    online_status TEXT NOT NULL CHECK (online_status IN ('online', 'offline')) DEFAULT 'offline',
    reported_state TEXT NOT NULL CHECK (reported_state IN ('locked', 'unlocked', 'unknown')) DEFAULT 'unknown',
    state_reported_at INTEGER,
    model TEXT NOT NULL DEFAULT '',
    fw_version TEXT NOT NULL DEFAULT '',
    token_hash TEXT NOT NULL,
    pending_token_hash TEXT,
    pending_token_msg_id TEXT,
    token_refresh_interval INTEGER NOT NULL DEFAULT 43200,
    last_seen_at INTEGER,
    approved_by TEXT,
    approved_at INTEGER,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS locks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    adapter_id TEXT UNIQUE REFERENCES adapters(id) ON DELETE SET NULL,
    created_by TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS lock_group_rules (
    lock_id TEXT NOT NULL REFERENCES locks(id) ON DELETE CASCADE,
    authentik_group TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    PRIMARY KEY (lock_id, authentik_group)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    actor_type TEXT NOT NULL CHECK (actor_type IN ('user', 'admin', 'adapter', 'system')),
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    result TEXT NOT NULL CHECK (result IN ('success', 'failed', 'timeout', 'denied')),
    detail_json TEXT NOT NULL DEFAULT '{}',
    ip TEXT NOT NULL DEFAULT '',
    request_id TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at
    ON audit_logs(created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_actor
    ON audit_logs(actor_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_target
    ON audit_logs(target_type, target_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_target_id
    ON audit_logs(target_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_audit_logs_result
    ON audit_logs(result, created_at DESC);

CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY,
    value_json TEXT NOT NULL,
    updated_at INTEGER NOT NULL
);

INSERT OR IGNORE INTO system_config (key, value_json, updated_at) VALUES
    ('unlock_replay_window_sec', '60', 0),
    ('command_timeout_ms', '10000', 0),
    ('max_devices_per_user', '3', 0),
    ('audit_retention_days', '90', 0),
    ('offline_unknown_sec', '300', 0),
    ('state_report_period_sec', '60', 0),
    ('admin_groups', '["locker-admins"]', 0);
