-- ============================================================================
-- PHARE 2.0 - SUPABASE / POSTGRESQL PRODUCTION SECURE SCHEMA (IDEMPOTENT)
-- ============================================================================

-- 1. USERS TABLE
CREATE TABLE IF NOT EXISTS users (
    email VARCHAR(255) PRIMARY KEY,
    password_hash VARCHAR(255) NOT NULL,
    salt VARCHAR(255) NOT NULL,
    iterations INT NOT NULL DEFAULT 100000,
    role VARCHAR(50) NOT NULL,
    site VARCHAR(50) NOT NULL,
    agent_id VARCHAR(255)
);

-- 2. SESSIONS TABLE
CREATE TABLE IF NOT EXISTS sessions (
    token_hash VARCHAR(255) PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL,
    site VARCHAR(50) NOT NULL,
    expires_at DOUBLE PRECISION NOT NULL,
    supervisor_pin_validated_at DOUBLE PRECISION DEFAULT 0
);

-- 3. AGENTS TABLE
CREATE TABLE IF NOT EXISTS agents (
    id VARCHAR(255) PRIMARY KEY,
    full_name VARCHAR(255),
    role VARCHAR(50),
    status VARCHAR(50),
    battery_level INT,
    latitude DOUBLE PRECISION,
    longitude DOUBLE PRECISION,
    precision DOUBLE PRECISION,
    last_connection BIGINT,
    site_category VARCHAR(50)
);

-- 4. EVENTS TABLE (PTI Alerts, Acks, etc.)
CREATE TABLE IF NOT EXISTS events (
    id VARCHAR(255) PRIMARY KEY,
    agent_id VARCHAR(255),
    type VARCHAR(100),
    timestamp BIGINT,
    payload TEXT,
    site_category VARCHAR(50)
);
CREATE INDEX IF NOT EXISTS idx_events_agent_id ON events(agent_id);
CREATE INDEX IF NOT EXISTS idx_events_site_category ON events(site_category);

-- 5. MAIN COURANTE TABLE
CREATE TABLE IF NOT EXISTS main_courante (
    entry_id VARCHAR(255) PRIMARY KEY,
    site_category VARCHAR(50),
    agent_name VARCHAR(255),
    event_type VARCHAR(100),
    content TEXT,
    attachments TEXT,
    created_by VARCHAR(255),
    server_received_at BIGINT,
    status VARCHAR(50),
    agent_signed BOOLEAN,
    agent_signed_by VARCHAR(255),
    agent_signed_at BIGINT,
    chef_de_poste_signed BOOLEAN,
    chef_de_poste_signed_by VARCHAR(255),
    chef_de_poste_signed_at BIGINT,
    hdc_signed BOOLEAN,
    hdc_signed_by VARCHAR(255),
    hdc_signed_at BIGINT,
    gph_signed BOOLEAN,
    gph_signed_by VARCHAR(255),
    gph_signed_at BIGINT
);
CREATE INDEX IF NOT EXISTS idx_main_courante_site ON main_courante(site_category);

-- 6. ROUNDS TABLE
CREATE TABLE IF NOT EXISTS rounds (
    round_id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255),
    description TEXT,
    active BOOLEAN,
    configuration_version INT,
    points TEXT,
    created_at BIGINT,
    updated_at BIGINT
);

-- 7. MEDIA CATEGORIES TABLE
CREATE TABLE IF NOT EXISTS media_categories (
    filename VARCHAR(255) PRIMARY KEY,
    site_category VARCHAR(50)
);

-- 8. KV STORE TABLE (Supervisor Auth, etc.)
CREATE TABLE IF NOT EXISTS kv_store (
    key VARCHAR(255) PRIMARY KEY,
    value TEXT
);

-- 9. AUDIT LOGS TABLE (Durable DB Audit Trail)
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ DEFAULT NOW(),
    action VARCHAR(100) NOT NULL,
    email VARCHAR(255),
    ip VARCHAR(50),
    details TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);

-- ============================================================================
-- POSTGRESQL ROW LEVEL SECURITY (RLS) & LEAST PRIVILEGE STRATEGY
-- ============================================================================
-- Enable RLS on ALL NINE sensitive tables to block direct public/anon Supabase Data API access
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
ALTER TABLE main_courante ENABLE ROW LEVEL SECURITY;
ALTER TABLE rounds ENABLE ROW LEVEL SECURITY;
ALTER TABLE media_categories ENABLE ROW LEVEL SECURITY;
ALTER TABLE kv_store ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY;

-- Revoke all default privileges from public, anon, and authenticated roles
REVOKE ALL ON users FROM PUBLIC, anon, authenticated;
REVOKE ALL ON sessions FROM PUBLIC, anon, authenticated;
REVOKE ALL ON agents FROM PUBLIC, anon, authenticated;
REVOKE ALL ON events FROM PUBLIC, anon, authenticated;
REVOKE ALL ON main_courante FROM PUBLIC, anon, authenticated;
REVOKE ALL ON rounds FROM PUBLIC, anon, authenticated;
REVOKE ALL ON media_categories FROM PUBLIC, anon, authenticated;
REVOKE ALL ON kv_store FROM PUBLIC, anon, authenticated;
REVOKE ALL ON audit_logs FROM PUBLIC, anon, authenticated;

-- Create policies denying public/anon direct access across all nine tables
DROP POLICY IF EXISTS deny_all_users ON users;
CREATE POLICY deny_all_users ON users FOR ALL USING (false);

DROP POLICY IF EXISTS deny_all_sessions ON sessions;
CREATE POLICY deny_all_sessions ON sessions FOR ALL USING (false);

DROP POLICY IF EXISTS deny_all_agents ON agents;
CREATE POLICY deny_all_agents ON agents FOR ALL USING (false);

DROP POLICY IF EXISTS deny_all_events ON events;
CREATE POLICY deny_all_events ON events FOR ALL USING (false);

DROP POLICY IF EXISTS deny_all_main_courante ON main_courante;
CREATE POLICY deny_all_main_courante ON main_courante FOR ALL USING (false);

DROP POLICY IF EXISTS deny_all_rounds ON rounds;
CREATE POLICY deny_all_rounds ON rounds FOR ALL USING (false);

DROP POLICY IF EXISTS deny_all_media_categories ON media_categories;
CREATE POLICY deny_all_media_categories ON media_categories FOR ALL USING (false);

DROP POLICY IF EXISTS deny_all_kv ON kv_store;
CREATE POLICY deny_all_kv ON kv_store FOR ALL USING (false);

DROP POLICY IF EXISTS deny_all_audit ON audit_logs;
CREATE POLICY deny_all_audit ON audit_logs FOR ALL USING (false);
