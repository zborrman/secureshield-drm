-- =============================================================================
-- SecureShield DRM — Metabase read-only provisioning
-- =============================================================================
-- This script runs once on first PostgreSQL container start
-- (placed in /docker-entrypoint-initdb.d/).
--
-- Creates:
--   1. metabase_db        — Metabase's own metadata database
--   2. metabase_reader    — read-only role with SELECT on all SecureShield tables
--
-- The metabase_reader credential is what you enter in Metabase's
-- "Add a database" wizard when connecting to the SecureShield data.
-- =============================================================================

-- ── 1. Metabase metadata database ─────────────────────────────────────────────
-- Metabase stores its own questions, dashboards, and users here.
-- It is completely separate from the SecureShield application data.
CREATE DATABASE metabase_db;

-- ── 2. Read-only analytics role ───────────────────────────────────────────────
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'metabase_reader') THEN
        CREATE ROLE metabase_reader WITH LOGIN PASSWORD 'metabase_reader_password';
    END IF;
END
$$;

-- Grant connection to the SecureShield application database
GRANT CONNECT ON DATABASE main_db TO metabase_reader;

-- Grant SELECT on all current and future tables in the public schema
\connect main_db

GRANT USAGE ON SCHEMA public TO metabase_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO metabase_reader;

-- Automatically grant SELECT on tables created in the future
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT ON TABLES TO metabase_reader;

-- ── 3. Helpful comment for operators ──────────────────────────────────────────
COMMENT ON ROLE metabase_reader IS
    'Read-only role for Metabase BI dashboards. '
    'Connect Metabase to main_db using this credential. '
    'Cannot INSERT, UPDATE, DELETE, or DROP.';
