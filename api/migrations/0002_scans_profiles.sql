-- On-demand scans, user profiles, device presence.

ALTER TABLE devices ADD COLUMN IF NOT EXISTS online boolean NOT NULL DEFAULT false;
ALTER TABLE devices ADD COLUMN IF NOT EXISTS sensor_version text NOT NULL DEFAULT '';
ALTER TABLE devices ADD COLUMN IF NOT EXISTS os text NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS scans (
    scan_id        text PRIMARY KEY CHECK (scan_id ~ '^scn_[A-Za-z0-9_]{1,60}$'),
    tenant_id      text NOT NULL REFERENCES tenants,
    device_id      text NOT NULL,
    scope          text NOT NULL CHECK (scope IN ('quick', 'full')),
    state          text NOT NULL CHECK (state IN ('queued', 'running', 'completed', 'cancelled', 'failed')),
    requested_by   text NOT NULL,
    files_seen     bigint NOT NULL DEFAULT 0,
    files_analyzed bigint NOT NULL DEFAULT 0,
    bytes_analyzed bigint NOT NULL DEFAULT 0,
    findings       bigint NOT NULL DEFAULT 0,
    current_path   text NOT NULL DEFAULT '',
    error          text NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    started_at     timestamptz,
    finished_at    timestamptz,
    updated_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS scans_tenant_device ON scans (tenant_id, device_id, created_at DESC);

CREATE TABLE IF NOT EXISTS users (
    tenant_id             text NOT NULL REFERENCES tenants,
    user_id               text NOT NULL,
    display_name          text NOT NULL,
    email                 text NOT NULL DEFAULT '',
    notify_desktop        boolean NOT NULL DEFAULT true,
    notify_email_critical boolean NOT NULL DEFAULT false,
    updated_at            timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id)
);

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['scans','users'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = t AND policyname = 'tenant_isolation') THEN
            EXECUTE format(
                'CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_setting(''app.tenant_id'', true)) '
                'WITH CHECK (tenant_id = current_setting(''app.tenant_id'', true))', t);
        END IF;
    END LOOP;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'scanu_app') THEN
        GRANT SELECT, INSERT, UPDATE ON scans, users TO scanu_app;
    END IF;
END $$;
