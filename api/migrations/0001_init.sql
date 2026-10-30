-- Scanu API schema. Every tenant table has FORCE ROW LEVEL SECURITY: the app
-- role can only see rows of the tenant set via `SET LOCAL app.tenant_id`.

CREATE TABLE IF NOT EXISTS tenants (
    tenant_id   text PRIMARY KEY CHECK (tenant_id ~ '^[A-Za-z0-9-]{1,64}$'),
    name        text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS api_tokens (
    token_sha256 text PRIMARY KEY,
    tenant_id    text NOT NULL REFERENCES tenants,
    user_id      text NOT NULL,
    role         text NOT NULL CHECK (role IN ('owner', 'analyst', 'viewer'))
);

CREATE TABLE IF NOT EXISTS devices (
    tenant_id   text NOT NULL REFERENCES tenants,
    device_id   text NOT NULL,
    first_seen  timestamptz NOT NULL DEFAULT now(),
    last_seen   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, device_id)
);

CREATE TABLE IF NOT EXISTS alerts (
    alert_id    text PRIMARY KEY,
    tenant_id   text NOT NULL REFERENCES tenants,
    device_id   text NOT NULL,
    severity    text NOT NULL,
    kind        text NOT NULL,
    tier1       text NOT NULL,
    payload     jsonb NOT NULL,
    incident_id text,
    received_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS alerts_tenant_time ON alerts (tenant_id, received_at DESC);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id       text PRIMARY KEY CHECK (incident_id ~ '^inc_[0-9a-f]{32}$'),
    tenant_id         text NOT NULL REFERENCES tenants,
    device_id         text NOT NULL,
    title             text NOT NULL,
    severity          text NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    narrative         text NOT NULL,
    attack_techniques text[] NOT NULL DEFAULT '{}',
    member_entity_ids text[] NOT NULL DEFAULT '{}',
    alert_ids         text[] NOT NULL DEFAULT '{}',
    graph             jsonb NOT NULL,
    produced_by       text NOT NULL,
    created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS actions (
    action_id          text PRIMARY KEY,
    tenant_id          text NOT NULL REFERENCES tenants,
    incident_id        text NOT NULL REFERENCES incidents,
    device_id          text NOT NULL,
    state              text NOT NULL CHECK (state IN ('PROPOSED','APPROVED','REJECTED','EXECUTED','VERIFIED','FAILED','ROLLED_BACK')),
    recommended_choice text NOT NULL,
    proposal           jsonb NOT NULL,
    explanation        text NOT NULL,
    rollback_pending   boolean NOT NULL DEFAULT false,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS decisions (
    decision_id        text PRIMARY KEY,
    tenant_id          text NOT NULL REFERENCES tenants,
    action_id          text NOT NULL REFERENCES actions,
    choice             text NOT NULL,
    user_id            text NOT NULL,
    channel            text NOT NULL,
    webauthn_assertion bytea,
    decided_at         timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS commands (
    command_id   text PRIMARY KEY,
    tenant_id    text NOT NULL REFERENCES tenants,
    action_id    text NOT NULL REFERENCES actions,
    decision_id  text NOT NULL REFERENCES decisions,
    device_id    text NOT NULL,
    tool         text NOT NULL,
    args         jsonb NOT NULL,
    nonce        bigint NOT NULL,
    key_id       text NOT NULL,
    not_after    timestamptz NOT NULL,
    status       text NOT NULL DEFAULT 'sent',
    reason       text NOT NULL DEFAULT '',
    vault_id     text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz
);

CREATE TABLE IF NOT EXISTS audit_log (
    id         bigserial PRIMARY KEY,
    tenant_id  text NOT NULL REFERENCES tenants,
    at         timestamptz NOT NULL DEFAULT now(),
    actor      text NOT NULL,
    kind       text NOT NULL,
    subject    text NOT NULL,
    payload    jsonb NOT NULL,
    prev_hash  text NOT NULL,
    hash       text NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_tenant ON audit_log (tenant_id, id);

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['devices','alerts','incidents','actions','decisions','commands','audit_log'] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
        IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = t AND policyname = 'tenant_isolation') THEN
            EXECUTE format(
                'CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_setting(''app.tenant_id'', true)) '
                'WITH CHECK (tenant_id = current_setting(''app.tenant_id'', true))', t);
        END IF;
    END LOOP;
END $$;

-- Audit log is append-only for the app role.
REVOKE UPDATE, DELETE ON audit_log FROM PUBLIC;

-- App role (created by deploy/postgres-init.sql) gets DML only; it does not
-- own the tables, so FORCE RLS applies to it.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'scanu_app') THEN
        GRANT SELECT ON tenants, api_tokens TO scanu_app;
        GRANT SELECT, INSERT, UPDATE ON devices, alerts, incidents, actions, decisions, commands TO scanu_app;
        GRANT SELECT, INSERT ON audit_log TO scanu_app;
        GRANT USAGE ON SEQUENCE audit_log_id_seq TO scanu_app;
    END IF;
END $$;
