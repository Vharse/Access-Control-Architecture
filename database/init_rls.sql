-- 1. Create documents table schema
CREATE TABLE IF NOT EXISTS documents (
    id SERIAL PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL
);

-- 2. Create non-superuser role if missing
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'app_user') THEN
        CREATE USER app_user WITH PASSWORD 'secure_app_password';
    END IF;
END
$$;

-- 3. Grant schema & table permissions
DO $$
BEGIN
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO app_user;', current_database());
END
$$;
GRANT USAGE ON SCHEMA public TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_user;

ALTER DEFAULT PRIVILEGES IN SCHEMA public 
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO app_user;

ALTER DEFAULT PRIVILEGES IN SCHEMA public 
GRANT USAGE, SELECT ON SEQUENCES TO app_user;

-- 4. Enable and FORCE Row-Level Security
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;

-- 5. Attach Zero Trust tenant policy
DROP POLICY IF EXISTS tenant_isolation_policy ON documents;
CREATE POLICY tenant_isolation_policy ON documents
    FOR ALL
    TO app_user
    USING (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')
    )
    WITH CHECK (
        tenant_id = NULLIF(current_setting('app.current_tenant', true), '')
    );
