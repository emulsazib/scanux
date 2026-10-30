-- Runs once at first container start. The app role does not own any tables,
-- so FORCE ROW LEVEL SECURITY applies to it.
CREATE ROLE scanu_app LOGIN PASSWORD 'scanu-app-dev';
GRANT CONNECT ON DATABASE scanu TO scanu_app;
GRANT USAGE ON SCHEMA public TO scanu_app;
