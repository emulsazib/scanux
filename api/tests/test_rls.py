"""Cross-tenant isolation against a real Postgres (skipped unless SCANU_TEST_PG=1)."""

import os
import uuid

import psycopg
import pytest

pytestmark = pytest.mark.skipif(os.getenv("SCANU_TEST_PG") != "1", reason="needs Postgres (make up)")


async def test_tenant_cannot_read_other_tenant_rows():
    from scanu_api import db
    from scanu_api.config import settings

    await db.migrate()
    a, b = f"t-{uuid.uuid4().hex[:8]}", f"t-{uuid.uuid4().hex[:8]}"
    async with await psycopg.AsyncConnection.connect(settings.database_url_admin, autocommit=True) as c:
        for t in (a, b):
            await c.execute("INSERT INTO tenants (tenant_id, name) VALUES (%s, %s)", (t, t))
    await db.open_pool()
    try:
        async with db.tenant_tx(a) as cur:
            await cur.execute("INSERT INTO devices (tenant_id, device_id) VALUES (%s, 'dev-a')", (a,))
        async with db.tenant_tx(b) as cur:
            await cur.execute("SELECT count(*) AS n FROM devices WHERE device_id = 'dev-a'")
            assert (await cur.fetchone())["n"] == 0
            # Writing a row for another tenant is refused by WITH CHECK.
            with pytest.raises(psycopg.errors.InsufficientPrivilege):
                await cur.execute("INSERT INTO devices (tenant_id, device_id) VALUES (%s, 'evil')", (a,))
    finally:
        await db.close_pool()
