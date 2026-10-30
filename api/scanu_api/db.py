"""Postgres access. Every tenant-scoped query runs inside `tenant_tx`, which
sets `app.tenant_id` for the transaction so RLS filters every statement."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from psycopg_pool import AsyncConnectionPool

from .config import settings

MIGRATIONS = Path(__file__).resolve().parent.parent / "migrations"

pool: AsyncConnectionPool | None = None


async def migrate() -> None:
    async with await psycopg.AsyncConnection.connect(settings.database_url_admin, autocommit=True) as conn:
        for f in sorted(MIGRATIONS.glob("*.sql")):
            await conn.execute(f.read_text())


async def open_pool() -> None:
    global pool
    pool = AsyncConnectionPool(settings.database_url, min_size=1, max_size=10, open=False, kwargs={"row_factory": dict_row})
    await pool.open()


async def close_pool() -> None:
    if pool is not None:
        await pool.close()


@asynccontextmanager
async def tenant_tx(tenant_id: str):
    assert pool is not None, "pool not opened"
    async with pool.connection() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant_id,))
            async with conn.cursor() as cur:
                yield cur


@asynccontextmanager
async def global_cursor():
    """Only for non-tenant tables (tenants, api_tokens)."""
    assert pool is not None
    async with pool.connection() as conn:
        async with conn.cursor() as cur:
            yield cur
