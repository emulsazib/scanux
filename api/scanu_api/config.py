import os
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Settings:
    # Owner role: runs migrations only.
    database_url_admin: str = field(default_factory=lambda: os.getenv("SCANU_PG_ADMIN", "postgresql://scanu:scanu-dev@127.0.0.1:5432/scanu"))
    # App role: not the table owner, so FORCE RLS applies.
    database_url: str = field(default_factory=lambda: os.getenv("SCANU_PG", "postgresql://scanu_app:scanu-app-dev@127.0.0.1:5432/scanu"))
    kafka: str = field(default_factory=lambda: os.getenv("SCANU_KAFKA", "127.0.0.1:19092"))
    pki_dir: str = field(default_factory=lambda: os.getenv("SCANU_PKI", "../deploy/pki/out"))
    service_token: str = field(default_factory=lambda: os.getenv("SCANU_SERVICE_TOKEN", "dev-service-token"))
    clickhouse_url: str = field(default_factory=lambda: os.getenv("SCANU_CLICKHOUSE_URL", "http://127.0.0.1:8123"))
    clickhouse_user: str = field(default_factory=lambda: os.getenv("SCANU_CLICKHOUSE_USER", "scanu"))
    clickhouse_password: str = field(default_factory=lambda: os.getenv("SCANU_CLICKHOUSE_PASSWORD", "scanu-dev"))
    command_ttl_s: int = 300
    cors_origins: tuple[str, ...] = ("http://localhost:3000", "http://127.0.0.1:3000", "tauri://localhost", "http://tauri.localhost")


settings = Settings()
