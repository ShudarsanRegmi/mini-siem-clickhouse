"""
Database client helper module.
Enforces Least Privilege by providing role-specific connection factories.
Credentials are automatically loaded from environment variables (.env).
"""

import os
from pathlib import Path
from typing import Optional
import clickhouse_connect
from clickhouse_connect.driver.client import Client


def load_env_file(dotenv_path: Optional[str] = None) -> None:
    """Load key-value pairs from .env into os.environ if not already set."""
    if not dotenv_path:
        # Mini-siem repo root is 2 levels up from src/common
        repo_root = Path(__file__).resolve().parent.parent.parent
        dotenv_path = str(repo_root / ".env")

    env_path = Path(dotenv_path)
    if not env_path.exists():
        return

    with open(env_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            key = key.strip()
            val = val.strip().strip("'\"")
            if key not in os.environ:
                os.environ[key] = val


# Automatically load env when this module is imported
load_env_file()


def get_db_client(
    role: str = "ingest",
    host: Optional[str] = None,
    port: Optional[int] = None,
    database: Optional[str] = None,
) -> Client:
    """
    Returns an authenticated ClickHouse client restricted to the requested role.

    Allowed roles:
      - 'admin': Schema migrations and user administration.
      - 'ingest': INSERT only on telemetry and posture findings.
      - 'detector': SELECT on telemetry/posture, INSERT on alerts.
      - 'viewer' / 'grafana': Read-only SELECT on siem database.
    """
    ch_host = host or os.getenv("CLICKHOUSE_HOST", "127.0.0.1")
    ch_port = port or int(os.getenv("CLICKHOUSE_PORT", "8123"))
    ch_db = database or os.getenv("CLICKHOUSE_DB", "siem")

    if role == "admin":
        user = os.getenv("CLICKHOUSE_ADMIN_USER", "default")
        pwd = os.getenv("CLICKHOUSE_ADMIN_PASSWORD", "")
    elif role == "ingest":
        user = os.getenv("CLICKHOUSE_INGEST_USER", "siem_ingest")
        pwd = os.getenv("CLICKHOUSE_INGEST_PASSWORD", "")
    elif role == "detector":
        user = os.getenv("CLICKHOUSE_DETECTOR_USER", "siem_detector")
        pwd = os.getenv("CLICKHOUSE_DETECTOR_PASSWORD", "")
    elif role in ("viewer", "grafana"):
        user = os.getenv("CLICKHOUSE_GRAFANA_USER", "siem_grafana")
        pwd = os.getenv("CLICKHOUSE_GRAFANA_PASSWORD", "")
    else:
        raise ValueError(f"Unknown database role requested: {role}")

    try:
        client = clickhouse_connect.get_client(
            host=ch_host,
            port=ch_port,
            username=user,
            password=pwd,
            database=ch_db,
            connect_timeout=10,
            send_receive_timeout=15,
        )
        return client
    except Exception as e:
        # Secure error handling: do not log password or sensitive connection strings
        raise ConnectionError(
            f"Failed to connect to ClickHouse as role '{role}' ({user}@{ch_host}:{ch_port}/{ch_db}): {str(e)}"
        ) from None
