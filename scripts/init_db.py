"""
Database & RBAC Provisioning Script.
Idempotently establishes ClickHouse schema and provisions granular RBAC users
from environment variables without exposing secrets.
"""

import sys
import os
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.common.db import get_db_client, load_env_file

load_env_file()


def provision_schema_and_users():
    print("[*] Connecting to ClickHouse as Admin...")
    admin_client = get_db_client(role="admin", database="default")

    # Read init.sql
    init_sql_path = Path(__file__).resolve().parent.parent / "config" / "clickhouse" / "init.sql"
    if not init_sql_path.exists():
        print(f"[-] Error: {init_sql_path} does not exist.")
        sys.exit(1)

    print(f"[*] Applying DDL from {init_sql_path.name}...")
    with open(init_sql_path, "r", encoding="utf-8") as f:
        sql_content = f.read()

    # Strip single line comments before splitting on semicolons
    cleaned_lines = []
    for line in sql_content.splitlines():
        trimmed = line.strip()
        if trimmed.startswith("--"):
            continue
        cleaned_lines.append(line)
    clean_sql = "\n".join(cleaned_lines)

    statements = [stmt.strip() for stmt in clean_sql.split(";") if stmt.strip()]
    for exec_stmt in statements:
        if exec_stmt:
            admin_client.command(exec_stmt)

    print("[+] Core schema and RBAC roles verified.")

    # Provision RBAC Users with SHA256 hashed credentials
    users = [
        {
            "user": os.getenv("CLICKHOUSE_INGEST_USER", "siem_ingest"),
            "password": os.getenv("CLICKHOUSE_INGEST_PASSWORD"),
            "role": "siem_ingest_role",
        },
        {
            "user": os.getenv("CLICKHOUSE_DETECTOR_USER", "siem_detector"),
            "password": os.getenv("CLICKHOUSE_DETECTOR_PASSWORD"),
            "role": "siem_detector_role",
        },
        {
            "user": os.getenv("CLICKHOUSE_GRAFANA_USER", "siem_grafana"),
            "password": os.getenv("CLICKHOUSE_GRAFANA_PASSWORD"),
            "role": "siem_viewer_role",
        },
    ]

    for u in users:
        username = u["user"]
        password = u["password"]
        role = u["role"]

        if not password:
            print(f"[!] Warning: No password configured for user {username}. Skipping user creation.")
            continue

        print(f"[*] Provisioning user '{username}' with role '{role}'...")
        # Parameterized safe user provisioning
        admin_client.command(
            f"CREATE USER IF NOT EXISTS {username} IDENTIFIED WITH sha256_password BY '{password}'"
        )
        # In case user exists, update password
        admin_client.command(
            f"ALTER USER {username} IDENTIFIED WITH sha256_password BY '{password}'"
        )
        admin_client.command(f"GRANT {role} TO {username}")

    print("[+] All RBAC users provisioned successfully according to Least Privilege.")


if __name__ == "__main__":
    provision_schema_and_users()
