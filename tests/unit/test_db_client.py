"""
Unit Tests: Database Client Utilities & Role Parsing.
Tests role validation, configuration loader, and error handling in isolation.
"""

import os
import pytest
from src.common.db import get_db_client, load_env_file


@pytest.mark.unit
def test_invalid_role_raises_value_error():
    """Test that requesting an undefined database role raises ValueError."""
    with pytest.raises(ValueError) as exc:
        get_db_client(role="super_root_admin")
    assert "Unknown database role requested" in str(exc.value)


@pytest.mark.unit
def test_load_env_file_missing():
    """Test that loading a non-existent env file fails gracefully without crashing."""
    # Should not raise exception
    load_env_file("/path/to/non_existent_env_file_12345")


@pytest.mark.unit
def test_db_client_masks_credentials_on_connection_failure():
    """Verify Defense-in-Depth: Connection error messages must not leak passwords."""
    with pytest.raises(ConnectionError) as exc:
        get_db_client(
            role="ingest",
            host="127.0.0.1",
            port=59999,  # Non-listening port to force connection failure
        )
    err_str = str(exc.value)
    assert "Failed to connect to ClickHouse as role 'ingest'" in err_str
    # Verify password is NOT exposed in exception message
    ingest_pwd = os.getenv("CLICKHOUSE_INGEST_PASSWORD", "")
    if ingest_pwd:
        assert ingest_pwd not in err_str
