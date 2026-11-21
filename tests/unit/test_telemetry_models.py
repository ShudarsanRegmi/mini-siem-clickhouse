"""
Unit Tests: Telemetry and Posture Pydantic Data Models.
Tests input schema validation, type enforcement, boundary lengths, and defaults in isolation.
No database or external network required.
"""

import pytest
from pydantic import ValidationError
from src.ingestion.collector import TelemetryEvent, PostureFinding


@pytest.mark.unit
def test_valid_telemetry_event_instantiation(sample_telemetry_event):
    """Test that a well-formed telemetry payload instantiates correctly."""
    event = TelemetryEvent(**sample_telemetry_event)
    assert event.asset_type == "laptop"
    assert event.asset_id == "test-workstation-01"
    assert event.event_category == "process"
    assert event.severity == "INFO"


@pytest.mark.unit
def test_telemetry_invalid_asset_type():
    """Test that invalid asset_type raises ValidationError."""
    with pytest.raises(ValidationError) as exc:
        TelemetryEvent(
            asset_type="mainframe",  # Not in ("laptop", "vm", "k8s", "github")
            asset_id="host-1",
            event_category="audit",
            event_type="login",
        )
    assert "Input should be 'laptop', 'vm', 'k8s' or 'github'" in str(exc.value)


@pytest.mark.unit
def test_telemetry_field_length_constraints():
    """Test that asset_id exceeding max_length of 128 characters is rejected."""
    with pytest.raises(ValidationError) as exc:
        TelemetryEvent(
            asset_type="vm",
            asset_id="a" * 129,
            event_category="audit",
            event_type="login",
        )
    assert "String should have at most 128 characters" in str(exc.value)


@pytest.mark.unit
def test_valid_posture_finding_instantiation(sample_posture_finding):
    """Test that a well-formed posture finding parses and sets defaults."""
    finding = PostureFinding(**sample_posture_finding)
    assert finding.asset_type == "vm"
    assert finding.severity == "HIGH"
    assert finding.status == "OPEN"
    assert finding.finding_type == "vulnerability"


@pytest.mark.unit
def test_posture_invalid_severity():
    """Test that invalid severity values are rejected."""
    with pytest.raises(ValidationError) as exc:
        PostureFinding(
            asset_type="k8s",
            asset_id="cluster-01",
            scanner_tool="kube-bench",
            finding_type="misconfiguration",
            check_id="CIS-1.1",
            title="Anonymous Auth Enabled",
            severity="URGENT_APOCALYPSE",  # Invalid
        )
    assert "Input should be 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW' or 'INFO'" in str(exc.value)
