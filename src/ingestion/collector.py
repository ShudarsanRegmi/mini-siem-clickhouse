"""
Mini SIEM Ingestion Service.
Security Engineering Principles Applied:
 - Strict Authentication: Bearer token for agent push endpoints; HMAC-SHA256 for GitHub webhooks.
 - Fail-Secure: Rejects unauthenticated/invalid requests immediately (401/403) without processing.
 - Input Validation: Strict Pydantic models with constrained string lengths and typed fields.
 - Least Privilege: Connects to ClickHouse strictly using the 'ingest' role (INSERT only).
 - Error Sanitization: Safe error responses that do not leak internal stack traces or database info.
"""

import os
import hmac
import hashlib
import json
import datetime
from typing import List, Optional, Literal
from fastapi import FastAPI, Header, HTTPException, Request, Depends, status
from pydantic import BaseModel, Field, IPvAnyAddress

from src.common.db import get_db_client, load_env_file

load_env_file()

app = FastAPI(
    title="Mini SIEM Ingestion Gateway",
    description="Secure, authenticated telemetry and posture ingestion service",
    version="1.0.0",
    docs_url=None,  # Disable public OpenAPI docs in production
    redoc_url=None,
)

BEARER_TOKEN = os.getenv("INGESTION_BEARER_TOKEN")
GITHUB_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")


# --- Authentication Dependencies ---

def verify_bearer_token(authorization: Optional[str] = Header(None)) -> str:
    if not BEARER_TOKEN:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ingestion authentication is not configured on the server",
        )
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
        )
    token = authorization.split("Bearer ", 1)[1].strip()
    if not hmac.compare_digest(token, BEARER_TOKEN):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid credentials",
        )
    return token


async def verify_github_signature(request: Request, x_hub_signature_256: Optional[str] = Header(None)) -> bytes:
    if not GITHUB_SECRET:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GitHub webhook secret is not configured",
        )
    if not x_hub_signature_256 or not x_hub_signature_256.startswith("sha256="):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid X-Hub-Signature-256 header",
        )
    
    body = await request.body()
    expected_signature = "sha256=" + hmac.new(
        GITHUB_SECRET.encode("utf-8"),
        body,
        hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected_signature, x_hub_signature_256):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature",
        )
    return body


# --- Pydantic Data Models with Strict Validation ---

class TelemetryEvent(BaseModel):
    timestamp: Optional[datetime.datetime] = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc))
    asset_type: Literal["laptop", "vm", "k8s", "github"]
    asset_id: str = Field(..., max_length=128)
    event_category: str = Field(..., max_length=64)
    event_type: str = Field(..., max_length=64)
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] = "INFO"
    actor: str = Field(default="", max_length=128)
    source_ip: Optional[str] = None
    process_name: Optional[str] = Field(default=None, max_length=256)
    command_line: Optional[str] = Field(default=None, max_length=4096)
    target_resource: Optional[str] = Field(default=None, max_length=1024)
    raw_json: Optional[str] = "{}"


class PostureFinding(BaseModel):
    asset_type: Literal["laptop", "vm", "k8s", "github"]
    asset_id: str = Field(..., max_length=128)
    scanner_tool: str = Field(..., max_length=64)
    finding_type: Literal["vulnerability", "misconfiguration", "secret_leak"]
    check_id: str = Field(..., max_length=128)
    title: str = Field(..., max_length=512)
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    status: Literal["OPEN", "RESOLVED", "SUPPRESSED"] = "OPEN"
    remediation: Optional[str] = Field(default="", max_length=2048)
    details: Optional[str] = Field(default="", max_length=8192)


# --- Endpoints ---

@app.get("/health")
def health_check():
    return {"status": "healthy", "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()}


@app.post("/api/v1/telemetry", status_code=status.HTTP_201_CREATED)
def ingest_telemetry(
    events: List[TelemetryEvent],
    _auth: str = Depends(verify_bearer_token),
):
    if not events:
        raise HTTPException(status_code=400, detail="Empty telemetry payload")
    if len(events) > 5000:
        raise HTTPException(status_code=413, detail="Batch size exceeds maximum limit of 5000 events")

    # Transform to rows
    rows = []
    for ev in events:
        rows.append([
            ev.timestamp,
            ev.asset_type,
            ev.asset_id,
            ev.event_category,
            ev.event_type,
            ev.severity,
            ev.actor,
            ev.source_ip,
            ev.process_name,
            ev.command_line,
            ev.target_resource,
            ev.raw_json if ev.raw_json else "{}",
        ])

    client = get_db_client(role="ingest")
    client.insert(
        "raw_telemetry",
        rows,
        column_names=[
            "timestamp",
            "asset_type",
            "asset_id",
            "event_category",
            "event_type",
            "severity",
            "actor",
            "source_ip",
            "process_name",
            "command_line",
            "target_resource",
            "raw_json",
        ],
    )
    return {"inserted": len(rows), "status": "success"}


@app.post("/api/v1/posture", status_code=status.HTTP_201_CREATED)
def ingest_posture(
    findings: List[PostureFinding],
    _auth: str = Depends(verify_bearer_token),
):
    if not findings:
        raise HTTPException(status_code=400, detail="Empty posture findings payload")

    now = datetime.datetime.now(datetime.timezone.utc)
    rows = []
    for f in findings:
        rows.append([
            now,
            f.asset_type,
            f.asset_id,
            f.scanner_tool,
            f.finding_type,
            f.check_id,
            f.title,
            f.severity,
            f.status,
            f.remediation or "",
            f.details or "",
        ])

    client = get_db_client(role="ingest")
    client.insert(
        "posture_findings",
        rows,
        column_names=[
            "scan_timestamp",
            "asset_type",
            "asset_id",
            "scanner_tool",
            "finding_type",
            "check_id",
            "title",
            "severity",
            "status",
            "remediation",
            "details",
        ],
    )
    return {"inserted": len(rows), "status": "success"}


@app.post("/api/v1/webhooks/github", status_code=status.HTTP_202_ACCEPTED)
async def ingest_github_webhook(
    request: Request,
    raw_body: bytes = Depends(verify_github_signature),
    x_github_event: str = Header("unknown"),
):
    """
    Ingests authenticated GitHub webhooks into raw_telemetry.
    Validates HMAC signature before JSON decoding.
    """
    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except Exception:
        raise HTTPException(status_code=400, detail="Malformed JSON in webhook body")

    repo_name = payload.get("repository", {}).get("full_name", "unknown_repo")
    sender = payload.get("sender", {}).get("login", "unknown_actor")
    action = payload.get("action", x_github_event)

    now = datetime.datetime.now(datetime.timezone.utc)
    row = [[
        now,
        "github",
        repo_name,
        "github_audit",
        f"git_{x_github_event}_{action}",
        "INFO",
        sender,
        None,
        None,
        f"GitHub Event: {x_github_event} on {repo_name}",
        repo_name,
        json.dumps(payload),
    ]]

    client = get_db_client(role="ingest")
    client.insert(
        "raw_telemetry",
        row,
        column_names=[
            "timestamp",
            "asset_type",
            "asset_id",
            "event_category",
            "event_type",
            "severity",
            "actor",
            "source_ip",
            "process_name",
            "command_line",
            "target_resource",
            "raw_json",
        ],
    )
    return {"received": True, "event": x_github_event, "repo": repo_name}
