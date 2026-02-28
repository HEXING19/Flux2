from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, SQLModel


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ProviderConfig(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    provider: str = Field(index=True, unique=True)
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    model_name: Optional[str] = None
    enabled: bool = True
    extra_json: Optional[str] = None
    updated_at: datetime = Field(default_factory=utc_now)


class XDRCredential(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    base_url: str
    auth_code: Optional[str] = None
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    verify_ssl: bool = False
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class WorkflowConfig(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    cron_expr: str
    enabled: bool = True
    levels: str = "3,4"
    require_approval: bool = True
    webhook_url: Optional[str] = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class WorkflowRun(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    workflow_id: Optional[int] = Field(default=None, index=True)
    status: str = Field(default="Pending", index=True)
    trigger_type: str = "manual"
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: Optional[datetime] = None
    context_json: Optional[str] = None
    result_json: Optional[str] = None
    error: Optional[str] = None


class ApprovalRequest(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    workflow_run_id: int = Field(index=True)
    title: str
    payload_json: str
    status: str = Field(default="Pending", index=True)
    decision: Optional[str] = None
    reviewer: Optional[str] = None
    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)


class AuditAction(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    session_id: str = Field(index=True)
    action_name: str
    dangerous: bool = False
    status: str
    detail_json: Optional[str] = None
    created_at: datetime = Field(default_factory=utc_now)


class SafetyGateRule(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    rule_type: str = Field(index=True)  # ip, domain, cidr
    target: str = Field(index=True, unique=True)
    description: Optional[str] = None
    created_at: datetime = Field(default_factory=utc_now)


class SessionState(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    session_id: str = Field(index=True, unique=True)
    params_json: str = "{}"
    index_json: str = "{}"
    index_meta_json: str = "{}"
    pending_action_json: Optional[str] = None
    pending_form_json: Optional[str] = None
    updated_at: datetime = Field(default_factory=utc_now)
