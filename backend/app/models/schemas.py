from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, model_validator


class LoginRequest(BaseModel):
    base_url: str
    auth_code: Optional[str] = None
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    verify_ssl: bool = False

    @model_validator(mode="after")
    def validate_auth(self) -> "LoginRequest":
        if self.auth_code:
            return self
        if self.access_key and self.secret_key:
            return self
        raise ValueError("必须提供联动码或AK/SK")


class LoginResponse(BaseModel):
    success: bool
    message: str


class ProviderConfigIn(BaseModel):
    provider: Literal["openai", "zhipu", "deepseek", "custom"]
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    model_name: Optional[str] = None
    enabled: bool = True
    extra_json: Optional[str] = None


class ProviderConnectivityRequest(BaseModel):
    provider: Literal["openai", "zhipu", "deepseek", "custom"]
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    model_name: Optional[str] = None


class ChatRequest(BaseModel):
    session_id: str = Field(min_length=1)
    message: str = Field(min_length=1)


class Payload(BaseModel):
    type: Literal["text", "table", "echarts_graph", "approval_card", "form_card"]
    data: dict[str, Any]


class ChatResponse(BaseModel):
    session_id: str
    payloads: list[Payload]


class WorkflowConfigIn(BaseModel):
    name: str
    cron_expr: str
    enabled: bool = True
    levels: list[int] = Field(default_factory=lambda: [3, 4])
    require_approval: bool = True
    webhook_url: Optional[str] = None


class WorkflowRunTrigger(BaseModel):
    workflow_id: int


class ApprovalDecisionIn(BaseModel):
    decision: Literal["approve", "reject"]
    reviewer: str = "analyst"
    comment: Optional[str] = None
