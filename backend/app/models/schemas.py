from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator

from app.core.validation import (
    clean_optional_text,
    clean_text,
    validate_cron_expr,
    validate_http_url,
    validate_ipv4,
)
from app.core.semantic_rules import (
    normalize_rule_value,
    validate_action_type,
    validate_description as validate_semantic_description,
    validate_match_mode,
    validate_phrase,
    validate_rule_domain,
    validate_rule_slot,
)


class LoginRequest(BaseModel):
    base_url: str
    auth_code: Optional[str] = None
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    verify_ssl: bool = False

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str) -> str:
        return validate_http_url(value, field_name="base_url")

    @field_validator("auth_code", "access_key", "secret_key", mode="before")
    @classmethod
    def normalize_secret_fields(cls, value: Optional[str]) -> Optional[str]:
        return clean_optional_text(value)

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

    @field_validator("api_key", "model_name", "extra_json", mode="before")
    @classmethod
    def normalize_provider_text_fields(cls, value: Optional[str]) -> Optional[str]:
        return clean_optional_text(value)

    @field_validator("base_url", mode="before")
    @classmethod
    def validate_provider_base_url(cls, value: Optional[str]) -> Optional[str]:
        if value in (None, ""):
            return None
        return validate_http_url(value, field_name="base_url")


class ProviderConnectivityRequest(BaseModel):
    provider: Literal["openai", "zhipu", "deepseek", "custom"]
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    model_name: Optional[str] = None

    @field_validator("api_key", "model_name", mode="before")
    @classmethod
    def normalize_connectivity_text_fields(cls, value: Optional[str]) -> Optional[str]:
        return clean_optional_text(value)

    @field_validator("base_url", mode="before")
    @classmethod
    def validate_connectivity_base_url(cls, value: Optional[str]) -> Optional[str]:
        if value in (None, ""):
            return None
        return validate_http_url(value, field_name="base_url")


class ThreatbookConfigIn(BaseModel):
    api_key: Optional[str] = None
    enabled: bool = True

    @field_validator("api_key", mode="before")
    @classmethod
    def normalize_threatbook_key(cls, value: Optional[str]) -> Optional[str]:
        return clean_optional_text(value)


class ThreatbookConnectivityRequest(BaseModel):
    api_key: Optional[str] = None
    test_ip: str = Field(default="8.8.8.8")

    @field_validator("api_key", mode="before")
    @classmethod
    def normalize_threatbook_connectivity_key(cls, value: Optional[str]) -> Optional[str]:
        return clean_optional_text(value)

    @field_validator("test_ip")
    @classmethod
    def validate_test_ip(cls, value: str) -> str:
        return validate_ipv4(value, field_name="test_ip")


class CoreAssetIn(BaseModel):
    asset_name: str = Field(min_length=1)
    asset_ip: str = Field(min_length=1)
    biz_owner: Optional[str] = None
    metadata: Optional[str] = None

    @field_validator("asset_name")
    @classmethod
    def validate_asset_name(cls, value: str) -> str:
        text = clean_text(value)
        if not text:
            raise ValueError("asset_name 不能为空。")
        return text

    @field_validator("asset_ip")
    @classmethod
    def validate_asset_ip(cls, value: str) -> str:
        return validate_ipv4(value, field_name="asset_ip")

    @field_validator("biz_owner", "metadata", mode="before")
    @classmethod
    def normalize_core_asset_optional_fields(cls, value: Optional[str]) -> Optional[str]:
        return clean_optional_text(value)


class ChatRequest(BaseModel):
    session_id: str = Field(min_length=1)
    message: str = Field(min_length=1)
    active_playbook_run_id: Optional[int] = None

    @field_validator("session_id", "message")
    @classmethod
    def validate_chat_text(cls, value: str, info) -> str:
        text = clean_text(value)
        if not text:
            raise ValueError(f"{info.field_name} 不能为空。")
        return text


class Payload(BaseModel):
    type: Literal["text", "table", "echarts_graph", "approval_card", "form_card", "quick_actions"]
    data: dict[str, Any]


class ChatResponse(BaseModel):
    session_id: str
    payloads: list[Payload]


class SemanticRuleIn(BaseModel):
    domain: str
    slot_name: str
    phrase: str
    action_type: str | None = None
    rule_value: Any = None
    description: Optional[str] = None
    enabled: bool = True
    priority: int = Field(default=100, ge=0, le=10000)
    match_mode: str = "contains"

    @field_validator("phrase")
    @classmethod
    def validate_semantic_phrase(cls, value: str) -> str:
        return validate_phrase(value)

    @field_validator("description", mode="before")
    @classmethod
    def validate_semantic_rule_description(cls, value: Optional[str]) -> Optional[str]:
        return validate_semantic_description(value)

    @field_validator("match_mode", mode="before")
    @classmethod
    def validate_semantic_match_mode(cls, value: Optional[str]) -> str:
        return validate_match_mode(value or "contains")

    @model_validator(mode="after")
    def validate_semantic_rule(self) -> "SemanticRuleIn":
        self.domain = validate_rule_domain(self.domain)
        self.slot_name = validate_rule_slot(self.domain, self.slot_name)
        self.match_mode = validate_match_mode(self.match_mode)
        self.phrase = validate_phrase(self.phrase, match_mode=self.match_mode)
        self.action_type = validate_action_type(self.domain, self.slot_name, self.action_type)
        self.rule_value = normalize_rule_value(self.domain, self.slot_name, self.action_type, self.rule_value)
        return self


class WorkflowConfigIn(BaseModel):
    name: str
    cron_expr: str
    enabled: bool = True
    levels: list[int] = Field(default_factory=lambda: [3, 4])
    require_approval: bool = True
    webhook_url: Optional[str] = None

    @field_validator("name")
    @classmethod
    def validate_workflow_name(cls, value: str) -> str:
        text = clean_text(value)
        if not text:
            raise ValueError("name 不能为空。")
        return text

    @field_validator("cron_expr")
    @classmethod
    def validate_workflow_cron(cls, value: str) -> str:
        return validate_cron_expr(value)

    @field_validator("levels")
    @classmethod
    def validate_workflow_levels(cls, value: list[int]) -> list[int]:
        if not value:
            raise ValueError("levels 不能为空。")
        normalized: list[int] = []
        for level in value:
            if level not in {0, 1, 2, 3, 4}:
                raise ValueError("levels 仅支持 0-4。")
            if level not in normalized:
                normalized.append(level)
        return normalized

    @field_validator("webhook_url", mode="before")
    @classmethod
    def validate_workflow_webhook(cls, value: Optional[str]) -> Optional[str]:
        if value in (None, ""):
            return None
        return validate_http_url(value, field_name="webhook_url")


class WorkflowRunTrigger(BaseModel):
    workflow_id: int = Field(ge=1)


class ApprovalDecisionIn(BaseModel):
    decision: Literal["approve", "reject"]
    reviewer: str = "analyst"
    comment: Optional[str] = None

    @field_validator("reviewer")
    @classmethod
    def validate_reviewer(cls, value: str) -> str:
        text = clean_text(value)
        if not text:
            raise ValueError("reviewer 不能为空。")
        return text

    @field_validator("comment", mode="before")
    @classmethod
    def normalize_comment(cls, value: Optional[str]) -> Optional[str]:
        return clean_optional_text(value)
