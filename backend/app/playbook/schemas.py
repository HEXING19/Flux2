from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from app.core.validation import (
    clean_optional_text,
    clean_text,
    validate_incident_uuid,
    validate_incident_uuid_list,
    validate_ipv4,
    validate_ipv4_list,
    validate_time_range,
)


class PlaybookTemplateParam(BaseModel):
    key: str
    label: str
    description: Optional[str] = None
    required: bool = False
    default: Any = None


class PlaybookTemplateMeta(BaseModel):
    id: str
    name: str
    description: str
    button_label: str
    default_params: dict[str, Any] = Field(default_factory=dict)
    params: list[PlaybookTemplateParam] = Field(default_factory=list)


class RoutineCheckParams(BaseModel):
    window_hours: int = Field(default=24, ge=1, le=168)
    sample_size: int = Field(default=3, ge=1, le=10)


class AlertTriageParams(BaseModel):
    incident_uuid: str | None = None
    incident_uuids: list[str] | None = None
    event_index: int | None = Field(default=None, ge=1)
    event_indexes: list[int] | None = None
    window_days: int = Field(default=7, ge=1, le=30)
    mode: Literal["analyze", "block_ip"] = "analyze"
    ip: str | None = None
    ips: list[str] | None = None
    session_id: str | None = None

    @field_validator("incident_uuid")
    @classmethod
    def validate_incident_uuid_field(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_incident_uuid(value, field_name="incident_uuid")

    @field_validator("incident_uuids")
    @classmethod
    def validate_incident_uuid_list_field(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        return validate_incident_uuid_list(value, field_name="incident_uuids", allow_empty=False)

    @field_validator("event_indexes")
    @classmethod
    def validate_event_indexes(cls, value: list[int] | None) -> list[int] | None:
        if value is None:
            return None
        normalized: list[int] = []
        for item in value:
            if item <= 0:
                raise ValueError("event_indexes 必须大于 0。")
            if item not in normalized:
                normalized.append(item)
        return normalized or None

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_ipv4(value, field_name="ip")

    @field_validator("ips")
    @classmethod
    def validate_ips(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        return validate_ipv4_list(value, field_name="ips", allow_empty=False)

    @field_validator("session_id", mode="before")
    @classmethod
    def normalize_session_id(cls, value: str | None) -> str | None:
        return clean_optional_text(value)

    @model_validator(mode="after")
    def validate_required_target(self) -> "AlertTriageParams":
        has_uuid = bool(self.incident_uuid)
        has_uuid_list = bool(self.incident_uuids)
        has_index = bool(self.event_index) or bool(self.event_indexes)
        has_ip = bool(self.ip)
        has_ips = bool(self.ips)
        if self.mode == "analyze" and not (has_uuid or has_uuid_list or has_index):
            raise ValueError("alert_triage 缺少 incident_uuid 或 event_index 参数。")
        if self.mode == "block_ip" and not (has_ip or has_ips or has_uuid or has_uuid_list or has_index):
            raise ValueError("alert_triage(block_ip) 缺少 ip/ips 或事件定位参数。")
        return self


class ThreatHuntingParams(BaseModel):
    ip: str
    startTimestamp: int | None = None
    endTimestamp: int | None = None
    window_days: int = Field(default=30, ge=1, le=365)
    max_scan: int = Field(default=10000, ge=200, le=10000)
    evidence_limit: int = Field(default=20, ge=1, le=20)
    adaptive_port_topn: int = Field(default=5, ge=1, le=20)
    pivot_ports: list[int] | None = None
    src_only_first: bool = True
    mode: Literal["analyze", "export_summary"] = "analyze"

    @field_validator("ip")
    @classmethod
    def validate_target_ip(cls, value: str) -> str:
        return validate_ipv4(value, field_name="ip")

    @field_validator("pivot_ports")
    @classmethod
    def validate_pivot_ports(cls, value: list[int] | None) -> list[int] | None:
        if value is None:
            return None
        normalized: list[int] = []
        for port in value:
            if not 1 <= int(port) <= 65535:
                raise ValueError("pivot_ports 必须在 1-65535。")
            if port not in normalized:
                normalized.append(int(port))
        return normalized or None

    @model_validator(mode="after")
    def validate_window(self) -> "ThreatHuntingParams":
        validate_time_range(self.startTimestamp, self.endTimestamp)
        return self


class AssetGuardParams(BaseModel):
    asset_ip: str
    asset_name: str | None = None
    window_hours: int = Field(default=24, ge=1, le=168)
    top_external_ip: int = Field(default=5, ge=1, le=10)

    @field_validator("asset_ip")
    @classmethod
    def validate_asset_ip(cls, value: str) -> str:
        return validate_ipv4(value, field_name="asset_ip")

    @field_validator("asset_name", mode="before")
    @classmethod
    def normalize_asset_name(cls, value: str | None) -> str | None:
        return clean_optional_text(value)


PLAYBOOK_PARAM_MODELS: dict[str, type[BaseModel]] = {
    "routine_check": RoutineCheckParams,
    "alert_triage": AlertTriageParams,
    "threat_hunting": ThreatHuntingParams,
    "asset_guard": AssetGuardParams,
}


def validate_playbook_params(template_id: str, params: dict[str, Any]) -> dict[str, Any]:
    model_cls = PLAYBOOK_PARAM_MODELS.get(template_id)
    if not model_cls:
        return dict(params)
    try:
        return model_cls(**(params or {})).model_dump(exclude_none=True)
    except ValidationError as exc:
        errors = []
        for item in exc.errors():
            location = ".".join(str(part) for part in item.get("loc", []))
            message = item.get("msg", "参数不合法")
            errors.append(f"{location}: {message}" if location else message)
        raise ValueError("；".join(errors)) from exc


class PlaybookRunRequest(BaseModel):
    template_id: Literal["routine_check", "alert_triage", "threat_hunting", "asset_guard"]
    params: dict[str, Any] = Field(default_factory=dict)
    session_id: str | None = Field(default=None, min_length=1)

    @field_validator("session_id", mode="before")
    @classmethod
    def normalize_session_id(cls, value: str | None) -> str | None:
        return clean_optional_text(value)

    @model_validator(mode="after")
    def validate_params(self) -> "PlaybookRunRequest":
        self.params = validate_playbook_params(self.template_id, self.params)
        return self


class RoutineCheckBlockRequest(BaseModel):
    session_id: str = Field(min_length=1)
    ips: list[str] = Field(min_length=1)
    block_type: Literal["SRC_IP", "DST_IP"] = "SRC_IP"
    reason: str | None = None
    duration_hours: int = Field(default=24, ge=1, le=360)
    device_id: str | None = None
    rule_name: str | None = None

    @field_validator("session_id")
    @classmethod
    def validate_session_id(cls, value: str) -> str:
        text = clean_text(value)
        if not text:
            raise ValueError("session_id 不能为空。")
        return text

    @field_validator("ips")
    @classmethod
    def validate_ips(cls, value: list[str]) -> list[str]:
        return validate_ipv4_list(value, field_name="ips", allow_empty=False)

    @field_validator("reason", "device_id", "rule_name", mode="before")
    @classmethod
    def normalize_optional_text_fields(cls, value: Optional[str]) -> Optional[str]:
        return clean_optional_text(value)


class RoutineCheckBlockPreviewRequest(BaseModel):
    session_id: str = Field(min_length=1)
    ips: list[str] = Field(min_length=1)
    block_type: Literal["SRC_IP", "DST_IP"] = "SRC_IP"

    @field_validator("session_id")
    @classmethod
    def validate_session_id(cls, value: str) -> str:
        text = clean_text(value)
        if not text:
            raise ValueError("session_id 不能为空。")
        return text

    @field_validator("ips")
    @classmethod
    def validate_ips(cls, value: list[str]) -> list[str]:
        return validate_ipv4_list(value, field_name="ips", allow_empty=False)
