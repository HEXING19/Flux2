from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from app.core.payload import table_payload, text_payload
from app.core.validation import clean_optional_text, validate_time_range
from app.services.security_analytics_service import SecurityAnalyticsService

from .base import BaseSkill


SEVERITY_LABEL = {0: "信息", 1: "低危", 2: "中危", 3: "高危", 4: "严重"}


class AlertQueryInput(BaseModel):
    startTimestamp: int | None = None
    endTimestamp: int | None = None
    time_text: str | None = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=10, ge=5, le=200)
    severities: list[int] | None = None

    @field_validator("severities")
    @classmethod
    def validate_severities(cls, value: list[int] | None) -> list[int] | None:
        if value is None:
            return None
        normalized: list[int] = []
        for item in value:
            if item not in SEVERITY_LABEL:
                raise ValueError("severities 仅支持 0-4。")
            if item not in normalized:
                normalized.append(item)
        return normalized

    @field_validator("time_text", mode="before")
    @classmethod
    def normalize_time_text(cls, value: str | None) -> str | None:
        return clean_optional_text(value)

    @model_validator(mode="after")
    def validate_query_time_range(self) -> "AlertQueryInput":
        validate_time_range(self.startTimestamp, self.endTimestamp)
        return self


class AlertQuerySkill(BaseSkill):
    name = "AlertQuerySkill"
    __init_schema__ = AlertQueryInput

    def execute(self, session_id: str, params: dict[str, Any], user_text: str) -> list[dict[str, Any]]:
        _ = user_text
        model = self.validate_and_prepare(session_id, params)
        analytics = SecurityAnalyticsService(self.requester)
        filters = {"severities": model.severities} if model.severities else {}
        query_result = analytics.query_alerts(
            start_ts=int(model.startTimestamp or 0),
            end_ts=int(model.endTimestamp or 0),
            page=model.page,
            page_size=model.page_size,
            extra_filters=filters,
        )
        rows = query_result["rows"]
        uuids = [str(row.get("uuId") or "").strip() for row in rows if str(row.get("uuId") or "").strip()]
        self.context_manager.store_index_mapping(session_id, "alerts", uuids)
        if uuids:
            self.context_manager.update_params(session_id, {"last_alert_uuid": uuids[0], "last_alert_uuids": uuids})

        if rows:
            summary = f"已查询到 {len(rows)} 条告警，已写入上下文索引，可继续按时间范围或等级筛选。"
        else:
            summary = "未查询到匹配告警，请调整时间范围或筛选条件后重试。"

        return [
            text_payload(summary, title="告警查询结果"),
            table_payload(
                title="安全告警列表",
                columns=[
                    {"key": "index", "label": "序号", "width": "72px", "nowrap": True},
                    {"key": "uuId", "label": "告警ID", "width": "260px", "nowrap": True},
                    {"key": "name", "label": "告警名称", "width": "320px"},
                    {"key": "incidentSeverity", "label": "等级", "width": "76px", "nowrap": True},
                    {"key": "dealStatus", "label": "状态", "width": "96px", "nowrap": True},
                    {"key": "direction", "label": "方向", "width": "88px", "nowrap": True},
                    {"key": "hostIp", "label": "主机IP", "width": "132px", "nowrap": True},
                    {"key": "dstIp", "label": "目的IP", "width": "140px", "nowrap": True},
                    {"key": "endTime", "label": "最近发生", "width": "176px", "nowrap": True},
                ],
                rows=rows,
                namespace="alerts",
            ),
        ]
