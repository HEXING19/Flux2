from __future__ import annotations

from datetime import datetime
import re
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.core.exceptions import ConfirmationRequiredException, MissingParameterException, ValidationGuardException
from app.core.payload import table_payload, text_payload

from .base import BaseSkill


SEVERITY_LABEL = {0: "信息", 1: "低危", 2: "中危", 3: "高危", 4: "严重"}
DEAL_STATUS_LABEL = {0: "待处置", 10: "处置中", 40: "已处置", 50: "已挂起", 60: "接受风险", 70: "已遏制"}
EVENT_UUID_PATTERN = re.compile(r"incident-[A-Za-z0-9-]{6,}")


def _pick(item: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        value = item.get(key)
        if value not in (None, ""):
            return value
    return default


def _format_ts(timestamp: Any) -> str:
    try:
        return datetime.fromtimestamp(int(timestamp)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError):
        return "-"


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def extract_event_uuids_from_text(text: str) -> list[str]:
    if not text:
        return []
    matches = EVENT_UUID_PATTERN.findall(text)
    if not matches:
        return []
    # keep order, remove duplicates
    return list(dict.fromkeys(matches))


def extract_entity_items_from_response(response: dict[str, Any]) -> tuple[list[dict[str, Any]], str | None]:
    if not isinstance(response, dict):
        return [], "实体接口响应格式异常。"

    code = response.get("code")
    if code and code != "Success":
        return [], str(response.get("message") or f"实体接口返回异常状态: {code}")

    data = response.get("data")
    raw_items: list[Any] = []

    if isinstance(data, dict):
        for key in ("item", "items", "list", "rows"):
            value = data.get(key)
            if isinstance(value, list):
                raw_items.extend(value)
        if any(k in data for k in ("ip", "IP", "entityIp", "entityIP", "view")):
            raw_items.append(data)
    elif isinstance(data, list):
        raw_items.extend(data)

    top_item = response.get("item")
    if not raw_items and isinstance(top_item, list):
        raw_items.extend(top_item)

    entities: list[dict[str, Any]] = []
    seen = set()
    for item in raw_items:
        if not isinstance(item, dict):
            continue
        ip_value = _pick(item, "ip", "IP", "entityIp", "entityIP", "view")
        if ip_value in (None, ""):
            continue
        ip_str = str(ip_value)
        if ip_str in seen:
            continue
        seen.add(ip_str)
        normalized = dict(item)
        normalized["ip"] = ip_str
        entities.append(normalized)

    return entities, None


def _looks_like_event_reference(text: str) -> bool:
    if not text:
        return False
    has_event_word = any(token in text for token in ["事件", "告警"])
    has_reference = any(token in text for token in ["第", "前", "刚刚", "那个", "这条", "上一条", "全部", "所有", "剩下", "其余"])
    return has_event_word and has_reference


def _bootstrap_event_indices(skill: BaseSkill, session_id: str, utterance: str) -> list[str]:
    if not _looks_like_event_reference(utterance):
        return []
    response = skill.requester.request(
        "POST",
        "/api/xdr/v1/incidents/list",
        json_body={
            "page": 1,
            "pageSize": 50,
            "sort": "endTime:desc,severity:desc",
            "timeField": "endTime",
        },
    )
    items = response.get("data", {}).get("item", []) if response.get("code") == "Success" else []
    uuids = [_pick(item, "uuId", "uuid", "incidentId") for item in items]
    uuids = [uid for uid in uuids if uid]
    if not uuids:
        return []
    skill.context_manager.store_index_mapping(session_id, "events", uuids)
    skill.context_manager.update_params(session_id, {"last_event_uuid": uuids[0], "last_event_uuids": uuids})
    return skill.context_manager.resolve_indices(session_id, "events", utterance)


class EventQueryInput(BaseModel):
    startTimestamp: int | None = None
    endTimestamp: int | None = None
    time_text: str | None = None
    page: int = 1
    page_size: int = Field(default=10, ge=5, le=200)
    severities: list[int] | None = None
    deal_status: list[int] | None = None
    host_branch_ids: list[int] | None = None
    platform_host_branch_ids: list[str] | None = None


class EventDetailInput(BaseModel):
    uuids: list[str] | None = None
    ref_text: str | None = None


class EventActionInput(BaseModel):
    uuids: list[str] | None = None
    ref_text: str | None = None
    deal_status: int
    deal_comment: str = "由Flux自动处置"
    confirm: bool = False

    @field_validator("deal_status")
    @classmethod
    def validate_status(cls, value: int) -> int:
        if value not in {0, 10, 40, 50, 60, 70}:
            raise ValueError("deal_status 非法")
        return value


class EventQuerySkill(BaseSkill):
    name = "EventQuerySkill"
    __init_schema__ = EventQueryInput

    def execute(self, session_id: str, params: dict[str, Any], user_text: str) -> list[dict[str, Any]]:
        model = self.validate_and_prepare(session_id, params)
        req = {
            "startTimestamp": model.startTimestamp,
            "endTimestamp": model.endTimestamp,
            "page": model.page,
            "pageSize": model.page_size,
            "sort": "endTime:desc,severity:desc",
            "timeField": "endTime",
        }
        if model.severities:
            req["severities"] = model.severities
        if model.deal_status:
            req["dealStatus"] = model.deal_status
        if model.host_branch_ids:
            req["hostBranchId"] = model.host_branch_ids
        if model.platform_host_branch_ids:
            req["platformHostBranchIds"] = model.platform_host_branch_ids

        response = self.requester.request("POST", "/api/xdr/v1/incidents/list", json_body=req)
        items = response.get("data", {}).get("item", []) if response.get("code") == "Success" else []
        uuids = [_pick(item, "uuId", "uuid", "incidentId") for item in items]
        uuids = [uid for uid in uuids if uid]
        self.context_manager.store_index_mapping(session_id, "events", uuids)
        if uuids:
            self.context_manager.update_params(session_id, {"last_event_uuid": uuids[0], "last_event_uuids": uuids})

        rows = []
        for idx, item in enumerate(items, start=1):
            incident_id = _pick(item, "uuId", "uuid", "incidentId")
            incident_name = _pick(item, "name", "incidentName", "title", default="未知事件")
            severity = _to_int(_pick(item, "incidentSeverity", "severity"))
            status = _to_int(_pick(item, "dealStatus", "status"))
            rows.append(
                {
                    "index": idx,
                    "uuId": incident_id,
                    "name": incident_name,
                    "incidentSeverity": SEVERITY_LABEL.get(severity, "未知"),
                    "dealStatus": DEAL_STATUS_LABEL.get(status, "未知"),
                    "hostIp": _pick(item, "hostIp", "srcIp", "assetIp", default="-"),
                    "endTime": _format_ts(_pick(item, "endTime", "latestTime", "occurTime", default=0)),
                }
            )

        if rows:
            summary = f"已查询到 {len(rows)} 条事件，已写入上下文索引，可直接说“查看第3个详情”或“处置前两个”。"
        else:
            summary = "未查询到匹配事件，请调整时间范围或筛选条件后重试。"
        return [
            text_payload(summary, title="事件查询结果"),
            table_payload(
                title="安全事件列表",
                columns=[
                    {"key": "index", "label": "序号"},
                    {"key": "uuId", "label": "事件ID"},
                    {"key": "name", "label": "事件名称"},
                    {"key": "incidentSeverity", "label": "等级"},
                    {"key": "dealStatus", "label": "状态"},
                    {"key": "hostIp", "label": "主机IP"},
                    {"key": "endTime", "label": "最近发生"},
                ],
                rows=rows,
                namespace="events",
            ),
        ]


class EventDetailSkill(BaseSkill):
    name = "EventDetailSkill"
    __init_schema__ = EventDetailInput

    def execute(self, session_id: str, params: dict[str, Any], user_text: str) -> list[dict[str, Any]]:
        prepared = dict(params)
        ref_text = prepared.get("ref_text") or user_text
        if not prepared.get("uuids"):
            explicit_uuids = extract_event_uuids_from_text(ref_text)
            if explicit_uuids:
                prepared["uuids"] = explicit_uuids
        if not prepared.get("uuids"):
            refs = self.context_manager.resolve_indices(session_id, "events", ref_text)
            if not refs:
                refs = _bootstrap_event_indices(self, session_id, ref_text)
            if refs:
                prepared["uuids"] = refs

        model = self.validate_and_prepare(session_id, prepared)
        if not model.uuids:
            raise MissingParameterException(
                skill_name=self.name,
                missing_fields=["uuids"],
                question="请告诉我需要查看哪条事件，例如“查看第1个事件详情”。",
            )

        all_rows = []
        detail_text_chunks = []
        for uid in model.uuids[:5]:
            proof_resp = self.requester.request("GET", f"/api/xdr/v1/incidents/{uid}/proof")
            proof_error = None
            if proof_resp.get("code") != "Success":
                proof_data = {}
                proof_error = proof_resp.get("message") or "举证信息查询失败"
            else:
                proof_data = (proof_resp.get("data") or [{}])[0]
            entity_resp = self.requester.request("GET", f"/api/xdr/v1/incidents/{uid}/entities/ip")
            entities, entity_error = extract_entity_items_from_response(entity_resp)

            timelines = proof_data.get("alertTimeLine", [])
            for event in timelines:
                all_rows.append(
                    {
                        "uuId": uid,
                        "name": event.get("name"),
                        "severity": event.get("severity"),
                        "stage": event.get("stage"),
                        "lastTime": _format_ts(event.get("lastTime")),
                    }
                )

            entity_ip = entities[0].get("ip") if entities else ("查询失败" if entity_error else "N/A")
            risk_tags = proof_data.get("riskTag", [])
            if isinstance(risk_tags, str):
                risk_tag_text = risk_tags
            elif isinstance(risk_tags, list):
                risk_tag_text = ",".join(str(tag) for tag in risk_tags if tag)
            else:
                risk_tag_text = ""
            detail_text_chunks.append(
                f"事件 {uid}: {_pick(proof_data, 'name', 'incidentName', default='未知')}\n"
                f"- AI研判: {proof_data.get('gptResultDescription', '暂无') if not proof_error else f'查询失败: {proof_error}'}\n"
                f"- 风险标签: {risk_tag_text or '无'}\n"
                f"- 外网IP实体: {entity_ip}"
            )
            if entity_ip != "N/A":
                self.context_manager.update_params(session_id, {"last_entity_ip": entity_ip})

        return [
            text_payload("\n\n".join(detail_text_chunks), title="事件详情与举证"),
            table_payload(
                title="事件攻击时间线",
                columns=[
                    {"key": "uuId", "label": "事件ID"},
                    {"key": "name", "label": "告警名称"},
                    {"key": "severity", "label": "告警等级"},
                    {"key": "stage", "label": "阶段"},
                    {"key": "lastTime", "label": "时间"},
                ],
                rows=all_rows,
                namespace="event_timeline",
            ),
        ]


class EventActionSkill(BaseSkill):
    name = "EventActionSkill"
    __init_schema__ = EventActionInput
    required_fields = ["deal_status"]
    requires_confirmation = True
    apply_safety_gate = True

    def execute(self, session_id: str, params: dict[str, Any], user_text: str) -> list[dict[str, Any]]:
        prepared = dict(params)
        ref_text = prepared.get("ref_text") or user_text
        if not prepared.get("uuids"):
            explicit_uuids = extract_event_uuids_from_text(ref_text)
            if explicit_uuids:
                prepared["uuids"] = explicit_uuids
        if not prepared.get("uuids"):
            refs = self.context_manager.resolve_indices(session_id, "events", ref_text)
            if not refs:
                refs = _bootstrap_event_indices(self, session_id, ref_text)
            if refs:
                prepared["uuids"] = refs

        model = self.validate_and_prepare(session_id, prepared)
        if not model.uuids:
            raise MissingParameterException(
                skill_name=self.name,
                missing_fields=["uuids"],
                question="请指定要处置的事件序号，比如“把前两个标记为已处置”。",
            )

        if not model.confirm:
            raise ConfirmationRequiredException(
                skill_name=self.name,
                summary=f"即将把 {len(model.uuids)} 条事件更新为“{DEAL_STATUS_LABEL.get(model.deal_status, model.deal_status)}”。",
                action_payload={
                    "skill": self.name,
                    "params": {**prepared, "uuids": model.uuids, "confirm": True},
                },
            )

        payload = {
            "uuIds": model.uuids,
            "dealStatus": model.deal_status,
            "dealComment": model.deal_comment,
        }
        result = self.requester.request("POST", "/api/xdr/v1/incidents/dealstatus", json_body=payload)
        if result.get("code") != "Success":
            raise ValidationGuardException(f"事件处置失败: {result.get('message')}")

        data = result.get("data", {})
        return [
            text_payload(
                (
                    f"事件处置完成：目标 {data.get('total', len(model.uuids))} 条，"
                    f"成功 {data.get('succeededNum', 0)} 条。"
                ),
                title="事件处置结果",
                dangerous=True,
            )
        ]
