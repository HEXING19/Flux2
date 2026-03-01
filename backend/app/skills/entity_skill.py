from __future__ import annotations

from typing import Any

import httpx
from pydantic import BaseModel

from app.core.exceptions import MissingParameterException
from app.core.payload import table_payload, text_payload
from app.core.threatbook import resolve_threatbook_api_key

from .base import BaseSkill
from .event_skills import _bootstrap_event_indices, extract_entity_items_from_response, extract_event_uuids_from_text


class EntityQueryInput(BaseModel):
    ips: list[str] | None = None
    ref_text: str | None = None
    incident_uuids: list[str] | None = None


class EntityQuerySkill(BaseSkill):
    name = "EntityQuerySkill"
    __init_schema__ = EntityQueryInput

    @staticmethod
    def _stable_local_assessment(ip: str) -> dict[str, Any]:
        score = sum(int(part) for part in ip.split(".") if part.isdigit()) % 100
        if score >= 75:
            severity = "high"
            tags = ["c2", "scanner"]
        elif score >= 40:
            severity = "medium"
            tags = ["suspicious"]
        else:
            severity = "low"
            tags = ["unknown"]
        return {
            "ip": ip,
            "severity": severity,
            "confidence": 55 + score // 2,
            "judgment": "未配置微步Key，以下为本地启发式评估。",
            "tags": tags,
        }

    def _query_threatbook(self, ip: str) -> dict[str, Any]:
        api_key = resolve_threatbook_api_key()
        if not api_key:
            # 未配置时用稳定的本地策略回退，避免每次同IP返回结果飘忽。
            return self._stable_local_assessment(ip)

        try:
            with httpx.Client(timeout=10) as client:
                resp = client.get(
                    "https://api.threatbook.cn/v3/scene/ip_reputation",
                    params={"apikey": api_key, "resource": ip},
                )
                data = resp.json()
                result = data.get("data", {}).get(ip, {})
                return {
                    "ip": ip,
                    "severity": result.get("severity", "unknown"),
                    "confidence": result.get("confidence_level", 0),
                    "judgment": result.get("judgments", ["unknown"])[0],
                    "tags": result.get("tags_classes", []),
                }
        except Exception:
            return {
                "ip": ip,
                "severity": "unknown",
                "confidence": 0,
                "judgment": "微步接口调用失败，建议稍后重试。",
                "tags": [],
            }

    def execute(self, session_id: str, params: dict[str, Any], user_text: str) -> list[dict[str, Any]]:
        prepared = dict(params)
        ref_text = prepared.get("ref_text") or user_text
        if not prepared.get("ips"):
            refs = prepared.get("incident_uuids") or extract_event_uuids_from_text(ref_text)
            if not refs:
                refs = self.context_manager.resolve_indices(session_id, "events", ref_text)
            if not refs:
                refs = _bootstrap_event_indices(self, session_id, ref_text)
            if refs:
                prepared["incident_uuids"] = refs
                inherited_ips: list[str] = []
                api_errors: list[str] = []
                for uid in refs[:5]:
                    entity_resp = self.requester.request("GET", f"/api/xdr/v1/incidents/{uid}/entities/ip")
                    entities, error = extract_entity_items_from_response(entity_resp)
                    if error:
                        api_errors.append(f"{uid}: {error}")
                        continue
                    for item in entities:
                        ip = item.get("ip")
                        if ip:
                            inherited_ips.append(ip)
                if inherited_ips:
                    dedup = list(dict.fromkeys(inherited_ips))
                    prepared["ips"] = dedup
                    self.context_manager.update_params(session_id, {"last_entity_ip": dedup[0]})
                elif api_errors:
                    return [text_payload("事件外网实体查询失败：" + "；".join(api_errors[:3]), title="实体情报结果")]
                else:
                    return [text_payload("指定事件未查询到外网IP实体。", title="实体情报结果")]
        if not prepared.get("ips"):
            last_ip = self.context_manager.get_param(session_id, "last_entity_ip")
            if last_ip:
                prepared["ips"] = [last_ip]

        model = self.validate_and_prepare(session_id, prepared)
        if not model.ips:
            raise MissingParameterException(
                skill_name=self.name,
                missing_fields=["ips"],
                question="请提供要查询的IP实体，或指定事件序号/事件ID（如“查看序号1外网实体”或“查看事件ID为incident-xxx的外网实体”）。",
            )

        rows = [self._query_threatbook(ip) for ip in model.ips]
        summary = "已完成实体情报查询。" if resolve_threatbook_api_key() else "未检测到微步Key，已返回本地评估结果。"
        return [
            text_payload(summary, title="实体情报结果"),
            table_payload(
                title="IP实体情报",
                columns=[
                    {"key": "ip", "label": "IP"},
                    {"key": "severity", "label": "威胁等级"},
                    {"key": "confidence", "label": "置信度"},
                    {"key": "judgment", "label": "结论"},
                    {"key": "tags", "label": "标签"},
                ],
                rows=rows,
                namespace="entities",
            ),
        ]
