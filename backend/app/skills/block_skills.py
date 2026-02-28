from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator

from app.core.exceptions import ConfirmationRequiredException, MissingParameterException, ValidationGuardException
from app.core.payload import form_payload, table_payload, text_payload

from .base import BaseSkill


ALLOWED_BLOCK_TYPES = {"SRC_IP", "DST_IP", "URL", "DNS"}
ALLOWED_TIME_TYPES = {"forever", "temporary"}
ALLOWED_TIME_UNITS = {"d", "h", "m"}


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


class BlockQueryInput(BaseModel):
    page: int = 1
    page_size: int = Field(default=10)
    status: list[str] | None = None
    keyword: str | None = None
    startTimestamp: int | None = None
    endTimestamp: int | None = None
    time_text: str | None = None


class BlockActionInput(BaseModel):
    block_type: str | None = None
    views: list[str] | None = None
    mode: str = "in"
    time_type: str | None = None
    time_value: int | None = None
    time_unit: str | None = None
    devices: list[dict[str, Any]] | None = None
    reason: str | None = None
    name: str | None = None
    confirm: bool = False

    @field_validator("block_type")
    @classmethod
    def validate_block_type(cls, value: str | None) -> str | None:
        if value and value not in ALLOWED_BLOCK_TYPES:
            raise ValueError("block_type 非法")
        return value

    @field_validator("time_type")
    @classmethod
    def validate_time_type(cls, value: str | None) -> str | None:
        if value and value not in ALLOWED_TIME_TYPES:
            raise ValueError("time_type 非法")
        return value

    @field_validator("time_unit")
    @classmethod
    def validate_time_unit(cls, value: str | None) -> str | None:
        if value and value not in ALLOWED_TIME_UNITS:
            raise ValueError("time_unit 非法")
        return value


class BlockQuerySkill(BaseSkill):
    name = "BlockQuerySkill"
    __init_schema__ = BlockQueryInput

    def _build_quick_block_form(self, session_id: str, keyword: str) -> list[dict[str, Any]]:
        action_skill = BlockActionSkill(self.requester, self.context_manager)
        online_devices = action_skill._list_online_devices()
        prepared: dict[str, Any] = {
            "views": [keyword],
            "time_type": "temporary",
            "time_value": 1,
            "time_unit": "d",
        }
        prepared = action_skill._normalize_prepared(prepared, online_devices)
        if not prepared.get("block_type"):
            prepared["block_type"] = action_skill._guess_block_type(prepared.get("views")) or "SRC_IP"
        return action_skill._build_param_form(
            session_id,
            prepared,
            online_devices,
            reason=f"未查询到 {keyword} 的封禁策略。若需要立即封禁，请确认并提交以下必填参数。",
        )

    def execute(self, session_id: str, params: dict[str, Any], user_text: str) -> list[dict[str, Any]]:
        prepared = dict(params)
        if not prepared.get("keyword"):
            inherited_target = (
                self.context_manager.get_param(session_id, "last_block_target")
                or self.context_manager.get_param(session_id, "last_entity_ip")
                or self.context_manager.get_param(session_id, "keyword")
            )
            if inherited_target and any(k in user_text for k in ["这个IP", "该IP", "这个地址", "它", "是否", "是不是", "有没有"]):
                prepared["keyword"] = str(inherited_target)

        model = self.validate_and_prepare(session_id, prepared)
        if model.keyword:
            self.context_manager.update_params(session_id, {"last_block_target": model.keyword})
        payload = {
            "page": model.page,
            "pageSize": model.page_size,
            "status": model.status or [],
            "startTimestamp": model.startTimestamp,
            "endTimestamp": model.endTimestamp,
        }
        if model.keyword:
            payload["searchInfos"] = [{"fieldName": "view", "fieldValue": model.keyword}]

        response = self.requester.request("POST", "/api/xdr/v1/responses/blockiprule/list", json_body=payload)
        if response.get("code") != "Success":
            return [text_payload(f"封禁策略查询失败: {response.get('message', '未知错误')}", title="封禁策略查询")]
        items = response.get("data", {}).get("item", [])

        rule_ids = [_pick(item, "id", "ruleId", "taskId") for item in items]
        rule_ids = [rule_id for rule_id in rule_ids if rule_id]
        self.context_manager.store_index_mapping(session_id, "block_rules", rule_ids)

        rows = []
        for idx, item in enumerate(items, start=1):
            rows.append(
                {
                    "index": idx,
                    "id": _pick(item, "id", "ruleId", "taskId"),
                    "name": _pick(item, "name", "ruleName", default="-"),
                    "status": _pick(item, "status", "dealStatus", default="-"),
                    "view": _pick(item, "view", "target", default="-"),
                    "reason": _pick(item, "reason", "remark", default="-"),
                    "updateTime": _format_ts(_pick(item, "updateTime", "createTime", default=0)),
                }
            )

        if not rows:
            target = model.keyword or "目标对象"
            payloads = [
                text_payload(f"未查询到 {target} 的封禁策略，当前可视为未封禁。", title="封禁策略查询"),
            ]
            if model.keyword:
                try:
                    payloads.extend(self._build_quick_block_form(session_id, model.keyword))
                except Exception:
                    payloads.append(text_payload(f"如需立即封禁，可直接发送：封禁 {model.keyword} 24小时。"))
            return payloads

        return [
            text_payload(f"已查询 {len(rows)} 条封禁策略并建立序号映射。", title="封禁策略查询"),
            table_payload(
                title="封禁地址策略",
                columns=[
                    {"key": "index", "label": "序号"},
                    {"key": "id", "label": "规则ID"},
                    {"key": "name", "label": "规则名"},
                    {"key": "status", "label": "状态"},
                    {"key": "view", "label": "封禁对象"},
                    {"key": "reason", "label": "备注"},
                    {"key": "updateTime", "label": "更新时间"},
                ],
                rows=rows,
                namespace="block_rules",
            ),
        ]


class BlockActionSkill(BaseSkill):
    name = "BlockActionSkill"
    __init_schema__ = BlockActionInput
    required_fields: list[str] = []
    requires_confirmation = True
    apply_safety_gate = True

    def _list_online_devices(self) -> list[dict[str, Any]]:
        resp = self.requester.request("POST", "/api/xdr/v1/device/blockdevice/list", json_body={"type": ["AF"]})
        if resp.get("code") != "Success":
            return []
        devices = resp.get("data", {}).get("item", [])
        return [d for d in devices if d.get("deviceStatus") == "online"]

    @staticmethod
    def _to_block_device(device: dict[str, Any]) -> dict[str, Any]:
        return {
            "devId": device.get("deviceId"),
            "devName": device.get("deviceName"),
            "devType": device.get("deviceType"),
            "devVersion": device.get("deviceVersion"),
        }

    @staticmethod
    def _guess_block_type(views: list[str] | None) -> str | None:
        if not views:
            return None
        first = views[0]
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", first):
            return "SRC_IP"
        if "/" in first:
            return "URL"
        if re.match(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$", first):
            return "DNS"
        return None

    @staticmethod
    def _normalize_views(value: Any) -> list[str] | None:
        if value is None:
            return None
        if isinstance(value, list):
            result = [str(v).strip() for v in value if str(v).strip()]
            return result or None
        if isinstance(value, str):
            result = [v.strip() for v in re.split(r"[,\s，]+", value) if v.strip()]
            return result or None
        return None

    def _normalize_prepared(self, prepared: dict[str, Any], online_devices: list[dict[str, Any]]) -> dict[str, Any]:
        normalized = dict(prepared)
        normalized["views"] = self._normalize_views(normalized.get("views"))

        if not normalized.get("block_type"):
            guessed = self._guess_block_type(normalized.get("views"))
            if guessed:
                normalized["block_type"] = guessed

        if normalized.get("time_type") == "temporary":
            if normalized.get("time_value") in (None, ""):
                normalized["time_value"] = 1
            if not normalized.get("time_unit"):
                normalized["time_unit"] = "d"

        if not normalized.get("devices"):
            device_id = normalized.get("device_id")
            if device_id not in (None, ""):
                chosen = next((d for d in online_devices if str(d.get("deviceId")) == str(device_id)), None)
                if chosen:
                    normalized["devices"] = [self._to_block_device(chosen)]
            elif len(online_devices) == 1:
                normalized["devices"] = [self._to_block_device(online_devices[0])]

        return normalized

    def _build_param_form(
        self,
        session_id: str,
        prepared: dict[str, Any],
        online_devices: list[dict[str, Any]],
        *,
        reason: str,
    ) -> list[dict[str, Any]]:
        token = f"block-form-{session_id}"
        self.context_manager.save_pending_form(
            session_id,
            {
                "token": token,
                "intent": "block_action",
                "params": {k: v for k, v in prepared.items() if k != "confirm"},
            },
        )

        fields: list[dict[str, Any]] = [
            {
                "key": "block_type",
                "label": "封禁对象类型",
                "type": "select",
                "required": True,
                "value": prepared.get("block_type") or "SRC_IP",
                "options": [
                    {"label": "源IP", "value": "SRC_IP"},
                    {"label": "目的IP", "value": "DST_IP"},
                    {"label": "域名", "value": "DNS"},
                    {"label": "URL", "value": "URL"},
                ],
            },
            {
                "key": "views",
                "label": "封禁对象",
                "type": "text",
                "required": True,
                "placeholder": "例如 200.200.1.1，多个可用逗号分隔",
                "value": ",".join(prepared.get("views") or []),
            },
            {
                "key": "time_type",
                "label": "封禁方式",
                "type": "select",
                "required": True,
                "value": prepared.get("time_type") or "temporary",
                "options": [
                    {"label": "临时封禁", "value": "temporary"},
                    {"label": "永久封禁", "value": "forever"},
                ],
            },
            {
                "key": "time_value",
                "label": "封禁时长数值",
                "type": "number",
                "required": False,
                "value": prepared.get("time_value") or 1,
                "placeholder": "例如 1、5、24",
            },
            {
                "key": "time_unit",
                "label": "时长单位",
                "type": "select",
                "required": False,
                "value": prepared.get("time_unit") or "d",
                "options": [
                    {"label": "天", "value": "d"},
                    {"label": "小时", "value": "h"},
                    {"label": "分钟", "value": "m"},
                ],
            },
        ]

        if online_devices:
            default_device_id = prepared.get("device_id")
            if default_device_id in (None, ""):
                default_device_id = str(online_devices[0].get("deviceId"))
            fields.append(
                {
                    "key": "device_id",
                    "label": "联动设备",
                    "type": "select",
                    "required": True,
                    "value": str(default_device_id),
                    "options": [
                        {
                            "label": f"{d.get('deviceName')} ({d.get('deviceId')})",
                            "value": str(d.get("deviceId")),
                        }
                        for d in online_devices
                    ],
                }
            )
        else:
            fields.append(
                {
                    "key": "device_id",
                    "label": "联动设备ID",
                    "type": "text",
                    "required": True,
                    "value": str(prepared.get("device_id") or ""),
                    "placeholder": "请先在平台确认AF设备在线，再填写设备ID重试",
                }
            )

        fields.extend(
            [
                {
                    "key": "reason",
                    "label": "备注",
                    "type": "text",
                    "required": False,
                    "value": prepared.get("reason") or "由Flux自动封禁",
                },
                {
                    "key": "name",
                    "label": "规则名称",
                    "type": "text",
                    "required": False,
                    "value": prepared.get("name") or "",
                    "placeholder": "可留空自动命名",
                },
            ]
        )

        return [
            form_payload(
                title="封禁参数确认",
                description=reason,
                token=token,
                intent="block_action",
                fields=fields,
                submit_label="确认并下发封禁",
            )
        ]

    def execute(self, session_id: str, params: dict[str, Any], user_text: str) -> list[dict[str, Any]]:
        prepared = dict(params or {})
        prepared.setdefault("mode", "in")

        if not prepared.get("views"):
            inherited_target = (
                self.context_manager.get_param(session_id, "last_block_target")
                or self.context_manager.get_param(session_id, "last_entity_ip")
                or self.context_manager.get_param(session_id, "keyword")
            )
            if inherited_target and any(k in user_text for k in ["它", "该IP", "这个IP", "这个地址", "这个实体", "封禁"]):
                prepared["views"] = [str(inherited_target)]

        online_devices = self._list_online_devices()
        prepared = self._normalize_prepared(prepared, online_devices)

        missing: list[str] = []
        if not prepared.get("block_type"):
            missing.append("封禁对象类型")
        if not prepared.get("views"):
            missing.append("封禁对象")
        if not prepared.get("time_type"):
            missing.append("封禁方式")
        if prepared.get("time_type") == "temporary" and not prepared.get("time_value"):
            missing.append("封禁时长数值")
        if prepared.get("time_type") == "temporary" and not prepared.get("time_unit"):
            missing.append("封禁时长单位")
        if not prepared.get("devices"):
            if not online_devices:
                missing.append("联动设备")
            elif len(online_devices) > 1 and not prepared.get("device_id"):
                missing.append("联动设备")
            elif prepared.get("device_id"):
                missing.append("联动设备(请确认设备在线)")

        if missing:
            reason = f"请先补充参数后再执行封禁，当前缺少：{'、'.join(missing)}。"
            if not online_devices:
                reason += " 当前未检测到在线AF联动设备，请先在平台检查设备接入与在线状态。"
            return self._build_param_form(session_id, prepared, online_devices, reason=reason)

        model = self.validate_and_prepare(session_id, prepared)

        if not model.devices:
            if len(online_devices) > 1:
                return self._build_param_form(
                    session_id,
                    prepared,
                    online_devices,
                    reason="检测到多个在线设备，请先选择执行封禁的目标设备。",
                )
            raise MissingParameterException(skill_name=self.name, missing_fields=["devices"], question="当前无可用在线设备，无法下发封禁。")

        if model.time_type == "temporary":
            if model.time_unit == "d" and not (1 <= model.time_value <= 15):
                raise ValidationGuardException("temporary+d 的 time_value 必须在 1-15")
            if model.time_unit == "h" and not (1 <= model.time_value <= 360):
                raise ValidationGuardException("temporary+h 的 time_value 必须在 1-360")
            if model.time_unit == "m" and not (3 <= model.time_value <= 21600):
                raise ValidationGuardException("temporary+m 的 time_value 必须在 3-21600")

        if not model.confirm:
            raise ConfirmationRequiredException(
                skill_name=self.name,
                summary=f"即将对 {','.join(model.views or [])} 执行网侧封禁（{model.time_type}）。",
                action_payload={"skill": self.name, "params": {**prepared, "confirm": True}},
            )

        name = model.name or f"Flux封禁_{(model.views or ['unknown'])[0]}"
        payload = {
            "name": name,
            "reason": model.reason or "由Flux自动封禁",
            "timeType": model.time_type,
            "timeValue": model.time_value,
            "timeUnit": model.time_unit,
            "blockIpRule": {
                "type": model.block_type,
                "mode": model.mode,
                "view": model.views,
            },
            "devices": model.devices,
        }
        resp = self.requester.request("POST", "/api/xdr/v1/responses/blockiprule/network", json_body=payload)
        if resp.get("code") != "Success":
            raise ValidationGuardException(f"封禁失败: {resp.get('message')}")
        ids = resp.get("data", {}).get("ids", [])
        self.context_manager.store_index_mapping(session_id, "block_rules", ids)
        return [
            text_payload(
                f"封禁执行成功，生成规则ID: {', '.join(ids) if ids else 'N/A'}",
                title="网侧封禁结果",
                dangerous=True,
            )
        ]
