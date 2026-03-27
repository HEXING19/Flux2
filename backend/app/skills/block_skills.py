from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from app.core.block_devices import fetch_linkable_af_devices
from app.core.validation import (
    clean_optional_text,
    clean_text,
    infer_block_view_type,
    validate_block_view,
    validate_time_range,
)
from app.core.exceptions import ConfirmationRequiredException, MissingParameterException, ValidationGuardException
from app.core.payload import form_payload, quick_action_payload, table_payload, text_payload

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


def _format_block_views(item: dict[str, Any]) -> str:
    block_rule = item.get("blockIpRule") if isinstance(item.get("blockIpRule"), dict) else {}
    raw_views = (
        block_rule.get("view")
        or item.get("view")
        or item.get("target")
        or item.get("views")
    )
    if isinstance(raw_views, list):
        values = [str(v).strip() for v in raw_views if str(v).strip()]
        return "、".join(values) if values else "-"
    if raw_views not in (None, ""):
        return str(raw_views).strip() or "-"
    return "-"


def _dedup_text(values: list[Any]) -> list[str]:
    result: list[str] = []
    for value in values:
        text = str(value).strip()
        if text and text not in result:
            result.append(text)
    return result


def _is_multi_ip_followup_text(user_text: str) -> bool:
    text = str(user_text or "").strip()
    if not text:
        return False
    phrases = [
        "以上所有IP",
        "以上所有ip",
        "所有IP",
        "所有ip",
        "这些IP",
        "这些ip",
        "上面的IP",
        "上面的ip",
        "上述IP",
        "上述ip",
    ]
    return any(token in text for token in phrases)


def _normalize_block_views(value: Any) -> list[str] | None:
    if value is None:
        return None
    if isinstance(value, list):
        result = [str(v).strip() for v in value if str(v).strip()]
        return result or None
    if isinstance(value, str):
        result = [v.strip() for v in re.split(r"[,\s，]+", value) if v.strip()]
        return result or None
    return None


class BlockQueryInput(BaseModel):
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=10, ge=1, le=200)
    status: list[str] | None = None
    keyword: str | None = None
    startTimestamp: int | None = None
    endTimestamp: int | None = None
    time_text: str | None = None

    @field_validator("status")
    @classmethod
    def normalize_status(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        normalized: list[str] = []
        for item in value:
            text = clean_text(item)
            if text and text not in normalized:
                normalized.append(text)
        return normalized or None

    @field_validator("keyword", "time_text", mode="before")
    @classmethod
    def normalize_optional_text_fields(cls, value: str | None) -> str | None:
        return clean_optional_text(value)

    @model_validator(mode="after")
    def validate_query_time_range(self) -> "BlockQueryInput":
        validate_time_range(self.startTimestamp, self.endTimestamp)
        return self


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

    @field_validator("block_type", mode="before")
    @classmethod
    def normalize_block_type(cls, value: str | None) -> str | None:
        text = clean_optional_text(value)
        return text.upper() if text else None

    @field_validator("block_type")
    @classmethod
    def validate_block_type(cls, value: str | None) -> str | None:
        if value and value not in ALLOWED_BLOCK_TYPES:
            raise ValueError("block_type 非法")
        return value

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, value: str) -> str:
        normalized = clean_text(value).lower()
        if normalized not in {"in", "out"}:
            raise ValueError("mode 非法")
        return normalized

    @field_validator("views", mode="before")
    @classmethod
    def normalize_views(cls, value: Any) -> list[str] | None:
        return _normalize_block_views(value)

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

    @field_validator("devices")
    @classmethod
    def validate_devices(cls, value: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
        if value is None:
            return None
        if not isinstance(value, list):
            raise ValueError("devices 非法")
        normalized: list[dict[str, Any]] = []
        for idx, item in enumerate(value, start=1):
            if not isinstance(item, dict):
                raise ValueError(f"devices[{idx}] 非法")
            dev_id = item.get("devId")
            if dev_id in (None, ""):
                raise ValueError(f"devices[{idx}].devId 不能为空")
            normalized.append(
                {
                    "devId": dev_id,
                    "devName": clean_text(item.get("devName")),
                    "devType": clean_text(item.get("devType")),
                    "devVersion": clean_text(item.get("devVersion")),
                }
            )
        return normalized

    @field_validator("reason", "name", mode="before")
    @classmethod
    def normalize_reason_and_name(cls, value: str | None) -> str | None:
        return clean_optional_text(value)

    @model_validator(mode="after")
    def validate_block_action(self) -> "BlockActionInput":
        if self.time_type == "temporary":
            if self.time_value is None:
                raise ValueError("temporary 模式必须提供 time_value")
            if self.time_unit is None:
                raise ValueError("temporary 模式必须提供 time_unit")
        if self.block_type and self.views:
            self.views = [
                validate_block_view(view, block_type=self.block_type, field_name=f"views[{idx}]")
                for idx, view in enumerate(self.views, start=1)
            ]
        return self


class BlockQuerySkill(BaseSkill):
    name = "BlockQuerySkill"
    __init_schema__ = BlockQueryInput

    @staticmethod
    def _is_multi_ip_followup(user_text: str) -> bool:
        return _is_multi_ip_followup_text(user_text)

    def _build_query_payload(self, model: BlockQueryInput, keyword: str | None = None) -> dict[str, Any]:
        payload = {
            "page": model.page,
            "pageSize": model.page_size,
            "status": model.status or [],
            "startTimestamp": model.startTimestamp,
            "endTimestamp": model.endTimestamp,
        }
        if keyword:
            payload["searchInfos"] = [{"fieldName": "view", "fieldValue": keyword}]
        return payload

    def _request_rules(self, model: BlockQueryInput, keyword: str | None = None) -> tuple[list[dict[str, Any]], str | None]:
        payload = self._build_query_payload(model, keyword)
        response = self.requester.request("POST", "/api/xdr/v1/responses/blockiprule/list", json_body=payload)
        if response.get("code") != "Success":
            return [], response.get("message", "未知错误")
        items = response.get("data", {}).get("item", [])
        return items, None

    @staticmethod
    def _build_rule_rows(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        rows = []
        for idx, item in enumerate(items, start=1):
            rows.append(
                {
                    "index": idx,
                    "id": _pick(item, "id", "ruleId", "taskId"),
                    "name": _pick(item, "name", "ruleName", default="-"),
                    "status": _pick(item, "status", "dealStatus", default="-"),
                    "view": _format_block_views(item),
                    "reason": _pick(item, "reason", "remark", default="-"),
                    "updateTime": _format_ts(_pick(item, "updateTime", "createTime", default=0)),
                }
            )
        return rows

    @staticmethod
    def _append_unmatched_target_rows(rows: list[dict[str, Any]], targets: list[str]) -> list[dict[str, Any]]:
        next_index = len(rows) + 1
        for target in targets:
            rows.append(
                {
                    "index": next_index,
                    "id": "-",
                    "name": "-",
                    "status": "未封禁",
                    "view": target,
                    "reason": "未查询到封禁策略",
                    "updateTime": "-",
                }
            )
            next_index += 1
        return rows

    @staticmethod
    def _build_quick_block_actions(keyword: str) -> dict[str, Any]:
        return quick_action_payload(
            title="封禁操作建议",
            text=f"当前 {keyword} 可视为未封禁。若需要立即处置，可点击下方气泡继续填写封禁参数。",
            actions=[
                {
                    "label": f"封禁 {keyword}",
                    "message": f"封禁 {keyword}",
                    "style": "primary",
                }
            ],
        )

    def execute(self, session_id: str, params: dict[str, Any], user_text: str) -> list[dict[str, Any]]:
        prepared = dict(params)
        multi_targets: list[str] = []
        if not prepared.get("keyword"):
            recent_targets = self.context_manager.get_param(session_id, "last_entity_ips")
            if self._is_multi_ip_followup(user_text) and isinstance(recent_targets, list):
                multi_targets = _dedup_text(recent_targets)
            inherited_target = (
                self.context_manager.get_param(session_id, "last_block_target")
                or self.context_manager.get_param(session_id, "last_entity_ip")
                or self.context_manager.get_param(session_id, "keyword")
            )
            if not multi_targets and inherited_target and any(k in user_text for k in ["这个IP", "该IP", "这个地址", "它", "是否", "是不是", "有没有"]):
                prepared["keyword"] = str(inherited_target)

        model = self.validate_and_prepare(session_id, prepared)
        if multi_targets:
            self.context_manager.update_params(session_id, {"last_block_target": multi_targets[-1]})
        elif model.keyword:
            self.context_manager.update_params(session_id, {"last_block_target": model.keyword})

        if multi_targets:
            items: list[dict[str, Any]] = []
            seen_rule_ids: set[str] = set()
            unmatched_targets: list[str] = []
            for target in multi_targets:
                target_items, error = self._request_rules(model, target)
                if error:
                    return [text_payload(f"封禁策略查询失败: {error}", title="封禁策略查询")]
                if not target_items:
                    unmatched_targets.append(target)
                    continue
                for item in target_items:
                    rule_id = str(_pick(item, "id", "ruleId", "taskId", default="")).strip()
                    dedup_key = rule_id or f"{target}:{_format_block_views(item)}:{_pick(item, 'name', 'ruleName', default='-')}:{_pick(item, 'status', 'dealStatus', default='-')}"
                    if dedup_key in seen_rule_ids:
                        continue
                    seen_rule_ids.add(dedup_key)
                    items.append(item)
        else:
            items, error = self._request_rules(model, model.keyword)
            if error:
                return [text_payload(f"封禁策略查询失败: {error}", title="封禁策略查询")]

        rule_ids = [_pick(item, "id", "ruleId", "taskId") for item in items]
        rule_ids = [rule_id for rule_id in rule_ids if rule_id]
        self.context_manager.store_index_mapping(session_id, "block_rules", rule_ids)

        rows = self._build_rule_rows(items)
        if multi_targets and unmatched_targets:
            rows = self._append_unmatched_target_rows(rows, unmatched_targets)

        if not rows:
            target = "、".join(multi_targets) if multi_targets else (model.keyword or "目标对象")
            payloads = [
                text_payload(f"未查询到 {target} 的封禁策略，当前可视为未封禁。", title="封禁策略查询"),
            ]
            if model.keyword and not multi_targets:
                payloads.append(self._build_quick_block_actions(model.keyword))
            return payloads

        summary_text = (
            f"已查询 {len(multi_targets)} 个IP，共命中 {len(items)} 条封禁策略"
            + (f"，其中 {len(unmatched_targets)} 个IP未命中策略。" if unmatched_targets else "。")
            if multi_targets
            else f"已查询 {len(rows)} 条封禁策略并建立序号映射。"
        )
        return [
            text_payload(summary_text, title="封禁策略查询"),
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

    def _lookup_linkable_devices(self) -> dict[str, Any]:
        return fetch_linkable_af_devices(self.requester)

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
        inferred = infer_block_view_type(first)
        if inferred == "ip":
            return "SRC_IP"
        if inferred == "url":
            return "URL"
        if inferred == "domain":
            return "DNS"
        return None

    @staticmethod
    def _normalize_views(value: Any) -> list[str] | None:
        return _normalize_block_views(value)

    def _normalize_prepared(self, prepared: dict[str, Any], linkable_devices: list[dict[str, Any]]) -> dict[str, Any]:
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
                chosen = next((d for d in linkable_devices if str(d.get("deviceId")) == str(device_id)), None)
                if chosen:
                    normalized["devices"] = [self._to_block_device(chosen)]
            elif len(linkable_devices) == 1:
                normalized["devices"] = [self._to_block_device(linkable_devices[0])]

        return normalized

    def _build_param_form(
        self,
        session_id: str,
        prepared: dict[str, Any],
        linkable_devices: list[dict[str, Any]],
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
                "title": "IP 类型只接受 IPv4；域名类型只接受域名；URL 类型需填写完整 URL 或 host/path。",
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
                "min": 1,
                "max": 21600,
                "step": 1,
                "inputmode": "numeric",
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

        if linkable_devices:
            default_device_id = prepared.get("device_id")
            if default_device_id in (None, ""):
                default_device_id = str(linkable_devices[0].get("deviceId"))
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
                        for d in linkable_devices
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
                    "placeholder": "请先在平台确认 AF 设备可联动，再填写设备ID重试",
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
            recent_targets = self.context_manager.get_param(session_id, "last_entity_ips")
            if _is_multi_ip_followup_text(user_text) and isinstance(recent_targets, list):
                prepared["views"] = _dedup_text(recent_targets)
            inherited_target = (
                self.context_manager.get_param(session_id, "last_block_target")
                or self.context_manager.get_param(session_id, "last_entity_ip")
                or self.context_manager.get_param(session_id, "keyword")
            )
            if not prepared.get("views") and inherited_target and any(k in user_text for k in ["它", "该IP", "这个IP", "这个地址", "这个实体", "封禁"]):
                prepared["views"] = [str(inherited_target)]

        device_lookup = self._lookup_linkable_devices()
        linkable_devices = device_lookup.get("devices") or []
        prepared = self._normalize_prepared(prepared, linkable_devices)
        if prepared.get("views"):
            self.ensure_safe_gate_targets({"views": prepared.get("views")})

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
            if not linkable_devices:
                missing.append("联动设备")
            elif len(linkable_devices) > 1 and not prepared.get("device_id"):
                missing.append("联动设备")
            elif prepared.get("device_id"):
                missing.append("联动设备(请确认设备可联动)")

        if missing:
            reason = f"请先补充参数后再执行封禁，当前缺少：{'、'.join(missing)}。"
            if not linkable_devices:
                lookup_message = str(device_lookup.get("message") or "").strip()
                if lookup_message:
                    reason += f" {lookup_message}"
                else:
                    reason += " 当前未检测到可联动 AF 设备，请先在平台检查设备接入与在线状态。"
            return self._build_param_form(session_id, prepared, linkable_devices, reason=reason)

        model = self.validate_and_prepare(session_id, prepared)

        if not model.devices:
            if len(linkable_devices) > 1:
                return self._build_param_form(
                    session_id,
                    prepared,
                    linkable_devices,
                    reason="检测到多台可联动设备，请先选择执行封禁的目标设备。",
                )
            raise MissingParameterException(
                skill_name=self.name,
                missing_fields=["devices"],
                question=str(device_lookup.get("message") or "当前无可用可联动设备，无法下发封禁。"),
            )

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
