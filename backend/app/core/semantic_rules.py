from __future__ import annotations

import copy
import json
import re
from typing import Any

from app.core.validation import clean_optional_text, clean_text


SEVERITY_OPTIONS = [
    {"value": 0, "label": "信息"},
    {"value": 1, "label": "低危"},
    {"value": 2, "label": "中危"},
    {"value": 3, "label": "高危"},
    {"value": 4, "label": "严重"},
]

EVENT_STATUS_OPTIONS = [
    {"value": 0, "label": "待处置"},
    {"value": 10, "label": "处置中"},
    {"value": 40, "label": "已处置"},
    {"value": 50, "label": "已挂起"},
    {"value": 60, "label": "接受风险"},
    {"value": 70, "label": "已遏制"},
]

BLOCK_TYPE_OPTIONS = [
    {"value": "SRC_IP", "label": "源IP"},
    {"value": "DST_IP", "label": "目的IP"},
    {"value": "DNS", "label": "域名"},
    {"value": "URL", "label": "URL"},
]

TIME_TYPE_OPTIONS = [
    {"value": "temporary", "label": "临时封禁"},
    {"value": "forever", "label": "永久封禁"},
]

TIME_UNIT_OPTIONS = [
    {"value": "m", "label": "分钟"},
    {"value": "h", "label": "小时"},
    {"value": "d", "label": "天"},
]

ANALYTICS_GROUP_OPTIONS = [
    {"value": "day", "label": "按天"},
    {"value": "hour", "label": "按小时"},
]

BLOCK_STATUS_OPTIONS = [
    {"value": "block success", "label": "封禁成功"},
    {"value": "block failed", "label": "封禁失败"},
    {"value": "unblocked", "label": "未封禁"},
]

MATCH_MODE_OPTIONS = {
    "contains": "包含匹配",
    "exact": "完整匹配",
    "regex": "正则匹配",
}

ACTION_TYPE_OPTIONS = {
    "append": "追加到参数",
    "replace": "直接替换参数",
    "set_if_missing": "仅在未指定时生效",
}

SEMANTIC_RULE_META: dict[str, dict[str, Any]] = {
    "event_query": {
        "label": "事件查询",
        "targets": {
            "severities": {
                "label": "事件等级",
                "value_type": "int",
                "editor": "enum",
                "multiple": True,
                "options": SEVERITY_OPTIONS,
                "supported_actions": ["append", "replace", "set_if_missing"],
                "default_action": "append",
            },
            "deal_status": {
                "label": "处置状态",
                "value_type": "int",
                "editor": "enum",
                "multiple": True,
                "options": EVENT_STATUS_OPTIONS,
                "supported_actions": ["append", "replace", "set_if_missing"],
                "default_action": "append",
            },
            "time_text": {
                "label": "时间范围表达",
                "value_type": "string",
                "editor": "text",
                "multiple": False,
                "placeholder": "如：昨天、最近三天、近12小时",
                "supported_actions": ["replace", "set_if_missing"],
                "default_action": "set_if_missing",
            },
            "page_size": {
                "label": "返回条数",
                "value_type": "int",
                "editor": "number",
                "multiple": False,
                "min": 5,
                "max": 200,
                "supported_actions": ["replace", "set_if_missing"],
                "default_action": "set_if_missing",
            },
        },
    },
    "log_stats": {
        "label": "日志统计",
        "targets": {
            "severities": {
                "label": "事件等级",
                "value_type": "int",
                "editor": "enum",
                "multiple": True,
                "options": SEVERITY_OPTIONS,
                "supported_actions": ["append", "replace", "set_if_missing"],
                "default_action": "append",
            },
            "time_text": {
                "label": "时间范围表达",
                "value_type": "string",
                "editor": "text",
                "multiple": False,
                "placeholder": "如：最近一周、昨天、本月",
                "supported_actions": ["replace", "set_if_missing"],
                "default_action": "set_if_missing",
            },
        },
    },
    "event_trend": {
        "label": "事件趋势分析",
        "targets": {
            "severities": {
                "label": "事件等级",
                "value_type": "int",
                "editor": "enum",
                "multiple": True,
                "options": SEVERITY_OPTIONS,
                "supported_actions": ["append", "replace", "set_if_missing"],
                "default_action": "append",
            },
            "time_text": {
                "label": "时间范围表达",
                "value_type": "string",
                "editor": "text",
                "multiple": False,
                "placeholder": "如：最近7天、近24小时",
                "supported_actions": ["replace", "set_if_missing"],
                "default_action": "set_if_missing",
            },
            "page_size": {
                "label": "返回条数",
                "value_type": "int",
                "editor": "number",
                "multiple": False,
                "min": 1,
                "max": 50,
                "supported_actions": ["replace", "set_if_missing"],
                "default_action": "set_if_missing",
            },
            "top_n": {
                "label": "TopN",
                "value_type": "int",
                "editor": "number",
                "multiple": False,
                "min": 1,
                "max": 20,
                "supported_actions": ["replace", "set_if_missing"],
                "default_action": "set_if_missing",
            },
            "group_by": {
                "label": "聚合粒度",
                "value_type": "string",
                "editor": "enum",
                "multiple": False,
                "options": ANALYTICS_GROUP_OPTIONS,
                "supported_actions": ["replace", "set_if_missing"],
                "default_action": "set_if_missing",
            },
        },
    },
    "event_type_distribution": {
        "label": "事件类型分布",
        "targets": {
            "severities": {
                "label": "事件等级",
                "value_type": "int",
                "editor": "enum",
                "multiple": True,
                "options": SEVERITY_OPTIONS,
                "supported_actions": ["append", "replace", "set_if_missing"],
                "default_action": "append",
            },
            "time_text": {
                "label": "时间范围表达",
                "value_type": "string",
                "editor": "text",
                "multiple": False,
                "placeholder": "如：最近7天、最近三天",
                "supported_actions": ["replace", "set_if_missing"],
                "default_action": "set_if_missing",
            },
            "page_size": {
                "label": "返回条数",
                "value_type": "int",
                "editor": "number",
                "multiple": False,
                "min": 1,
                "max": 50,
                "supported_actions": ["replace", "set_if_missing"],
                "default_action": "set_if_missing",
            },
            "top_n": {
                "label": "TopN",
                "value_type": "int",
                "editor": "number",
                "multiple": False,
                "min": 1,
                "max": 20,
                "supported_actions": ["replace", "set_if_missing"],
                "default_action": "set_if_missing",
            },
            "group_by": {
                "label": "聚合粒度",
                "value_type": "string",
                "editor": "enum",
                "multiple": False,
                "options": ANALYTICS_GROUP_OPTIONS,
                "supported_actions": ["replace", "set_if_missing"],
                "default_action": "set_if_missing",
            },
        },
    },
    "event_disposition_summary": {
        "label": "事件处置成果",
        "targets": {
            "severities": {
                "label": "事件等级",
                "value_type": "int",
                "editor": "enum",
                "multiple": True,
                "options": SEVERITY_OPTIONS,
                "supported_actions": ["append", "replace", "set_if_missing"],
                "default_action": "append",
            },
            "time_text": {
                "label": "时间范围表达",
                "value_type": "string",
                "editor": "text",
                "multiple": False,
                "placeholder": "如：最近7天、近24小时",
                "supported_actions": ["replace", "set_if_missing"],
                "default_action": "set_if_missing",
            },
            "page_size": {
                "label": "返回条数",
                "value_type": "int",
                "editor": "number",
                "multiple": False,
                "min": 1,
                "max": 50,
                "supported_actions": ["replace", "set_if_missing"],
                "default_action": "set_if_missing",
            },
            "top_n": {
                "label": "TopN",
                "value_type": "int",
                "editor": "number",
                "multiple": False,
                "min": 1,
                "max": 20,
                "supported_actions": ["replace", "set_if_missing"],
                "default_action": "set_if_missing",
            },
            "group_by": {
                "label": "聚合粒度",
                "value_type": "string",
                "editor": "enum",
                "multiple": False,
                "options": ANALYTICS_GROUP_OPTIONS,
                "supported_actions": ["replace", "set_if_missing"],
                "default_action": "set_if_missing",
            },
        },
    },
    "key_event_insight": {
        "label": "重点事件解读",
        "targets": {
            "severities": {
                "label": "事件等级",
                "value_type": "int",
                "editor": "enum",
                "multiple": True,
                "options": SEVERITY_OPTIONS,
                "supported_actions": ["append", "replace", "set_if_missing"],
                "default_action": "append",
            },
            "time_text": {
                "label": "时间范围表达",
                "value_type": "string",
                "editor": "text",
                "multiple": False,
                "placeholder": "如：最近7天、昨天",
                "supported_actions": ["replace", "set_if_missing"],
                "default_action": "set_if_missing",
            },
            "page_size": {
                "label": "返回条数",
                "value_type": "int",
                "editor": "number",
                "multiple": False,
                "min": 1,
                "max": 50,
                "supported_actions": ["replace", "set_if_missing"],
                "default_action": "set_if_missing",
            },
            "top_n": {
                "label": "TopN",
                "value_type": "int",
                "editor": "number",
                "multiple": False,
                "min": 1,
                "max": 20,
                "supported_actions": ["replace", "set_if_missing"],
                "default_action": "set_if_missing",
            },
            "group_by": {
                "label": "聚合粒度",
                "value_type": "string",
                "editor": "enum",
                "multiple": False,
                "options": ANALYTICS_GROUP_OPTIONS,
                "supported_actions": ["replace", "set_if_missing"],
                "default_action": "set_if_missing",
            },
        },
    },
    "alert_classification_summary": {
        "label": "告警分类分析",
        "targets": {
            "severities": {
                "label": "告警等级",
                "value_type": "int",
                "editor": "enum",
                "multiple": True,
                "options": SEVERITY_OPTIONS,
                "supported_actions": ["append", "replace", "set_if_missing"],
                "default_action": "append",
            },
            "time_text": {
                "label": "时间范围表达",
                "value_type": "string",
                "editor": "text",
                "multiple": False,
                "placeholder": "如：最近7天、近24小时",
                "supported_actions": ["replace", "set_if_missing"],
                "default_action": "set_if_missing",
            },
            "page_size": {
                "label": "返回条数",
                "value_type": "int",
                "editor": "number",
                "multiple": False,
                "min": 1,
                "max": 50,
                "supported_actions": ["replace", "set_if_missing"],
                "default_action": "set_if_missing",
            },
            "top_n": {
                "label": "TopN",
                "value_type": "int",
                "editor": "number",
                "multiple": False,
                "min": 1,
                "max": 20,
                "supported_actions": ["replace", "set_if_missing"],
                "default_action": "set_if_missing",
            },
            "group_by": {
                "label": "聚合粒度",
                "value_type": "string",
                "editor": "enum",
                "multiple": False,
                "options": ANALYTICS_GROUP_OPTIONS,
                "supported_actions": ["replace", "set_if_missing"],
                "default_action": "set_if_missing",
            },
        },
    },
    "block_query": {
        "label": "封禁状态查询",
        "targets": {
            "status": {
                "label": "封禁状态筛选",
                "value_type": "string",
                "editor": "enum",
                "multiple": True,
                "options": BLOCK_STATUS_OPTIONS,
                "supported_actions": ["append", "replace", "set_if_missing"],
                "default_action": "append",
            },
            "time_text": {
                "label": "时间范围表达",
                "value_type": "string",
                "editor": "text",
                "multiple": False,
                "placeholder": "如：最近三天、近24小时",
                "supported_actions": ["replace", "set_if_missing"],
                "default_action": "set_if_missing",
            },
        },
    },
    "block_action": {
        "label": "封禁动作",
        "targets": {
            "block_type": {
                "label": "封禁对象类型",
                "value_type": "string",
                "editor": "enum",
                "multiple": False,
                "options": BLOCK_TYPE_OPTIONS,
                "supported_actions": ["replace", "set_if_missing"],
                "default_action": "set_if_missing",
            },
            "time_type": {
                "label": "封禁方式",
                "value_type": "string",
                "editor": "enum",
                "multiple": False,
                "options": TIME_TYPE_OPTIONS,
                "supported_actions": ["replace", "set_if_missing"],
                "default_action": "set_if_missing",
            },
            "time_value": {
                "label": "封禁时长数值",
                "value_type": "int",
                "editor": "number",
                "multiple": False,
                "min": 1,
                "max": 21600,
                "supported_actions": ["replace", "set_if_missing"],
                "default_action": "set_if_missing",
            },
            "time_unit": {
                "label": "封禁时长单位",
                "value_type": "string",
                "editor": "enum",
                "multiple": False,
                "options": TIME_UNIT_OPTIONS,
                "supported_actions": ["replace", "set_if_missing"],
                "default_action": "set_if_missing",
            },
        },
    },
}


def normalize_rule_text(value: object) -> str:
    return clean_text(value).casefold()


def validate_rule_domain(value: object) -> str:
    text = clean_text(value)
    if text not in SEMANTIC_RULE_META:
        raise ValueError("domain 不受支持。")
    return text


def get_target_meta(domain: object, slot_name: object) -> dict[str, Any]:
    domain_text = validate_rule_domain(domain)
    slot_text = clean_text(slot_name)
    targets = SEMANTIC_RULE_META[domain_text].get("targets") or {}
    if slot_text not in targets:
        raise ValueError("slot_name 不受支持。")
    return targets[slot_text]


def validate_rule_slot(domain: object, slot_name: object) -> str:
    _ = get_target_meta(domain, slot_name)
    return clean_text(slot_name)


def validate_match_mode(value: object) -> str:
    text = clean_text(value) or "contains"
    if text not in MATCH_MODE_OPTIONS:
        raise ValueError("match_mode 不受支持。")
    return text


def validate_phrase(value: object, *, match_mode: object = "contains") -> str:
    text = clean_text(value)
    if not text:
        raise ValueError("phrase 不能为空。")
    if validate_match_mode(match_mode) == "regex":
        try:
            re.compile(text, re.IGNORECASE)
        except re.error as exc:
            raise ValueError("正则表达式不合法。") from exc
    return text


def validate_description(value: object) -> str | None:
    return clean_optional_text(value)


def validate_action_type(domain: object, slot_name: object, value: object | None) -> str:
    target_meta = get_target_meta(domain, slot_name)
    action = clean_text(value) or clean_text(target_meta.get("default_action")) or "append"
    supported = target_meta.get("supported_actions") or []
    if action not in ACTION_TYPE_OPTIONS or action not in supported:
        raise ValueError("action_type 不受支持。")
    return action


def _normalize_single_value(target_meta: dict[str, Any], value: Any) -> Any:
    value_type = clean_text(target_meta.get("value_type")) or "string"
    if value_type == "int":
        try:
            normalized = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError("rule_value 中存在非法数字。") from exc
        min_value = target_meta.get("min")
        max_value = target_meta.get("max")
        if min_value is not None and normalized < int(min_value):
            raise ValueError(f"rule_value 不能小于 {min_value}。")
        if max_value is not None and normalized > int(max_value):
            raise ValueError(f"rule_value 不能大于 {max_value}。")
        return normalized

    normalized = clean_text(value)
    if not normalized:
        raise ValueError("rule_value 不能为空。")
    return normalized


def _validate_options(target_meta: dict[str, Any], value: Any) -> Any:
    options = target_meta.get("options") or []
    if not options:
        return value
    allowed = {option["value"] for option in options}
    if value not in allowed:
        raise ValueError("rule_value 中存在未定义枚举值。")
    return value


def normalize_rule_value(domain: object, slot_name: object, action_type: object, rule_value: Any) -> Any:
    target_meta = get_target_meta(domain, slot_name)
    action = validate_action_type(domain, slot_name, action_type)
    multiple = bool(target_meta.get("multiple"))

    if multiple:
        if not isinstance(rule_value, list):
            raise ValueError("rule_value 必须是数组。")
        normalized: list[Any] = []
        seen: set[Any] = set()
        for item in rule_value:
            single = _normalize_single_value(target_meta, item)
            single = _validate_options(target_meta, single)
            if single in seen:
                continue
            seen.add(single)
            normalized.append(single)
        if not normalized:
            raise ValueError("rule_value 不能为空。")
        return normalized

    if isinstance(rule_value, list):
        raise ValueError("当前目标参数只接受单个值。")
    single = _normalize_single_value(target_meta, rule_value)
    single = _validate_options(target_meta, single)
    if action == "append":
        raise ValueError("append 仅支持多值目标参数。")
    return single


def decode_rule_payload(raw: str | None) -> dict[str, Any]:
    if not raw:
        return {"action_type": "append", "rule_value": []}
    try:
        payload = copy.deepcopy(json.loads(raw))
    except Exception:
        return {"action_type": "append", "rule_value": []}
    if isinstance(payload, list):
        return {"action_type": "append", "rule_value": payload}
    if isinstance(payload, dict):
        action_type = clean_text(payload.get("action_type")) or "append"
        if action_type not in ACTION_TYPE_OPTIONS:
            action_type = "append"
        return {"action_type": action_type, "rule_value": payload.get("rule_value")}
    return {"action_type": "append", "rule_value": []}


def encode_rule_payload(action_type: object, rule_value: Any) -> str:
    return json.dumps(
        {
            "action_type": validate_match_or_action_passthrough(action_type, kind="action"),
            "rule_value": rule_value,
        },
        ensure_ascii=False,
    )


def validate_match_or_action_passthrough(value: object, *, kind: str) -> str:
    if kind == "action":
        text = clean_text(value) or "append"
        if text not in ACTION_TYPE_OPTIONS:
            raise ValueError("action_type 不受支持。")
        return text
    return validate_match_mode(value)


def get_rule_meta_payload() -> dict[str, Any]:
    domains: list[dict[str, Any]] = []
    for domain, domain_meta in SEMANTIC_RULE_META.items():
        targets: list[dict[str, Any]] = []
        for slot_name, slot_meta in (domain_meta.get("targets") or {}).items():
            supported_actions = slot_meta.get("supported_actions") or []
            targets.append(
                {
                    "value": slot_name,
                    "label": slot_meta.get("label") or slot_name,
                    "value_type": slot_meta.get("value_type") or "string",
                    "editor": slot_meta.get("editor") or "text",
                    "multiple": bool(slot_meta.get("multiple")),
                    "options": list(slot_meta.get("options") or []),
                    "placeholder": slot_meta.get("placeholder"),
                    "min": slot_meta.get("min"),
                    "max": slot_meta.get("max"),
                    "default_action": slot_meta.get("default_action") or "append",
                    "supported_actions": [
                        {"value": action, "label": ACTION_TYPE_OPTIONS[action]} for action in supported_actions
                    ],
                }
            )
        domains.append(
            {
                "value": domain,
                "label": domain_meta.get("label") or domain,
                "targets": targets,
            }
        )
    return {
        "domains": domains,
        "match_modes": [{"value": value, "label": label} for value, label in MATCH_MODE_OPTIONS.items()],
        "action_types": [{"value": value, "label": label} for value, label in ACTION_TYPE_OPTIONS.items()],
    }


def get_domain_label(domain: object) -> str:
    text = validate_rule_domain(domain)
    return str(SEMANTIC_RULE_META[text]["label"])


def get_slot_label(domain: object, slot_name: object) -> str:
    return str(get_target_meta(domain, slot_name).get("label") or clean_text(slot_name))


def get_match_mode_label(match_mode: object) -> str:
    mode = validate_match_mode(match_mode)
    return MATCH_MODE_OPTIONS[mode]


def get_action_type_label(action_type: object) -> str:
    action = validate_match_or_action_passthrough(action_type, kind="action")
    return ACTION_TYPE_OPTIONS[action]


def get_rule_value_labels(domain: object, slot_name: object, rule_value: Any) -> list[str]:
    target_meta = get_target_meta(domain, slot_name)
    values = rule_value if isinstance(rule_value, list) else [rule_value]
    option_map = {option["value"]: option["label"] for option in target_meta.get("options") or []}
    labels: list[str] = []
    for value in values:
        if value in (None, ""):
            continue
        labels.append(str(option_map.get(value, value)))
    return labels


def match_rule_phrase(text: object, phrase: object, match_mode: object = "contains") -> bool:
    normalized_text = normalize_rule_text(text)
    raw_phrase = clean_text(phrase)
    mode = validate_match_mode(match_mode)
    if not normalized_text or not raw_phrase:
        return False
    if mode == "exact":
        return normalized_text == normalize_rule_text(raw_phrase)
    if mode == "regex":
        try:
            return bool(re.search(raw_phrase, str(text or ""), flags=re.IGNORECASE))
        except re.error:
            return False
    return normalize_rule_text(raw_phrase) in normalized_text


def apply_rule_to_params(params: dict[str, Any], *, domain: object, slot_name: object, action_type: object, rule_value: Any) -> None:
    slot = validate_rule_slot(domain, slot_name)
    normalized_action = validate_action_type(domain, slot, action_type)
    normalized_value = normalize_rule_value(domain, slot, normalized_action, rule_value)

    if normalized_action == "replace":
        params[slot] = copy.deepcopy(normalized_value)
        return

    current = params.get(slot)
    if normalized_action == "set_if_missing":
        if current not in (None, "", []):
            return
        params[slot] = copy.deepcopy(normalized_value)
        return

    current_list = current if isinstance(current, list) else []
    merged: list[Any] = []
    seen: set[Any] = set()
    for item in current_list:
        if item in seen:
            continue
        seen.add(item)
        merged.append(item)
    for item in normalized_value:
        if item in seen:
            continue
        seen.add(item)
        merged.append(item)
    params[slot] = merged
