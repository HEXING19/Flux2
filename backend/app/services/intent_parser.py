from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from app.core.semantic_rules import apply_rule_to_params, match_rule_phrase
from app.core.time_parser import parse_cn_number


SEVERITY_MAP = {
    "信息": 0,
    "低危": 1,
    "中危": 2,
    "高危": 3,
    "严重": 4,
}

DEAL_STATUS_MAP = {
    "待处置": 0,
    "未处置": 0,
    "处置中": 10,
    "已处置": 40,
    "已挂起": 50,
    "接受风险": 60,
    "已遏制": 70,
}

BLOCK_TYPE_MAP = {
    "源ip": "SRC_IP",
    "源IP": "SRC_IP",
    "目的ip": "DST_IP",
    "目的IP": "DST_IP",
    "url": "URL",
    "链接": "URL",
    "域名": "DNS",
    "dns": "DNS",
}

IPV4_PATTERN = r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)"
DOMAIN_PATTERN = r"(?<![a-zA-Z0-9-])(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?![a-zA-Z0-9-])"


@dataclass
class ParsedIntent:
    intent: str
    params: dict[str, Any]


class IntentParser:
    def parse(self, text: str, semantic_rules: list[dict[str, Any]] | None = None) -> ParsedIntent:
        normalized = text.strip()

        if normalized in {"确认", "同意", "批准", "执行"}:
            return ParsedIntent(intent="confirm_pending", params={})
        if normalized in {"取消", "拒绝", "算了"}:
            return ParsedIntent(intent="cancel_pending", params={})

        if any(k in normalized for k in ["运行工作流", "触发闭环", "执行闭环"]):
            return ParsedIntent(intent="workflow_trigger", params={})

        if any(k in normalized for k in ["审批", "批准", "驳回"]):
            return ParsedIntent(intent="workflow_approval", params={})

        if any(k in normalized for k in ["日志统计", "日志数量", "日志趋势", "网络安全日志", "日志总数", "安全日志"]):
            return ParsedIntent(intent="log_stats", params=self._parse_common_filters(normalized, intent="log_stats", semantic_rules=semantic_rules))

        if self._looks_like_event_trend(normalized):
            return ParsedIntent(
                intent="event_trend",
                params=self._parse_security_analytics_filters(normalized, intent="event_trend", semantic_rules=semantic_rules),
            )

        if self._looks_like_alert_trend(normalized):
            return ParsedIntent(
                intent="alert_trend",
                params=self._parse_security_analytics_filters(normalized, intent="alert_trend", semantic_rules=semantic_rules),
            )

        if self._looks_like_event_type_distribution(normalized):
            return ParsedIntent(
                intent="event_type_distribution",
                params=self._parse_security_analytics_filters(
                    normalized, intent="event_type_distribution", semantic_rules=semantic_rules
                ),
            )

        if self._looks_like_event_disposition_summary(normalized):
            return ParsedIntent(
                intent="event_disposition_summary",
                params=self._parse_security_analytics_filters(
                    normalized, intent="event_disposition_summary", semantic_rules=semantic_rules
                ),
            )

        if self._looks_like_key_event_insight(normalized):
            return ParsedIntent(
                intent="key_event_insight",
                params=self._parse_security_analytics_filters(normalized, intent="key_event_insight", semantic_rules=semantic_rules),
            )

        if self._looks_like_alert_classification_summary(normalized):
            return ParsedIntent(
                intent="alert_classification_summary",
                params=self._parse_security_analytics_filters(
                    normalized, intent="alert_classification_summary", semantic_rules=semantic_rules
                ),
            )

        if self._looks_like_block_query(normalized):
            params = self._parse_common_filters(normalized, intent="block_query", semantic_rules=semantic_rules)
            keyword = self._extract_keyword(normalized)
            if not keyword:
                keyword = self._extract_ip_or_domain(normalized)
            if keyword:
                params["keyword"] = keyword
            return ParsedIntent(intent="block_query", params=params)

        if any(k in normalized for k in ["封禁", "拉黑", "阻断"]) and not self._looks_like_block_query(normalized):
            params = self._parse_block_action(normalized, semantic_rules=semantic_rules)
            return ParsedIntent(intent="block_action", params=params)

        if any(k in normalized for k in ["实体", "情报", "外网ip", "外网IP"]):
            return ParsedIntent(intent="entity_query", params=self._parse_entity_query(normalized))

        if any(k in normalized for k in ["详情", "举证", "时间线"]) and any(k in normalized for k in ["事件", "告警", "第"]):
            return ParsedIntent(intent="event_detail", params={"ref_text": normalized})

        if any(k in normalized for k in ["处置", "标记", "挂起", "接受风险", "遏制"]):
            params = self._parse_event_action(normalized)
            return ParsedIntent(intent="event_action", params=params)

        if self._looks_like_alert_query(normalized):
            params = self._parse_common_filters(normalized, intent="alert_query", semantic_rules=semantic_rules)
            return ParsedIntent(intent="alert_query", params=params)

        if self._looks_like_event_query(normalized):
            params = self._parse_common_filters(normalized, intent="event_query", semantic_rules=semantic_rules)
            return ParsedIntent(intent="event_query", params=params)

        return ParsedIntent(intent="chat_fallback", params={"query": normalized})

    @staticmethod
    def _merge_param_list(params: dict[str, Any], key: str, values: list[Any]) -> None:
        if not values:
            return
        existing = params.get(key)
        merged: list[Any] = []
        seen: set[Any] = set()
        if isinstance(existing, list):
            for item in existing:
                if item in seen:
                    continue
                seen.add(item)
                merged.append(item)
        for item in values:
            if item in seen:
                continue
            seen.add(item)
            merged.append(item)
        if merged:
            params[key] = merged

    def _apply_semantic_rules(
        self,
        text: str,
        *,
        intent: str,
        params: dict[str, Any],
        semantic_rules: list[dict[str, Any]] | None = None,
    ) -> None:
        rules = sorted(semantic_rules or [], key=lambda item: int(item.get("priority", 100)))
        for rule in rules:
            if str(rule.get("domain") or "").strip() != intent:
                continue
            phrase = str(rule.get("phrase") or "").strip()
            if not phrase or not match_rule_phrase(text, phrase, rule.get("match_mode") or "contains"):
                continue
            slot_name = str(rule.get("slot_name") or "").strip()
            action_type = rule.get("action_type") or "append"
            rule_value = rule.get("rule_value")
            if slot_name:
                try:
                    apply_rule_to_params(params, domain=intent, slot_name=slot_name, action_type=action_type, rule_value=rule_value)
                except ValueError:
                    continue

    def _parse_common_filters(
        self,
        text: str,
        *,
        intent: str,
        semantic_rules: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {}

        severities = self._extract_severities(text)
        if severities:
            params["severities"] = sorted(set(severities))

        statuses = [v for k, v in DEAL_STATUS_MAP.items() if k in text]
        if statuses:
            params["deal_status"] = sorted(set(statuses))

        time_text = self._extract_time_text(text)
        if time_text:
            params["time_text"] = time_text

        page_size = self._extract_page_size(text)
        if page_size:
            params["page_size"] = page_size

        self._apply_semantic_rules(text, intent=intent, params=params, semantic_rules=semantic_rules)
        return params

    def _parse_security_analytics_filters(
        self,
        text: str,
        *,
        intent: str,
        semantic_rules: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        params = self._parse_common_filters(text, intent=intent, semantic_rules=semantic_rules)
        top_n = self._extract_top_n(text)
        if top_n:
            params["top_n"] = top_n
        return params

    @staticmethod
    def _extract_time_text(text: str) -> str | None:
        time_match = re.search(
            r"((?:最近|近|过去)?\s*(?:\d+|[一二两三四五六七八九十]+)\s*(?:天|小时|分钟)|昨天|今天|本周|本月|近一周|最近三天)",
            text,
        )
        if not time_match:
            return None
        return re.sub(r"\s+", "", time_match.group(1))

    @staticmethod
    def _extract_page_size(text: str) -> int | None:
        page_match = re.search(r"前\s*(\d+|[一二两三四五六七八九十]+)\s*条", text)
        if not page_match:
            return None
        count = parse_cn_number(page_match.group(1))
        if not count:
            return None
        return min(200, max(5, count))

    @staticmethod
    def _extract_top_n(text: str) -> int | None:
        patterns = [
            r"[Tt][Oo][Pp]\s*(\d+|[一二两三四五六七八九十]+)",
            r"前\s*(\d+|[一二两三四五六七八九十]+)\s*(?:类|种|项)",
            r"重点事件(?:解读|分析)?\s*(\d+|[一二两三四五六七八九十]+)\s*(?:条|个)",
        ]
        for pattern in patterns:
            matched = re.search(pattern, text)
            if not matched:
                continue
            count = parse_cn_number(matched.group(1))
            if count:
                return min(20, max(1, count))
        return None

    @staticmethod
    def _looks_like_event_trend(text: str) -> bool:
        keywords = ("趋势", "发生趋势", "态势趋势", "每天多少事件")
        return "事件" in text and any(keyword in text for keyword in keywords)

    @staticmethod
    def _looks_like_alert_trend(text: str) -> bool:
        keywords = ("趋势", "发生趋势", "态势趋势", "每天多少告警")
        exclusions = ("分类", "分布")
        return "告警" in text and any(keyword in text for keyword in keywords) and not any(token in text for token in exclusions)

    @staticmethod
    def _looks_like_event_type_distribution(text: str) -> bool:
        keywords = ("类型分布", "事件分布", "威胁类型分布", "事件分类分布")
        return "事件" in text and any(keyword in text for keyword in keywords)

    @staticmethod
    def _looks_like_event_disposition_summary(text: str) -> bool:
        keywords = ("处置成果", "处置情况", "处置效果", "处置统计")
        return "事件" in text and any(keyword in text for keyword in keywords)

    @staticmethod
    def _looks_like_key_event_insight(text: str) -> bool:
        keywords = ("重点事件解读", "重点安全事件", "重点事件分析", "帮我解读重点事件")
        return any(keyword in text for keyword in keywords)

    @staticmethod
    def _looks_like_alert_classification_summary(text: str) -> bool:
        keywords = ("告警分类情况", "告警分类分布", "告警一级分类", "告警二级分类", "告警三级分类")
        return "告警" in text and any(keyword in text for keyword in keywords)

    @staticmethod
    def _looks_like_alert_query(text: str) -> bool:
        query_tokens = ("查询", "查看", "看下", "看看", "查下", "查一下", "列出", "列表", "清单", "信息", "有哪些", "有什么")
        exclusions = ("趋势", "分类", "分布", "处置成果", "处置情况", "重点事件", "解读")
        return "告警" in text and any(token in text for token in query_tokens) and not any(token in text for token in exclusions)

    @staticmethod
    def _looks_like_event_query(text: str) -> bool:
        query_tokens = ("事件", "incident", "查询", "查看", "看下", "看看", "查下", "查一下", "列出", "列表", "清单", "信息", "有哪些", "有什么")
        return any(token in text for token in query_tokens)

    @staticmethod
    def _extract_severities(text: str) -> list[int]:
        severities = [value for label, value in SEVERITY_MAP.items() if label != "信息" and label in text]
        if re.search(r"信息(?:级|级别|类|告警|事件)", text):
            severities.append(SEVERITY_MAP["信息"])
        return severities

    def _extract_keyword(self, text: str) -> str | None:
        m = re.search(r"(?:包含|关键词|匹配)([\w\u4e00-\u9fa5.:_-]{1,32})", text)
        if m:
            return m.group(1)
        return None

    def _looks_like_block_query(self, text: str) -> bool:
        explicit = [
            "封禁状态",
            "封禁策略",
            "查询封禁",
            "封禁列表",
            "是否被封禁",
            "被封禁",
            "已封禁",
            "被封了吗",
            "有没有被封",
            "有无被封",
            "是不是被封",
        ]
        if any(token in text for token in explicit):
            return True

        query_verb = any(token in text for token in ["查询", "查看", "检查", "核查", "确认", "查下"])
        if query_verb and "封禁" in text:
            return True

        # "查xxx是否封禁" style without explicit query keyword
        if text.startswith("查") and "封禁" in text:
            return True

        if "封禁" in text and any(token in text for token in ["是否", "是不是", "有没有", "有无"]):
            return True

        return False

    def _extract_ip_or_domain(self, text: str) -> str | None:
        ip_match = re.search(IPV4_PATTERN, text)
        if ip_match:
            return ip_match.group(0)
        domain_match = re.search(DOMAIN_PATTERN, text)
        if domain_match:
            return domain_match.group(0)
        return None

    def _parse_event_action(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {"ref_text": text}
        for k, v in DEAL_STATUS_MAP.items():
            if k in text:
                params["deal_status"] = v
                break
        if "备注" in text:
            parts = text.split("备注", 1)
            if len(parts) == 2:
                params["deal_comment"] = parts[1].strip("：: ")
        return params

    def _parse_block_action(self, text: str, semantic_rules: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {"raw_text": text}
        for key, mapped in BLOCK_TYPE_MAP.items():
            if key in text:
                params["block_type"] = mapped
                break

        ip_list = re.findall(IPV4_PATTERN, text)
        domain_list = re.findall(DOMAIN_PATTERN, text)
        views = ip_list or domain_list
        if views:
            params["views"] = views

        if "永久" in text:
            params["time_type"] = "forever"
        if "临时" in text:
            params["time_type"] = "temporary"

        duration = re.search(r"(\d+|[一二两三四五六七八九十]+)\s*(天|小时|分钟)", text)
        if duration:
            val = parse_cn_number(duration.group(1))
            unit_map = {"天": "d", "小时": "h", "分钟": "m"}
            if val:
                params["time_value"] = val
                params["time_unit"] = unit_map[duration.group(2)]
                params["time_type"] = "temporary"

        self._apply_semantic_rules(text, intent="block_action", params=params, semantic_rules=semantic_rules)
        return params

    def _parse_entity_query(self, text: str) -> dict[str, Any]:
        ip_list = re.findall(IPV4_PATTERN, text)
        params: dict[str, Any] = {"ref_text": text}
        if ip_list:
            params["ips"] = ip_list
        return params
