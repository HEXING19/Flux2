from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

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
    def parse(self, text: str) -> ParsedIntent:
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
            return ParsedIntent(intent="log_stats", params=self._parse_common_filters(normalized))

        if self._looks_like_block_query(normalized):
            params = self._parse_common_filters(normalized)
            keyword = self._extract_keyword(normalized)
            if not keyword:
                keyword = self._extract_ip_or_domain(normalized)
            if keyword:
                params["keyword"] = keyword
            return ParsedIntent(intent="block_query", params=params)

        if any(k in normalized for k in ["封禁", "拉黑", "阻断"]) and not self._looks_like_block_query(normalized):
            params = self._parse_block_action(normalized)
            return ParsedIntent(intent="block_action", params=params)

        if any(k in normalized for k in ["实体", "情报", "外网ip", "外网IP"]):
            return ParsedIntent(intent="entity_query", params=self._parse_entity_query(normalized))

        if any(k in normalized for k in ["详情", "举证", "时间线"]) and any(k in normalized for k in ["事件", "告警", "第"]):
            return ParsedIntent(intent="event_detail", params={"ref_text": normalized})

        if any(k in normalized for k in ["处置", "标记", "挂起", "接受风险", "遏制"]):
            params = self._parse_event_action(normalized)
            return ParsedIntent(intent="event_action", params=params)

        if any(k in normalized for k in ["事件", "告警", "incident", "查询"]):
            params = self._parse_common_filters(normalized)
            return ParsedIntent(intent="event_query", params=params)

        return ParsedIntent(intent="chat_fallback", params={"query": normalized})

    def _parse_common_filters(self, text: str) -> dict[str, Any]:
        params: dict[str, Any] = {}

        severities = [v for k, v in SEVERITY_MAP.items() if k in text]
        if severities:
            params["severities"] = sorted(set(severities))

        statuses = [v for k, v in DEAL_STATUS_MAP.items() if k in text]
        if statuses:
            params["deal_status"] = sorted(set(statuses))

        time_match = re.search(
            r"(最近\d+[天小时分钟]|近\d+[天小时分钟]|最近[一二两三四五六七八九十]+天|近[一二两三四五六七八九十]+天|昨天|今天|本周|本月|近一周|最近三天)",
            text,
        )
        if time_match:
            params["time_text"] = time_match.group(1)

        page_match = re.search(r"前(\d+|[一二两三四五六七八九十]+)条", text)
        if page_match:
            count = parse_cn_number(page_match.group(1))
            if count:
                params["page_size"] = min(200, max(5, count))

        return params

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

    def _parse_block_action(self, text: str) -> dict[str, Any]:
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

        return params

    def _parse_entity_query(self, text: str) -> dict[str, Any]:
        ip_list = re.findall(IPV4_PATTERN, text)
        params: dict[str, Any] = {"ref_text": text}
        if ip_list:
            params["ips"] = ip_list
        return params
