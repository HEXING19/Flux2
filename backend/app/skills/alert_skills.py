from __future__ import annotations

from datetime import datetime
import json
import re
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from app.core.exceptions import MissingParameterException
from app.core.payload import table_payload, text_payload
from app.core.validation import clean_optional_text, validate_alert_uuid_list, validate_time_range
from app.services.security_analytics_service import SecurityAnalyticsService

from .base import BaseSkill


SEVERITY_LABEL = {0: "信息", 1: "低危", 2: "中危", 3: "高危", 4: "严重"}
ALERT_DEAL_STATUS_LABEL = {1: "待处置", 2: "处置中", 3: "处置完成"}
ACCESS_DIRECTION_LABEL = {0: "无", 1: "内对外", 2: "外对内", 3: "内对内"}
ATTACK_RESULT_LABEL = {0: "尝试", 1: "成功", 2: "失败", 3: "失陷"}
ALERT_STAGE_LABEL = {
    0: "默认值",
    10: "存在风险",
    20: "扫描探测",
    30: "遭受攻击",
    40: "主机异常",
    50: "内网扩散",
    60: "C&C通信",
    70: "黑产牟利",
    80: "窃取数据",
}
THREAT_DEFINE_LABEL = {
    0: "未知威胁",
    100: "误报",
    200: "业务不规范",
    300: "脆弱性风险",
    400: "扫描器攻击",
    500: "病毒",
    600: "内部测试",
    700: "监管通报",
    800: "攻防演练",
    900: "定向攻击",
}
GPT_RESULT_LABEL = {
    0: "等待GPT研判",
    10: "人工入侵",
    20: "病毒木马",
    30: "疑似入侵",
    40: "脆弱性访问",
    50: "误报",
    60: "数据不足",
    110: "真实攻击成功",
    120: "病毒木马活动",
    130: "真实攻击未成功",
    140: "脆弱性访问",
    150: "疑似攻击行为",
    160: "误报",
    170: "数据不足",
    180: "自定义类型",
}
ALERT_UUID_SEARCH_PATTERN = re.compile(r"alert-[A-Za-z0-9-]{6,}")


def _pick(item: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        value = item.get(key)
        if value not in (None, ""):
            return value
    return default


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _format_ts(timestamp: Any) -> str:
    try:
        value = int(timestamp)
    except (TypeError, ValueError):
        return "-"
    if value <= 0:
        return "-"
    try:
        return datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M:%S")
    except (OSError, ValueError):
        return "-"


def _first_dict(data: Any) -> dict[str, Any]:
    if isinstance(data, dict):
        return data
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                return item
    return {}


def _normalize_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def _stringify(value: Any, default: str = "-") -> str:
    if value in (None, "", [], {}):
        return default
    if isinstance(value, list):
        items = [_stringify(item, default="") for item in value]
        items = [item for item in items if item]
        return "、".join(items) if items else default
    if isinstance(value, dict):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def _join_values(value: Any, default: str = "-") -> str:
    items = [str(item).strip() for item in _normalize_list(value) if str(item).strip()]
    return "、".join(items) if items else default


def _label_from_code(value: Any, mapping: dict[int, str], default: str = "未知") -> str:
    parsed = _to_int(value)
    if parsed is None:
        text = str(value or "").strip()
        return text or default
    return mapping.get(parsed, str(parsed))


def _severity_label(value: Any) -> str:
    text = str(value or "").strip()
    if "严重" in text:
        return "严重"
    if "高危" in text or text == "高":
        return "高危"
    if "中危" in text or text == "中":
        return "中危"
    if "低危" in text or text == "低":
        return "低危"
    score = _to_int(value)
    if score is None:
        return text or "信息"
    if score in SEVERITY_LABEL:
        return SEVERITY_LABEL[score]
    if score <= 10:
        return "信息"
    if score <= 30:
        return "低危"
    if score <= 50:
        return "中危"
    if score <= 70:
        return "高危"
    return "严重"


def extract_alert_uuids_from_text(text: str) -> list[str]:
    if not text:
        return []
    matches = ALERT_UUID_SEARCH_PATTERN.findall(text)
    return list(dict.fromkeys(matches))


def _load_recent_alert_candidates(skill: BaseSkill, session_id: str, limit: int = 10) -> list[dict[str, Any]]:
    response = skill.requester.request(
        "POST",
        "/api/xdr/v1/alerts/list",
        json_body={
            "page": 1,
            "pageSize": max(5, min(limit, 50)),
            "sortField": "lastTime",
            "sortOrder": "desc",
            "timeField": "lastTime",
        },
    )
    items = response.get("data", {}).get("item", []) if response.get("code") == "Success" else []
    uuids = [str(_pick(item, "uuId", "alertId", "id", default="")).strip() for item in items if isinstance(item, dict)]
    uuids = [uid for uid in uuids if uid]
    if not uuids:
        return []
    skill.context_manager.store_index_mapping(session_id, "alerts", uuids)
    skill.context_manager.update_params(
        session_id,
        {"last_alert_uuid": uuids[0], "last_alert_uuids": uuids, "last_result_namespace": "alerts"},
    )
    return [item for item in items if isinstance(item, dict)]


def _bootstrap_alert_indices(skill: BaseSkill, session_id: str, utterance: str) -> list[str]:
    if not any(token in utterance for token in ["第", "前", "刚刚", "那个", "这条", "上一条", "全部", "所有"]):
        return []
    items = _load_recent_alert_candidates(skill, session_id)
    return skill.context_manager.resolve_indices(session_id, "alerts", utterance) if items else []


PROOF_FIELD_LABELS = {
    "requestHead": "请求头",
    "requestBody": "请求体",
    "responseHead": "响应头",
    "responseBody": "响应体",
    "dnsQueries": "DNS查询",
    "dnsAnswers": "DNS响应",
    "dnsQTypes": "DNS查询类型",
    "fileMd5": "文件MD5",
    "filePath": "文件路径",
    "fileName": "文件名",
    "fileStatus": "文件信誉",
    "fileClass": "文件分类",
    "virusFamily": "病毒家族",
    "virusName": "病毒名称",
    "virusType": "病毒类型",
    "bfCount": "暴破次数",
    "bfIpList": "暴破IP",
    "bfAccountList": "暴破账号",
    "scanStartTime": "扫描开始",
    "scanEndTime": "扫描结束",
    "scanCount": "扫描次数",
    "cmdLine": "命令行",
    "name": "进程/对象名称",
    "path": "路径",
    "pid": "PID",
    "ruleName": "规则名称",
    "user": "用户",
    "cve": "CVE",
    "domain": "域名",
    "srcIp": "源IP",
    "dstIp": "目的IP",
    "proto": "协议",
    "mitreIds": "MITRE技术",
    "rawProofData": "原始举证",
}


PROOF_PRIORITY_KEYS = [
    "requestHead",
    "requestBody",
    "responseHead",
    "responseBody",
    "dnsQueries",
    "dnsAnswers",
    "dnsQTypes",
    "fileMd5",
    "filePath",
    "fileName",
    "fileStatus",
    "fileClass",
    "virusFamily",
    "virusName",
    "virusType",
    "bfCount",
    "bfIpList",
    "bfAccountList",
    "scanStartTime",
    "scanEndTime",
    "scanCount",
    "cmdLine",
    "name",
    "path",
    "pid",
    "mitreIds",
    "rawProofData",
]


ORIGINAL_ALERT_KEYS = [
    "ruleName",
    "cmdLine",
    "name",
    "path",
    "pid",
    "user",
    "mitreIds",
    "cve",
    "domain",
    "srcIp",
    "dstIp",
    "fileMd5",
    "proto",
]


def _build_key_value_rows(uid: str, source: str, data: dict[str, Any], keys: list[str]) -> list[dict[str, str]]:
    rows = []
    for key in keys:
        value = data.get(key)
        if value in (None, "", [], {}):
            continue
        if key.endswith("Time"):
            rendered = _format_ts(value)
        else:
            rendered = _stringify(value)
        if rendered == "-":
            continue
        rows.append(
            {
                "uuId": uid,
                "source": source,
                "field": key,
                "label": PROOF_FIELD_LABELS.get(key, key),
                "value": rendered,
            }
        )
    return rows


def _build_network_row(uid: str, data: dict[str, Any]) -> dict[str, Any]:
    proof = data.get("proof") if isinstance(data.get("proof"), dict) else {}
    return {
        "uuId": uid,
        "srcIp": _join_values(_pick(data, "srcIp", default=proof.get("srcIp")), default="-"),
        "srcPort": _join_values(_pick(data, "srcPort", default=proof.get("srcPort")), default="-"),
        "dstIp": _join_values(_pick(data, "dstIp", default=proof.get("dstIp")), default="-"),
        "dstPort": _join_values(_pick(data, "dstPort", default=proof.get("dstPort")), default="-"),
        "domain": _join_values(_pick(data, "domain", default=proof.get("domain")), default="-"),
        "url": _join_values(_pick(data, "url", default=proof.get("url")), default="-"),
        "direction": _label_from_code(_pick(data, "direction"), ACCESS_DIRECTION_LABEL, default="-"),
        "hostIp": _pick(data, "hostIp", "assetIp", default="-"),
        "devSourceName": _join_values(_pick(data, "devSourceName", "devSourceNames"), default="-"),
    }


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


class AlertDetailInput(BaseModel):
    uuids: list[str] | None = None
    ref_text: str | None = None

    @field_validator("uuids")
    @classmethod
    def validate_uuids(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        return validate_alert_uuid_list(value, field_name="uuids", allow_empty=False)

    @field_validator("ref_text", mode="before")
    @classmethod
    def normalize_ref_text(cls, value: str | None) -> str | None:
        return clean_optional_text(value)


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
            self.context_manager.update_params(
                session_id,
                {"last_alert_uuid": uuids[0], "last_alert_uuids": uuids, "last_result_namespace": "alerts"},
            )

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


class AlertDetailSkill(BaseSkill):
    name = "AlertDetailSkill"
    __init_schema__ = AlertDetailInput

    def _fetch_alert_list_detail(self, uuid: str) -> dict[str, Any]:
        response = self.requester.request(
            "POST",
            "/api/xdr/v1/alerts/list",
            json_body={"page": 1, "pageSize": 5, "uuIds": [uuid]},
        )
        if response.get("code") != "Success":
            return {}
        items = response.get("data", {}).get("item", []) if isinstance(response.get("data"), dict) else []
        for item in items:
            if isinstance(item, dict) and str(_pick(item, "uuId", "alertId", "id", default="")).strip() == uuid:
                return item
        return _first_dict(items)

    def execute(self, session_id: str, params: dict[str, Any], user_text: str) -> list[dict[str, Any]]:
        prepared = dict(params)
        ref_text = prepared.get("ref_text") or user_text
        if not prepared.get("uuids"):
            explicit_uuids = extract_alert_uuids_from_text(ref_text)
            if explicit_uuids:
                prepared["uuids"] = explicit_uuids
        if not prepared.get("uuids"):
            refs = self.context_manager.resolve_indices(session_id, "alerts", ref_text)
            if not refs:
                refs = _bootstrap_alert_indices(self, session_id, ref_text)
            if refs:
                prepared["uuids"] = refs

        model = self.validate_and_prepare(session_id, prepared)
        if not model.uuids:
            raise MissingParameterException(
                skill_name=self.name,
                missing_fields=["uuids"],
                question="请告诉我需要查看哪条告警，例如“查看第1个告警详情”。",
            )

        detail_text_chunks: list[str] = []
        network_rows: list[dict[str, Any]] = []
        proof_rows: list[dict[str, str]] = []
        original_rows: list[dict[str, str]] = []

        for uid in model.uuids[:5]:
            list_data = self._fetch_alert_list_detail(uid)
            proof_resp = self.requester.request("GET", f"/api/xdr/v1/alerts/{uid}/proof")
            if proof_resp.get("code") != "Success":
                error = proof_resp.get("message") or "告警举证信息查询失败"
                data = dict(list_data)
                detail_text_chunks.append(f"告警 {uid}: 举证查询失败：{error}")
            else:
                data = {**list_data, **_first_dict(proof_resp.get("data"))}
                if not data:
                    detail_text_chunks.append(f"告警 {uid}: 未返回可用的告警举证信息。")
                    continue

            proof = data.get("proof") if isinstance(data.get("proof"), dict) else {}
            original = data.get("originalAlert") if isinstance(data.get("originalAlert"), dict) else {}
            network_rows.append(_build_network_row(uid, data))
            proof_rows.extend(_build_key_value_rows(uid, "proof", proof, PROOF_PRIORITY_KEYS))
            original_rows.extend(_build_key_value_rows(uid, "originalAlert", original, ORIGINAL_ALERT_KEYS))

            severity = _severity_label(_pick(data, "severity", "incidentSeverity"))
            status = _label_from_code(_pick(data, "dealStatus", "alertDealStatus", "status"), ALERT_DEAL_STATUS_LABEL, default="-")
            direction = _label_from_code(_pick(data, "direction", "accessDirection"), ACCESS_DIRECTION_LABEL, default="-")
            attack_result = _label_from_code(_pick(data, "attackResult", "attackState"), ATTACK_RESULT_LABEL, default="-")
            stage = _label_from_code(_pick(data, "stage"), ALERT_STAGE_LABEL, default="-")
            gpt_result = _label_from_code(_pick(data, "gptResult"), GPT_RESULT_LABEL, default="-")
            gpt_desc = str(_pick(data, "gptResultDescription", default="")).strip()
            threat_define = "、".join(
                _label_from_code(item, THREAT_DEFINE_LABEL, default=str(item))
                for item in _normalize_list(_pick(data, "threatDefine"))
            ) or "-"
            detail_text_chunks.append(
                f"告警 {uid}: {_pick(data, 'name', 'alertName', default='未知告警')}\n"
                f"- 等级/状态: {severity} / {status}\n"
                f"- 最近发生: {_format_ts(_pick(data, 'lastTime', 'latestTime', 'occurTime', 'endTime'))}\n"
                f"- 访问方向/攻击结果/阶段: {direction} / {attack_result} / {stage}\n"
                f"- 告警定性: {threat_define}\n"
                f"- 三级分类: {_pick(data, 'threatSubTypeDesc', default='-')}\n"
                f"- 命中日志数: {_pick(data, 'logCount', default='-')}\n"
                f"- 检测引擎: {_join_values(_pick(data, 'engineName'), default='-')}\n"
                f"- 数据源: {_join_values(_pick(data, 'devSourceName', 'devSourceNames'), default='-')}\n"
                f"- GPT研判: {gpt_desc or gpt_result}"
            )
            self.context_manager.update_params(session_id, {"last_alert_uuid": uid, "last_result_namespace": "alerts"})

        return [
            text_payload("\n\n".join(detail_text_chunks), title="告警详情与举证"),
            table_payload(
                title="告警网络对象",
                columns=[
                    {"key": "uuId", "label": "告警ID"},
                    {"key": "srcIp", "label": "源IP"},
                    {"key": "srcPort", "label": "源端口"},
                    {"key": "dstIp", "label": "目的IP"},
                    {"key": "dstPort", "label": "目的端口"},
                    {"key": "domain", "label": "域名"},
                    {"key": "url", "label": "URL"},
                    {"key": "direction", "label": "访问方向"},
                    {"key": "hostIp", "label": "主机IP"},
                    {"key": "devSourceName", "label": "数据源"},
                ],
                rows=network_rows,
                namespace="alert_network",
            ),
            table_payload(
                title="告警举证关键信息",
                columns=[
                    {"key": "uuId", "label": "告警ID"},
                    {"key": "source", "label": "来源"},
                    {"key": "label", "label": "字段"},
                    {"key": "value", "label": "值"},
                ],
                rows=proof_rows,
                namespace="alert_proof",
            ),
            table_payload(
                title="原始告警关键信息",
                columns=[
                    {"key": "uuId", "label": "告警ID"},
                    {"key": "source", "label": "来源"},
                    {"key": "label", "label": "字段"},
                    {"key": "value", "label": "值"},
                ],
                rows=original_rows,
                namespace="alert_original",
            ),
        ]
