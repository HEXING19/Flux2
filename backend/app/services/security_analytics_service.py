from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from app.core.requester import APIRequester


SEVERITY_LABEL = {0: "信息", 1: "低危", 2: "中危", 3: "高危", 4: "严重"}
DEAL_STATUS_LABEL = {0: "待处置", 10: "处置中", 40: "已处置", 50: "已挂起", 60: "接受风险", 70: "已遏制"}
ALERT_DEAL_STATUS_LABEL = {1: "待处置", 2: "处置中", 3: "处置完成"}
ALERT_ACCESS_DIRECTION_LABEL = {0: "无", 1: "内对外", 2: "外对内", 3: "内对内"}
SEVERITY_ORDER = ["严重", "高危", "中危", "低危", "信息"]
UNKNOWN_CATEGORY = "未分类"
GPT_RESULT_LABEL = {
    110: "真实攻击成功",
    120: "病毒木马活动",
    130: "真实攻击未成功",
    140: "脆弱性访问",
    150: "疑似攻击行为",
    160: "误报",
    170: "数据不足",
    180: "自定义类型",
}


def _pick(item: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        value = item.get(key)
        if value not in (None, ""):
            return value
    return default


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _format_ts(timestamp: Any) -> str:
    try:
        return datetime.fromtimestamp(int(timestamp)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError):
        return "-"


def _pick_first_dict(data: Any) -> dict[str, Any]:
    if isinstance(data, dict):
        return data
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                return item
    return {}


def _normalize_str(value: Any, default: str = "-") -> str:
    text = str(value or "").strip()
    return text or default


def _normalize_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value in (None, ""):
        return []
    return [value]


def _join_values(values: Any, default: str = "-") -> str:
    items = [str(item).strip() for item in _normalize_list(values) if str(item).strip()]
    return ",".join(items) if items else default


def _normalize_gpt_results(item: dict[str, Any]) -> str:
    values = _normalize_list(_pick(item, "gptResults", "gptResult"))
    labels: list[str] = []
    seen: set[str] = set()
    for value in values:
        if isinstance(value, str) and value.strip() and not value.strip().isdigit():
            label = value.strip()
        else:
            code = _to_int(value, -1)
            label = GPT_RESULT_LABEL.get(code, str(value).strip())
        if not label or label in seen:
            continue
        seen.add(label)
        labels.append(label)
    if labels:
        return "、".join(labels)

    description = _normalize_str(_pick(item, "gptResultDescription"), default="")
    if description:
        return description
    return UNKNOWN_CATEGORY


def _safe_ratio(part: int, total: int) -> str:
    if total <= 0:
        return "0.0%"
    return f"{part * 100 / total:.1f}%"


class SecurityAnalyticsService:
    def __init__(self, requester: APIRequester):
        self.requester = requester

    @staticmethod
    def _normalize_event_row(item: dict[str, Any], index: int = 0) -> dict[str, Any]:
        severity_code = _to_int(_pick(item, "incidentSeverity", "severity"), -1)
        deal_status_code = _to_int(_pick(item, "dealStatus", "status"), -1)
        end_time_ts = _to_int(_pick(item, "endTime", "latestTime", "occurTime"), 0)
        return {
            "index": index,
            "uuId": _normalize_str(_pick(item, "uuId", "uuid", "incidentId", default=""), default=""),
            "name": _normalize_str(_pick(item, "name", "incidentName", "title", default="未知事件"), default="未知事件"),
            "severityCode": severity_code,
            "incidentSeverity": SEVERITY_LABEL.get(severity_code, _normalize_str(severity_code, default="未知")),
            "dealStatusCode": deal_status_code,
            "dealStatus": DEAL_STATUS_LABEL.get(deal_status_code, _normalize_str(deal_status_code, default="未知")),
            "dealAction": _normalize_str(_pick(item, "dealAction", "dealMethod", "actionName"), default="未记录"),
            "hostIp": _normalize_str(_pick(item, "hostIp", "assetIp", "srcIp"), default="-"),
            "srcIp": _normalize_str(_pick(item, "srcIp", "sourceIp"), default="-"),
            "dstIp": _normalize_str(_pick(item, "dstIp", "destIp", "destinationIp"), default="-"),
            "threatDefineName": _normalize_str(_pick(item, "threatDefineName", "threatName", "name"), default=UNKNOWN_CATEGORY),
            "gptResultLabel": _normalize_gpt_results(item),
            "incidentThreatClass": _normalize_str(_pick(item, "incidentThreatClass", "threatClass"), default="-"),
            "incidentThreatType": _normalize_str(_pick(item, "incidentThreatType", "threatType"), default="-"),
            "gptResultDescription": _normalize_str(_pick(item, "gptResultDescription"), default=""),
            "endTime": _format_ts(end_time_ts),
            "endTimeTs": end_time_ts,
        }

    @staticmethod
    def _normalize_alert_severity(value: Any) -> str:
        text = str(value or "").strip()
        if "严重" in text:
            return "严重"
        if "高危" in text or text == "高":
            return "高危"
        if "中危" in text or text == "中":
            return "中危"
        if "低危" in text or text == "低":
            return "低危"
        score = _to_int(value, -1)
        if score in SEVERITY_LABEL:
            return SEVERITY_LABEL[score]
        if score < 0:
            return "信息"
        if score <= 10:
            return "信息"
        if score <= 30:
            return "低危"
        if score <= 50:
            return "中危"
        if score <= 70:
            return "高危"
        return "严重"

    @staticmethod
    def _normalize_alert_deal_status(value: Any) -> str:
        code = _to_int(value, -1)
        if code in ALERT_DEAL_STATUS_LABEL:
            return ALERT_DEAL_STATUS_LABEL[code]
        if code in DEAL_STATUS_LABEL:
            return DEAL_STATUS_LABEL[code]
        return _normalize_str(value, default="-")

    @staticmethod
    def _normalize_access_direction(value: Any) -> str:
        code = _to_int(value, -1)
        if code in ALERT_ACCESS_DIRECTION_LABEL:
            return ALERT_ACCESS_DIRECTION_LABEL[code]
        text = str(value or "").strip()
        aliases = {
            "internal_to_external": "内对外",
            "external_to_internal": "外对内",
            "internal_to_internal": "内对内",
            "none": "无",
        }
        return aliases.get(text.lower(), text or "-")

    def _normalize_alert_row(self, item: dict[str, Any], index: int = 0) -> dict[str, Any]:
        last_time_ts = _to_int(_pick(item, "lastTime", "latestTime", "occurTime", "endTime"), 0)
        severity_value = _pick(item, "severity", "incidentSeverity")
        return {
            "index": index,
            "uuId": _normalize_str(_pick(item, "uuId", "alertId", "id", default=""), default=""),
            "name": _normalize_str(_pick(item, "name", "alertName"), default="未知告警"),
            "severityCode": _to_int(severity_value, -1),
            "incidentSeverity": self._normalize_alert_severity(severity_value),
            "dealStatus": self._normalize_alert_deal_status(_pick(item, "alertDealStatus", "dealStatus", "status")),
            "direction": self._normalize_access_direction(_pick(item, "direction", "accessDirection")),
            "threatClassDesc": _normalize_str(_pick(item, "threatClassDesc"), default=UNKNOWN_CATEGORY),
            "threatTypeDesc": _normalize_str(_pick(item, "threatTypeDesc"), default=UNKNOWN_CATEGORY),
            "threatSubTypeDesc": _normalize_str(_pick(item, "threatSubTypeDesc"), default=UNKNOWN_CATEGORY),
            "hostIp": _normalize_str(_pick(item, "hostIp", "assetIp"), default="-"),
            "srcIp": _join_values(_pick(item, "srcIp", "sourceIp"), default="-"),
            "dstIp": _join_values(_pick(item, "dstIp", "destIp", "destinationIp"), default="-"),
            "endTime": _format_ts(last_time_ts),
            "lastTimeTs": last_time_ts,
        }

    @staticmethod
    def _normalize_entity_items(response: dict[str, Any]) -> tuple[list[dict[str, Any]], str | None]:
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
            if any(key in data for key in ("ip", "IP", "entityIp", "entityIP", "view")):
                raw_items.append(data)
        elif isinstance(data, list):
            raw_items.extend(data)

        top_item = response.get("item")
        if not raw_items and isinstance(top_item, list):
            raw_items.extend(top_item)

        entities: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in raw_items:
            if not isinstance(item, dict):
                continue
            ip_value = _pick(item, "ip", "IP", "entityIp", "entityIP", "view")
            ip_text = str(ip_value or "").strip()
            if not ip_text or ip_text in seen:
                continue
            seen.add(ip_text)
            normalized = dict(item)
            normalized["ip"] = ip_text
            entities.append(normalized)
        return entities, None

    @staticmethod
    def _extract_proof_timeline_items(proof_data: dict[str, Any]) -> list[dict[str, Any]]:
        if not isinstance(proof_data, dict):
            return []
        for key in ("alertTimeLine", "alertTimeline", "incidentTimeLines", "incidentTimeline"):
            value = proof_data.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
        return []

    @staticmethod
    def _normalize_timeline_severity(value: Any) -> str:
        return SecurityAnalyticsService._normalize_alert_severity(value)

    @staticmethod
    def _normalize_timeline_stage(stage_value: Any, alert_name: str = "") -> str:
        score = _to_int(stage_value, -1)
        if score == 20:
            return "侦察"
        if score in {30, 40}:
            return "利用"
        if score in {50, 60}:
            return "横向"
        if score in {70, 80}:
            return "结果"

        sample = f"{stage_value} {alert_name}".lower()
        if any(token in sample for token in ("扫描", "探测", "侦察", "recon")):
            return "侦察"
        if any(token in sample for token in ("利用", "攻击", "执行", "webshell", "rce")):
            return "利用"
        if any(token in sample for token in ("横向", "扩散", "shell", "c2", "控制", "通信")):
            return "横向"
        if any(token in sample for token in ("窃取", "外传", "泄露", "牟利", "impact", "结果")):
            return "结果"
        return "未知"

    @staticmethod
    def _merge_topn(counter: dict[str, int], *, top_n: int) -> list[dict[str, Any]]:
        sorted_rows = sorted(
            [{"name": name, "count": count} for name, count in counter.items()],
            key=lambda item: (-item["count"], item["name"]),
        )
        if top_n <= 0 or len(sorted_rows) <= top_n:
            return sorted_rows
        kept = sorted_rows[:top_n]
        other_count = sum(item["count"] for item in sorted_rows[top_n:])
        if other_count > 0:
            kept.append({"name": "其他", "count": other_count})
        return kept

    @staticmethod
    def _chart_rows(counter: dict[str, int], *, total: int, top_n: int) -> list[dict[str, Any]]:
        rows = SecurityAnalyticsService._merge_topn(counter, top_n=top_n)
        return [{**row, "ratio": _safe_ratio(row["count"], total)} for row in rows]

    @staticmethod
    def _detail_distribution_rows(counter: dict[str, int], *, total: int) -> list[dict[str, Any]]:
        rows = sorted(counter.items(), key=lambda item: (-item[1], item[0]))
        return [{"name": name, "count": count, "ratio": _safe_ratio(count, total)} for name, count in rows]

    @staticmethod
    def _sort_key_event(row: dict[str, Any]) -> tuple[int, int, int]:
        severity = _to_int(row.get("severityCode"), -1)
        pending = 1 if row.get("dealStatus") in {"待处置", "处置中"} else 0
        timestamp = _to_int(row.get("endTimeTs"), 0)
        return (severity, pending, timestamp)

    @staticmethod
    def _is_snapshot_disposed(status: str) -> bool:
        return status in {"已处置", "已遏制", "接受风险"}

    @staticmethod
    def _bucket_start(ts: int, granularity: str) -> datetime:
        dt = datetime.fromtimestamp(ts)
        if granularity == "hour":
            return dt.replace(minute=0, second=0, microsecond=0)
        return dt.replace(hour=0, minute=0, second=0, microsecond=0)

    def query_incidents(
        self,
        *,
        start_ts: int,
        end_ts: int,
        page: int = 1,
        page_size: int = 200,
        extra_filters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        request = {
            "page": page,
            "pageSize": page_size,
            "sort": "endTime:desc,severity:desc",
            "timeField": "endTime",
            "startTimestamp": start_ts,
            "endTimestamp": end_ts,
        }
        request.update(extra_filters or {})
        response = self.requester.request("POST", "/api/xdr/v1/incidents/list", json_body=request)
        if response.get("code") != "Success":
            return {
                "rows": [],
                "raw_items": [],
                "truncated": False,
                "max_scan": page_size,
                "total_hint": 0,
                "error": str(response.get("message") or "事件查询失败"),
                "request": request,
            }
        data = response.get("data", {}) if isinstance(response.get("data"), dict) else {}
        items = data.get("item", []) or []
        total_hint = _to_int(_pick(data, "total", "count", "totalCount"), len(items))
        rows = [self._normalize_event_row(item, idx) for idx, item in enumerate(items, start=1)]
        return {
            "rows": rows,
            "raw_items": items,
            "truncated": False,
            "max_scan": page_size,
            "total_hint": total_hint,
            "error": None,
            "request": request,
        }

    def scan_incidents(
        self,
        *,
        start_ts: int,
        end_ts: int,
        max_scan: int = 10000,
        page_size: int = 200,
        extra_filters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        scanned = 0
        page = 1
        truncated = False
        total_hint: int | None = None
        error: str | None = None

        while scanned < max_scan:
            request = {
                "page": page,
                "pageSize": page_size,
                "sort": "endTime:desc,severity:desc",
                "timeField": "endTime",
                "startTimestamp": start_ts,
                "endTimestamp": end_ts,
            }
            request.update(extra_filters or {})
            response = self.requester.request("POST", "/api/xdr/v1/incidents/list", json_body=request)
            if response.get("code") != "Success":
                error = str(response.get("message") or "事件查询失败")
                break
            data = response.get("data", {}) if isinstance(response.get("data"), dict) else {}
            if total_hint is None:
                hint = _to_int(_pick(data, "total", "count", "totalCount"), -1)
                total_hint = hint if hint >= 0 else None
            items = data.get("item", []) or []
            if not items:
                break

            for item in items:
                if scanned >= max_scan:
                    truncated = True
                    break
                scanned += 1
                rows.append(self._normalize_event_row(item, len(rows) + 1))
            if scanned >= max_scan and ((total_hint is not None and total_hint > scanned) or len(items) >= page_size):
                truncated = True
            if len(items) < page_size or truncated:
                break
            page += 1

        return {
            "rows": rows,
            "truncated": truncated,
            "max_scan": max_scan,
            "total_hint": total_hint if total_hint is not None else len(rows),
            "error": error,
        }

    def query_alerts(
        self,
        *,
        start_ts: int,
        end_ts: int,
        page: int = 1,
        page_size: int = 200,
        extra_filters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        request = {
            "page": page,
            "pageSize": page_size,
            "sortField": "lastTime",
            "sortOrder": "desc",
            "timeField": "lastTime",
            "startTimestamp": start_ts,
            "endTimestamp": end_ts,
        }
        request.update(extra_filters or {})
        response = self.requester.request("POST", "/api/xdr/v1/alerts/list", json_body=request)
        if response.get("code") != "Success":
            return {
                "rows": [],
                "raw_items": [],
                "truncated": False,
                "max_scan": page_size,
                "total_hint": 0,
                "error": str(response.get("message") or "告警查询失败"),
                "request": request,
            }
        data = response.get("data", {}) if isinstance(response.get("data"), dict) else {}
        items = data.get("item", []) or []
        total_hint = _to_int(_pick(data, "total", "count", "totalCount"), len(items))
        rows = [self._normalize_alert_row(item, idx) for idx, item in enumerate(items, start=1)]
        return {
            "rows": rows,
            "raw_items": items,
            "truncated": False,
            "max_scan": page_size,
            "total_hint": total_hint,
            "error": None,
            "request": request,
        }

    def scan_alerts(
        self,
        *,
        start_ts: int,
        end_ts: int,
        max_scan: int = 10000,
        page_size: int = 200,
        extra_filters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        rows: list[dict[str, Any]] = []
        scanned = 0
        page = 1
        truncated = False
        total_hint: int | None = None
        error: str | None = None

        while scanned < max_scan:
            request = {
                "page": page,
                "pageSize": page_size,
                "sortField": "lastTime",
                "sortOrder": "desc",
                "timeField": "lastTime",
                "startTimestamp": start_ts,
                "endTimestamp": end_ts,
            }
            request.update(extra_filters or {})
            response = self.requester.request("POST", "/api/xdr/v1/alerts/list", json_body=request)
            if response.get("code") != "Success":
                error = str(response.get("message") or "告警查询失败")
                break
            data = response.get("data", {}) if isinstance(response.get("data"), dict) else {}
            if total_hint is None:
                hint = _to_int(_pick(data, "total", "count", "totalCount"), -1)
                total_hint = hint if hint >= 0 else None
            items = data.get("item", []) or []
            if not items:
                break

            for item in items:
                if scanned >= max_scan:
                    truncated = True
                    break
                scanned += 1
                rows.append(self._normalize_alert_row(item, len(rows) + 1))
            if scanned >= max_scan and ((total_hint is not None and total_hint > scanned) or len(items) >= page_size):
                truncated = True
            if len(items) < page_size or truncated:
                break
            page += 1

        return {
            "rows": rows,
            "truncated": truncated,
            "max_scan": max_scan,
            "total_hint": total_hint if total_hint is not None else len(rows),
            "error": error,
        }

    def build_time_buckets(self, *, start_ts: int, end_ts: int, granularity: str | None = None) -> dict[str, Any]:
        selected = granularity or ("hour" if end_ts - start_ts <= 48 * 3600 else "day")
        current = self._bucket_start(start_ts, selected)
        end_bucket = self._bucket_start(end_ts, selected)
        step = timedelta(hours=1) if selected == "hour" else timedelta(days=1)
        buckets: list[dict[str, Any]] = []
        while current <= end_bucket:
            bucket_ts = int(current.timestamp())
            buckets.append(
                {
                    "bucket_ts": bucket_ts,
                    "label": current.strftime("%m-%d %H:00" if selected == "hour" else "%m-%d"),
                    "start_ts": bucket_ts,
                    "end_ts": int((current + step).timestamp()) - 1,
                }
            )
            current += step
        return {"granularity": selected, "buckets": buckets, "labels": [bucket["label"] for bucket in buckets]}

    def aggregate_event_trend(
        self,
        rows: list[dict[str, Any]],
        *,
        start_ts: int,
        end_ts: int,
        granularity: str | None = None,
    ) -> dict[str, Any]:
        bucket_info = self.build_time_buckets(start_ts=start_ts, end_ts=end_ts, granularity=granularity)
        buckets = bucket_info["buckets"]
        bucket_index = {bucket["bucket_ts"]: idx for idx, bucket in enumerate(buckets)}
        overall = [0 for _ in buckets]
        severity_counter = {label: [0 for _ in buckets] for label in SEVERITY_ORDER}

        for row in rows:
            ts = _to_int(row.get("endTimeTs"), 0)
            if ts <= 0:
                continue
            key = int(self._bucket_start(ts, bucket_info["granularity"]).timestamp())
            idx = bucket_index.get(key)
            if idx is None:
                continue
            overall[idx] += 1
            severity = str(row.get("incidentSeverity") or "信息")
            if severity not in severity_counter:
                severity_counter[severity] = [0 for _ in buckets]
            severity_counter[severity][idx] += 1

        detail_rows = []
        for idx, bucket in enumerate(buckets):
            row = {"bucket": bucket["label"], "total": overall[idx]}
            for severity in SEVERITY_ORDER:
                row[severity] = severity_counter.get(severity, [0 for _ in buckets])[idx]
            detail_rows.append(row)

        peak_count = max(overall, default=0)
        peak_label = "-"
        if peak_count > 0:
            peak_idx = overall.index(peak_count)
            peak_label = buckets[peak_idx]["label"]

        severity_series = [
            {"name": severity, "data": severity_counter.get(severity, [0 for _ in buckets])}
            for severity in SEVERITY_ORDER
            if any(severity_counter.get(severity, []))
        ]

        return {
            "granularity": bucket_info["granularity"],
            "labels": bucket_info["labels"],
            "overall": overall,
            "severity_series": severity_series,
            "detail_rows": detail_rows,
            "total": len(rows),
            "peak_label": peak_label,
            "peak_count": peak_count,
        }

    def aggregate_alert_trend(
        self,
        rows: list[dict[str, Any]],
        *,
        start_ts: int,
        end_ts: int,
        granularity: str | None = None,
    ) -> dict[str, Any]:
        bucket_info = self.build_time_buckets(start_ts=start_ts, end_ts=end_ts, granularity=granularity)
        buckets = bucket_info["buckets"]
        bucket_index = {bucket["bucket_ts"]: idx for idx, bucket in enumerate(buckets)}
        overall = [0 for _ in buckets]
        severity_counter = {label: [0 for _ in buckets] for label in SEVERITY_ORDER}

        for row in rows:
            ts = _to_int(row.get("lastTimeTs"), 0)
            if ts <= 0:
                continue
            key = int(self._bucket_start(ts, bucket_info["granularity"]).timestamp())
            idx = bucket_index.get(key)
            if idx is None:
                continue
            overall[idx] += 1
            severity = str(row.get("incidentSeverity") or "信息")
            if severity not in severity_counter:
                severity_counter[severity] = [0 for _ in buckets]
            severity_counter[severity][idx] += 1

        detail_rows = []
        for idx, bucket in enumerate(buckets):
            row = {"bucket": bucket["label"], "total": overall[idx]}
            for severity in SEVERITY_ORDER:
                row[severity] = severity_counter.get(severity, [0 for _ in buckets])[idx]
            detail_rows.append(row)

        peak_count = max(overall, default=0)
        peak_label = "-"
        if peak_count > 0:
            peak_idx = overall.index(peak_count)
            peak_label = buckets[peak_idx]["label"]

        severity_series = [
            {"name": severity, "data": severity_counter.get(severity, [0 for _ in buckets])}
            for severity in SEVERITY_ORDER
            if any(severity_counter.get(severity, []))
        ]

        return {
            "granularity": bucket_info["granularity"],
            "labels": bucket_info["labels"],
            "overall": overall,
            "severity_series": severity_series,
            "detail_rows": detail_rows,
            "total": len(rows),
            "peak_label": peak_label,
            "peak_count": peak_count,
        }

    def aggregate_event_type_distribution(self, rows: list[dict[str, Any]], *, top_n: int = 6) -> dict[str, Any]:
        gpt_counter: dict[str, int] = {}
        type_counter: dict[str, int] = {}
        high_risk_counter: dict[str, int] = {}
        detail_counter: dict[tuple[str, str, str], int] = {}

        for row in rows:
            gpt_label = _normalize_str(row.get("gptResultLabel"), default=UNKNOWN_CATEGORY)
            class_name = _normalize_str(row.get("incidentThreatClass"), default="-")
            type_name = _normalize_str(row.get("incidentThreatType"), default="-")
            gpt_counter[gpt_label] = gpt_counter.get(gpt_label, 0) + 1
            type_counter[type_name] = type_counter.get(type_name, 0) + 1
            detail_counter[(gpt_label, class_name, type_name)] = detail_counter.get((gpt_label, class_name, type_name), 0) + 1
            if _to_int(row.get("severityCode"), -1) >= 3:
                high_risk_counter[gpt_label] = high_risk_counter.get(gpt_label, 0) + 1

        total = len(rows)
        detail_rows = [
            {
                "gptResultLabel": gpt_label,
                "incidentThreatClass": class_name,
                "incidentThreatType": type_name,
                "count": count,
                "ratio": _safe_ratio(count, total),
            }
            for (gpt_label, class_name, type_name), count in sorted(
                detail_counter.items(),
                key=lambda item: (-item[1], item[0][0], item[0][1], item[0][2]),
            )
        ]
        return {
            "total": total,
            "gpt_result_top": self._chart_rows(gpt_counter, total=total, top_n=top_n),
            "threat_type_top": self._chart_rows(type_counter, total=total, top_n=top_n),
            "high_risk_top": self._chart_rows(high_risk_counter, total=max(sum(high_risk_counter.values()), 1), top_n=top_n),
            "detail_rows": detail_rows,
        }

    def aggregate_event_disposition_summary(
        self,
        rows: list[dict[str, Any]],
        *,
        top_n: int = 6,
        pending_limit: int = 10,
    ) -> dict[str, Any]:
        status_counter: dict[str, int] = {}
        action_counter: dict[str, int] = {}
        for row in rows:
            status = _normalize_str(row.get("dealStatus"), default="未知")
            action = _normalize_str(row.get("dealAction"), default="未记录")
            status_counter[status] = status_counter.get(status, 0) + 1
            action_counter[action] = action_counter.get(action, 0) + 1

        total = len(rows)
        disposed_count = sum(
            count for status, count in status_counter.items() if self._is_snapshot_disposed(status)
        )
        pending_rows = [
            row
            for row in sorted(rows, key=self._sort_key_event, reverse=True)
            if not self._is_snapshot_disposed(str(row.get("dealStatus") or ""))
        ][:pending_limit]
        pending_table_rows = [
            {
                "uuId": row.get("uuId"),
                "name": row.get("name"),
                "incidentSeverity": row.get("incidentSeverity"),
                "dealStatus": row.get("dealStatus"),
                "hostIp": row.get("hostIp"),
                "endTime": row.get("endTime"),
            }
            for row in pending_rows
        ]

        summary_table_rows = [
            {"category": "处置状态", "name": row["name"], "count": row["count"], "ratio": row["ratio"]}
            for row in self._detail_distribution_rows(status_counter, total=total)
        ] + [
            {"category": "处置动作", "name": row["name"], "count": row["count"], "ratio": row["ratio"]}
            for row in self._detail_distribution_rows(action_counter, total=total)
        ]

        return {
            "total": total,
            "disposed_count": disposed_count,
            "disposed_ratio": _safe_ratio(disposed_count, total),
            "status_rows": self._chart_rows(status_counter, total=total, top_n=top_n),
            "action_rows": self._chart_rows(action_counter, total=total, top_n=top_n),
            "summary_table_rows": summary_table_rows,
            "pending_table_rows": pending_table_rows,
        }

    def select_key_events(self, rows: list[dict[str, Any]], *, top_n: int = 3) -> list[dict[str, Any]]:
        return sorted(rows, key=self._sort_key_event, reverse=True)[:top_n]

    @staticmethod
    def _build_disposition_advice(*, severity: str, status: str, risk_tags: list[str], entity_count: int) -> str:
        if status in {"待处置", "处置中"} and severity in {"严重", "高危"}:
            return "优先隔离受影响主机并继续追踪同源实体。"
        if "c2" in {str(tag).lower() for tag in risk_tags}:
            return "建议立即核查外联目标并评估封禁。"
        if entity_count > 0:
            return "建议结合关联外网实体继续做横向排查。"
        return "建议结合举证结果安排人工复核。"

    def build_key_event_insight(self, row: dict[str, Any]) -> dict[str, Any]:
        uid = str(row.get("uuId") or "").strip()
        proof_resp = self.requester.request("GET", f"/api/xdr/v1/incidents/{uid}/proof")
        entity_resp = self.requester.request("GET", f"/api/xdr/v1/incidents/{uid}/entities/ip")

        proof_error = None
        proof_data: dict[str, Any] = {}
        if proof_resp.get("code") != "Success":
            proof_error = str(proof_resp.get("message") or "举证信息查询失败")
        else:
            proof_data = _pick_first_dict(proof_resp.get("data"))

        entities, entity_error = self._normalize_entity_items(entity_resp)
        entity_ips = [str(item.get("ip")).strip() for item in entities if str(item.get("ip") or "").strip()]

        risk_tags_raw = proof_data.get("riskTag", [])
        if isinstance(risk_tags_raw, str):
            risk_tags = [risk_tags_raw] if risk_tags_raw.strip() else []
        else:
            risk_tags = [str(item).strip() for item in _normalize_list(risk_tags_raw) if str(item).strip()]

        timeline_rows = []
        timeline_summary_parts: list[str] = []
        for item in self._extract_proof_timeline_items(proof_data)[:8]:
            name = _normalize_str(item.get("name"), default="未知阶段")
            stage = self._normalize_timeline_stage(item.get("stage"), name)
            last_time = _format_ts(item.get("lastTime"))
            severity = self._normalize_timeline_severity(item.get("severity"))
            timeline_rows.append(
                {
                    "name": name,
                    "stage": stage,
                    "severity": severity,
                    "lastTime": last_time,
                }
            )
            if len(timeline_summary_parts) < 3:
                timeline_summary_parts.append(f"{last_time} {stage}:{name}")

        gpt_result = _normalize_str(
            proof_data.get("gptResultDescription") or row.get("gptResultDescription"),
            default="暂无 GPT 研判结论。",
        )
        if proof_error:
            gpt_result = f"举证接口异常，已回退到列表字段。{proof_error}"

        entity_summary = "、".join(entity_ips[:5]) if entity_ips else ("查询失败" if entity_error else "未发现关联外网实体")

        return {
            "event_row": {
                "uuId": row.get("uuId"),
                "name": row.get("name"),
                "incidentSeverity": row.get("incidentSeverity"),
                "dealStatus": row.get("dealStatus"),
                "endTime": row.get("endTime"),
            },
            "gpt_result": gpt_result,
            "risk_tags": risk_tags,
            "timeline_summary": "；".join(timeline_summary_parts) if timeline_summary_parts else "暂无关键时间线。",
            "timeline_rows": timeline_rows,
            "entities": entity_ips,
            "entity_summary": entity_summary,
            "advice": self._build_disposition_advice(
                severity=str(row.get("incidentSeverity") or ""),
                status=str(row.get("dealStatus") or ""),
                risk_tags=risk_tags,
                entity_count=len(entity_ips),
            ),
            "errors": [msg for msg in [proof_error, entity_error] if msg],
        }

    def aggregate_alert_classification_summary(self, rows: list[dict[str, Any]], *, top_n: int = 6) -> dict[str, Any]:
        class_counter: dict[str, int] = {}
        type_counter: dict[str, int] = {}
        subtype_counter: dict[str, int] = {}
        severity_counter: dict[str, int] = {}
        status_counter: dict[str, int] = {}
        direction_counter: dict[str, int] = {}
        detail_counter: dict[tuple[str, str, str], int] = {}

        for row in rows:
            class_name = _normalize_str(row.get("threatClassDesc"), default=UNKNOWN_CATEGORY)
            type_name = _normalize_str(row.get("threatTypeDesc"), default=UNKNOWN_CATEGORY)
            subtype_name = _normalize_str(row.get("threatSubTypeDesc"), default=UNKNOWN_CATEGORY)
            severity = _normalize_str(row.get("incidentSeverity"), default="信息")
            status = _normalize_str(row.get("dealStatus"), default="-")
            direction = _normalize_str(row.get("direction"), default="-")

            class_counter[class_name] = class_counter.get(class_name, 0) + 1
            type_counter[type_name] = type_counter.get(type_name, 0) + 1
            subtype_counter[subtype_name] = subtype_counter.get(subtype_name, 0) + 1
            severity_counter[severity] = severity_counter.get(severity, 0) + 1
            status_counter[status] = status_counter.get(status, 0) + 1
            direction_counter[direction] = direction_counter.get(direction, 0) + 1
            detail_counter[(class_name, type_name, subtype_name)] = detail_counter.get((class_name, type_name, subtype_name), 0) + 1

        total = len(rows)
        detail_rows = [
            {
                "threatClassDesc": class_name,
                "threatTypeDesc": type_name,
                "threatSubTypeDesc": subtype_name,
                "count": count,
                "ratio": _safe_ratio(count, total),
            }
            for (class_name, type_name, subtype_name), count in sorted(
                detail_counter.items(),
                key=lambda item: (-item[1], item[0][0], item[0][1], item[0][2]),
            )
        ]

        return {
            "total": total,
            "class_top": self._chart_rows(class_counter, total=total, top_n=top_n),
            "type_top": self._chart_rows(type_counter, total=total, top_n=top_n),
            "subtype_top": self._chart_rows(subtype_counter, total=total, top_n=top_n),
            "severity_rows": self._chart_rows(severity_counter, total=total, top_n=top_n),
            "status_rows": self._chart_rows(status_counter, total=total, top_n=top_n),
            "direction_rows": self._chart_rows(direction_counter, total=total, top_n=top_n),
            "detail_rows": detail_rows,
        }
