from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator

from app.core.payload import echarts_payload, table_payload, text_payload
from app.core.validation import clean_optional_text, validate_time_range
from app.services.security_analytics_service import SecurityAnalyticsService

from .base import BaseSkill


SEVERITY_LABEL = {0: "信息", 1: "低危", 2: "中危", 3: "高危", 4: "严重"}
def _format_window(start_ts: int, end_ts: int) -> str:
    return f"{datetime.fromtimestamp(start_ts):%Y-%m-%d %H:%M:%S} 至 {datetime.fromtimestamp(end_ts):%Y-%m-%d %H:%M:%S}"


def _build_scan_notice(scan_result: dict[str, Any]) -> str:
    if not scan_result.get("truncated"):
        return ""
    total_hint = int(scan_result.get("total_hint") or 0)
    max_scan = int(scan_result.get("max_scan") or 0)
    if total_hint > max_scan > 0:
        return f" 注意：本次仅扫描前 {max_scan} 条数据，接口提示总量约为 {total_hint} 条，统计结果可能被截断。"
    return f" 注意：本次扫描达到上限 {max_scan} 条，统计结果可能被截断。"


def _remember_incidents(skill: BaseSkill, session_id: str, rows: list[dict[str, Any]]) -> None:
    uuids = [str(row.get("uuId") or "").strip() for row in rows if str(row.get("uuId") or "").strip()]
    if not uuids:
        return
    skill.context_manager.store_index_mapping(session_id, "events", uuids[:50])
    skill.context_manager.update_params(
        session_id,
        {"last_event_uuid": uuids[0], "last_event_uuids": uuids[:50], "last_result_namespace": "events"},
    )


def _remember_alerts(skill: BaseSkill, session_id: str, rows: list[dict[str, Any]]) -> None:
    uuids = [str(row.get("uuId") or "").strip() for row in rows if str(row.get("uuId") or "").strip()]
    if not uuids:
        return
    skill.context_manager.store_index_mapping(session_id, "alerts", uuids[:50])
    skill.context_manager.update_params(
        session_id,
        {"last_alert_uuid": uuids[0], "last_alert_uuids": uuids[:50], "last_result_namespace": "alerts"},
    )


def _bar_chart_option(*, title: str, rows: list[dict[str, Any]], series_name: str) -> dict[str, Any]:
    max_label_length = max((len(str(row["name"])) for row in rows), default=0)
    return {
        "title": {"text": title},
        "tooltip": {"trigger": "axis"},
        "xAxis": {
            "type": "category",
            "data": [row["name"] for row in rows],
            "axisLabel": {
                "interval": 0,
                "hideOverlap": False,
                "rotate": 20 if max_label_length >= 8 else 0,
            },
        },
        "yAxis": {"type": "value"},
        "series": [
            {
                "name": series_name,
                "type": "bar",
                "data": [row["count"] for row in rows],
            }
        ],
    }


def _pie_chart_option(*, title: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "title": {"text": title},
        "tooltip": {"trigger": "item"},
        "legend": {"bottom": 0, "left": "center"},
        "series": [
            {
                "name": title,
                "type": "pie",
                "radius": ["35%", "65%"],
                "center": ["50%", "44%"],
                "avoidLabelOverlap": True,
                "minShowLabelAngle": 3,
                "label": {"show": True, "formatter": "{b}"},
                "labelLine": {"show": True},
                "data": [{"name": row["name"], "value": row["count"]} for row in rows],
            }
        ],
    }


class SecurityAnalyticsBaseInput(BaseModel):
    startTimestamp: int | None = None
    endTimestamp: int | None = None
    time_text: str | None = None
    severities: list[int] | None = None
    page_size: int = Field(default=10, ge=1, le=50)
    top_n: int | None = Field(default=None, ge=1, le=20)
    max_scan: int = Field(default=10000, ge=200, le=10000)
    group_by: str | None = None

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

    @field_validator("group_by", mode="before")
    @classmethod
    def normalize_group_by(cls, value: str | None) -> str | None:
        text = clean_optional_text(value)
        return text.lower() if text else None

    @model_validator(mode="after")
    def ensure_time_range(self) -> "SecurityAnalyticsBaseInput":
        validate_time_range(self.startTimestamp, self.endTimestamp)
        if self.startTimestamp is None and self.endTimestamp is None:
            now = datetime.now()
            self.endTimestamp = int(now.timestamp())
            self.startTimestamp = int((now - timedelta(days=7)).timestamp())
        elif self.startTimestamp is not None and self.endTimestamp is None:
            self.endTimestamp = int(datetime.now().timestamp())
        elif self.startTimestamp is None and self.endTimestamp is not None:
            self.startTimestamp = max(0, self.endTimestamp - 7 * 24 * 3600)
        return self

    @property
    def effective_top_n(self) -> int:
        return int(self.top_n or self.page_size or 10)


class EventTrendSkill(BaseSkill):
    name = "EventTrendSkill"
    __init_schema__ = SecurityAnalyticsBaseInput

    def execute(self, session_id: str, params: dict[str, Any], user_text: str) -> list[dict[str, Any]]:
        _ = user_text
        model = self.validate_and_prepare(session_id, params)
        analytics = SecurityAnalyticsService(self.requester)
        filters = {"severities": model.severities} if model.severities else {}
        scan_result = analytics.scan_incidents(
            start_ts=int(model.startTimestamp or 0),
            end_ts=int(model.endTimestamp or 0),
            max_scan=model.max_scan,
            extra_filters=filters,
        )
        if scan_result.get("error") and not scan_result.get("rows"):
            return [text_payload(f"安全事件趋势分析失败：{scan_result['error']}", title="安全事件发生趋势")]

        rows = scan_result["rows"]
        _remember_incidents(self, session_id, rows)
        aggregated = analytics.aggregate_event_trend(
            rows,
            start_ts=int(model.startTimestamp or 0),
            end_ts=int(model.endTimestamp or 0),
            granularity=model.group_by if model.group_by in {"hour", "day"} else None,
        )
        summary = (
            f"统计时间范围：{_format_window(int(model.startTimestamp or 0), int(model.endTimestamp or 0))}。"
            f" 共扫描并纳入统计 {aggregated['total']} 条事件，按{('小时' if aggregated['granularity'] == 'hour' else '天')}聚合。"
            f" 峰值出现在 {aggregated['peak_label']}，峰值数量 {aggregated['peak_count']} 条。"
            f"{_build_scan_notice(scan_result)}"
        )

        trend_option = {
            "title": {"text": "安全事件总体趋势"},
            "tooltip": {"trigger": "axis"},
            "xAxis": {"type": "category", "data": aggregated["labels"]},
            "yAxis": {"type": "value"},
            "series": [{"name": "事件总数", "type": "line", "smooth": True, "data": aggregated["overall"]}],
        }
        severity_option = {
            "title": {"text": "安全事件等级拆分趋势"},
            "tooltip": {"trigger": "axis"},
            "legend": {"data": [series["name"] for series in aggregated["severity_series"]]},
            "xAxis": {"type": "category", "data": aggregated["labels"]},
            "yAxis": {"type": "value"},
            "series": [
                {
                    "name": series["name"],
                    "type": "bar",
                    "stack": "total",
                    "data": series["data"],
                }
                for series in aggregated["severity_series"]
            ],
        }

        table_columns = [
            {"key": "bucket", "label": "时间桶"},
            {"key": "total", "label": "总数"},
            {"key": "严重", "label": "严重"},
            {"key": "高危", "label": "高危"},
            {"key": "中危", "label": "中危"},
            {"key": "低危", "label": "低危"},
            {"key": "信息", "label": "信息"},
        ]
        return [
            text_payload(summary, title="安全事件发生趋势"),
            echarts_payload(title="安全事件总体趋势", option=trend_option, summary=summary),
            echarts_payload(title="安全事件等级拆分趋势", option=severity_option, summary="按事件等级拆分的堆叠趋势图。"),
            table_payload(title="安全事件趋势明细", columns=table_columns, rows=aggregated["detail_rows"], namespace="event_trend"),
        ]


class EventTypeDistributionSkill(BaseSkill):
    name = "EventTypeDistributionSkill"
    __init_schema__ = SecurityAnalyticsBaseInput

    def execute(self, session_id: str, params: dict[str, Any], user_text: str) -> list[dict[str, Any]]:
        _ = user_text
        model = self.validate_and_prepare(session_id, params)
        analytics = SecurityAnalyticsService(self.requester)
        filters = {"severities": model.severities} if model.severities else {}
        scan_result = analytics.scan_incidents(
            start_ts=int(model.startTimestamp or 0),
            end_ts=int(model.endTimestamp or 0),
            max_scan=model.max_scan,
            extra_filters=filters,
        )
        if scan_result.get("error") and not scan_result.get("rows"):
            return [text_payload(f"安全事件类型分布分析失败：{scan_result['error']}", title="安全事件类型分布")]

        rows = scan_result["rows"]
        _remember_incidents(self, session_id, rows)
        aggregated = analytics.aggregate_event_type_distribution(rows, top_n=model.effective_top_n)
        top_name = aggregated["gpt_result_top"][0]["name"] if aggregated["gpt_result_top"] else "无"
        summary = (
            f"统计时间范围：{_format_window(int(model.startTimestamp or 0), int(model.endTimestamp or 0))}。"
            f" 共统计 {aggregated['total']} 条事件，当前占比最高的研判结论为 {top_name}。"
            f" 已输出研判结论 TopN 与高危/严重事件研判分布。{_build_scan_notice(scan_result)}"
        )
        return [
            text_payload(summary, title="安全事件类型分布"),
            echarts_payload(
                title="事件研判结论 TopN",
                option=_bar_chart_option(title="事件研判结论 TopN", rows=aggregated["gpt_result_top"], series_name="事件数"),
                summary="按“研判结论”聚合，缺失时回退到“GPT研判结论中文描述”的 TopN 分布。",
            ),
            echarts_payload(
                title="高危/严重事件研判 TopN",
                option=_bar_chart_option(title="高危/严重事件研判 TopN", rows=aggregated["high_risk_top"], series_name="事件数"),
                summary="仅统计高危/严重事件后的研判结论分布。",
            ),
            table_payload(
                title="事件类型分布明细",
                columns=[
                    {"key": "gptResultLabel", "label": "研判结论"},
                    {"key": "incidentThreatClass", "label": "一级分类"},
                    {"key": "incidentThreatType", "label": "二级分类"},
                    {"key": "count", "label": "数量"},
                    {"key": "ratio", "label": "占比"},
                ],
                rows=aggregated["detail_rows"],
                namespace="event_type_distribution",
            ),
        ]


class AlertTrendSkill(BaseSkill):
    name = "AlertTrendSkill"
    __init_schema__ = SecurityAnalyticsBaseInput

    def execute(self, session_id: str, params: dict[str, Any], user_text: str) -> list[dict[str, Any]]:
        _ = user_text
        model = self.validate_and_prepare(session_id, params)
        analytics = SecurityAnalyticsService(self.requester)
        scan_result = analytics.scan_alerts(
            start_ts=int(model.startTimestamp or 0),
            end_ts=int(model.endTimestamp or 0),
            max_scan=model.max_scan,
        )
        if scan_result.get("error") and not scan_result.get("rows"):
            return [text_payload(f"安全告警趋势分析失败：{scan_result['error']}", title="安全告警发生趋势")]

        rows = scan_result["rows"]
        _remember_alerts(self, session_id, rows)
        aggregated = analytics.aggregate_alert_trend(
            rows,
            start_ts=int(model.startTimestamp or 0),
            end_ts=int(model.endTimestamp or 0),
            granularity=model.group_by if model.group_by in {"hour", "day"} else None,
        )
        summary = (
            f"统计时间范围：{_format_window(int(model.startTimestamp or 0), int(model.endTimestamp or 0))}。"
            f" 共扫描并纳入统计 {aggregated['total']} 条告警，按{('小时' if aggregated['granularity'] == 'hour' else '天')}聚合。"
            f" 峰值出现在 {aggregated['peak_label']}，峰值数量 {aggregated['peak_count']} 条。"
            f"{_build_scan_notice(scan_result)}"
        )

        trend_option = {
            "title": {"text": "安全告警总体趋势"},
            "tooltip": {"trigger": "axis"},
            "xAxis": {"type": "category", "data": aggregated["labels"]},
            "yAxis": {"type": "value"},
            "series": [{"name": "告警总数", "type": "line", "smooth": True, "data": aggregated["overall"]}],
        }
        severity_option = {
            "title": {"text": "安全告警等级拆分趋势"},
            "tooltip": {"trigger": "axis"},
            "legend": {"data": [series["name"] for series in aggregated["severity_series"]]},
            "xAxis": {"type": "category", "data": aggregated["labels"]},
            "yAxis": {"type": "value"},
            "series": [
                {
                    "name": series["name"],
                    "type": "bar",
                    "stack": "total",
                    "data": series["data"],
                }
                for series in aggregated["severity_series"]
            ],
        }

        table_columns = [
            {"key": "bucket", "label": "时间桶"},
            {"key": "total", "label": "总数"},
            {"key": "严重", "label": "严重"},
            {"key": "高危", "label": "高危"},
            {"key": "中危", "label": "中危"},
            {"key": "低危", "label": "低危"},
            {"key": "信息", "label": "信息"},
        ]
        return [
            text_payload(summary, title="安全告警发生趋势"),
            echarts_payload(title="安全告警总体趋势", option=trend_option, summary=summary),
            echarts_payload(title="安全告警等级拆分趋势", option=severity_option, summary="按告警等级拆分的堆叠趋势图。"),
            table_payload(title="安全告警趋势明细", columns=table_columns, rows=aggregated["detail_rows"], namespace="alert_trend"),
        ]


class EventDispositionSummarySkill(BaseSkill):
    name = "EventDispositionSummarySkill"
    __init_schema__ = SecurityAnalyticsBaseInput

    def execute(self, session_id: str, params: dict[str, Any], user_text: str) -> list[dict[str, Any]]:
        _ = user_text
        model = self.validate_and_prepare(session_id, params)
        analytics = SecurityAnalyticsService(self.requester)
        filters = {"severities": model.severities} if model.severities else {}
        scan_result = analytics.scan_incidents(
            start_ts=int(model.startTimestamp or 0),
            end_ts=int(model.endTimestamp or 0),
            max_scan=model.max_scan,
            extra_filters=filters,
        )
        if scan_result.get("error") and not scan_result.get("rows"):
            return [text_payload(f"安全事件处置成果分析失败：{scan_result['error']}", title="安全事件处置成果")]

        rows = scan_result["rows"]
        _remember_incidents(self, session_id, rows)
        aggregated = analytics.aggregate_event_disposition_summary(rows, top_n=model.effective_top_n)
        pending_count = len(aggregated["pending_table_rows"])
        summary = (
            f"统计时间范围：{_format_window(int(model.startTimestamp or 0), int(model.endTimestamp or 0))}。"
            f" 共统计 {aggregated['total']} 条事件，当前已处置率为 {aggregated['disposed_ratio']}。"
            f" 仍有 {pending_count} 条高优先级待处置事件已列出。"
            " 当前版本为状态快照，不代表历史处置流水。"
            f"{_build_scan_notice(scan_result)}"
        )
        return [
            text_payload(summary, title="安全事件处置成果"),
            echarts_payload(
                title="事件处置状态分布",
                option=_pie_chart_option(title="事件处置状态分布", rows=aggregated["status_rows"]),
                summary="按当前处置状态聚合的状态快照。",
            ),
            echarts_payload(
                title="事件处置动作分布",
                option=_pie_chart_option(title="事件处置动作分布", rows=aggregated["action_rows"]),
                summary="按当前处置动作聚合的分布。",
            ),
            table_payload(
                title="事件处置状态/动作明细",
                columns=[
                    {"key": "category", "label": "类别"},
                    {"key": "name", "label": "名称"},
                    {"key": "count", "label": "数量"},
                    {"key": "ratio", "label": "占比"},
                ],
                rows=aggregated["summary_table_rows"],
                namespace="event_disposition_summary",
            ),
            table_payload(
                title="待处置重点事件清单",
                columns=[
                    {"key": "uuId", "label": "事件ID"},
                    {"key": "name", "label": "事件名称"},
                    {"key": "incidentSeverity", "label": "等级"},
                    {"key": "dealStatus", "label": "状态"},
                    {"key": "hostIp", "label": "主机IP"},
                    {"key": "endTime", "label": "最近发生"},
                ],
                rows=aggregated["pending_table_rows"],
                namespace="event_disposition_pending",
            ),
        ]


class KeyEventInsightSkill(BaseSkill):
    name = "KeyEventInsightSkill"
    __init_schema__ = SecurityAnalyticsBaseInput

    def execute(self, session_id: str, params: dict[str, Any], user_text: str) -> list[dict[str, Any]]:
        _ = user_text
        model = self.validate_and_prepare(session_id, params)
        analytics = SecurityAnalyticsService(self.requester)
        filters = {"severities": model.severities} if model.severities else {}
        scan_result = analytics.scan_incidents(
            start_ts=int(model.startTimestamp or 0),
            end_ts=int(model.endTimestamp or 0),
            max_scan=model.max_scan,
            extra_filters=filters,
        )
        if scan_result.get("error") and not scan_result.get("rows"):
            return [text_payload(f"重点事件解读失败：{scan_result['error']}", title="重点安全事件解读")]

        rows = scan_result["rows"]
        _remember_incidents(self, session_id, rows)
        selected = analytics.select_key_events(rows, top_n=model.effective_top_n)
        if not selected:
            return [text_payload("当前时间范围内未找到可解读的重点事件。", title="重点安全事件解读")]

        insights = [analytics.build_key_event_insight(row) for row in selected]
        overview_rows = [
            {
                **insight["event_row"],
                "riskTags": "、".join(insight["risk_tags"]) if insight["risk_tags"] else "-",
                "entitySummary": insight["entity_summary"],
            }
            for insight in insights
        ]
        summary = (
            f"统计时间范围：{_format_window(int(model.startTimestamp or 0), int(model.endTimestamp or 0))}。"
            f" 已按“严重度 > 未处置 > 最近发生时间”筛选 Top {len(insights)} 重点事件。"
            f"{_build_scan_notice(scan_result)}"
        )

        payloads: list[dict[str, Any]] = [
            text_payload(summary, title="重点安全事件解读"),
            table_payload(
                title="重点事件总表",
                columns=[
                    {"key": "uuId", "label": "事件ID"},
                    {"key": "name", "label": "事件名称"},
                    {"key": "incidentSeverity", "label": "等级"},
                    {"key": "dealStatus", "label": "状态"},
                    {"key": "endTime", "label": "最近发生"},
                    {"key": "riskTags", "label": "风险标签"},
                    {"key": "entitySummary", "label": "关联外网实体"},
                ],
                rows=overview_rows,
                namespace="key_event_overview",
            ),
        ]
        for idx, insight in enumerate(insights, start=1):
            event_row = insight["event_row"]
            detail_text = (
                f"重点事件 {idx}：{event_row['name']}（{event_row['uuId']}）\n"
                f"等级：{event_row['incidentSeverity']}，状态：{event_row['dealStatus']}，最近发生：{event_row['endTime']}\n"
                f"GPT研判结论：{insight['gpt_result']}\n"
                f"风险标签：{'、'.join(insight['risk_tags']) if insight['risk_tags'] else '无'}\n"
                f"关键时间线摘要：{insight['timeline_summary']}\n"
                f"关联外网实体：{insight['entity_summary']}\n"
                f"建议处置动作：{insight['advice']}"
            )
            if insight["errors"]:
                detail_text += f"\n补充说明：{'；'.join(insight['errors'])}"
            payloads.append(text_payload(detail_text, title=f"重点事件解读 #{idx}"))
            if insight["timeline_rows"]:
                payloads.append(
                    table_payload(
                        title=f"重点事件 #{idx} 时间线",
                        columns=[
                            {"key": "name", "label": "节点"},
                            {"key": "stage", "label": "阶段"},
                            {"key": "severity", "label": "等级"},
                            {"key": "lastTime", "label": "时间"},
                        ],
                        rows=insight["timeline_rows"],
                        namespace="key_event_timeline",
                    )
                )
        return payloads


class AlertClassificationSummarySkill(BaseSkill):
    name = "AlertClassificationSummarySkill"
    __init_schema__ = SecurityAnalyticsBaseInput

    def execute(self, session_id: str, params: dict[str, Any], user_text: str) -> list[dict[str, Any]]:
        _ = (session_id, user_text)
        model = self.validate_and_prepare(session_id, params)
        analytics = SecurityAnalyticsService(self.requester)
        scan_result = analytics.scan_alerts(
            start_ts=int(model.startTimestamp or 0),
            end_ts=int(model.endTimestamp or 0),
            max_scan=model.max_scan,
        )
        if scan_result.get("error") and not scan_result.get("rows"):
            return [text_payload(f"安全告警分类分析失败：{scan_result['error']}", title="安全告警分类情况")]

        rows = scan_result["rows"]
        _remember_alerts(self, session_id, rows)
        aggregated = analytics.aggregate_alert_classification_summary(rows, top_n=model.effective_top_n)
        top_class = aggregated["class_top"][0]["name"] if aggregated["class_top"] else "无"
        top_direction = aggregated["direction_rows"][0]["name"] if aggregated["direction_rows"] else "无"
        summary = (
            f"统计时间范围：{_format_window(int(model.startTimestamp or 0), int(model.endTimestamp or 0))}。"
            f" 共统计 {aggregated['total']} 条告警，一级分类 Top1 为 {top_class}，访问方向高发类型为 {top_direction}。"
            f"{_build_scan_notice(scan_result)}"
        )
        return [
            text_payload(summary, title="安全告警分类情况"),
            echarts_payload(
                title="告警一级分类 TopN",
                option=_bar_chart_option(title="告警一级分类 TopN", rows=aggregated["class_top"], series_name="告警数"),
                summary="按告警一级分类聚合。",
            ),
            echarts_payload(
                title="告警二级分类 TopN",
                option=_bar_chart_option(title="告警二级分类 TopN", rows=aggregated["type_top"], series_name="告警数"),
                summary="按告警二级分类聚合。",
            ),
            echarts_payload(
                title="告警三级分类 TopN",
                option=_bar_chart_option(title="告警三级分类 TopN", rows=aggregated["subtype_top"], series_name="告警数"),
                summary="按告警三级分类聚合。",
            ),
            echarts_payload(
                title="告警严重性分布",
                option=_pie_chart_option(title="告警严重性分布", rows=aggregated["severity_rows"]),
                summary="按告警严重性聚合。",
            ),
            echarts_payload(
                title="告警处置状态分布",
                option=_pie_chart_option(title="告警处置状态分布", rows=aggregated["status_rows"]),
                summary="按当前告警处置状态聚合。",
            ),
            echarts_payload(
                title="告警访问方向分布",
                option=_pie_chart_option(title="告警访问方向分布", rows=aggregated["direction_rows"]),
                summary="按访问方向聚合。",
            ),
            table_payload(
                title="告警分类明细",
                columns=[
                    {"key": "threatClassDesc", "label": "一级分类"},
                    {"key": "threatTypeDesc", "label": "二级分类"},
                    {"key": "threatSubTypeDesc", "label": "三级分类"},
                    {"key": "count", "label": "数量"},
                    {"key": "ratio", "label": "占比"},
                ],
                rows=aggregated["detail_rows"],
                namespace="alert_classification_summary",
            ),
        ]
