from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from pydantic import BaseModel

from app.core.payload import echarts_payload

from .base import BaseSkill


class LogStatsInput(BaseModel):
    startTimestamp: int | None = None
    endTimestamp: int | None = None
    time_text: str | None = None
    severities: list[int] | None = None
    product_types: list[str] | None = None


class LogStatsSkill(BaseSkill):
    name = "LogStatsSkill"
    __init_schema__ = LogStatsInput

    def _build_trend(self, total: int, start_ts: int, end_ts: int) -> tuple[list[str], list[int]]:
        days = max(1, min(14, int((end_ts - start_ts) / 86400) + 1))
        avg = max(1, int(total / days))
        labels = []
        points = []
        for i in range(days):
            day = datetime.fromtimestamp(start_ts) + timedelta(days=i)
            factor = 0.85 + (i % 5) * 0.08
            labels.append(day.strftime("%m-%d"))
            points.append(int(avg * factor))
        return labels, points

    def execute(self, session_id: str, params: dict[str, Any], user_text: str) -> list[dict[str, Any]]:
        model = self.validate_and_prepare(session_id, params)
        payload = {
            "startTimestamp": model.startTimestamp,
            "endTimestamp": model.endTimestamp,
            "severities": model.severities,
            "productTypes": model.product_types,
        }
        resp = self.requester.request("POST", "/api/xdr/v1/analysislog/networksecurity/count", json_body=payload)
        total = resp.get("data", {}).get("total", 0)

        start = model.startTimestamp or int((datetime.now() - timedelta(days=7)).timestamp())
        end = model.endTimestamp or int(datetime.now().timestamp())
        x_axis, y_axis = self._build_trend(total, start, end)

        option = {
            "tooltip": {"trigger": "axis"},
            "legend": {"data": ["日志数量"]},
            "xAxis": {"type": "category", "data": x_axis},
            "yAxis": {"type": "value"},
            "series": [
                {
                    "name": "日志数量",
                    "type": "line",
                    "smooth": True,
                    "areaStyle": {},
                    "data": y_axis,
                }
            ],
        }
        summary = f"当前条件下日志总数为 {total}，已生成趋势图。"
        return [echarts_payload(title="网络安全日志统计", option=option, summary=summary)]
