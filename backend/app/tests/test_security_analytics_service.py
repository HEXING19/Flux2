from __future__ import annotations

import unittest
from datetime import datetime

from app.services.security_analytics_service import SecurityAnalyticsService


def to_ts(text: str) -> int:
    return int(datetime.strptime(text, "%Y-%m-%d %H:%M:%S").timestamp())


class AnalyticsRequester:
    def __init__(self) -> None:
        self.incidents = [
            {
                "uuId": "incident-analytics-001",
                "name": "异常横向移动",
                "incidentSeverity": 4,
                "dealStatus": 0,
                "dealAction": "未处理",
                "hostIp": "10.0.0.1",
                "threatDefineName": "横向移动",
                "gptResults": [110],
                "incidentThreatClass": "横向渗透",
                "incidentThreatType": "SMB探测",
                "endTime": to_ts("2025-02-20 10:00:00"),
            },
            {
                "uuId": "incident-analytics-002",
                "name": "疑似C2通信",
                "incidentSeverity": 3,
                "dealStatus": 10,
                "dealAction": "研判中",
                "hostIp": "10.0.0.2",
                "threatDefineName": "恶意外联",
                "gptResultDescription": "疑似攻击行为",
                "incidentThreatClass": "外联风险",
                "incidentThreatType": "C2通信",
                "endTime": to_ts("2025-02-20 15:00:00"),
            },
            {
                "uuId": "incident-analytics-003",
                "name": "漏洞利用尝试",
                "incidentSeverity": 2,
                "dealStatus": 40,
                "dealAction": "已处置",
                "hostIp": "10.0.0.3",
                "threatDefineName": "漏洞利用",
                "gptResults": [160],
                "incidentThreatClass": "主机风险",
                "incidentThreatType": "命令执行",
                "endTime": to_ts("2025-02-21 09:00:00"),
            },
            {
                "uuId": "incident-analytics-004",
                "name": "可疑登录",
                "incidentSeverity": 1,
                "dealStatus": 70,
                "dealAction": "已遏制",
                "hostIp": "10.0.0.4",
                "threatDefineName": "异常登录",
                "gptResults": [170],
                "incidentThreatClass": "账号风险",
                "incidentThreatType": "口令撞库",
                "endTime": to_ts("2025-02-21 11:00:00"),
            },
        ]
        self.alerts = [
            {
                "uuId": "alert-analytics-001",
                "name": "高危Web攻击",
                "severity": 80,
                "alertDealStatus": 1,
                "direction": 2,
                "threatClassDesc": "Web攻击",
                "threatTypeDesc": "漏洞利用",
                "threatSubTypeDesc": "命令执行",
                "lastTime": to_ts("2025-02-21 10:00:00"),
            },
            {
                "uuId": "alert-analytics-002",
                "name": "异常外联",
                "severity": 65,
                "alertDealStatus": 2,
                "direction": 1,
                "threatClassDesc": "主机风险",
                "threatTypeDesc": "恶意外联",
                "threatSubTypeDesc": "C2通信",
                "lastTime": to_ts("2025-02-21 11:00:00"),
            },
            {
                "uuId": "alert-analytics-003",
                "name": "横向探测",
                "severity": 48,
                "alertDealStatus": 1,
                "direction": 3,
                "threatClassDesc": "主机风险",
                "threatTypeDesc": "横向移动",
                "threatSubTypeDesc": "SMB探测",
                "lastTime": to_ts("2025-02-21 12:00:00"),
            },
        ]

    def request(self, method, path, *, json_body=None, params=None, timeout=15, max_retries=3):
        _ = (method, params, timeout, max_retries)
        body = json_body or {}
        if path == "/api/xdr/v1/incidents/list":
            page = int(body.get("page", 1))
            page_size = int(body.get("pageSize", 200))
            start = (page - 1) * page_size
            end = start + page_size
            items = self.incidents[start:end]
            return {"code": "Success", "data": {"item": items, "total": len(self.incidents)}}
        if path == "/api/xdr/v1/alerts/list":
            return {"code": "Success", "data": {"item": list(self.alerts), "total": len(self.alerts)}}
        return {"code": "Failed", "message": f"unhandled path: {path}", "data": {}}


class SecurityAnalyticsServiceTest(unittest.TestCase):
    def setUp(self):
        self.requester = AnalyticsRequester()
        self.service = SecurityAnalyticsService(self.requester)
        self.event_rows = [self.service._normalize_event_row(item, idx) for idx, item in enumerate(self.requester.incidents, start=1)]
        self.alert_rows = [self.service._normalize_alert_row(item, idx) for idx, item in enumerate(self.requester.alerts, start=1)]

    def test_event_trend_should_aggregate_by_day(self):
        aggregated = self.service.aggregate_event_trend(
            self.event_rows[:3],
            start_ts=to_ts("2025-02-20 00:00:00"),
            end_ts=to_ts("2025-02-23 00:00:00"),
        )
        self.assertEqual(aggregated["granularity"], "day")
        self.assertEqual(aggregated["overall"][:2], [2, 1])
        self.assertEqual(aggregated["peak_count"], 2)

    def test_event_trend_should_switch_to_hour_for_24h_window(self):
        rows = [
            self.service._normalize_event_row(
                {
                    "uuId": "incident-hour-001",
                    "name": "凌晨攻击",
                    "incidentSeverity": 4,
                    "dealStatus": 0,
                    "endTime": to_ts("2025-02-21 01:15:00"),
                },
                1,
            ),
            self.service._normalize_event_row(
                {
                    "uuId": "incident-hour-002",
                    "name": "午间攻击",
                    "incidentSeverity": 3,
                    "dealStatus": 0,
                    "endTime": to_ts("2025-02-21 12:05:00"),
                },
                2,
            ),
        ]
        aggregated = self.service.aggregate_event_trend(
            rows,
            start_ts=to_ts("2025-02-21 00:00:00"),
            end_ts=to_ts("2025-02-21 23:59:59"),
        )
        self.assertEqual(aggregated["granularity"], "hour")
        self.assertEqual(sum(aggregated["overall"]), 2)
        self.assertEqual(len(aggregated["labels"]), 24)

    def test_event_type_distribution_should_merge_other_bucket(self):
        aggregated = self.service.aggregate_event_type_distribution(self.event_rows, top_n=2)
        top_rows = aggregated["gpt_result_top"]
        self.assertEqual(len(top_rows), 3)
        self.assertEqual(top_rows[-1]["name"], "其他")
        self.assertEqual(sum(row["count"] for row in top_rows), 4)
        detail_labels = {row["gptResultLabel"] for row in aggregated["detail_rows"]}
        self.assertIn("真实攻击成功", detail_labels)

    def test_event_disposition_summary_should_calculate_snapshot_metrics(self):
        aggregated = self.service.aggregate_event_disposition_summary(self.event_rows, top_n=5)
        self.assertEqual(aggregated["disposed_count"], 2)
        self.assertEqual(aggregated["disposed_ratio"], "50.0%")
        self.assertTrue(aggregated["pending_table_rows"])
        self.assertEqual(aggregated["pending_table_rows"][0]["uuId"], "incident-analytics-001")

    def test_alert_classification_summary_should_aggregate_dimensions(self):
        aggregated = self.service.aggregate_alert_classification_summary(self.alert_rows, top_n=3)
        self.assertEqual(aggregated["class_top"][0]["name"], "主机风险")
        self.assertEqual(aggregated["class_top"][0]["count"], 2)
        direction_names = [row["name"] for row in aggregated["direction_rows"]]
        self.assertIn("外对内", direction_names)
        self.assertEqual(len(aggregated["detail_rows"]), 3)

    def test_empty_results_should_return_empty_structures(self):
        aggregated = self.service.aggregate_event_type_distribution([], top_n=3)
        self.assertEqual(aggregated["total"], 0)
        self.assertEqual(aggregated["gpt_result_top"], [])
        self.assertEqual(aggregated["detail_rows"], [])

    def test_scan_incidents_should_mark_truncated(self):
        scanned = self.service.scan_incidents(
            start_ts=to_ts("2025-02-20 00:00:00"),
            end_ts=to_ts("2025-02-21 23:59:59"),
            max_scan=2,
            page_size=1,
        )
        self.assertTrue(scanned["truncated"])
        self.assertEqual(len(scanned["rows"]), 2)
        self.assertEqual(scanned["total_hint"], 4)


if __name__ == "__main__":
    unittest.main()
