from __future__ import annotations

import unittest
from datetime import datetime

from app.core.context import SkillContextManager
from app.skills.security_analytics_skills import (
    AlertClassificationSummarySkill,
    EventDispositionSummarySkill,
    EventTrendSkill,
    EventTypeDistributionSkill,
    KeyEventInsightSkill,
)


def to_ts(text: str) -> int:
    return int(datetime.strptime(text, "%Y-%m-%d %H:%M:%S").timestamp())


class SkillRequester:
    def __init__(self, *, fail_incidents: bool = False, fail_alerts: bool = False) -> None:
        self.fail_incidents = fail_incidents
        self.fail_alerts = fail_alerts
        self.incidents = [
            {
                "uuId": "incident-skill-001",
                "name": "严重横向移动",
                "incidentSeverity": 4,
                "dealStatus": 0,
                "dealAction": "未处理",
                "hostIp": "10.10.0.1",
                "threatDefineName": "横向移动",
                "gptResults": [110],
                "incidentThreatClass": "主机风险",
                "incidentThreatType": "SMB探测",
                "gptResultDescription": "存在横向扩散迹象。",
                "endTime": to_ts("2025-02-21 09:00:00"),
            },
            {
                "uuId": "incident-skill-002",
                "name": "高危恶意外联",
                "incidentSeverity": 3,
                "dealStatus": 10,
                "dealAction": "人工研判",
                "hostIp": "10.10.0.2",
                "threatDefineName": "恶意外联",
                "gptResults": [150],
                "incidentThreatClass": "网络风险",
                "incidentThreatType": "C2通信",
                "gptResultDescription": "怀疑与外部控制端通信。",
                "endTime": to_ts("2025-02-21 11:00:00"),
            },
            {
                "uuId": "incident-skill-003",
                "name": "中危漏洞利用",
                "incidentSeverity": 2,
                "dealStatus": 40,
                "dealAction": "已处置",
                "hostIp": "10.10.0.3",
                "threatDefineName": "漏洞利用",
                "gptResults": [160],
                "incidentThreatClass": "Web风险",
                "incidentThreatType": "命令执行",
                "gptResultDescription": "利用尝试已被拦截。",
                "endTime": to_ts("2025-02-22 08:00:00"),
            },
        ]
        self.alerts = [
            {
                "uuId": "alert-skill-001",
                "name": "高危Web攻击",
                "severity": 80,
                "alertDealStatus": 1,
                "direction": 2,
                "threatClassDesc": "Web攻击",
                "threatTypeDesc": "漏洞利用",
                "threatSubTypeDesc": "命令执行",
                "lastTime": to_ts("2025-02-22 09:00:00"),
            },
            {
                "uuId": "alert-skill-002",
                "name": "异常外联",
                "severity": 65,
                "alertDealStatus": 2,
                "direction": 1,
                "threatClassDesc": "主机风险",
                "threatTypeDesc": "恶意外联",
                "threatSubTypeDesc": "C2通信",
                "lastTime": to_ts("2025-02-22 10:00:00"),
            },
        ]

    def request(self, method, path, *, json_body=None, params=None, timeout=15, max_retries=3):
        _ = (method, params, timeout, max_retries)
        body = json_body or {}
        if path == "/api/xdr/v1/incidents/list":
            if self.fail_incidents:
                return {"code": "Failed", "message": "incident api down", "data": {}}
            severities = set(body.get("severities") or [])
            items = [row for row in self.incidents if not severities or row["incidentSeverity"] in severities]
            return {"code": "Success", "data": {"item": items, "total": len(items)}}
        if path == "/api/xdr/v1/alerts/list":
            if self.fail_alerts:
                return {"code": "Failed", "message": "alert api down", "data": {}}
            return {"code": "Success", "data": {"item": list(self.alerts), "total": len(self.alerts)}}
        if path.endswith("/proof"):
            uid = path.split("/")[-2]
            return {
                "code": "Success",
                "data": [
                    {
                        "name": f"{uid}-proof",
                        "gptResultDescription": f"{uid} 的 GPT 研判结论",
                        "riskTag": ["横向移动", "C2"],
                        "alertTimeLine": [
                            {
                                "name": "初始利用",
                                "severity": 85,
                                "stage": "遭受攻击",
                                "lastTime": to_ts("2025-02-22 08:30:00"),
                            }
                        ],
                    }
                ],
            }
        if path.endswith("/entities/ip"):
            return {"code": "Success", "data": {"item": [{"ip": "8.8.8.8"}, {"ip": "3.3.3.3"}]}}
        return {"code": "Failed", "message": f"unhandled path: {path}", "data": {}}


class SecurityAnalyticsSkillsTest(unittest.TestCase):
    def setUp(self):
        self.context = SkillContextManager(enable_persistence=False)
        self.requester = SkillRequester()

    def test_event_trend_skill_should_return_text_charts_and_table(self):
        skill = EventTrendSkill(self.requester, self.context)
        result = skill.execute("s1", {"time_text": "最近7天"}, "最近7天安全事件发生趋势")
        self.assertEqual([payload["type"] for payload in result], ["text", "echarts_graph", "echarts_graph", "table"])
        self.assertIn("峰值", result[0]["data"]["text"])
        self.assertTrue(result[1]["data"]["option"]["series"])
        self.assertEqual(result[3]["data"]["columns"][0]["key"], "bucket")

    def test_event_type_distribution_skill_should_return_expected_payloads(self):
        skill = EventTypeDistributionSkill(self.requester, self.context)
        result = skill.execute("s2", {"time_text": "最近7天", "top_n": 2}, "最近7天安全事件类型分布")
        self.assertEqual([payload["type"] for payload in result], ["text", "echarts_graph", "echarts_graph", "table"])
        self.assertIn("研判结论", result[0]["data"]["text"])
        self.assertEqual(result[1]["data"]["title"], "事件研判结论 TopN")
        self.assertTrue(result[-1]["data"]["rows"])

    def test_event_disposition_summary_skill_should_include_snapshot_notice(self):
        skill = EventDispositionSummarySkill(self.requester, self.context)
        result = skill.execute("s3", {"time_text": "最近7天"}, "最近7天安全事件处置成果")
        self.assertEqual([payload["type"] for payload in result], ["text", "echarts_graph", "echarts_graph", "table", "table"])
        self.assertIn("状态快照", result[0]["data"]["text"])
        self.assertIn("当前版本为状态快照", result[0]["data"]["text"])

    def test_key_event_insight_skill_should_return_overview_and_details(self):
        skill = KeyEventInsightSkill(self.requester, self.context)
        result = skill.execute("s4", {"time_text": "最近7天", "top_n": 2}, "重点安全事件解读")
        self.assertEqual(result[0]["type"], "text")
        self.assertEqual(result[1]["type"], "table")
        self.assertEqual(result[1]["data"]["title"], "重点事件总表")
        detail_texts = [payload["data"]["text"] for payload in result if payload["type"] == "text"][1:]
        self.assertTrue(any("GPT研判结论" in text for text in detail_texts))

    def test_alert_classification_summary_skill_should_return_multi_chart_payloads(self):
        skill = AlertClassificationSummarySkill(self.requester, self.context)
        result = skill.execute("s5", {"time_text": "最近7天", "top_n": 3}, "最近7天安全告警分类情况")
        self.assertEqual(result[0]["type"], "text")
        self.assertEqual(result[-1]["type"], "table")
        self.assertEqual(sum(1 for payload in result if payload["type"] == "echarts_graph"), 6)
        self.assertIn("告警", result[0]["data"]["text"])

    def test_skill_should_return_friendly_text_when_api_fails(self):
        skill = EventTrendSkill(SkillRequester(fail_incidents=True), self.context)
        result = skill.execute("s6", {"time_text": "最近7天"}, "最近7天安全事件发生趋势")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["type"], "text")
        self.assertIn("分析失败", result[0]["data"]["text"])


if __name__ == "__main__":
    unittest.main()
