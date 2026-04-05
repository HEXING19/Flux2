from __future__ import annotations

import unittest

from app.services.intent_parser import IntentParser


class IntentParserTest(unittest.TestCase):
    def setUp(self):
        self.parser = IntentParser()

    def test_block_status_question_should_route_to_block_query(self):
        parsed = self.parser.parse("查看这个IP地址是不是已经被封禁")
        self.assertEqual(parsed.intent, "block_query")

    def test_block_status_question_with_has_any_should_route_to_block_query(self):
        parsed = self.parser.parse("这个IP有没有被封禁")
        self.assertEqual(parsed.intent, "block_query")

    def test_explicit_block_action_should_route_to_block_action(self):
        parsed = self.parser.parse("封禁1.1.1.1 2小时")
        self.assertEqual(parsed.intent, "block_action")
        self.assertEqual(parsed.params.get("time_type"), "temporary")

    def test_explicit_block_action_should_extract_ip_without_spaces(self):
        parsed = self.parser.parse("帮我封禁124.34.53.234这个IP地址")
        self.assertEqual(parsed.intent, "block_action")
        self.assertEqual(parsed.params.get("views"), ["124.34.53.234"])

    def test_custom_semantic_rule_should_expand_event_severities(self):
        parsed = self.parser.parse(
            "查询昨日的高等级安全事件",
            semantic_rules=[
                {
                    "domain": "event_query",
                    "slot_name": "severities",
                    "phrase": "高等级",
                    "match_mode": "contains",
                    "action_type": "append",
                    "rule_value": [3, 4],
                    "priority": 100,
                }
            ],
        )
        self.assertEqual(parsed.intent, "event_query")
        self.assertEqual(parsed.params.get("severities"), [3, 4])

    def test_generic_semantic_rule_should_fill_missing_time_text(self):
        parsed = self.parser.parse(
            "查询近期安全事件",
            semantic_rules=[
                {
                    "domain": "event_query",
                    "slot_name": "time_text",
                    "phrase": "近期",
                    "match_mode": "contains",
                    "action_type": "set_if_missing",
                    "rule_value": "最近三天",
                    "priority": 100,
                }
            ],
        )
        self.assertEqual(parsed.intent, "event_query")
        self.assertEqual(parsed.params.get("time_text"), "最近三天")

    def test_generic_semantic_rule_should_replace_block_action_type(self):
        parsed = self.parser.parse(
            "请立即封禁这个域名",
            semantic_rules=[
                {
                    "domain": "block_action",
                    "slot_name": "block_type",
                    "phrase": "域名",
                    "match_mode": "contains",
                    "action_type": "replace",
                    "rule_value": "DNS",
                    "priority": 100,
                }
            ],
        )
        self.assertEqual(parsed.intent, "block_action")
        self.assertEqual(parsed.params.get("block_type"), "DNS")

    def test_event_trend_question_should_route_to_event_trend(self):
        parsed = self.parser.parse("最近 7 天安全事件发生趋势")
        self.assertEqual(parsed.intent, "event_trend")
        self.assertEqual(parsed.params.get("time_text"), "最近7天")

    def test_event_type_distribution_question_should_route_to_event_type_distribution(self):
        parsed = self.parser.parse("最近7天安全事件类型分布")
        self.assertEqual(parsed.intent, "event_type_distribution")

    def test_event_disposition_summary_question_should_route_to_event_disposition_summary(self):
        parsed = self.parser.parse("最近7天安全事件处置成果")
        self.assertEqual(parsed.intent, "event_disposition_summary")

    def test_key_event_insight_question_should_route_to_key_event_insight(self):
        parsed = self.parser.parse("重点安全事件解读")
        self.assertEqual(parsed.intent, "key_event_insight")

    def test_alert_classification_question_should_route_to_alert_classification_summary(self):
        parsed = self.parser.parse("最近7天安全告警分类情况")
        self.assertEqual(parsed.intent, "alert_classification_summary")

    def test_semantic_rule_should_fill_new_analytics_slot(self):
        parsed = self.parser.parse(
            "请帮我看重点安全事件",
            semantic_rules=[
                {
                    "domain": "key_event_insight",
                    "slot_name": "time_text",
                    "phrase": "重点安全事件",
                    "match_mode": "contains",
                    "action_type": "set_if_missing",
                    "rule_value": "最近三天",
                    "priority": 100,
                }
            ],
        )
        self.assertEqual(parsed.intent, "key_event_insight")
        self.assertEqual(parsed.params.get("time_text"), "最近三天")


if __name__ == "__main__":
    unittest.main()
