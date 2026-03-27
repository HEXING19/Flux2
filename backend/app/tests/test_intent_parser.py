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


if __name__ == "__main__":
    unittest.main()
