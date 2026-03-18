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


if __name__ == "__main__":
    unittest.main()
