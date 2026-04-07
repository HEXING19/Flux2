from __future__ import annotations

import unittest

from app.core.time_parser import parse_time_range


class TimeParserTest(unittest.TestCase):
    def test_recent_days(self):
        start, end = parse_time_range("最近三天")
        self.assertLess(start, end)
        self.assertGreater(end - start, 2 * 86400)

    def test_yesterday(self):
        start, end = parse_time_range("昨天")
        self.assertEqual(end - start, 86399)

    def test_raw_hours_without_prefix(self):
        start, end = parse_time_range("24小时")
        self.assertLess(start, end)
        self.assertGreaterEqual(end - start, 24 * 3600 - 2)

    def test_raw_days_without_prefix(self):
        start, end = parse_time_range("7天")
        self.assertLess(start, end)
        self.assertGreaterEqual(end - start, 7 * 86400 - 2)

    def test_default(self):
        start, end = parse_time_range(None)
        self.assertLess(start, end)


if __name__ == "__main__":
    unittest.main()
