from __future__ import annotations

import unittest

from app.core.context import SkillContextManager


class ContextManagerTest(unittest.TestCase):
    def setUp(self):
        self.ctx = SkillContextManager()
        self.session = "s1"
        self.ctx.store_index_mapping(self.session, "events", ["u1", "u2", "u3", "u4"])

    def test_front_n(self):
        resolved = self.ctx.resolve_indices(self.session, "events", "把前两个处置")
        self.assertEqual(resolved, ["u1", "u2"])

    def test_skip_first_and_remaining(self):
        resolved = self.ctx.resolve_indices(self.session, "events", "跳过第一个把剩下全办了")
        self.assertEqual(resolved, ["u2", "u3", "u4"])

    def test_specific_index(self):
        resolved = self.ctx.resolve_indices(self.session, "events", "查看第3个详情")
        self.assertEqual(resolved, ["u3"])

    def test_serial_wording_index(self):
        resolved = self.ctx.resolve_indices(self.session, "events", "查看序号2事件详情")
        self.assertEqual(resolved, ["u2"])


if __name__ == "__main__":
    unittest.main()
