from __future__ import annotations

import unittest
from typing import Any

from app.core.context import SkillContextManager
from app.core.exceptions import ValidationGuardException
from app.skills.block_skills import BlockActionSkill, BlockQuerySkill


class FakeRequester:
    def __init__(self, *, block_items: list[dict[str, Any]] | None = None, online_devices: list[dict[str, Any]] | None = None):
        self.block_items = block_items or []
        self.online_devices = online_devices if online_devices is not None else []

    def request(self, method, path, *, json_body=None, params=None, timeout=15):
        _ = (method, json_body, params, timeout)
        if path == "/api/xdr/v1/device/blockdevice/list":
            return {"code": "Success", "message": "成功", "data": {"item": self.online_devices}}
        if path == "/api/xdr/v1/responses/blockiprule/list":
            return {"code": "Success", "message": "成功", "data": {"item": self.block_items}}
        if path == "/api/xdr/v1/responses/blockiprule/network":
            return {"code": "Success", "message": "成功", "data": {"ids": ["rule-001"]}}
        return {"code": "Failed", "message": f"unhandled path: {path}", "data": {}}


class BlockSkillValidationTest(unittest.TestCase):
    def setUp(self):
        self.ctx = SkillContextManager()
        self.online_devices = [
            {"deviceId": 1, "deviceName": "AF_001", "deviceStatus": "online", "deviceType": "AF", "deviceVersion": "8.0"}
        ]

    def test_missing_core_params_returns_form(self):
        skill = BlockActionSkill(FakeRequester(online_devices=self.online_devices), self.ctx)
        payloads = skill.execute("s1", {"time_type": "forever"}, "封禁")
        self.assertEqual(payloads[0]["type"], "form_card")
        field_keys = {f["key"] for f in payloads[0]["data"]["fields"]}
        self.assertIn("views", field_keys)
        self.assertIn("block_type", field_keys)

    def test_temporary_duration_bounds(self):
        skill = BlockActionSkill(FakeRequester(online_devices=self.online_devices), self.ctx)
        with self.assertRaises(ValidationGuardException):
            skill.execute(
                "s1",
                {
                    "block_type": "SRC_IP",
                    "views": ["1.1.1.1"],
                    "time_type": "temporary",
                    "time_value": 20,
                    "time_unit": "d",
                    "devices": [{"devId": 1, "devName": "AF", "devType": "AF", "devVersion": "8"}],
                },
                "临时封禁",
            )

    def test_block_query_empty_returns_unblocked_with_form(self):
        query_skill = BlockQuerySkill(FakeRequester(block_items=[], online_devices=self.online_devices), self.ctx)
        payloads = query_skill.execute("s1", {"keyword": "200.200.1.1"}, "查询IP地址200.200.1.1是否被封禁")
        self.assertEqual(payloads[0]["type"], "text")
        self.assertIn("未封禁", payloads[0]["data"]["text"])
        self.assertEqual(payloads[1]["type"], "form_card")
        view_field = next(f for f in payloads[1]["data"]["fields"] if f["key"] == "views")
        self.assertIn("200.200.1.1", view_field["value"])


if __name__ == "__main__":
    unittest.main()
