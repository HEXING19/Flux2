from __future__ import annotations

import unittest
from typing import Any

from app.core.context import SkillContextManager
from app.core.exceptions import ValidationGuardException
from app.skills.block_skills import BlockActionSkill, BlockQuerySkill


class FakeRequester:
    def __init__(
        self,
        *,
        block_items: list[dict[str, Any]] | None = None,
        online_devices: list[dict[str, Any]] | None = None,
        device_response: dict[str, Any] | None = None,
    ):
        self.block_items = block_items or []
        self.online_devices = online_devices if online_devices is not None else []
        self.device_response = device_response

    def request(self, method, path, *, json_body=None, params=None, timeout=15):
        _ = (method, json_body, params, timeout)
        if path == "/api/xdr/v1/device/blockdevice/list":
            if self.device_response is not None:
                return self.device_response
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

    def test_block_query_can_inherit_last_entity_ip_for_pronoun_question(self):
        query_skill = BlockQuerySkill(FakeRequester(block_items=[], online_devices=self.online_devices), self.ctx)
        self.ctx.update_params("s1", {"last_entity_ip": "111.112.113.201"})
        payloads = query_skill.execute("s1", {}, "查看这个IP地址是不是已经被封禁")
        self.assertEqual(payloads[0]["type"], "text")
        self.assertIn("111.112.113.201", payloads[0]["data"]["text"])

    def test_block_query_table_should_show_ip_from_block_ip_rule_view(self):
        query_skill = BlockQuerySkill(
            FakeRequester(
                block_items=[
                    {
                        "id": "rule-001",
                        "name": "新增IP封锁_1773786034",
                        "status": "unblocked",
                        "reason": "智能对抗",
                        "updateTime": 1710249600,
                        "blockIpRule": {
                            "type": "SRC_IP",
                            "mode": "in",
                            "view": ["49.210.199.214"],
                        },
                    }
                ],
                online_devices=self.online_devices,
            ),
            self.ctx,
        )
        payloads = query_skill.execute("s1", {"keyword": "49.210.199.214"}, "查看这个IP地址是不是已经被封禁")
        self.assertEqual(payloads[1]["type"], "table")
        self.assertEqual(payloads[1]["data"]["rows"][0]["view"], "49.210.199.214")

    def test_block_action_form_should_include_device_field_when_no_online_device(self):
        skill = BlockActionSkill(FakeRequester(online_devices=[]), self.ctx)
        payloads = skill.execute(
            "s1",
            {
                "block_type": "SRC_IP",
                "views": ["111.112.113.201"],
                "time_type": "temporary",
                "time_value": 1,
                "time_unit": "d",
            },
            "封禁这个IP",
        )
        self.assertEqual(payloads[0]["type"], "form_card")
        self.assertIn("联动设备", payloads[0]["data"]["description"])
        field_keys = {f["key"] for f in payloads[0]["data"]["fields"]}
        self.assertIn("device_id", field_keys)

    def test_block_action_should_recognize_linkable_device_by_remark(self):
        skill = BlockActionSkill(
            FakeRequester(
                online_devices=[
                    {
                        "deviceId": 9,
                        "deviceName": "AF_009",
                        "deviceStatus": "block success",
                        "deviceType": "AF",
                        "deviceVersion": "8.0",
                        "remark": "(可联动)",
                    }
                ]
            ),
            self.ctx,
        )
        payloads = skill.execute(
            "s1",
            {
                "block_type": "SRC_IP",
                "views": ["111.112.113.201"],
                "time_type": "temporary",
                "time_value": 1,
                "time_unit": "d",
                "confirm": True,
            },
            "封禁这个IP",
        )
        self.assertEqual(payloads[0]["type"], "text")
        self.assertIn("封禁执行成功", payloads[0]["data"]["text"])

    def test_block_action_should_surface_device_lookup_error(self):
        skill = BlockActionSkill(
            FakeRequester(
                device_response={
                    "code": "Failed",
                    "message": "请求失败(403): forbid。认证失败或权限不足，请重新登录并确认账号已开通该接口权限。",
                    "data": {},
                }
            ),
            self.ctx,
        )
        payloads = skill.execute(
            "s1",
            {
                "block_type": "SRC_IP",
                "views": ["111.112.113.201"],
                "time_type": "temporary",
                "time_value": 1,
                "time_unit": "d",
            },
            "封禁这个IP",
        )
        self.assertEqual(payloads[0]["type"], "form_card")
        self.assertIn("查询 AF 联动设备失败", payloads[0]["data"]["description"])

    def test_block_action_should_prefer_explicit_ip_over_inherited_context(self):
        skill = BlockActionSkill(FakeRequester(online_devices=self.online_devices), self.ctx)
        self.ctx.update_params("s1", {"last_block_target": "49.210.199.214", "last_entity_ip": "49.210.199.214"})
        payloads = skill.execute(
            "s1",
            {
                "block_type": "SRC_IP",
                "views": ["124.34.53.234"],
            },
            "帮我封禁124.34.53.234这个IP地址",
        )
        self.assertEqual(payloads[0]["type"], "form_card")
        view_field = next(f for f in payloads[0]["data"]["fields"] if f["key"] == "views")
        self.assertEqual(view_field["value"], "124.34.53.234")


if __name__ == "__main__":
    unittest.main()
