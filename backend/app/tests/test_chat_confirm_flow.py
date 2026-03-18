from __future__ import annotations

import unittest
from unittest.mock import patch

from sqlmodel import Session

from app.core.db import engine, init_db
from app.services.chat_service import ChatService


class FakeRequester:
    def __init__(self) -> None:
        self.incidents = [
            {
                "uuId": "incident-real-001",
                "name": "异常横向移动告警",
                "incidentSeverity": 3,
                "dealStatus": 0,
                "hostIp": "10.10.0.2",
                "endTime": 1739999900,
            },
            {
                "uuId": "incident-real-002",
                "name": "疑似C2通信活动",
                "incidentSeverity": 3,
                "dealStatus": 10,
                "hostIp": "10.10.0.3",
                "endTime": 1739999800,
            },
        ]

    def request(self, method, path, *, json_body=None, params=None, timeout=15):
        _ = (method, params, timeout)
        payload = json_body or {}
        if path == "/api/xdr/v1/incidents/list":
            severity = set(payload.get("severities") or [])
            items = [row for row in self.incidents if not severity or row["incidentSeverity"] in severity]
            return {"code": "Success", "message": "成功", "data": {"item": items, "total": len(items), "page": 1, "pageSize": 10}}
        if path == "/api/xdr/v1/incidents/dealstatus":
            return {"code": "Success", "message": "成功", "data": {"total": len(payload.get("uuIds", [])), "succeededNum": 1}}
        if path.endswith("/proof"):
            uid = path.split("/")[-2]
            return {
                "code": "Success",
                "message": "成功",
                "data": [
                    {
                        "name": f"{uid}-detail",
                        "gptResultDescription": "测试研判",
                        "riskTag": ["测试标签"],
                        "alertTimeLine": [],
                    }
                ],
            }
        if path.endswith("/entities/ip"):
            return {"code": "Success", "message": "成功", "data": {"item": [{"ip": "8.8.8.8"}]}}
        return {"code": "Failed", "message": f"unhandled path: {path}", "data": {}}


class FakeRequesterEntityVariant(FakeRequester):
    def request(self, method, path, *, json_body=None, params=None, timeout=15):
        if path.endswith("/entities/ip"):
            return {"code": "Success", "message": "成功", "data": [{"IP": "111.112.113.201"}]}
        return super().request(method, path, json_body=json_body, params=params, timeout=timeout)


class FakeRequesterEntityHistory(FakeRequester):
    def __init__(self) -> None:
        super().__init__()
        self.incidents = [
            {
                "uuId": f"incident-real-00{i}",
                "name": f"测试事件{i}",
                "incidentSeverity": 3,
                "dealStatus": 0,
                "hostIp": f"10.10.0.{i}",
                "endTime": 1739999900 - i,
            }
            for i in range(1, 10)
        ]
        self.entity_map = {
            "incident-real-002": [{"ip": "3.3.1.1"}],
            "incident-real-004": [{"ip": "1.1.10.110"}],
            "incident-real-008": [],
        }
        self.block_rules = [
            {
                "id": "rule-3",
                "name": "block_3.3.1.1",
                "status": "block success",
                "reason": "test",
                "updateTime": 1739999000,
                "blockIpRule": {"type": "SRC_IP", "mode": "in", "view": ["3.3.1.1"]},
            },
            {
                "id": "rule-1",
                "name": "block_1.1.10.110",
                "status": "unblocked",
                "reason": "test",
                "updateTime": 1739998000,
                "blockIpRule": {"type": "SRC_IP", "mode": "in", "view": ["1.1.10.110"]},
            },
            {
                "id": "rule-other",
                "name": "block_9.9.9.9",
                "status": "unblocked",
                "reason": "other",
                "updateTime": 1739997000,
                "blockIpRule": {"type": "SRC_IP", "mode": "in", "view": ["9.9.9.9"]},
            },
        ]

    def request(self, method, path, *, json_body=None, params=None, timeout=15):
        if path.endswith("/entities/ip"):
            uid = path.split("/")[-2]
            return {"code": "Success", "message": "成功", "data": {"item": self.entity_map.get(uid, [])}}
        if path == "/api/xdr/v1/responses/blockiprule/list":
            keyword = ""
            search_infos = (json_body or {}).get("searchInfos") or []
            if search_infos:
                keyword = str(search_infos[0].get("fieldValue") or "").strip()
            items = self.block_rules
            if keyword:
                items = [row for row in self.block_rules if keyword in str(row.get("blockIpRule", {}).get("view", []))]
            return {"code": "Success", "message": "成功", "data": {"item": items}}
        return super().request(method, path, json_body=json_body, params=params, timeout=timeout)


class FakeRequesterEntityHistoryPartial(FakeRequesterEntityHistory):
    def __init__(self) -> None:
        super().__init__()
        self.block_rules = [
            {
                "id": "rule-1",
                "name": "block_1.1.10.110",
                "status": "unblocked",
                "reason": "test",
                "updateTime": 1739998000,
                "blockIpRule": {"type": "SRC_IP", "mode": "in", "view": ["1.1.10.110"]},
            }
        ]


class ChatConfirmFlowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def test_confirmable_dangerous_action(self):
        with Session(engine) as session:
            with patch("app.services.chat_service.get_requester_from_credential", return_value=FakeRequester()):
                chat = ChatService(session)
                chat.handle("t1", "查询最近三天高危事件")
                result = chat.handle("t1", "把前两个标记为已处置")
                self.assertEqual(result[0]["type"], "approval_card")
                done = chat.handle("t1", "确认")
                self.assertEqual(done[0]["type"], "text")

    def test_entity_query_can_inherit_first_event_reference(self):
        with Session(engine) as session:
            with patch("app.services.chat_service.get_requester_from_credential", return_value=FakeRequester()):
                chat = ChatService(session)
                chat.handle("t2", "查询最近三天高危事件")
                result = chat.handle("t2", "查询第一个事件的外网实体")
                self.assertEqual(result[0]["type"], "text")
                self.assertEqual(result[1]["type"], "table")
                rows = result[1]["data"]["rows"]
                self.assertTrue(rows)
                self.assertEqual(rows[0]["ip"], "8.8.8.8")

    def test_entity_query_can_bootstrap_event_reference_when_context_missing(self):
        with Session(engine) as session:
            with patch("app.services.chat_service.get_requester_from_credential", return_value=FakeRequester()):
                chat = ChatService(session)
                result = chat.handle("t3", "查询第一个事件的外网实体")
                self.assertEqual(result[0]["type"], "text")
                self.assertEqual(result[1]["type"], "table")
                self.assertTrue(result[1]["data"]["rows"])

    def test_entity_query_supports_serial_number_wording(self):
        with Session(engine) as session:
            with patch("app.services.chat_service.get_requester_from_credential", return_value=FakeRequester()):
                chat = ChatService(session)
                chat.handle("t4", "查看近7天安全事件")
                result = chat.handle("t4", "查看序号1安全事件外网实体")
                self.assertEqual(result[0]["type"], "text")
                self.assertEqual(result[1]["type"], "table")
                self.assertTrue(result[1]["data"]["rows"])

    def test_entity_query_supports_explicit_event_uuid(self):
        with Session(engine) as session:
            with patch("app.services.chat_service.get_requester_from_credential", return_value=FakeRequester()):
                chat = ChatService(session)
                result = chat.handle("t5", "查看事件ID为incident-real-001的外网IP实体")
                self.assertEqual(result[0]["type"], "text")
                self.assertEqual(result[1]["type"], "table")
                self.assertTrue(result[1]["data"]["rows"])

    def test_event_detail_and_action_support_explicit_event_uuid(self):
        with Session(engine) as session:
            with patch("app.services.chat_service.get_requester_from_credential", return_value=FakeRequester()):
                chat = ChatService(session)
                detail_result = chat.handle("t6", "查看事件ID为incident-real-001的详情")
                self.assertEqual(detail_result[0]["type"], "text")
                self.assertEqual(detail_result[1]["type"], "table")
                action_result = chat.handle("t6", "把事件ID为incident-real-001标记为已处置")
                self.assertEqual(action_result[0]["type"], "approval_card")

    def test_entity_query_compatible_with_variant_response_shape(self):
        with Session(engine) as session:
            with patch("app.services.chat_service.get_requester_from_credential", return_value=FakeRequesterEntityVariant()):
                chat = ChatService(session)
                result = chat.handle("t7", "查看incident-real-001这个事件的外网实体")
                self.assertEqual(result[0]["type"], "text")
                self.assertEqual(result[1]["type"], "table")
                self.assertEqual(result[1]["data"]["rows"][0]["ip"], "111.112.113.201")

    def test_block_query_can_use_all_recent_entity_ips(self):
        with Session(engine) as session:
            with patch("app.services.chat_service.get_requester_from_credential", return_value=FakeRequesterEntityHistory()):
                chat = ChatService(session)
                chat.handle("t8", "查看近7天安全事件")
                result_1 = chat.handle("t8", "查看序号2安全事件的外网实体")
                self.assertEqual(result_1[1]["data"]["rows"][0]["ip"], "3.3.1.1")
                result_2 = chat.handle("t8", "查看序号8安全事件的外网实体")
                self.assertEqual(result_2[0]["type"], "text")
                result_3 = chat.handle("t8", "查看序号4安全事件的外网实体")
                self.assertEqual(result_3[1]["data"]["rows"][0]["ip"], "1.1.10.110")

                block_result = chat.handle("t8", "查看以上所有IP的封禁状态")
                self.assertEqual(block_result[0]["type"], "text")
                self.assertIn("已查询 2 个IP", block_result[0]["data"]["text"])
                self.assertEqual(block_result[1]["type"], "table")
                views = [row["view"] for row in block_result[1]["data"]["rows"]]
                self.assertEqual(views, ["3.3.1.1", "1.1.10.110"])

    def test_block_query_should_show_unmatched_ip_when_querying_all_recent_entity_ips(self):
        with Session(engine) as session:
            with patch("app.services.chat_service.get_requester_from_credential", return_value=FakeRequesterEntityHistoryPartial()):
                chat = ChatService(session)
                chat.handle("t9", "查看近7天安全事件")
                chat.handle("t9", "查看序号2安全事件的外网实体")
                chat.handle("t9", "查看序号4安全事件的外网实体")

                block_result = chat.handle("t9", "查看以上所有IP的封禁状态")
                self.assertEqual(block_result[0]["type"], "text")
                self.assertIn("其中 1 个IP未命中策略", block_result[0]["data"]["text"])
                self.assertEqual(block_result[1]["type"], "table")
                rows = block_result[1]["data"]["rows"]
                views = [row["view"] for row in rows]
                self.assertEqual(views, ["1.1.10.110", "3.3.1.1"])
                unmatched_row = next(row for row in rows if row["view"] == "3.3.1.1")
                self.assertEqual(unmatched_row["status"], "未封禁")


if __name__ == "__main__":
    unittest.main()
