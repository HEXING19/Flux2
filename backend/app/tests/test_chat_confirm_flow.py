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


if __name__ == "__main__":
    unittest.main()
