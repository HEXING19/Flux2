from __future__ import annotations

import unittest
from unittest.mock import patch

from sqlmodel import Session

from app.core.db import engine, init_db
from app.workflow.service import workflow_service


class FakeRequester:
    def request(self, method, path, *, json_body=None, params=None, timeout=15):
        _ = (method, params, timeout)
        payload = json_body or {}
        if path == "/api/xdr/v1/incidents/list":
            return {
                "code": "Success",
                "message": "成功",
                "data": {
                    "total": 2,
                    "page": 1,
                    "pageSize": 50,
                    "item": [
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
                            "incidentSeverity": 4,
                            "dealStatus": 0,
                            "hostIp": "10.10.0.3",
                            "endTime": 1739999800,
                        },
                    ],
                },
            }
        if path.endswith("/proof"):
            uid = path.split("/")[-2]
            return {
                "code": "Success",
                "message": "成功",
                "data": [{"name": f"{uid}-proof", "gptResultDescription": "测试", "riskTag": ["x"], "alertTimeLine": []}],
            }
        if path.endswith("/entities/ip"):
            return {"code": "Success", "message": "成功", "data": {"item": [{"ip": "8.8.8.8"}]}}
        if path == "/api/xdr/v1/incidents/dealstatus":
            return {"code": "Success", "message": "成功", "data": {"total": len(payload.get("uuIds", [])), "succeededNum": 2}}
        if path == "/api/xdr/v1/device/blockdevice/list":
            return {
                "code": "Success",
                "message": "成功",
                "data": {"item": [{"deviceId": 1, "deviceName": "AF_001", "deviceStatus": "online", "deviceType": "AF", "deviceVersion": "8.0"}]},
            }
        if path == "/api/xdr/v1/responses/blockiprule/network":
            return {"code": "Success", "message": "成功", "data": {"ids": ["rule-real-001"]}}
        return {"code": "Failed", "message": f"unhandled path: {path}", "data": {}}


class WorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def test_run_suspend_and_approve(self):
        with Session(engine) as session:
            with (
                patch("app.workflow.service.get_requester_from_credential", return_value=FakeRequester()),
                patch("app.workflow.service.LLMRouter.complete", return_value="workflow summary"),
            ):
                wf = workflow_service.create_or_update_workflow(
                    session,
                    {
                        "name": "每日高危闭环测试",
                        "cron_expr": "0 9 * * *",
                        "enabled": True,
                        "levels": [3, 4],
                        "require_approval": True,
                    },
                )
                run = workflow_service.run_workflow(session, wf.id)
                self.assertEqual(run.status, "Suspended")
                approvals = workflow_service.list_approvals(session)
                pending = next(a for a in approvals if a.workflow_run_id == run.id)
                result = workflow_service.decide_approval(session, pending.id, decision="approve", reviewer="tester", comment=None)
                self.assertEqual(result["status"], "Finished")


if __name__ == "__main__":
    unittest.main()
