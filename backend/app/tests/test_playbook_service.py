from __future__ import annotations

import time
import unittest
from unittest.mock import patch

from sqlmodel import Session, delete

from app.core.db import engine, init_db
from app.models.db_models import PlaybookRun
from app.playbook.service import playbook_service


class PlaybookRequester:
    def __init__(self) -> None:
        self.count_payloads: list[dict] = []

    def request(self, method, path, *, json_body=None, params=None, timeout=15, max_retries=3):
        _ = (method, params, timeout, max_retries)
        body = json_body or {}

        if path == "/api/xdr/v1/analysislog/networksecurity/count":
            self.count_payloads.append(dict(body))
            if body.get("attackStates") == [2, 3]:
                return {"code": "Success", "data": {"total": 3}}
            if body.get("severities") == [3, 4]:
                return {"code": "Success", "data": {"total": 11}}
            return {"code": "Success", "data": {"total": 66}}

        if path == "/api/xdr/v1/incidents/list":
            page_size = body.get("pageSize", 50)
            page = body.get("page", 1)
            if page_size >= 200:
                if page > 1:
                    return {"code": "Success", "data": {"item": []}}
                return {
                    "code": "Success",
                    "data": {
                        "item": [
                            {
                                "uuId": "incident-hunt-001",
                                "name": "疑似外联",
                                "incidentSeverity": 3,
                                "dealStatus": 0,
                                "hostIp": "8.8.8.8",
                                "description": "src ip 8.8.8.8",
                                "endTime": 1739999900,
                            }
                        ]
                    },
                }
            return {
                "code": "Success",
                "data": {
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
                    ]
                },
            }

        if path.endswith("/proof"):
            uid = path.split("/")[-2]
            return {
                "code": "Success",
                "data": [
                    {
                        "name": f"{uid}-proof",
                        "gptResultDescription": "测试研判",
                        "riskTag": ["c2"],
                        "alertTimeLine": [{"name": "x", "severity": 3, "stage": "利用", "lastTime": 1739999000}],
                    }
                ],
            }

        if path.endswith("/entities/ip"):
            return {
                "code": "Success",
                "data": {
                    "item": [
                        {"ip": "8.8.8.8", "country": "US", "province": "CA", "dealSuggestion": "建议封禁"},
                    ]
                },
            }

        return {"code": "Failed", "message": f"unhandled path: {path}", "data": {}}


class EndlessIncidentsRequester:
    def __init__(self) -> None:
        self.page_calls = 0

    def request(self, method, path, *, json_body=None, params=None, timeout=15, max_retries=3):
        _ = (method, params, timeout, max_retries)
        body = json_body or {}
        if path != "/api/xdr/v1/incidents/list":
            return {"code": "Success", "data": {"total": 0, "item": []}}
        self.page_calls += 1
        page_size = body.get("pageSize", 200)
        page = body.get("page", 1)
        items = []
        for i in range(page_size):
            items.append(
                {
                    "uuId": f"incident-{page}-{i}",
                    "name": "模拟事件",
                    "description": "src 9.9.9.9",
                    "hostIp": "9.9.9.9",
                    "incidentSeverity": 3,
                    "dealStatus": 0,
                    "endTime": 1739990000,
                }
            )
        return {"code": "Success", "data": {"item": items}}


class PlaybookServiceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        init_db()

    def setUp(self):
        with Session(engine) as session:
            session.exec(delete(PlaybookRun))
            session.commit()

    def _wait_run_finished(self, session: Session, run_id: int, timeout_seconds: float = 8.0) -> PlaybookRun:
        deadline = time.time() + timeout_seconds
        while time.time() < deadline:
            session.expire_all()
            run = session.get(PlaybookRun, run_id)
            if run and run.status in {"Finished", "Failed"}:
                return run
            time.sleep(0.05)
        self.fail(f"playbook run timeout, run_id={run_id}")

    def test_alert_triage_and_threat_hunting_input_validation(self):
        with Session(engine) as session:
            with self.assertRaises(ValueError):
                playbook_service.start_run(
                    session,
                    template_id="alert_triage",
                    params={},
                    session_id="s-validation-1",
                )
            with self.assertRaises(ValueError):
                playbook_service.start_run(
                    session,
                    template_id="threat_hunting",
                    params={},
                    session_id="s-validation-2",
                )

    def test_alert_triage_count_payloads(self):
        fake_requester = PlaybookRequester()
        with (
            patch("app.playbook.service.get_requester_from_credential", return_value=fake_requester),
            patch("app.playbook.service.LLMRouter.complete", return_value="triage summary"),
        ):
            with Session(engine) as session:
                run = playbook_service.start_run(
                    session,
                    template_id="alert_triage",
                    params={"incident_uuid": "incident-real-001"},
                    session_id="s-triage-1",
                )
                final_run = self._wait_run_finished(session, run.id)
                self.assertEqual(final_run.status, "Finished")

        payloads = fake_requester.count_payloads
        self.assertTrue(any(p.get("srcIps") == ["8.8.8.8"] for p in payloads))
        self.assertTrue(any(p.get("srcIps") == ["8.8.8.8"] and p.get("severities") == [3, 4] for p in payloads))
        self.assertTrue(any(p.get("srcIps") == ["8.8.8.8"] and p.get("attackStates") == [2, 3] for p in payloads))

    def test_threat_hunting_scan_limit(self):
        fake_requester = EndlessIncidentsRequester()
        result = playbook_service._scan_incidents_for_ip(
            fake_requester,
            ip="9.9.9.9",
            start_ts=1730000000,
            end_ts=1740000000,
            max_scan=2000,
            page_size=200,
        )
        self.assertEqual(result["scanned"], 2000)
        self.assertTrue(result["truncated"])
        self.assertEqual(fake_requester.page_calls, 10)

    def test_routine_check_returns_cards_and_next_actions(self):
        fake_requester = PlaybookRequester()
        with (
            patch("app.playbook.service.get_requester_from_credential", return_value=fake_requester),
            patch("app.playbook.service.LLMRouter.complete", return_value="morning summary"),
        ):
            with Session(engine) as session:
                run = playbook_service.start_run(
                    session,
                    template_id="routine_check",
                    params={},
                    session_id="s-routine-1",
                )
                final_run = self._wait_run_finished(session, run.id)
                self.assertEqual(final_run.status, "Finished")
                payload = playbook_service.serialize_run(final_run)
                result = payload.get("result", {})
                self.assertIn("summary", result)
                self.assertGreaterEqual(len(result.get("cards", [])), 3)
                self.assertGreaterEqual(len(result.get("next_actions", [])), 1)


if __name__ == "__main__":
    unittest.main()
