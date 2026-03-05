from __future__ import annotations

import time
import unittest
from unittest.mock import patch

from sqlmodel import Session, delete

from app.core.db import engine, init_db
from app.models.db_models import PlaybookRun
from app.playbook.service import playbook_service


class PlaybookRequester:
    def __init__(self, *, proof_as_dict: bool = False) -> None:
        self.count_payloads: list[dict] = []
        self.proof_as_dict = proof_as_dict

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
            if body.get("dealStatus") == [0] and body.get("severities") == [3, 4]:
                return {
                    "code": "Success",
                    "data": {
                        "total": 509,
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
            record = {
                "name": f"{uid}-proof",
                "gptResultDescription": "测试研判",
                "riskTag": ["c2"],
                "alertTimeLine": [{"name": "x", "severity": 3, "stage": "利用", "lastTime": 1739999000}],
            }
            return {
                "code": "Success",
                "data": record if self.proof_as_dict else [record],
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
            with self.assertRaises(ValueError):
                playbook_service.start_run(
                    session,
                    template_id="asset_guard",
                    params={},
                    session_id="s-validation-3",
                )
            with self.assertRaises(ValueError):
                playbook_service.start_run(
                    session,
                    template_id="asset_guard",
                    params={"asset_ip": "bad-ip"},
                    session_id="s-validation-4",
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
                payload = playbook_service.serialize_run(final_run)
                result = payload.get("result", {})
                cards = result.get("cards", [])
                impact_card = next((card for card in cards if card.get("data", {}).get("namespace") == "triage_impact"), {})
                rows = impact_card.get("data", {}).get("rows", [])
                self.assertTrue(rows)
                self.assertIn("src_total", rows[0])
                self.assertIn("dst_total", rows[0])

        payloads = fake_requester.count_payloads
        self.assertTrue(any(p.get("srcIps") == ["8.8.8.8"] for p in payloads))
        self.assertTrue(any(p.get("dstIps") == ["8.8.8.8"] for p in payloads))
        self.assertTrue(any(p.get("srcIps") == ["8.8.8.8"] and p.get("severities") == [3, 4] for p in payloads))
        self.assertTrue(any(p.get("dstIps") == ["8.8.8.8"] and p.get("severities") == [3, 4] for p in payloads))
        self.assertTrue(any(p.get("srcIps") == ["8.8.8.8"] and p.get("attackStates") == [2, 3] for p in payloads))
        self.assertTrue(any(p.get("dstIps") == ["8.8.8.8"] and p.get("attackStates") == [2, 3] for p in payloads))

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

    def test_threat_hunting_param_normalization_caps_max_scan(self):
        normalized = playbook_service._normalize_params("threat_hunting", {"ip": "9.9.9.9", "max_scan": 100000})
        self.assertEqual(normalized.get("max_scan"), 10000)

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
                self.assertIn("509", result.get("summary", ""))
                self.assertGreaterEqual(len(result.get("cards", [])), 3)
                self.assertGreaterEqual(len(result.get("next_actions", [])), 1)

    def test_routine_check_dependency_declared(self):
        status = playbook_service._initial_node_status("routine_check", None)
        self.assertEqual(
            status["node_2_unhandled_high_events_24h"].get("depends_on"),
            ["node_1_log_count_24h"],
        )

    def test_asset_guard_returns_summary_and_cards(self):
        fake_requester = PlaybookRequester()
        with (
            patch("app.playbook.service.get_requester_from_credential", return_value=fake_requester),
            patch("app.playbook.service.LLMRouter.complete", return_value="asset guard summary"),
        ):
            with Session(engine) as session:
                run = playbook_service.start_run(
                    session,
                    template_id="asset_guard",
                    params={"asset_ip": "10.10.0.2", "asset_name": "核心资产A"},
                    session_id="s-asset-1",
                )
                final_run = self._wait_run_finished(session, run.id)
                self.assertEqual(final_run.status, "Finished")
                payload = playbook_service.serialize_run(final_run)
                result = payload.get("result", {})
                self.assertIn("summary", result)
                self.assertGreaterEqual(len(result.get("cards", [])), 3)
                next_actions = result.get("next_actions", [])
                self.assertTrue(next_actions)
                self.assertTrue(all(action.get("template_id") == "alert_triage" for action in next_actions))
                self.assertTrue(all("进行封禁" in (action.get("label") or "") for action in next_actions))

    def test_action_labels_include_concrete_ip(self):
        fake_requester = PlaybookRequester()
        with (
            patch("app.playbook.service.get_requester_from_credential", return_value=fake_requester),
            patch("app.playbook.service.LLMRouter.complete", return_value="summary"),
        ):
            with Session(engine) as session:
                triage_run = playbook_service.start_run(
                    session,
                    template_id="alert_triage",
                    params={"incident_uuid": "incident-real-001"},
                    session_id="s-triage-action-label",
                )
                triage_final = self._wait_run_finished(session, triage_run.id)
                triage_result = playbook_service.serialize_run(triage_final).get("result", {})
                triage_labels = [action.get("label") or "" for action in triage_result.get("next_actions", [])]
                self.assertTrue(any("8.8.8.8" in label for label in triage_labels))

                hunting_run = playbook_service.start_run(
                    session,
                    template_id="threat_hunting",
                    params={"ip": "8.8.8.8"},
                    session_id="s-hunting-action-label",
                )
                hunting_final = self._wait_run_finished(session, hunting_run.id)
                hunting_result = playbook_service.serialize_run(hunting_final).get("result", {})
                hunting_labels = [action.get("label") or "" for action in hunting_result.get("next_actions", [])]
                self.assertTrue(any("执行IP 8.8.8.8封禁" in label for label in hunting_labels))
                self.assertIn("告警轨迹分析完成", hunting_result.get("summary", ""))

    def test_parallel_nodes_tolerate_dict_proof_payload(self):
        fake_requester = PlaybookRequester(proof_as_dict=True)
        with (
            patch("app.playbook.service.get_requester_from_credential", return_value=fake_requester),
            patch("app.playbook.service.LLMRouter.complete", return_value="safe summary"),
        ):
            with Session(engine) as session:
                routine_run = playbook_service.start_run(
                    session,
                    template_id="routine_check",
                    params={},
                    session_id="s-proof-dict-routine",
                )
                routine_final = self._wait_run_finished(session, routine_run.id)
                self.assertEqual(routine_final.status, "Finished")

                hunting_run = playbook_service.start_run(
                    session,
                    template_id="threat_hunting",
                    params={"ip": "8.8.8.8"},
                    session_id="s-proof-dict-hunting",
                )
                hunting_final = self._wait_run_finished(session, hunting_run.id)
                self.assertEqual(hunting_final.status, "Finished")


if __name__ == "__main__":
    unittest.main()
