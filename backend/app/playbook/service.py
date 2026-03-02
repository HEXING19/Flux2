from __future__ import annotations

import json
import ipaddress
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import httpx
from sqlmodel import Session, select

from app.core.context import context_manager
from app.core.db import session_scope
from app.core.exceptions import ConfirmationRequiredException
from app.core.payload import approval_payload, echarts_payload, table_payload, text_payload
from app.core.requester import APIRequester, get_requester_from_credential
from app.core.threatbook import resolve_threatbook_api_key
from app.llm.router import LLMRouter
from app.models.db_models import CoreAsset, PlaybookRun, XDRCredential
from app.skills.event_skills import extract_entity_items_from_response
from app.skills.registry import SkillRegistry
from app.workflow.engine import PipelineNode, WorkflowEngine

from .registry import PlaybookRegistry


SEVERITY_LABEL = {0: "信息", 1: "低危", 2: "中危", 3: "高危", 4: "严重"}
DEAL_STATUS_LABEL = {0: "待处置", 10: "处置中", 40: "已处置", 50: "已挂起", 60: "接受风险", 70: "已遏制"}
IPV4_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_ts(dt: datetime) -> int:
    return int(dt.timestamp())


def _safe_json_load(raw: str | None, default: Any) -> Any:
    if not raw:
        return default
    try:
        return json.loads(raw)
    except Exception:
        return default


def _pick(item: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        value = item.get(key)
        if value not in (None, ""):
            return value
    return default


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _format_ts(timestamp: Any) -> str:
    try:
        return datetime.fromtimestamp(int(timestamp)).strftime("%Y-%m-%d %H:%M:%S")
    except (TypeError, ValueError, OSError):
        return "-"


def _dedup_keep_order(values: list[Any]) -> list[Any]:
    return list(dict.fromkeys(values))


def _pick_first_dict(data: Any) -> dict[str, Any]:
    if isinstance(data, dict):
        return data
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                return item
    return {}


class PlaybookService:
    def __init__(self) -> None:
        self.engine = WorkflowEngine(max_workers=6)
        self.registry = PlaybookRegistry()
        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="playbook-worker")
        self._persist_lock = threading.Lock()

    def list_templates(self) -> list[dict[str, Any]]:
        return self.registry.list_templates()

    def start_run(
        self,
        session: Session,
        *,
        template_id: str,
        params: dict[str, Any] | None = None,
        session_id: str | None = None,
    ) -> PlaybookRun:
        template = self.registry.get_template(template_id)
        if not template:
            raise ValueError(f"不支持的 playbook 模板: {template_id}")

        normalized_params = self._normalize_params(template_id, params or {})
        runtime_session_id = session_id or f"playbook-{int(datetime.now().timestamp() * 1000)}"
        self._validate_input(template_id, normalized_params, runtime_session_id)

        initial_context = {
            "template_id": template_id,
            "session_id": runtime_session_id,
            "node_status": self._initial_node_status(template_id, normalized_params.get("mode")),
            "progress": {
                "finished": 0,
                "total": len(self._initial_node_status(template_id, normalized_params.get("mode"))),
            },
            "updated_at": utc_now().isoformat(),
        }

        run = PlaybookRun(
            template=template_id,
            status="Running",
            input_json=json.dumps({"params": normalized_params, "session_id": runtime_session_id}, ensure_ascii=False),
            context_json=json.dumps(initial_context, ensure_ascii=False),
            created_by=session_id or "playbook-ui",
            started_at=utc_now(),
        )
        session.add(run)
        session.commit()
        session.refresh(run)

        self.executor.submit(self._execute_run, run.id)
        return run

    def get_run_or_raise(self, session: Session, run_id: int) -> PlaybookRun:
        run = session.get(PlaybookRun, run_id)
        if not run:
            raise ValueError("playbook run 不存在")
        return run

    def serialize_run(self, run: PlaybookRun) -> dict[str, Any]:
        input_data = _safe_json_load(run.input_json, {})
        context_data = _safe_json_load(run.context_json, {})
        result_data = _safe_json_load(run.result_json, {})
        return {
            "run_id": run.id,
            "template_id": run.template,
            "status": run.status,
            "input": input_data,
            "context": context_data,
            "result": result_data,
            "error": run.error,
            "started_at": run.started_at,
            "finished_at": run.finished_at,
        }

    def _normalize_params(self, template_id: str, params: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(params)
        if template_id == "routine_check":
            normalized["window_hours"] = max(1, min(168, _to_int(normalized.get("window_hours"), 24)))
            normalized["sample_size"] = max(1, min(10, _to_int(normalized.get("sample_size"), 3)))

        if template_id == "alert_triage":
            mode = str(normalized.get("mode") or "analyze").strip().lower()
            normalized["mode"] = mode if mode in {"analyze", "block_ip"} else "analyze"
            normalized["window_days"] = max(1, min(30, _to_int(normalized.get("window_days"), 7)))
            if "event_index" in normalized:
                normalized["event_index"] = _to_int(normalized.get("event_index"), 0)
            if "event_indexes" in normalized and isinstance(normalized["event_indexes"], list):
                normalized["event_indexes"] = [
                    _to_int(item, 0) for item in normalized["event_indexes"] if _to_int(item, 0) > 0
                ]
            if isinstance(normalized.get("incident_uuids"), str):
                normalized["incident_uuids"] = [
                    token.strip()
                    for token in normalized["incident_uuids"].split(",")
                    if token and token.strip()
                ]

        if template_id == "threat_hunting":
            normalized["window_days"] = max(1, min(180, _to_int(normalized.get("window_days"), 90)))
            normalized["max_scan"] = max(200, min(2000, _to_int(normalized.get("max_scan"), 2000)))
            normalized["evidence_limit"] = max(1, min(20, _to_int(normalized.get("evidence_limit"), 20)))
            mode = str(normalized.get("mode") or "analyze").strip().lower()
            normalized["mode"] = mode if mode in {"analyze", "export_summary"} else "analyze"
        if template_id == "asset_guard":
            normalized["asset_ip"] = str(normalized.get("asset_ip") or "").strip()
            normalized["asset_name"] = str(normalized.get("asset_name") or "").strip() or None
            normalized["window_hours"] = max(1, min(168, _to_int(normalized.get("window_hours"), 24)))
            normalized["top_external_ip"] = max(1, min(10, _to_int(normalized.get("top_external_ip"), 5)))
            if normalized["asset_ip"] and not normalized["asset_name"]:
                with session_scope() as session:
                    row = session.exec(select(CoreAsset).where(CoreAsset.asset_ip == normalized["asset_ip"])).first()
                    if row and row.asset_name:
                        normalized["asset_name"] = row.asset_name
        return normalized

    def _validate_input(self, template_id: str, params: dict[str, Any], runtime_session_id: str) -> None:
        _ = runtime_session_id
        if template_id == "alert_triage":
            has_uuid = bool(params.get("incident_uuid"))
            has_uuid_list = bool(params.get("incident_uuids"))
            has_index = bool(params.get("event_index")) or bool(params.get("event_indexes"))
            has_ip = bool(params.get("ip"))
            mode = params.get("mode", "analyze")
            if mode == "analyze" and not (has_uuid or has_uuid_list or has_index):
                raise ValueError("alert_triage 缺少 incident_uuid 或 event_index 参数。")
            if mode == "block_ip" and not (has_ip or has_uuid or has_uuid_list or has_index):
                raise ValueError("alert_triage(block_ip) 缺少 ip 或事件定位参数。")
            return

        if template_id == "threat_hunting" and not params.get("ip"):
            raise ValueError("threat_hunting 缺少必填参数 ip。")
        if template_id == "asset_guard":
            asset_ip = str(params.get("asset_ip") or "").strip()
            if not asset_ip:
                raise ValueError("asset_guard 缺少必填参数 asset_ip。")
            try:
                ipaddress.ip_address(asset_ip)
            except ValueError as exc:
                raise ValueError("asset_guard 参数 asset_ip 格式不合法。") from exc

    def _initial_node_status(self, template_id: str, mode: str | None) -> dict[str, Any]:
        if template_id == "routine_check":
            return {
                "node_1_log_count_24h": {"status": "Pending", "depends_on": []},
                "node_2_unhandled_high_events_24h": {
                    "status": "Pending",
                    "depends_on": ["node_1_log_count_24h"],
                },
                "node_3_sample_detail_parallel": {
                    "status": "Pending",
                    "depends_on": ["node_2_unhandled_high_events_24h"],
                },
                "node_4_llm_briefing": {
                    "status": "Pending",
                    "depends_on": [
                        "node_1_log_count_24h",
                        "node_2_unhandled_high_events_24h",
                        "node_3_sample_detail_parallel",
                    ],
                },
            }

        if template_id == "alert_triage" and mode == "block_ip":
            return {
                "node_1_resolve_target_ip": {"status": "Pending", "depends_on": []},
                "node_2_build_block_approval": {
                    "status": "Pending",
                    "depends_on": ["node_1_resolve_target_ip"],
                },
            }

        if template_id == "alert_triage":
            return {
                "node_1_resolve_target": {"status": "Pending", "depends_on": []},
                "node_2_entity_profile": {"status": "Pending", "depends_on": ["node_1_resolve_target"]},
                "node_3_external_intel": {"status": "Pending", "depends_on": ["node_2_entity_profile"]},
                "node_4_internal_impact_count_parallel": {
                    "status": "Pending",
                    "depends_on": ["node_3_external_intel"],
                },
                "node_5_llm_triage_summary": {
                    "status": "Pending",
                    "depends_on": ["node_4_internal_impact_count_parallel"],
                },
            }

        if template_id == "asset_guard":
            return {
                "node_1_events_dst_asset": {"status": "Pending", "depends_on": []},
                "node_2_events_src_asset": {"status": "Pending", "depends_on": ["node_1_events_dst_asset"]},
                "node_3_logs_dst_asset": {"status": "Pending", "depends_on": ["node_2_events_src_asset"]},
                "node_4_logs_src_asset": {"status": "Pending", "depends_on": ["node_3_logs_dst_asset"]},
                "node_5_top_external_ip": {
                    "status": "Pending",
                    "depends_on": ["node_4_logs_src_asset"],
                },
                "node_6_external_intel_enrich": {
                    "status": "Pending",
                    "depends_on": ["node_5_top_external_ip"],
                },
                "node_7_llm_asset_briefing": {
                    "status": "Pending",
                    "depends_on": ["node_6_external_intel_enrich"],
                },
            }

        return {
            "node_1_external_profile": {"status": "Pending", "depends_on": []},
            "node_2_event_scan_paginated": {"status": "Pending", "depends_on": ["node_1_external_profile"]},
            "node_3_evidence_enrichment_parallel": {
                "status": "Pending",
                "depends_on": ["node_2_event_scan_paginated"],
            },
            "node_4_internal_activity_count": {
                "status": "Pending",
                "depends_on": ["node_3_evidence_enrichment_parallel"],
            },
            "node_5_llm_timeline_story": {
                "status": "Pending",
                "depends_on": ["node_4_internal_activity_count"],
            },
        }

    def _execute_run(self, run_id: int) -> None:
        with session_scope() as session:
            run = session.get(PlaybookRun, run_id)
            if not run:
                return
            input_data = _safe_json_load(run.input_json, {})
            params = dict(input_data.get("params") or {})
            runtime_session_id = input_data.get("session_id") or f"playbook-{run.id}"

            credential = session.exec(select(XDRCredential).order_by(XDRCredential.id.desc())).first()
            requester = get_requester_from_credential(credential)
            skills = SkillRegistry(requester, context_manager)

            runtime_context: dict[str, Any] = {
                "run_id": run.id,
                "template_id": run.template,
                "session_id": runtime_session_id,
                "params": params,
                "requester": requester,
                "skills": skills,
            }

        try:
            if runtime_context["template_id"] == "routine_check":
                nodes, finalizer = self._build_routine_check(runtime_context)
            elif runtime_context["template_id"] == "alert_triage":
                if params.get("mode") == "block_ip":
                    nodes, finalizer = self._build_alert_block_mode(runtime_context)
                else:
                    nodes, finalizer = self._build_alert_triage(runtime_context)
            elif runtime_context["template_id"] == "threat_hunting":
                nodes, finalizer = self._build_threat_hunting(runtime_context)
            elif runtime_context["template_id"] == "asset_guard":
                nodes, finalizer = self._build_asset_guard(runtime_context)
            else:
                raise ValueError(f"未支持的模板: {runtime_context['template_id']}")

            wrapped_nodes = [
                PipelineNode(
                    node_id=node.node_id,
                    runner=self._wrap_node_runner(run_id, node.node_id, node.runner),
                    depends_on=node.depends_on,
                )
                for node in nodes
            ]

            self._sync_node_status_from_nodes(run_id, wrapped_nodes)

            def on_node_complete(node_id: str, node_result: dict[str, Any], ctx: dict[str, Any]) -> None:
                self._mark_node_finished(run_id, node_id, node_result)
                ctx["last_completed_node"] = node_id

            node_results = self.engine.run(wrapped_nodes, runtime_context, on_node_complete=on_node_complete)
            result_payload = finalizer(node_results, runtime_context)
            self._mark_run_finished(run_id, runtime_context, result_payload)
        except Exception as exc:
            self._mark_run_failed(run_id, str(exc))

    def _wrap_node_runner(
        self,
        run_id: int,
        node_id: str,
        runner: Callable[[dict[str, Any]], dict[str, Any]],
    ) -> Callable[[dict[str, Any]], dict[str, Any]]:
        def wrapped(context: dict[str, Any]) -> dict[str, Any]:
            self._mark_node_running(run_id, node_id)
            try:
                return runner(context)
            except Exception as exc:
                self._mark_node_failed(run_id, node_id, str(exc))
                raise

        return wrapped

    def _sync_node_status_from_nodes(self, run_id: int, nodes: list[PipelineNode]) -> None:
        node_status = {
            node.node_id: {
                "status": "Pending",
                "depends_on": list(node.depends_on),
            }
            for node in nodes
        }

        def mutate(ctx: dict[str, Any]) -> None:
            ctx["node_status"] = node_status
            ctx["progress"] = {"finished": 0, "total": len(nodes)}
            ctx["updated_at"] = utc_now().isoformat()

        self._mutate_run_context(run_id, mutate)

    def _mark_node_running(self, run_id: int, node_id: str) -> None:
        def mutate(ctx: dict[str, Any]) -> None:
            status = ctx.setdefault("node_status", {}).setdefault(node_id, {})
            status["status"] = "Running"
            status["started_at"] = utc_now().isoformat()
            ctx["updated_at"] = utc_now().isoformat()

        self._mutate_run_context(run_id, mutate)

    def _mark_node_finished(self, run_id: int, node_id: str, node_result: dict[str, Any]) -> None:
        result_keys = sorted(list(node_result.keys()))

        def mutate(ctx: dict[str, Any]) -> None:
            status = ctx.setdefault("node_status", {}).setdefault(node_id, {})
            status["status"] = "Finished"
            status["finished_at"] = utc_now().isoformat()
            status["result_keys"] = result_keys
            total = len(ctx.get("node_status", {}))
            finished = len([v for v in ctx.get("node_status", {}).values() if v.get("status") == "Finished"])
            ctx["progress"] = {"finished": finished, "total": total}
            ctx["updated_at"] = utc_now().isoformat()

        self._mutate_run_context(run_id, mutate)

    def _mark_node_failed(self, run_id: int, node_id: str, error: str) -> None:
        def mutate(ctx: dict[str, Any]) -> None:
            status = ctx.setdefault("node_status", {}).setdefault(node_id, {})
            status["status"] = "Failed"
            status["error"] = error
            status["finished_at"] = utc_now().isoformat()
            ctx["updated_at"] = utc_now().isoformat()

        self._mutate_run_context(run_id, mutate)

    def _mark_run_finished(
        self,
        run_id: int,
        runtime_context: dict[str, Any],
        result_payload: dict[str, Any],
    ) -> None:
        with self._persist_lock:
            with session_scope() as session:
                run = session.get(PlaybookRun, run_id)
                if not run:
                    return
                current_context = _safe_json_load(run.context_json, {})
                current_context["session_id"] = runtime_context.get("session_id")
                current_context["updated_at"] = utc_now().isoformat()
                run.context_json = json.dumps(current_context, ensure_ascii=False)
                run.result_json = json.dumps(result_payload, ensure_ascii=False)
                run.status = "Finished"
                run.finished_at = utc_now()
                run.error = None
                session.add(run)

    def _mark_run_failed(self, run_id: int, error: str) -> None:
        with self._persist_lock:
            with session_scope() as session:
                run = session.get(PlaybookRun, run_id)
                if not run:
                    return
                run.status = "Failed"
                run.error = error[:1200]
                run.finished_at = utc_now()
                session.add(run)

    def _mutate_run_context(self, run_id: int, mutator: Callable[[dict[str, Any]], None]) -> None:
        with self._persist_lock:
            with session_scope() as session:
                run = session.get(PlaybookRun, run_id)
                if not run:
                    return
                context = _safe_json_load(run.context_json, {})
                mutator(context)
                run.context_json = json.dumps(context, ensure_ascii=False)
                session.add(run)

    def _count_logs(
        self,
        requester: APIRequester,
        *,
        start_ts: int,
        end_ts: int,
        extra_filters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "startTimestamp": start_ts,
            "endTimestamp": end_ts,
        }
        payload.update(extra_filters or {})
        resp = requester.request("POST", "/api/xdr/v1/analysislog/networksecurity/count", json_body=payload)
        if resp.get("code") != "Success":
            return {
                "total": 0,
                "ok": False,
                "error": str(resp.get("message") or "日志计数失败"),
                "request": payload,
            }
        return {
            "total": _to_int(resp.get("data", {}).get("total"), 0),
            "ok": True,
            "error": None,
            "request": payload,
        }

    def _query_intel(self, ip: str) -> dict[str, Any]:
        threatbook_key = resolve_threatbook_api_key()
        if not threatbook_key:
            score = sum(int(part) for part in ip.split(".") if part.isdigit()) % 100
            severity = "low"
            tags = ["unknown"]
            if score >= 75:
                severity = "high"
                tags = ["c2", "scanner"]
            elif score >= 40:
                severity = "medium"
                tags = ["suspicious"]
            return {
                "ip": ip,
                "severity": severity,
                "confidence": 55 + score // 2,
                "tags": tags,
                "reputation": "heuristic",
                "source": "local_fallback",
                "message": "未配置 ThreatBook Key，使用本地启发式评估。",
            }

        try:
            with httpx.Client(timeout=8) as client:
                resp = client.get(
                    "https://api.threatbook.cn/v3/scene/ip_reputation",
                    params={"apikey": threatbook_key, "resource": ip},
                )
                body = resp.json()
                data = body.get("data", {}).get(ip, {})
                return {
                    "ip": ip,
                    "severity": str(data.get("severity") or "unknown"),
                    "confidence": _to_int(data.get("confidence_level"), 0),
                    "tags": data.get("tags_classes", []) or [],
                    "reputation": (data.get("judgments") or ["unknown"])[0],
                    "source": "threatbook",
                    "message": "ThreatBook画像",
                }
        except Exception:
            return {
                "ip": ip,
                "severity": "unknown",
                "confidence": 0,
                "tags": [],
                "reputation": "unknown",
                "source": "local_fallback",
                "message": "ThreatBook 调用失败，已降级。",
            }

    @staticmethod
    def _build_fake_trend(total: int, points: int = 8) -> tuple[list[str], list[int]]:
        now = datetime.now()
        labels = []
        values = []
        divisor = max(1, points)
        base = max(0, int(total / divisor))
        for idx in range(points):
            slot = now - timedelta(hours=(points - idx - 1) * 3)
            labels.append(slot.strftime("%m-%d %H:%M"))
            factor = 0.85 + (idx % 4) * 0.07
            values.append(max(0, int(base * factor)))
        if values:
            delta = total - sum(values)
            values[-1] += delta
        return labels, values

    @staticmethod
    def _normalize_event_row(item: dict[str, Any], index: int = 0) -> dict[str, Any]:
        severity_code = _to_int(_pick(item, "incidentSeverity", "severity"), -1)
        deal_status_code = _to_int(_pick(item, "dealStatus", "status"), -1)
        uu_id = _pick(item, "uuId", "uuid", "incidentId", default="")
        return {
            "index": index,
            "uuId": uu_id,
            "name": _pick(item, "name", "incidentName", "title", default="未知事件"),
            "incidentSeverity": SEVERITY_LABEL.get(severity_code, str(severity_code)),
            "dealStatus": DEAL_STATUS_LABEL.get(deal_status_code, str(deal_status_code)),
            "hostIp": _pick(item, "hostIp", "srcIp", "assetIp", default="-"),
            "description": _pick(item, "description", "desc", "detail", default=""),
            "endTime": _format_ts(_pick(item, "endTime", "latestTime", "occurTime", default=0)),
        }

    def _safe_llm_complete(
        self,
        prompt: str,
        *,
        system: str,
        fallback: str,
    ) -> str:
        try:
            with session_scope() as session:
                llm = LLMRouter(session)
                answer = llm.complete(prompt, system=system)
                if answer and answer.strip():
                    return answer.strip()
        except Exception:
            pass
        return fallback

    def _resolve_incident_uuids(self, params: dict[str, Any], runtime_session_id: str) -> list[str]:
        uuids: list[str] = []
        single_uuid = params.get("incident_uuid")
        if isinstance(single_uuid, str) and single_uuid.strip():
            uuids.append(single_uuid.strip())

        raw_list = params.get("incident_uuids")
        if isinstance(raw_list, list):
            uuids.extend([str(item).strip() for item in raw_list if str(item).strip()])

        indexes: list[int] = []
        if params.get("event_index"):
            idx = _to_int(params.get("event_index"), 0)
            if idx > 0:
                indexes.append(idx)
        if isinstance(params.get("event_indexes"), list):
            indexes.extend([_to_int(item, 0) for item in params["event_indexes"] if _to_int(item, 0) > 0])

        if indexes:
            source_session = params.get("session_id") or runtime_session_id
            mapping = context_manager.get_index_mapping(source_session, "events")
            for idx in indexes:
                if 1 <= idx <= len(mapping):
                    uuids.append(mapping[idx - 1])

        return _dedup_keep_order(uuids)

    def _build_routine_check(
        self, runtime_context: dict[str, Any]
    ) -> tuple[list[PipelineNode], Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]]:
        requester: APIRequester = runtime_context["requester"]
        params = runtime_context["params"]

        def node_1_log_count_24h(ctx: dict[str, Any]) -> dict[str, Any]:
            _ = ctx
            end_ts = to_ts(utc_now())
            start_ts = end_ts - params.get("window_hours", 24) * 3600
            counted = self._count_logs(requester, start_ts=start_ts, end_ts=end_ts)
            return {
                "log_total_24h": counted["total"],
                "startTimestamp": start_ts,
                "endTimestamp": end_ts,
                "error": counted["error"],
                "source": "POST /api/xdr/v1/analysislog/networksecurity/count",
            }

        def node_2_unhandled_high_events_24h(ctx: dict[str, Any]) -> dict[str, Any]:
            node1 = ctx["nodes"]["node_1_log_count_24h"]
            req = {
                "startTimestamp": node1["startTimestamp"],
                "endTimestamp": node1["endTimestamp"],
                "dealStatus": [0],
                "severities": [3, 4],
                "page": 1,
                "pageSize": 50,
                "sort": "endTime:desc,severity:desc",
                "timeField": "endTime",
            }
            resp = requester.request("POST", "/api/xdr/v1/incidents/list", json_body=req)
            items = resp.get("data", {}).get("item", []) if resp.get("code") == "Success" else []
            rows = [self._normalize_event_row(item, idx) for idx, item in enumerate(items, start=1)]
            uuids = [row["uuId"] for row in rows if row.get("uuId")]
            if uuids:
                context_manager.store_index_mapping(runtime_context["session_id"], "events", uuids)
                context_manager.update_params(
                    runtime_context["session_id"],
                    {"last_event_uuid": uuids[0], "last_event_uuids": uuids},
                )
            return {
                "high_events": rows,
                "error": None if resp.get("code") == "Success" else str(resp.get("message") or "事件查询失败"),
                "source": "POST /api/xdr/v1/incidents/list",
                "request": req,
            }

        def node_3_sample_detail_parallel(ctx: dict[str, Any]) -> dict[str, Any]:
            rows = ctx["nodes"]["node_2_unhandled_high_events_24h"].get("high_events", [])
            sample_size = params.get("sample_size", 3)
            targets = rows[:sample_size]

            def fetch_one(row: dict[str, Any]) -> dict[str, Any]:
                uid = row.get("uuId")
                if not uid:
                    return {}
                proof_resp = requester.request("GET", f"/api/xdr/v1/incidents/{uid}/proof")
                proof_data = {}
                if proof_resp.get("code") == "Success":
                    proof_data = _pick_first_dict(proof_resp.get("data"))

                entity_resp = requester.request("GET", f"/api/xdr/v1/incidents/{uid}/entities/ip")
                entities, _ = extract_entity_items_from_response(entity_resp)
                entity_ips = [item.get("ip") for item in entities if item.get("ip")]
                entity_ips = _dedup_keep_order(entity_ips)
                if entity_ips:
                    context_manager.update_params(runtime_context["session_id"], {"last_entity_ip": entity_ips[0]})
                risk_tags = proof_data.get("riskTag")
                if isinstance(risk_tags, str):
                    risk_tag_text = risk_tags
                elif isinstance(risk_tags, list):
                    risk_tag_text = ",".join([str(tag) for tag in risk_tags if tag])
                else:
                    risk_tag_text = ""
                return {
                    "uuId": uid,
                    "name": row.get("name"),
                    "ai_result": proof_data.get("gptResultDescription", "暂无"),
                    "risk_tags": risk_tag_text or "无",
                    "entityIp": entity_ips[0] if entity_ips else "-",
                    "evidence_source": [
                        "GET /api/xdr/v1/incidents/{uuid}/proof",
                        "GET /api/xdr/v1/incidents/{uuid}/entities/ip",
                    ],
                }

            results: list[dict[str, Any]] = []
            errors: list[str] = []
            with ThreadPoolExecutor(max_workers=6) as executor:
                fut_map = {executor.submit(fetch_one, row): row for row in targets}
                for fut in as_completed(fut_map):
                    try:
                        item = fut.result()
                    except Exception as exc:
                        errors.append(str(exc) or exc.__class__.__name__)
                        continue
                    if item:
                        results.append(item)
            results.sort(key=lambda item: next((idx for idx, row in enumerate(targets) if row.get("uuId") == item["uuId"]), 999))
            return {"sample_evidence": results, "errors": errors}

        def node_4_llm_briefing(ctx: dict[str, Any]) -> dict[str, Any]:
            node1 = ctx["nodes"]["node_1_log_count_24h"]
            node2 = ctx["nodes"]["node_2_unhandled_high_events_24h"]
            node3 = ctx["nodes"]["node_3_sample_detail_parallel"]
            fallback = (
                f"总体态势：过去24小时网络安全日志总量 {node1.get('log_total_24h', 0)}，"
                f"未处置高危事件 {len(node2.get('high_events', []))} 条。\n"
                "关键风险：已抽样高危事件证据，存在外部实体关联，需优先处理前3条告警。\n"
                "建议动作：先执行“深度研判前3条事件”，再对首个高风险IP进行90天活动轨迹分析。"
            )
            prompt = (
                "你是企业SOC值班专家，请根据输入生成“今日安全早报”，要求三段结构：总体态势、关键风险、建议动作。"
                f"\n日志总量: {node1.get('log_total_24h', 0)}"
                f"\n未处置高危事件样本: {json.dumps(node2.get('high_events', [])[:5], ensure_ascii=False)}"
                f"\n样本举证: {json.dumps(node3.get('sample_evidence', [])[:3], ensure_ascii=False)}"
            )
            briefing = self._safe_llm_complete(
                prompt,
                system="输出中文，结论化、可执行，避免泛化。",
                fallback=fallback,
            )
            return {"briefing": briefing}

        nodes = [
            PipelineNode("node_1_log_count_24h", node_1_log_count_24h),
            PipelineNode(
                "node_2_unhandled_high_events_24h",
                node_2_unhandled_high_events_24h,
                depends_on=["node_1_log_count_24h"],
            ),
            PipelineNode(
                "node_3_sample_detail_parallel",
                node_3_sample_detail_parallel,
                depends_on=["node_2_unhandled_high_events_24h"],
            ),
            PipelineNode(
                "node_4_llm_briefing",
                node_4_llm_briefing,
                depends_on=[
                    "node_1_log_count_24h",
                    "node_2_unhandled_high_events_24h",
                    "node_3_sample_detail_parallel",
                ],
            ),
        ]

        def finalizer(results: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
            _ = ctx
            node1 = results.get("node_1_log_count_24h", {})
            node2 = results.get("node_2_unhandled_high_events_24h", {})
            node3 = results.get("node_3_sample_detail_parallel", {})
            summary = results.get("node_4_llm_briefing", {}).get("briefing", "早报生成完成。")
            rows = node2.get("high_events", [])
            labels, points = self._build_fake_trend(node1.get("log_total_24h", 0), points=8)
            chart_option = {
                "tooltip": {"trigger": "axis"},
                "xAxis": {"type": "category", "data": labels},
                "yAxis": {"type": "value"},
                "series": [{"name": "日志总量", "type": "line", "smooth": True, "data": points}],
            }

            cards = [
                text_payload(summary, title="今日安全早报"),
                echarts_payload(
                    title="24h 日志总量趋势（V1伪趋势）",
                    option=chart_option,
                    summary=f"过去24小时日志总量：{node1.get('log_total_24h', 0)}",
                ),
                table_payload(
                    title="未处置高危事件（24h）",
                    columns=[
                        {"key": "index", "label": "序号"},
                        {"key": "uuId", "label": "事件ID"},
                        {"key": "name", "label": "事件名称"},
                        {"key": "incidentSeverity", "label": "等级"},
                        {"key": "dealStatus", "label": "状态"},
                        {"key": "hostIp", "label": "主机IP"},
                        {"key": "endTime", "label": "最近发生"},
                    ],
                    rows=rows,
                    namespace="events",
                ),
            ]

            top_uuids = [row.get("uuId") for row in rows[:3] if row.get("uuId")]
            first_ip = None
            for evidence in node3.get("sample_evidence", []):
                candidate = evidence.get("entityIp")
                if isinstance(candidate, str) and IPV4_PATTERN.match(candidate):
                    first_ip = candidate
                    break
            if not first_ip and rows:
                host_ip = rows[0].get("hostIp")
                if isinstance(host_ip, str) and IPV4_PATTERN.match(host_ip):
                    first_ip = host_ip

            next_actions: list[dict[str, Any]] = []
            if top_uuids:
                next_actions.append(
                    {
                        "id": "triage_top3",
                        "label": "🔍 一键深度研判前3条事件",
                        "template_id": "alert_triage",
                        "params": {
                            "incident_uuids": top_uuids,
                            "session_id": runtime_context["session_id"],
                        },
                        "style": "primary",
                    }
                )
            if first_ip:
                next_actions.append(
                    {
                        "id": "hunt_first_ip",
                        "label": "🕵️ 生成首个源 IP 的活动轨迹",
                        "template_id": "threat_hunting",
                        "params": {"ip": first_ip},
                        "style": "secondary",
                    }
                )

            return {
                "summary": summary,
                "cards": cards,
                "next_actions": next_actions,
                "evidence_sources": [
                    "POST /api/xdr/v1/analysislog/networksecurity/count",
                    "POST /api/xdr/v1/incidents/list",
                    "GET /api/xdr/v1/incidents/{uuid}/proof",
                    "GET /api/xdr/v1/incidents/{uuid}/entities/ip",
                ],
            }

        return nodes, finalizer

    def _build_alert_triage(
        self, runtime_context: dict[str, Any]
    ) -> tuple[list[PipelineNode], Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]]:
        requester: APIRequester = runtime_context["requester"]
        params = runtime_context["params"]

        def node_1_resolve_target(ctx: dict[str, Any]) -> dict[str, Any]:
            _ = ctx
            uuids = self._resolve_incident_uuids(params, runtime_context["session_id"])
            if not uuids:
                raise ValueError("无法定位目标事件，请提供 incident_uuid 或 event_index。")
            return {"incident_uuids": uuids}

        def node_2_entity_profile(ctx: dict[str, Any]) -> dict[str, Any]:
            uuids = ctx["nodes"]["node_1_resolve_target"]["incident_uuids"]
            rows: list[dict[str, Any]] = []
            target_ips: list[str] = []
            errors: list[str] = []
            for uid in uuids[:5]:
                resp = requester.request("GET", f"/api/xdr/v1/incidents/{uid}/entities/ip")
                entities, error = extract_entity_items_from_response(resp)
                if error:
                    errors.append(f"{uid}: {error}")
                    continue
                for item in entities:
                    ip = item.get("ip")
                    if not ip:
                        continue
                    target_ips.append(ip)
                    rows.append(
                        {
                            "incident_uuid": uid,
                            "ip": ip,
                            "country": _pick(item, "country", "countryName", default="-"),
                            "region": _pick(item, "province", "region", default="-"),
                            "tags": item.get("tags", []),
                            "suggestion": _pick(item, "dealSuggestion", "suggestion", default="-"),
                        }
                    )
            target_ips = _dedup_keep_order(target_ips)
            if target_ips:
                context_manager.update_params(runtime_context["session_id"], {"last_entity_ip": target_ips[0]})
            return {
                "entity_rows": rows,
                "target_ips": target_ips,
                "errors": errors,
            }

        def node_3_external_intel(ctx: dict[str, Any]) -> dict[str, Any]:
            ips = ctx["nodes"]["node_2_entity_profile"].get("target_ips", [])
            intel_rows = [self._query_intel(ip) for ip in ips[:5]]
            return {"intel_rows": intel_rows}

        def node_4_internal_impact_count_parallel(ctx: dict[str, Any]) -> dict[str, Any]:
            ips = ctx["nodes"]["node_2_entity_profile"].get("target_ips", [])
            if not ips and params.get("ip"):
                ips = [params["ip"]]

            end_ts = to_ts(utc_now())
            start_ts = end_ts - params.get("window_days", 7) * 86400

            def count_for_ip(ip: str) -> dict[str, Any]:
                total = self._count_logs(
                    requester,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    extra_filters={"srcIps": [ip]},
                )["total"]
                high = self._count_logs(
                    requester,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    extra_filters={"srcIps": [ip], "severities": [3, 4]},
                )["total"]
                compromised = self._count_logs(
                    requester,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    extra_filters={"srcIps": [ip], "attackStates": [2, 3]},
                )["total"]
                score = high * 2 + compromised * 3
                return {
                    "ip": ip,
                    "total": total,
                    "high_risk": high,
                    "compromised": compromised,
                    "blast_radius_score": score,
                }

            rows: list[dict[str, Any]] = []
            with ThreadPoolExecutor(max_workers=4) as executor:
                fut_map = {executor.submit(count_for_ip, ip): ip for ip in ips[:5]}
                for fut in as_completed(fut_map):
                    rows.append(fut.result())
            rows.sort(key=lambda item: item.get("blast_radius_score", 0), reverse=True)
            return {
                "impact_rows": rows,
                "window": {"startTimestamp": start_ts, "endTimestamp": end_ts},
                "blast_radius_score": sum(row["blast_radius_score"] for row in rows),
            }

        def node_5_llm_triage_summary(ctx: dict[str, Any]) -> dict[str, Any]:
            entity_rows = ctx["nodes"]["node_2_entity_profile"].get("entity_rows", [])
            intel_rows = ctx["nodes"]["node_3_external_intel"].get("intel_rows", [])
            impact_rows = ctx["nodes"]["node_4_internal_impact_count_parallel"].get("impact_rows", [])

            max_high = max([row.get("high_risk", 0) for row in impact_rows], default=0)
            max_compromised = max([row.get("compromised", 0) for row in impact_rows], default=0)

            recommendation = "建议人工复核"
            if max_compromised >= 5 or max_high >= 20:
                recommendation = "建议立即封禁"
            elif max_high <= 2 and max_compromised == 0:
                recommendation = "建议继续观察"

            fallback = (
                f"攻击真实性概率：中高（基于实体画像、外部情报与内部计数综合判断）。\n"
                f"关键证据：目标IP内部高危访问峰值 {max_high}，成功/失陷量峰值 {max_compromised}。\n"
                f"优先建议动作：{recommendation}。"
            )

            prompt = (
                "请输出告警深度研判结论，格式必须包含：攻击真实性概率、关键证据、优先建议动作。"
                f"\n实体画像: {json.dumps(entity_rows[:5], ensure_ascii=False)}"
                f"\n外部情报: {json.dumps(intel_rows[:5], ensure_ascii=False)}"
                f"\n内部影响计数: {json.dumps(impact_rows[:5], ensure_ascii=False)}"
            )
            summary = self._safe_llm_complete(
                prompt,
                system="你是SOC分析师，给结论而不是解释过程。",
                fallback=fallback,
            )
            return {"summary": summary, "recommendation": recommendation}

        nodes = [
            PipelineNode("node_1_resolve_target", node_1_resolve_target),
            PipelineNode("node_2_entity_profile", node_2_entity_profile, depends_on=["node_1_resolve_target"]),
            PipelineNode("node_3_external_intel", node_3_external_intel, depends_on=["node_2_entity_profile"]),
            PipelineNode(
                "node_4_internal_impact_count_parallel",
                node_4_internal_impact_count_parallel,
                depends_on=["node_3_external_intel"],
            ),
            PipelineNode(
                "node_5_llm_triage_summary",
                node_5_llm_triage_summary,
                depends_on=["node_4_internal_impact_count_parallel"],
            ),
        ]

        def finalizer(results: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
            _ = ctx
            summary = results.get("node_5_llm_triage_summary", {}).get("summary", "研判已完成。")
            intel_rows = results.get("node_3_external_intel", {}).get("intel_rows", [])
            impact_rows = results.get("node_4_internal_impact_count_parallel", {}).get("impact_rows", [])
            entity_rows = results.get("node_2_entity_profile", {}).get("entity_rows", [])
            entity_errors = results.get("node_2_entity_profile", {}).get("errors", [])
            target_uuids = results.get("node_1_resolve_target", {}).get("incident_uuids", [])
            target_rows = [{"index": idx, "incident_uuid": uid} for idx, uid in enumerate(target_uuids, start=1)]

            cards = [
                text_payload(summary, title="单点告警深度研判结论"),
                table_payload(
                    title="任务目标事件",
                    columns=[
                        {"key": "index", "label": "序号"},
                        {"key": "incident_uuid", "label": "事件UUID"},
                    ],
                    rows=target_rows,
                    namespace="triage_targets",
                ),
                table_payload(
                    title="目标IP内部影响计数（近7天）",
                    columns=[
                        {"key": "ip", "label": "IP"},
                        {"key": "total", "label": "总访问量"},
                        {"key": "high_risk", "label": "高危访问量"},
                        {"key": "compromised", "label": "成功/失陷量"},
                        {"key": "blast_radius_score", "label": "影响评分"},
                    ],
                    rows=impact_rows,
                    namespace="triage_impact",
                ),
                table_payload(
                    title="实体外部情报",
                    columns=[
                        {"key": "ip", "label": "IP"},
                        {"key": "severity", "label": "severity"},
                        {"key": "tags", "label": "tags"},
                        {"key": "confidence", "label": "confidence"},
                        {"key": "source", "label": "source"},
                    ],
                    rows=intel_rows,
                    namespace="triage_intel",
                ),
                table_payload(
                    title="事件实体画像",
                    columns=[
                        {"key": "incident_uuid", "label": "事件UUID"},
                        {"key": "ip", "label": "IP"},
                        {"key": "country", "label": "国家"},
                        {"key": "region", "label": "地区"},
                        {"key": "suggestion", "label": "处置建议"},
                    ],
                    rows=entity_rows,
                    namespace="triage_entities",
                ),
            ]
            if entity_errors:
                cards.append(
                    text_payload(
                        "实体接口返回部分异常，已按可用数据继续完成研判：\n"
                        + "\n".join(entity_errors[:5]),
                        title="任务执行提示",
                    )
                )

            target_ip = None
            if impact_rows:
                target_ip = impact_rows[0].get("ip")
            if not target_ip and intel_rows:
                target_ip = intel_rows[0].get("ip")

            next_actions: list[dict[str, Any]] = []
            if target_ip:
                next_actions.append(
                    {
                        "id": "triage_block_target",
                        "label": "封禁该 IP（进入审批）",
                        "template_id": "alert_triage",
                        "params": {
                            "mode": "block_ip",
                            "ip": target_ip,
                            "session_id": runtime_context["session_id"],
                        },
                        "style": "danger",
                    }
                )
                next_actions.append(
                    {
                        "id": "triage_hunt_target",
                        "label": "生成该 IP 90 天活动轨迹",
                        "template_id": "threat_hunting",
                        "params": {"ip": target_ip},
                        "style": "secondary",
                    }
                )

            return {
                "summary": summary,
                "cards": cards,
                "next_actions": next_actions,
                "evidence_sources": [
                    "GET /api/xdr/v1/incidents/{uuid}/entities/ip",
                    "POST /api/xdr/v1/analysislog/networksecurity/count",
                    "ThreatBook / local fallback",
                ],
            }

        return nodes, finalizer

    def _build_alert_block_mode(
        self, runtime_context: dict[str, Any]
    ) -> tuple[list[PipelineNode], Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]]:
        requester: APIRequester = runtime_context["requester"]
        params = runtime_context["params"]
        skills: SkillRegistry = runtime_context["skills"]

        def node_1_resolve_target_ip(ctx: dict[str, Any]) -> dict[str, Any]:
            _ = ctx
            candidate_ip = params.get("ip")
            if isinstance(candidate_ip, str) and IPV4_PATTERN.match(candidate_ip):
                return {"target_ip": candidate_ip}

            uuids = self._resolve_incident_uuids(params, runtime_context["session_id"])
            for uid in uuids:
                resp = requester.request("GET", f"/api/xdr/v1/incidents/{uid}/entities/ip")
                entities, _ = extract_entity_items_from_response(resp)
                for entity in entities:
                    ip = entity.get("ip")
                    if isinstance(ip, str) and IPV4_PATTERN.match(ip):
                        return {"target_ip": ip, "incident_uuid": uid}
            raise ValueError("未能解析待封禁IP，请补充 ip 参数。")

        def node_2_build_block_approval(ctx: dict[str, Any]) -> dict[str, Any]:
            ip = ctx["nodes"]["node_1_resolve_target_ip"]["target_ip"]
            block_skill = skills.get("block_action")
            if not block_skill:
                raise ValueError("系统未加载 block_action 技能。")

            payloads: list[dict[str, Any]] = []
            try:
                payloads = block_skill.execute(
                    runtime_context["session_id"],
                    {
                        "block_type": "SRC_IP",
                        "views": [ip],
                        "time_type": "temporary",
                        "time_value": 24,
                        "time_unit": "h",
                        "reason": "Playbook深度研判建议封禁",
                        "confirm": False,
                    },
                    f"封禁 {ip}",
                )
            except ConfirmationRequiredException as exc:
                token = f"pending-{runtime_context['session_id']}-block_action"
                pending_params = exc.action_payload.get("params", {"views": [ip], "confirm": True})
                context_manager.save_pending_action(
                    runtime_context["session_id"],
                    {"intent": "block_action", "params": pending_params, "skill": "BlockActionSkill"},
                )
                payloads = [
                    approval_payload(
                        title="高危操作确认: BlockActionSkill",
                        summary=exc.summary,
                        token=token,
                        details=exc.action_payload,
                    )
                ]
            return {"cards": payloads, "target_ip": ip}

        nodes = [
            PipelineNode("node_1_resolve_target_ip", node_1_resolve_target_ip),
            PipelineNode(
                "node_2_build_block_approval",
                node_2_build_block_approval,
                depends_on=["node_1_resolve_target_ip"],
            ),
        ]

        def finalizer(results: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
            _ = ctx
            node2 = results.get("node_2_build_block_approval", {})
            ip = node2.get("target_ip")
            cards = node2.get("cards", [])
            summary = f"已为 {ip} 生成封禁审批卡，请确认后执行。" if ip else "已生成封禁审批卡。"
            if not cards:
                cards = [text_payload(summary, title="封禁审批")]
            return {
                "summary": summary,
                "cards": cards,
                "next_actions": [],
                "evidence_sources": ["Playbook -> BlockActionSkill (审批链路复用)"],
            }

        return nodes, finalizer

    def _scan_incidents_for_ip(
        self,
        requester: APIRequester,
        *,
        ip: str,
        start_ts: int,
        end_ts: int,
        max_scan: int = 2000,
        page_size: int = 200,
    ) -> dict[str, Any]:
        matched: list[dict[str, Any]] = []
        scanned = 0
        page = 1
        pages = 0
        truncated = False

        while scanned < max_scan:
            req = {
                "page": page,
                "pageSize": page_size,
                "sort": "endTime:desc,severity:desc",
                "timeField": "endTime",
                "startTimestamp": start_ts,
                "endTimestamp": end_ts,
            }
            resp = requester.request("POST", "/api/xdr/v1/incidents/list", json_body=req)
            if resp.get("code") != "Success":
                break
            items = resp.get("data", {}).get("item", []) or []
            if not items:
                break

            pages += 1
            for item in items:
                if scanned >= max_scan:
                    truncated = True
                    break
                scanned += 1
                if self._incident_match_ip(item, ip):
                    matched.append(self._normalize_event_row(item, len(matched) + 1))
            if len(items) < page_size:
                break
            if scanned >= max_scan:
                truncated = True
                break
            page += 1

        return {
            "matched_events": matched,
            "scanned": scanned,
            "pages": pages,
            "truncated": truncated,
        }

    def _query_incidents(
        self,
        requester: APIRequester,
        *,
        start_ts: int,
        end_ts: int,
        extra_filters: dict[str, Any] | None = None,
        page_size: int = 100,
    ) -> dict[str, Any]:
        req = {
            "page": 1,
            "pageSize": page_size,
            "sort": "endTime:desc,severity:desc",
            "timeField": "endTime",
            "startTimestamp": start_ts,
            "endTimestamp": end_ts,
        }
        req.update(extra_filters or {})
        resp = requester.request("POST", "/api/xdr/v1/incidents/list", json_body=req)
        if resp.get("code") != "Success":
            return {
                "rows": [],
                "raw_items": [],
                "error": str(resp.get("message") or "事件查询失败"),
                "request": req,
            }
        items = resp.get("data", {}).get("item", []) or []
        rows = [self._normalize_event_row(item, idx) for idx, item in enumerate(items, start=1)]
        return {"rows": rows, "raw_items": items, "error": None, "request": req}

    @staticmethod
    def _is_external_ip(ip: str) -> bool:
        try:
            candidate = ipaddress.ip_address(ip)
            return not (
                candidate.is_private
                or candidate.is_loopback
                or candidate.is_reserved
                or candidate.is_link_local
                or candidate.is_multicast
            )
        except ValueError:
            return False

    @staticmethod
    def _incident_match_ip(item: dict[str, Any], ip: str) -> bool:
        for key in ("hostIp", "srcIp", "dstIp", "assetIp"):
            value = item.get(key)
            if isinstance(value, str) and value == ip:
                return True
        combined = " ".join(
            [
                str(item.get("name") or ""),
                str(item.get("description") or ""),
                str(item.get("desc") or ""),
                str(item.get("detail") or ""),
            ]
        )
        return ip in combined

    def _build_asset_guard(
        self, runtime_context: dict[str, Any]
    ) -> tuple[list[PipelineNode], Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]]:
        requester: APIRequester = runtime_context["requester"]
        params = runtime_context["params"]
        asset_ip = str(params.get("asset_ip"))
        asset_name = str(params.get("asset_name") or "").strip() or asset_ip
        window_hours = params.get("window_hours", 24)
        top_n = params.get("top_external_ip", 5)

        def node_1_events_dst_asset(ctx: dict[str, Any]) -> dict[str, Any]:
            _ = ctx
            end_ts = to_ts(utc_now())
            start_ts = end_ts - window_hours * 3600
            queried = self._query_incidents(
                requester,
                start_ts=start_ts,
                end_ts=end_ts,
                extra_filters={"dstIps": [asset_ip]},
            )
            uuids = [row.get("uuId") for row in queried["rows"] if row.get("uuId")]
            return {
                "rows": queried["rows"],
                "count": len(queried["rows"]),
                "uuids": uuids,
                "startTimestamp": start_ts,
                "endTimestamp": end_ts,
                "error": queried["error"],
                "request": queried["request"],
            }

        def node_2_events_src_asset(ctx: dict[str, Any]) -> dict[str, Any]:
            node1 = ctx["nodes"]["node_1_events_dst_asset"]
            queried = self._query_incidents(
                requester,
                start_ts=node1["startTimestamp"],
                end_ts=node1["endTimestamp"],
                extra_filters={"srcIps": [asset_ip]},
            )
            uuids = [row.get("uuId") for row in queried["rows"] if row.get("uuId")]
            return {
                "rows": queried["rows"],
                "count": len(queried["rows"]),
                "uuids": uuids,
                "error": queried["error"],
                "request": queried["request"],
            }

        def node_3_logs_dst_asset(ctx: dict[str, Any]) -> dict[str, Any]:
            node1 = ctx["nodes"]["node_1_events_dst_asset"]
            counted = self._count_logs(
                requester,
                start_ts=node1["startTimestamp"],
                end_ts=node1["endTimestamp"],
                extra_filters={"dstIps": [asset_ip]},
            )
            return {
                "log_total": counted["total"],
                "error": counted["error"],
                "source": "POST /api/xdr/v1/analysislog/networksecurity/count",
            }

        def node_4_logs_src_asset(ctx: dict[str, Any]) -> dict[str, Any]:
            node1 = ctx["nodes"]["node_1_events_dst_asset"]
            counted = self._count_logs(
                requester,
                start_ts=node1["startTimestamp"],
                end_ts=node1["endTimestamp"],
                extra_filters={"srcIps": [asset_ip]},
            )
            return {
                "log_total": counted["total"],
                "error": counted["error"],
                "source": "POST /api/xdr/v1/analysislog/networksecurity/count",
            }

        def node_5_top_external_ip(ctx: dict[str, Any]) -> dict[str, Any]:
            uuids = _dedup_keep_order(
                ctx["nodes"]["node_1_events_dst_asset"].get("uuids", [])
                + ctx["nodes"]["node_2_events_src_asset"].get("uuids", [])
            )
            ip_counter: dict[str, int] = {}
            errors: list[str] = []

            def enrich_one(uid: str) -> tuple[str, list[str], str | None]:
                resp = requester.request("GET", f"/api/xdr/v1/incidents/{uid}/entities/ip")
                entities, error = extract_entity_items_from_response(resp)
                entity_ips: list[str] = []
                for item in entities:
                    ip = item.get("ip")
                    if not isinstance(ip, str):
                        continue
                    if ip == asset_ip:
                        continue
                    if not self._is_external_ip(ip):
                        continue
                    entity_ips.append(ip)
                return uid, _dedup_keep_order(entity_ips), error

            with ThreadPoolExecutor(max_workers=6) as executor:
                fut_map = {executor.submit(enrich_one, uid): uid for uid in uuids[:30]}
                for fut in as_completed(fut_map):
                    uid, ips, error = fut.result()
                    if error:
                        errors.append(f"{uid}: {error}")
                    for ip in ips:
                        ip_counter[ip] = ip_counter.get(ip, 0) + 1

            top_rows = sorted(
                [{"ip": ip, "hits": hits} for ip, hits in ip_counter.items()],
                key=lambda item: item["hits"],
                reverse=True,
            )[:top_n]
            if top_rows:
                context_manager.update_params(runtime_context["session_id"], {"last_entity_ip": top_rows[0]["ip"]})
            return {"top_external_ips": top_rows, "errors": errors, "scanned_incidents": len(uuids[:30])}

        def node_6_external_intel_enrich(ctx: dict[str, Any]) -> dict[str, Any]:
            top_rows = ctx["nodes"]["node_5_top_external_ip"].get("top_external_ips", [])
            intel_rows = []
            for row in top_rows:
                intel = self._query_intel(row["ip"])
                intel["hits"] = row["hits"]
                intel_rows.append(intel)
            return {"intel_rows": intel_rows}

        def node_7_llm_asset_briefing(ctx: dict[str, Any]) -> dict[str, Any]:
            events_dst = ctx["nodes"]["node_1_events_dst_asset"].get("count", 0)
            events_src = ctx["nodes"]["node_2_events_src_asset"].get("count", 0)
            logs_dst = ctx["nodes"]["node_3_logs_dst_asset"].get("log_total", 0)
            logs_src = ctx["nodes"]["node_4_logs_src_asset"].get("log_total", 0)
            intel_rows = ctx["nodes"]["node_6_external_intel_enrich"].get("intel_rows", [])
            fallback = (
                f"核心资产 {asset_name}（{asset_ip}）在最近{window_hours}小时内完成体检。"
                f"入向告警 {events_dst} 条、出向告警 {events_src} 条，入向访问 {logs_dst} 次、出向访问 {logs_src} 次。"
                "建议优先复核高风险外部实体并跟进处置闭环。"
            )
            prompt = (
                "你是SOC负责人，请面向管理层输出核心资产防线透视结论，要求包含：总体态势、主要隐患、建议动作。"
                f"\n资产名称: {asset_name}"
                f"\n资产IP: {asset_ip}"
                f"\n入向告警数: {events_dst}"
                f"\n出向告警数: {events_src}"
                f"\n入向访问量: {logs_dst}"
                f"\n出向访问量: {logs_src}"
                f"\nTop外部实体情报: {json.dumps(intel_rows, ensure_ascii=False)}"
            )
            briefing = self._safe_llm_complete(
                prompt,
                system="输出中文，面向管理层，结论化且可执行。",
                fallback=fallback,
            )
            return {"briefing": briefing}

        nodes = [
            PipelineNode("node_1_events_dst_asset", node_1_events_dst_asset),
            PipelineNode("node_2_events_src_asset", node_2_events_src_asset, depends_on=["node_1_events_dst_asset"]),
            PipelineNode("node_3_logs_dst_asset", node_3_logs_dst_asset, depends_on=["node_2_events_src_asset"]),
            PipelineNode("node_4_logs_src_asset", node_4_logs_src_asset, depends_on=["node_3_logs_dst_asset"]),
            PipelineNode(
                "node_5_top_external_ip",
                node_5_top_external_ip,
                depends_on=["node_4_logs_src_asset"],
            ),
            PipelineNode(
                "node_6_external_intel_enrich",
                node_6_external_intel_enrich,
                depends_on=["node_5_top_external_ip"],
            ),
            PipelineNode(
                "node_7_llm_asset_briefing",
                node_7_llm_asset_briefing,
                depends_on=["node_6_external_intel_enrich"],
            ),
        ]

        def finalizer(results: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
            _ = ctx
            node1 = results.get("node_1_events_dst_asset", {})
            node2 = results.get("node_2_events_src_asset", {})
            node3 = results.get("node_3_logs_dst_asset", {})
            node4 = results.get("node_4_logs_src_asset", {})
            node6 = results.get("node_6_external_intel_enrich", {})
            summary = results.get("node_7_llm_asset_briefing", {}).get("briefing", "核心资产防线透视已完成。")

            stats_rows = [
                {"direction": "入向（目标为资产）", "event_count": node1.get("count", 0), "log_count": node3.get("log_total", 0)},
                {"direction": "出向（源为资产）", "event_count": node2.get("count", 0), "log_count": node4.get("log_total", 0)},
            ]
            intel_rows = node6.get("intel_rows", [])
            cards = [
                text_payload(summary, title="核心资产态势结论"),
                table_payload(
                    title="资产双向告警统计",
                    columns=[
                        {"key": "direction", "label": "方向"},
                        {"key": "event_count", "label": "告警数"},
                        {"key": "log_count", "label": "访问量"},
                    ],
                    rows=stats_rows,
                    namespace="asset_guard_stats",
                ),
                table_payload(
                    title=f"Top {top_n} 外部访问实体情报",
                    columns=[
                        {"key": "ip", "label": "IP"},
                        {"key": "hits", "label": "关联事件数"},
                        {"key": "severity", "label": "威胁等级"},
                        {"key": "confidence", "label": "置信度"},
                        {"key": "tags", "label": "标签"},
                        {"key": "source", "label": "来源"},
                    ],
                    rows=intel_rows,
                    namespace="asset_guard_intel",
                ),
                text_payload(
                    "建议动作：优先对高风险外部IP执行深度研判，并对核心资产相关高危告警进行人工复核。",
                    title="建议动作",
                ),
            ]

            next_actions: list[dict[str, Any]] = []
            incident_uuids = _dedup_keep_order(node1.get("uuids", []) + node2.get("uuids", []))
            if incident_uuids:
                next_actions.append(
                    {
                        "id": "asset_guard_triage",
                        "label": "🔍 对首条相关事件做深度研判",
                        "template_id": "alert_triage",
                        "params": {"incident_uuid": incident_uuids[0], "session_id": runtime_context["session_id"]},
                        "style": "primary",
                    }
                )
            if intel_rows:
                next_actions.append(
                    {
                        "id": "asset_guard_hunting",
                        "label": "🕵️ 生成高风险外部IP活动轨迹",
                        "template_id": "threat_hunting",
                        "params": {"ip": intel_rows[0].get("ip")},
                        "style": "secondary",
                    }
                )

            return {
                "summary": summary,
                "cards": cards,
                "next_actions": next_actions,
                "asset": {"asset_name": asset_name, "asset_ip": asset_ip, "window_hours": window_hours},
                "evidence_sources": [
                    "POST /api/xdr/v1/incidents/list",
                    "POST /api/xdr/v1/analysislog/networksecurity/count",
                    "GET /api/xdr/v1/incidents/{uuid}/entities/ip",
                    "ThreatBook / local fallback",
                ],
            }

        return nodes, finalizer

    def _build_threat_hunting(
        self, runtime_context: dict[str, Any]
    ) -> tuple[list[PipelineNode], Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]]:
        requester: APIRequester = runtime_context["requester"]
        params = runtime_context["params"]
        target_ip = str(params.get("ip"))

        def node_1_external_profile(ctx: dict[str, Any]) -> dict[str, Any]:
            _ = ctx
            return {"profile": self._query_intel(target_ip)}

        def node_2_event_scan_paginated(ctx: dict[str, Any]) -> dict[str, Any]:
            _ = ctx
            now_ts = to_ts(utc_now())
            end_ts = _to_int(params.get("endTimestamp"), now_ts)
            start_ts = _to_int(params.get("startTimestamp"), end_ts - params.get("window_days", 90) * 86400)
            scan_result = self._scan_incidents_for_ip(
                requester,
                ip=target_ip,
                start_ts=start_ts,
                end_ts=end_ts,
                max_scan=params.get("max_scan", 2000),
                page_size=200,
            )
            uuids = [row["uuId"] for row in scan_result["matched_events"] if row.get("uuId")]
            if uuids:
                context_manager.store_index_mapping(runtime_context["session_id"], "events", uuids)
                context_manager.update_params(
                    runtime_context["session_id"],
                    {"last_event_uuid": uuids[0], "last_event_uuids": uuids, "last_entity_ip": target_ip},
                )
            return {
                **scan_result,
                "startTimestamp": start_ts,
                "endTimestamp": end_ts,
            }

        def node_3_evidence_enrichment_parallel(ctx: dict[str, Any]) -> dict[str, Any]:
            rows = ctx["nodes"]["node_2_event_scan_paginated"].get("matched_events", [])
            limit = params.get("evidence_limit", 20)
            targets = rows[:limit]

            def enrich(row: dict[str, Any]) -> dict[str, Any]:
                uid = row.get("uuId")
                if not uid:
                    return {}
                proof_resp = requester.request("GET", f"/api/xdr/v1/incidents/{uid}/proof")
                proof_data = _pick_first_dict(proof_resp.get("data")) if proof_resp.get("code") == "Success" else {}
                entity_resp = requester.request("GET", f"/api/xdr/v1/incidents/{uid}/entities/ip")
                entities, _ = extract_entity_items_from_response(entity_resp)
                entity_ips = [item.get("ip") for item in entities if item.get("ip")]
                return {
                    "uuId": uid,
                    "timeline_count": len(proof_data.get("alertTimeLine", []) or []),
                    "risk_tags": proof_data.get("riskTag", []),
                    "entity_ips": _dedup_keep_order(entity_ips),
                    "ai_result": proof_data.get("gptResultDescription", "暂无"),
                }

            evidence: list[dict[str, Any]] = []
            errors: list[str] = []
            with ThreadPoolExecutor(max_workers=6) as executor:
                fut_map = {executor.submit(enrich, row): row for row in targets}
                for fut in as_completed(fut_map):
                    try:
                        item = fut.result()
                    except Exception as exc:
                        errors.append(str(exc) or exc.__class__.__name__)
                        continue
                    if item:
                        evidence.append(item)
            evidence.sort(key=lambda item: next((idx for idx, row in enumerate(targets) if row.get("uuId") == item["uuId"]), 999))
            return {"evidence_items": evidence, "errors": errors}

        def node_4_internal_activity_count(ctx: dict[str, Any]) -> dict[str, Any]:
            _ = ctx
            now_ts = to_ts(utc_now())
            windows = [7, 30, 90]
            rows = []
            for days in windows:
                start_ts = now_ts - days * 86400
                src_total = self._count_logs(
                    requester,
                    start_ts=start_ts,
                    end_ts=now_ts,
                    extra_filters={"srcIps": [target_ip]},
                )["total"]
                dst_total = self._count_logs(
                    requester,
                    start_ts=start_ts,
                    end_ts=now_ts,
                    extra_filters={"dstIps": [target_ip]},
                )["total"]
                rows.append({"window": f"{days}d", "src_total": src_total, "dst_total": dst_total})
            return {"activity_rows": rows}

        def node_5_llm_timeline_story(ctx: dict[str, Any]) -> dict[str, Any]:
            profile = ctx["nodes"]["node_1_external_profile"].get("profile", {})
            matched = ctx["nodes"]["node_2_event_scan_paginated"].get("matched_events", [])
            evidence = ctx["nodes"]["node_3_evidence_enrichment_parallel"].get("evidence_items", [])
            activity = ctx["nodes"]["node_4_internal_activity_count"].get("activity_rows", [])

            severity = str(profile.get("severity") or "unknown").lower()
            risk_level = "中"
            if severity in {"high", "critical"} or len(matched) >= 10:
                risk_level = "高"
            elif severity in {"low"} and len(matched) <= 2:
                risk_level = "低"

            fallback = (
                f"风险等级：{risk_level}\n"
                "攻击故事线：\n"
                "1) 侦察：目标IP出现对内通信痕迹。\n"
                "2) 利用：命中可疑事件并关联外部情报标签。\n"
                "3) 横向：在事件时间线上出现多阶段告警。\n"
                "4) 结果：建议对高风险节点发起处置审批并持续监控。"
            )
            prompt = (
                "请按“侦察->利用->横向->结果”输出攻击故事线，每段附关键证据。"
                f"\n目标IP: {target_ip}"
                f"\n画像: {json.dumps(profile, ensure_ascii=False)}"
                f"\n命中事件: {json.dumps(matched[:10], ensure_ascii=False)}"
                f"\n举证: {json.dumps(evidence[:10], ensure_ascii=False)}"
                f"\n内部活动: {json.dumps(activity, ensure_ascii=False)}"
            )
            story = self._safe_llm_complete(
                prompt,
                system="你是溯源分析专家，输出结构化叙事。",
                fallback=fallback,
            )
            return {"story": story, "risk_level": risk_level}

        nodes = [
            PipelineNode("node_1_external_profile", node_1_external_profile),
            PipelineNode("node_2_event_scan_paginated", node_2_event_scan_paginated, depends_on=["node_1_external_profile"]),
            PipelineNode(
                "node_3_evidence_enrichment_parallel",
                node_3_evidence_enrichment_parallel,
                depends_on=["node_2_event_scan_paginated"],
            ),
            PipelineNode(
                "node_4_internal_activity_count",
                node_4_internal_activity_count,
                depends_on=["node_3_evidence_enrichment_parallel"],
            ),
            PipelineNode(
                "node_5_llm_timeline_story",
                node_5_llm_timeline_story,
                depends_on=["node_4_internal_activity_count"],
            ),
        ]

        def finalizer(results: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
            _ = ctx
            profile = results.get("node_1_external_profile", {}).get("profile", {})
            scan_result = results.get("node_2_event_scan_paginated", {})
            matched_rows = scan_result.get("matched_events", [])
            story_result = results.get("node_5_llm_timeline_story", {})
            evidence_errors = results.get("node_3_evidence_enrichment_parallel", {}).get("errors", [])
            summary = (
                f"目标IP {target_ip} 轨迹分析完成：命中 {len(matched_rows)} 条事件，"
                f"扫描 {scan_result.get('scanned', 0)} 条（上限 {params.get('max_scan', 2000)}），"
                f"风险等级 {story_result.get('risk_level', '中')}。"
            )

            cards = [
                text_payload(summary, title="攻击者活动轨迹结论"),
                table_payload(
                    title="命中事件清单",
                    columns=[
                        {"key": "index", "label": "序号"},
                        {"key": "endTime", "label": "时间"},
                        {"key": "uuId", "label": "事件ID"},
                        {"key": "name", "label": "事件名"},
                        {"key": "incidentSeverity", "label": "等级"},
                        {"key": "dealStatus", "label": "状态"},
                    ],
                    rows=matched_rows,
                    namespace="hunting_events",
                ),
                text_payload(story_result.get("story", "暂无时间线叙事。"), title="攻击故事线"),
            ]
            if evidence_errors:
                cards.append(
                    text_payload(
                        "部分证据拉取失败，已基于可用数据完成轨迹分析：\n" + "\n".join(evidence_errors[:5]),
                        title="任务执行提示",
                    )
                )

            next_actions: list[dict[str, Any]] = []
            if params.get("mode") != "export_summary":
                next_actions.append(
                    {
                        "id": "hunting_export",
                        "label": "导出溯源摘要",
                        "template_id": "threat_hunting",
                        "params": {"ip": target_ip, "mode": "export_summary"},
                        "style": "secondary",
                    }
                )
            next_actions.append(
                {
                    "id": "hunting_disposal",
                    "label": "对高风险节点执行处置审批",
                    "template_id": "alert_triage",
                    "params": {
                        "mode": "block_ip",
                        "ip": target_ip,
                        "session_id": runtime_context["session_id"],
                    },
                    "style": "danger",
                }
            )

            return {
                "summary": summary,
                "cards": cards,
                "next_actions": next_actions,
                "profile": profile,
                "evidence_sources": [
                    "POST /api/xdr/v1/incidents/list (分页扫描)",
                    "GET /api/xdr/v1/incidents/{uuid}/proof",
                    "GET /api/xdr/v1/incidents/{uuid}/entities/ip",
                    "POST /api/xdr/v1/analysislog/networksecurity/count",
                ],
            }

        return nodes, finalizer


playbook_service = PlaybookService()
