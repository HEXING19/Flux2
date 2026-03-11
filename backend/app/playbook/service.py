from __future__ import annotations

import json
import ipaddress
import re
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError, as_completed
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
from app.models.db_models import CoreAsset, PlaybookRun, SafetyGateRule, XDRCredential
from app.skills.event_skills import extract_entity_items_from_response
from app.skills.registry import SkillRegistry
from app.workflow.engine import PipelineNode, WorkflowEngine

from .registry import PlaybookRegistry


SEVERITY_LABEL = {0: "信息", 1: "低危", 2: "中危", 3: "高危", 4: "严重"}
DEAL_STATUS_LABEL = {0: "待处置", 10: "处置中", 40: "已处置", 50: "已挂起", 60: "接受风险", 70: "已遏制"}
IPV4_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
INTEL_SEVERITY_CN = {
    "low": "低",
    "medium": "中",
    "high": "高",
    "critical": "严重",
    "unknown": "未知",
}
INTEL_SOURCE_CN = {
    "threatbook": "ThreatBook情报",
    "local_fallback": "本地启发式",
}
INTEL_TAG_CN = {
    "c2": "C2控制",
    "scanner": "扫描器",
    "suspicious": "可疑",
    "unknown": "未知",
}
BUILTIN_PROTECTED_IPS = {
    "8.8.8.8",
    "8.8.4.4",
    "1.1.1.1",
    "1.0.0.1",
    "114.114.114.114",
    "223.5.5.5",
    "223.6.6.6",
    "119.29.29.29",
    "127.0.0.1",
    "0.0.0.0",
}
BUILTIN_PROTECTED_CIDRS = {
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
}


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


def _parse_ipv4(value: Any) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    if not IPV4_PATTERN.match(text):
        return None
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        return None
    if not isinstance(parsed, ipaddress.IPv4Address):
        return None
    return str(parsed)


def _is_private_ipv4(ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if not isinstance(parsed, ipaddress.IPv4Address):
        return False
    return parsed.is_private or parsed.is_loopback or parsed.is_link_local or parsed.is_multicast or parsed.is_reserved


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

    @staticmethod
    def _is_protected_ip(ip: str, protected_ips: set[str], protected_cidrs: list[ipaddress.IPv4Network]) -> bool:
        if ip in protected_ips:
            return True
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            return True
        if not isinstance(parsed, ipaddress.IPv4Address):
            return True
        return any(parsed in net for net in protected_cidrs)

    def _load_protected_ip_filters(
        self,
        session: Session | None = None,
    ) -> tuple[set[str], list[ipaddress.IPv4Network]]:
        protected_ips = set(BUILTIN_PROTECTED_IPS)
        protected_cidrs: list[ipaddress.IPv4Network] = []
        for cidr in BUILTIN_PROTECTED_CIDRS:
            try:
                net = ipaddress.ip_network(cidr, strict=False)
                if isinstance(net, ipaddress.IPv4Network):
                    protected_cidrs.append(net)
            except ValueError:
                continue

        def _merge_rules(rows: list[SafetyGateRule]) -> None:
            for row in rows:
                rule_type = str(row.rule_type or "").strip().lower()
                target = str(row.target or "").strip()
                if not target:
                    continue
                if rule_type == "ip":
                    ip = _parse_ipv4(target)
                    if ip:
                        protected_ips.add(ip)
                    continue
                if rule_type == "cidr":
                    try:
                        net = ipaddress.ip_network(target, strict=False)
                    except ValueError:
                        continue
                    if isinstance(net, ipaddress.IPv4Network):
                        protected_cidrs.append(net)

        if session is not None:
            rows = session.exec(select(SafetyGateRule)).all()
            _merge_rules(list(rows))
        else:
            with session_scope() as inner_session:
                rows = inner_session.exec(select(SafetyGateRule)).all()
                _merge_rules(list(rows))
        return protected_ips, protected_cidrs

    def _normalize_candidate_ips(
        self,
        candidates: list[str],
        *,
        host_ips: set[str],
        protected_ips: set[str],
        protected_cidrs: list[ipaddress.IPv4Network],
    ) -> list[str]:
        strict: list[str] = []
        relaxed: list[str] = []
        seen: set[str] = set()
        for raw in candidates:
            ip = _parse_ipv4(raw)
            if not ip or ip in seen:
                continue
            seen.add(ip)
            if ip in host_ips:
                continue
            if self._is_protected_ip(ip, protected_ips, protected_cidrs):
                continue
            if _is_private_ipv4(ip):
                relaxed.append(ip)
                continue
            strict.append(ip)
        return strict or relaxed

    @staticmethod
    def _classify_entity_ip_direction(entity: dict[str, Any]) -> str:
        if not isinstance(entity, dict):
            return "unknown"
        if entity.get("isSrc") is True or str(entity.get("isSrc") or "") == "1":
            return "source"
        if entity.get("isDst") is True or str(entity.get("isDst") or "") == "1":
            return "outbound"
        sample = " ".join(
            str(entity.get(key) or "").lower()
            for key in (
                "ipType",
                "direction",
                "flowDirection",
                "relation",
                "role",
                "type",
                "label",
                "name",
                "desc",
                "description",
            )
        )
        if any(token in sample for token in ("src", "source", "攻击源", "源ip", "源地址", "attacker")):
            return "source"
        if any(token in sample for token in ("dst", "dest", "destination", "外联", "目标", "目的", "victim")):
            return "outbound"
        return "unknown"

    @staticmethod
    def _recommend_disposition(severity_cn: str, confidence: int, tags: list[str]) -> str:
        sev = str(severity_cn or "").strip()
        risk_tags = {str(tag or "").strip() for tag in tags if str(tag or "").strip()}
        if sev in {"高", "严重"}:
            return "建议封禁"
        if confidence >= 80:
            return "建议封禁"
        if {"C2控制", "扫描器"} & risk_tags and confidence >= 60:
            return "建议封禁"
        if sev == "中" and confidence >= 60:
            return "建议封禁"
        return "建议观察"

    def _build_routine_block_targets(
        self,
        requester: APIRequester,
        rows: list[dict[str, Any]],
        *,
        protected_ips: set[str],
        protected_cidrs: list[ipaddress.IPv4Network],
    ) -> dict[str, Any]:
        host_ips = {_parse_ipv4(row.get("hostIp")) for row in rows}
        host_ips = {ip for ip in host_ips if ip}

        source_candidates: list[str] = []
        outbound_candidates: list[str] = []
        unknown_entity_candidates: list[str] = []
        for row in rows:
            src_ip = _parse_ipv4(row.get("srcIp"))
            dst_ip = _parse_ipv4(row.get("dstIp"))
            if src_ip:
                source_candidates.append(src_ip)
            if dst_ip:
                outbound_candidates.append(dst_ip)

        source_ips = self._normalize_candidate_ips(
            source_candidates,
            host_ips=host_ips,
            protected_ips=protected_ips,
            protected_cidrs=protected_cidrs,
        )
        outbound_ips = self._normalize_candidate_ips(
            outbound_candidates,
            host_ips=host_ips,
            protected_ips=protected_ips,
            protected_cidrs=protected_cidrs,
        )

        looked_up = False
        if not source_ips:
            looked_up = True
            for row in rows:
                uid = str(row.get("uuId") or "").strip()
                if not uid:
                    continue
                resp = requester.request("GET", f"/api/xdr/v1/incidents/{uid}/entities/ip")
                entities, _ = extract_entity_items_from_response(resp)
                for entity in entities:
                    ip = _parse_ipv4(entity.get("ip"))
                    if not ip:
                        continue
                    direction = self._classify_entity_ip_direction(entity)
                    if direction == "source":
                        source_candidates.append(ip)
                    elif direction == "outbound":
                        outbound_candidates.append(ip)
                    else:
                        unknown_entity_candidates.append(ip)
            if not source_candidates:
                source_candidates.extend(unknown_entity_candidates)
            if not outbound_candidates:
                outbound_candidates.extend(unknown_entity_candidates)
            source_ips = self._normalize_candidate_ips(
                source_candidates,
                host_ips=host_ips,
                protected_ips=protected_ips,
                protected_cidrs=protected_cidrs,
            )
            outbound_ips = self._normalize_candidate_ips(
                outbound_candidates,
                host_ips=host_ips,
                protected_ips=protected_ips,
                protected_cidrs=protected_cidrs,
            )

        return {
            "source_ips": source_ips[:3],
            "outbound_ips": outbound_ips[:3],
            "host_ips": sorted(host_ips),
            "full_entity_lookup": looked_up,
        }

    def block_malicious_sources(
        self,
        session: Session,
        *,
        session_id: str,
        ips: list[str],
        block_type: str = "SRC_IP",
        reason: str | None = None,
        duration_hours: int = 24,
        device_id: str | None = None,
        rule_name: str | None = None,
    ) -> dict[str, Any]:
        if not session_id or not str(session_id).strip():
            raise ValueError("缺少 session_id。")

        cleaned_ips: list[str] = []
        for raw in ips or []:
            text = str(raw or "").strip()
            if not text:
                continue
            ip = _parse_ipv4(text)
            if not ip:
                continue
            if ip not in cleaned_ips:
                cleaned_ips.append(ip)
        if not cleaned_ips:
            raise ValueError("未提供合法的 IPv4 封禁目标。")

        protected_ips, protected_cidrs = self._load_protected_ip_filters(session)
        filtered_ips = [ip for ip in cleaned_ips if not self._is_protected_ip(ip, protected_ips, protected_cidrs)]
        if not filtered_ips:
            raise ValueError("目标 IP 均命中“默认受保护基础组件/安全防线”规则，已自动拦截本次封禁。")

        credential = session.exec(select(XDRCredential).order_by(XDRCredential.id.desc())).first()
        requester = get_requester_from_credential(credential)
        device_resp = requester.request("POST", "/api/xdr/v1/device/blockdevice/list", json_body={"type": ["AF"]})
        raw_devices = device_resp.get("data", {}).get("item", []) if device_resp.get("code") == "Success" else []
        online_devices = [d for d in raw_devices if d.get("deviceStatus") == "online"]
        if not online_devices:
            raise ValueError("当前没有在线AF联动设备，无法直接下发封禁。")

        selected_device = None
        if device_id:
            selected_device = next((d for d in online_devices if str(d.get("deviceId")) == str(device_id)), None)
            if not selected_device:
                raise ValueError("所选联动设备不存在或不在线，请重新选择。")
        elif len(online_devices) == 1:
            selected_device = online_devices[0]
        else:
            raise ValueError("存在多个在线联动设备，请先选择设备后再下发封禁。")

        block_devices = [
            {
                "devId": selected_device.get("deviceId"),
                "devName": selected_device.get("deviceName"),
                "devType": selected_device.get("deviceType"),
                "devVersion": selected_device.get("deviceVersion"),
            }
        ]
        skills = SkillRegistry(requester, context_manager)
        block_skill = skills.get("block_action")
        if not block_skill:
            raise ValueError("系统未加载 block_action 技能。")

        safe_hours = max(1, min(360, _to_int(duration_hours, 24)))
        normalized_type = str(block_type or "SRC_IP").strip().upper()
        if normalized_type not in {"SRC_IP", "DST_IP"}:
            raise ValueError("block_type 仅支持 SRC_IP 或 DST_IP。")
        params = {
            "views": filtered_ips,
            "block_type": normalized_type,
            "mode": "in",
            "time_type": "temporary",
            "time_value": safe_hours,
            "time_unit": "h",
            "reason": reason or "由安全早报一键处置触发",
            "devices": block_devices,
            "name": (rule_name or "").strip() or None,
            "confirm": True,
        }
        payloads = block_skill.execute(str(session_id).strip(), params, "安全早报一键处置封禁恶意攻击源")
        success_payload = next((p for p in payloads if p.get("type") == "text"), {})
        success_text = str(success_payload.get("data", {}).get("text") or "").strip()
        if success_text and "封禁执行成功" in success_text:
            return {
                "success": True,
                "message": success_text,
                "ips": filtered_ips,
                "payloads": payloads,
            }
        if payloads and payloads[0].get("type") == "form_card":
            raise ValueError("封禁参数缺失，未能下发。请补充设备/时长后重试。")
        raise ValueError(success_text or "封禁执行失败，请检查联动设备状态与接口权限。")

    def preview_block_targets(
        self,
        session: Session,
        *,
        session_id: str,
        ips: list[str],
        block_type: str = "SRC_IP",
    ) -> dict[str, Any]:
        _ = session_id
        _ = block_type
        cleaned_ips: list[str] = []
        for raw in ips or []:
            ip = _parse_ipv4(raw)
            if ip and ip not in cleaned_ips:
                cleaned_ips.append(ip)
        if not cleaned_ips:
            raise ValueError("未提供合法的 IPv4 目标。")

        protected_ips, protected_cidrs = self._load_protected_ip_filters(session)
        filtered_ips = [ip for ip in cleaned_ips if not self._is_protected_ip(ip, protected_ips, protected_cidrs)]
        skipped_ips = [ip for ip in cleaned_ips if ip not in filtered_ips]
        if not filtered_ips:
            raise ValueError("目标 IP 均命中“默认受保护基础组件/安全防线”规则。")

        credential = session.exec(select(XDRCredential).order_by(XDRCredential.id.desc())).first()
        requester = get_requester_from_credential(credential)

        device_resp = requester.request("POST", "/api/xdr/v1/device/blockdevice/list", json_body={"type": ["AF"]})
        raw_devices = device_resp.get("data", {}).get("item", []) if device_resp.get("code") == "Success" else []
        online_devices = [d for d in raw_devices if d.get("deviceStatus") == "online"]
        device_options = [
            {
                "device_id": str(d.get("deviceId") or ""),
                "device_name": str(d.get("deviceName") or "-"),
                "device_type": str(d.get("deviceType") or "-"),
                "device_version": str(d.get("deviceVersion") or "-"),
            }
            for d in online_devices
            if d.get("deviceId")
        ]

        intel_rows: list[dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=6) as executor:
            future_map = {executor.submit(self._query_intel, ip): ip for ip in filtered_ips}
            for fut in as_completed(future_map):
                ip = future_map[fut]
                try:
                    raw_intel = fut.result()
                except Exception:
                    raw_intel = {"ip": ip, "severity": "unknown", "confidence": 0, "tags": [], "source": "local_fallback"}
                localized = self._localize_intel_row(raw_intel if isinstance(raw_intel, dict) else {"ip": ip})
                confidence_num = _to_int(raw_intel.get("confidence"), 0)
                tags = localized.get("tags") or []
                intel_rows.append(
                    {
                        "ip": ip,
                        "severity": localized.get("severity", "未知"),
                        "confidence": localized.get("confidence", "0%"),
                        "tags": ",".join(tags),
                        "source": localized.get("source", "未知"),
                        "suggestion": self._recommend_disposition(
                            localized.get("severity", "未知"),
                            confidence_num,
                            tags if isinstance(tags, list) else [],
                        ),
                        "reputation": str(raw_intel.get("reputation") or "unknown"),
                        "message": str(raw_intel.get("message") or ""),
                    }
                )
        intel_rows.sort(key=lambda row: filtered_ips.index(row["ip"]) if row["ip"] in filtered_ips else 9999)

        normalized_type = str(block_type or "SRC_IP").strip().upper()
        if normalized_type not in {"SRC_IP", "DST_IP"}:
            normalized_type = "SRC_IP"
        return {
            "session_id": session_id,
            "block_type": normalized_type,
            "ips": filtered_ips,
            "skipped_ips": skipped_ips,
            "device_options": device_options,
            "intel_rows": intel_rows,
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
            if isinstance(normalized.get("ips"), str):
                normalized["ips"] = [
                    token.strip()
                    for token in re.split(r"[,\s，]+", normalized["ips"])
                    if token and token.strip()
                ]
            if isinstance(normalized.get("ips"), list):
                normalized["ips"] = _dedup_keep_order(
                    [str(token).strip() for token in normalized["ips"] if str(token).strip()]
                )

        if template_id == "threat_hunting":
            normalized["window_days"] = max(1, min(180, _to_int(normalized.get("window_days"), 90)))
            normalized["max_scan"] = max(200, min(10000, _to_int(normalized.get("max_scan"), 10000)))
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
            has_ips = bool(params.get("ips"))
            mode = params.get("mode", "analyze")
            if mode == "analyze" and not (has_uuid or has_uuid_list or has_index):
                raise ValueError("alert_triage 缺少 incident_uuid 或 event_index 参数。")
            if mode == "block_ip" and not (has_ip or has_ips or has_uuid or has_uuid_list or has_index):
                raise ValueError("alert_triage(block_ip) 缺少 ip/ips 或事件定位参数。")
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

        session_id = str(runtime_context.get("session_id") or "").strip()
        if not session_id:
            return
        summary = str(result_payload.get("summary") or "").strip()
        context_manager.update_params(
            session_id,
            {
                "last_playbook_run_id": run_id,
                "last_playbook_template": runtime_context.get("template_id"),
                "last_playbook_summary": summary,
                "last_playbook_target_ips": self._extract_next_action_ips(result_payload),
            },
        )

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
    def _localize_intel_tags(tags: Any) -> list[str]:
        if not isinstance(tags, list):
            return []
        localized: list[str] = []
        for tag in tags:
            text = str(tag or "").strip()
            if not text:
                continue
            localized.append(INTEL_TAG_CN.get(text.lower(), text))
        return localized or ["未知"]

    def _localize_intel_row(self, row: dict[str, Any]) -> dict[str, Any]:
        severity_raw = str(row.get("severity") or "unknown").lower()
        source_raw = str(row.get("source") or "local_fallback").lower()
        confidence = _to_int(row.get("confidence"), 0)
        return {
            **row,
            "severity": INTEL_SEVERITY_CN.get(severity_raw, severity_raw or "未知"),
            "confidence": f"{max(0, min(100, confidence))}%",
            "tags": self._localize_intel_tags(row.get("tags")),
            "source": INTEL_SOURCE_CN.get(source_raw, source_raw or "未知"),
        }

    def _build_log_trend_series(
        self,
        requester: APIRequester,
        *,
        start_ts: int,
        end_ts: int,
        buckets: int = 12,
    ) -> tuple[list[str], list[int]]:
        bucket_count = max(4, min(24, _to_int(buckets, 12)))
        window = max(1, end_ts - start_ts)
        bucket_size = max(1, window // bucket_count)
        labels: list[str] = []
        values: list[int] = []
        for idx in range(bucket_count):
            seg_start = start_ts + idx * bucket_size
            seg_end = end_ts if idx == bucket_count - 1 else min(end_ts, seg_start + bucket_size)
            counted = self._count_logs(requester, start_ts=seg_start, end_ts=seg_end)
            slot = datetime.fromtimestamp(seg_end)
            labels.append(slot.strftime("%m-%d %H:%M"))
            values.append(max(0, _to_int(counted.get("total"), 0)))
        return labels, values

    @staticmethod
    def _normalize_event_row(item: dict[str, Any], index: int = 0) -> dict[str, Any]:
        severity_code = _to_int(_pick(item, "incidentSeverity", "severity"), -1)
        deal_status_code = _to_int(_pick(item, "dealStatus", "status"), -1)
        uu_id = _pick(item, "uuId", "uuid", "incidentId", default="")
        src_ip = _pick(item, "srcIp", "sourceIp", default="-")
        dst_ip = _pick(item, "dstIp", "destIp", "destinationIp", default="-")
        src_ips = _pick(item, "srcIps", default=[])
        dst_ips = _pick(item, "dstIps", default=[])
        src_ip_desc = _pick(item, "srcIpDesc", default=[])
        dst_ip_desc = _pick(item, "dstIpDesc", default=[])
        return {
            "index": index,
            "uuId": uu_id,
            "name": _pick(item, "name", "incidentName", "title", default="未知事件"),
            "incidentSeverity": SEVERITY_LABEL.get(severity_code, str(severity_code)),
            "dealStatus": DEAL_STATUS_LABEL.get(deal_status_code, str(deal_status_code)),
            "hostIp": _pick(item, "hostIp", "assetIp", "srcIp", default="-"),
            "srcIp": src_ip,
            "dstIp": dst_ip,
            "srcIps": src_ips if isinstance(src_ips, list) else [],
            "dstIps": dst_ips if isinstance(dst_ips, list) else [],
            "srcIpDesc": src_ip_desc if isinstance(src_ip_desc, list) else [],
            "dstIpDesc": dst_ip_desc if isinstance(dst_ip_desc, list) else [],
            "description": _pick(item, "description", "desc", "detail", default=""),
            "endTime": _format_ts(_pick(item, "endTime", "latestTime", "occurTime", default=0)),
        }

    def _safe_llm_complete(
        self,
        prompt: str,
        *,
        system: str,
        fallback: str,
        hard_timeout_seconds: int = 45,
    ) -> str:
        # The provider timeout is best-effort and may still block for several minutes.
        # Guard playbook node latency with an outer hard timeout so long model calls
        # do not make the whole run appear "stuck" to the UI.
        def complete_once() -> str:
            with session_scope() as session:
                llm = LLMRouter(session)
                return llm.complete(prompt, system=system)

        executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="playbook-llm")
        future = executor.submit(complete_once)
        try:
            answer = future.result(timeout=max(5, _to_int(hard_timeout_seconds, 45)))
            if answer and answer.strip():
                return answer.strip()
        except FutureTimeoutError:
            future.cancel()
        except Exception:
            pass
        finally:
            executor.shutdown(wait=False, cancel_futures=True)
        return fallback

    @staticmethod
    def _emphasize_key_points(text: str) -> str:
        if not text:
            return ""
        keys = (
            "总体态势",
            "关键风险",
            "建议动作",
            "攻击真实性概率",
            "关键证据",
            "优先建议动作",
            "风险等级",
            "处置结论",
        )
        lines: list[str] = []
        for line in str(text).splitlines():
            stripped = line.lstrip()
            indent = line[: len(line) - len(stripped)]
            rewritten = stripped
            for key in keys:
                for sep in ("：", ":"):
                    prefix = f"{key}{sep}"
                    if rewritten.startswith(prefix):
                        rewritten = rewritten.replace(prefix, f"**{key}{sep}**", 1)
                        break
            if "建议立即封禁" in rewritten and "**建议立即封禁**" not in rewritten:
                rewritten = rewritten.replace("建议立即封禁", "**建议立即封禁**")
            lines.append(f"{indent}{rewritten}")
        return "\n".join(lines)

    @staticmethod
    def _extract_next_action_ips(result_payload: dict[str, Any]) -> list[str]:
        ips: list[str] = []
        for action in result_payload.get("next_actions", []) if isinstance(result_payload, dict) else []:
            if not isinstance(action, dict):
                continue
            params = action.get("params") if isinstance(action.get("params"), dict) else {}
            single = params.get("ip")
            if isinstance(single, str) and single.strip():
                ips.append(single.strip())
            for item in params.get("ips") or []:
                text = str(item).strip()
                if text:
                    ips.append(text)
        return _dedup_keep_order(ips)

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
                "pageSize": 200,
                "sort": "endTime:desc,severity:desc",
                "timeField": "endTime",
            }
            resp = requester.request("POST", "/api/xdr/v1/incidents/list", json_body=req)
            data = resp.get("data", {}) if resp.get("code") == "Success" else {}
            items = data.get("item", []) or []
            rows = [self._normalize_event_row(item, idx) for idx, item in enumerate(items, start=1)]
            total_count = _to_int(_pick(data, "total", "count", "totalCount"), len(rows))
            uuids = [row["uuId"] for row in rows if row.get("uuId")]
            if uuids:
                context_manager.store_index_mapping(runtime_context["session_id"], "events", uuids)
                context_manager.update_params(
                    runtime_context["session_id"],
                    {"last_event_uuid": uuids[0], "last_event_uuids": uuids},
                )
            return {
                "high_events": rows,
                "high_events_total": total_count,
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
            high_total = _to_int(node2.get("high_events_total"), len(node2.get("high_events", [])))
            fallback = (
                f"总体态势：过去24小时网络安全日志总量 {node1.get('log_total_24h', 0)}，"
                f"未处置高危事件 {high_total} 条。\n"
                "关键风险：已抽样高危事件证据，存在外部实体关联，需优先处理前3条告警。\n"
                "建议动作：先执行“深度研判前3条事件”，再对首个高风险IP进行90天活动轨迹分析。"
            )
            prompt = (
                "你是企业SOC值班专家，请根据输入生成“今日安全早报”，要求三段结构：总体态势、关键风险、建议动作。"
                f"\n日志总量: {node1.get('log_total_24h', 0)}"
                f"\n未处置高危事件总数: {high_total}"
                f"\n未处置高危事件样本: {json.dumps(node2.get('high_events', [])[:5], ensure_ascii=False)}"
                f"\n样本举证: {json.dumps(node3.get('sample_evidence', [])[:3], ensure_ascii=False)}"
            )
            briefing = self._safe_llm_complete(
                prompt,
                system="输出中文，结论化、可执行，避免泛化。",
                fallback=fallback,
            )
            accurate_overview = (
                f"总体态势：今日共产生安全日志 {node1.get('log_total_24h', 0)} 条，"
                f"未处置高危及严重级别安全事件 {high_total} 起。"
            )
            return {"briefing": briefing, "accurate_overview": accurate_overview}

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
            llm_summary = results.get("node_4_llm_briefing", {}).get("briefing", "早报生成完成。")
            accurate_overview = results.get("node_4_llm_briefing", {}).get("accurate_overview", "")
            summary = self._emphasize_key_points(
                f"{accurate_overview}\n{llm_summary}".strip() if accurate_overview else llm_summary
            )
            rows = node2.get("high_events", [])
            high_total = _to_int(node2.get("high_events_total"), len(rows))
            protected_ips, protected_cidrs = self._load_protected_ip_filters()
            block_targets = self._build_routine_block_targets(
                requester,
                rows,
                protected_ips=protected_ips,
                protected_cidrs=protected_cidrs,
            )
            labels, points = self._build_log_trend_series(
                requester,
                start_ts=_to_int(node1.get("startTimestamp"), to_ts(utc_now()) - 24 * 3600),
                end_ts=_to_int(node1.get("endTimestamp"), to_ts(utc_now())),
                buckets=12,
            )
            chart_option = {
                "tooltip": {"trigger": "axis"},
                "xAxis": {"type": "category", "data": labels},
                "yAxis": {"type": "value"},
                "series": [{"name": "日志总量", "type": "line", "smooth": True, "data": points}],
            }

            cards = [
                text_payload(summary, title="今日安全早报"),
                echarts_payload(
                    title="24h 日志总量趋势（按2小时统计）",
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
                text_payload(
                    f"24小时未处置高危/严重事件总数：**{high_total}**。表格展示最新样本明细。",
                    title="统计口径说明",
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
            if not first_ip and block_targets.get("source_ips"):
                first_ip = str(block_targets["source_ips"][0])

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
                "block_targets": block_targets,
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
                src_total = self._count_logs(
                    requester,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    extra_filters={"srcIps": [ip]},
                )["total"]
                dst_total = self._count_logs(
                    requester,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    extra_filters={"dstIps": [ip]},
                )["total"]
                src_high = self._count_logs(
                    requester,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    extra_filters={"srcIps": [ip], "severities": [3, 4]},
                )["total"]
                dst_high = self._count_logs(
                    requester,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    extra_filters={"dstIps": [ip], "severities": [3, 4]},
                )["total"]
                src_compromised = self._count_logs(
                    requester,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    extra_filters={"srcIps": [ip], "attackStates": [2, 3]},
                )["total"]
                dst_compromised = self._count_logs(
                    requester,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    extra_filters={"dstIps": [ip], "attackStates": [2, 3]},
                )["total"]
                total = src_total + dst_total
                high = src_high + dst_high
                compromised = src_compromised + dst_compromised
                score = high * 2 + compromised * 3
                return {
                    "ip": ip,
                    "src_total": src_total,
                    "dst_total": dst_total,
                    "total": total,
                    "src_high_risk": src_high,
                    "dst_high_risk": dst_high,
                    "high_risk": high,
                    "src_compromised": src_compromised,
                    "dst_compromised": dst_compromised,
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
            summary = self._emphasize_key_points(
                results.get("node_5_llm_triage_summary", {}).get("summary", "研判已完成。")
            )
            intel_rows = results.get("node_3_external_intel", {}).get("intel_rows", [])
            localized_intel_rows = [self._localize_intel_row(row) for row in intel_rows]
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
                        {"key": "src_total", "label": "源总访问"},
                        {"key": "dst_total", "label": "目的总访问"},
                        {"key": "total", "label": "总访问量"},
                        {"key": "src_high_risk", "label": "源高危"},
                        {"key": "dst_high_risk", "label": "目的高危"},
                        {"key": "high_risk", "label": "高危访问量"},
                        {"key": "src_compromised", "label": "源成功/失陷"},
                        {"key": "dst_compromised", "label": "目的成功/失陷"},
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
                        {"key": "severity", "label": "威胁等级"},
                        {"key": "tags", "label": "威胁标签"},
                        {"key": "confidence", "label": "置信度"},
                        {"key": "source", "label": "情报来源"},
                    ],
                    rows=localized_intel_rows,
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
            if not target_ip and localized_intel_rows:
                target_ip = localized_intel_rows[0].get("ip")

            next_actions: list[dict[str, Any]] = []
            candidate_ips = _dedup_keep_order(
                [
                    row.get("ip")
                    for row in impact_rows + localized_intel_rows
                    if isinstance(row.get("ip"), str) and IPV4_PATTERN.match(row.get("ip"))
                ]
            )[:3]
            if not candidate_ips and isinstance(target_ip, str) and IPV4_PATTERN.match(target_ip):
                candidate_ips = [target_ip]
            if candidate_ips:
                cards.append(
                    text_payload(
                        "本次下一步动作涉及 IP："
                        + "、".join(f"`{ip}`" for ip in candidate_ips)
                        + "。请按下方动作逐项执行。",
                        title="下一步动作目标IP",
                    )
                )

            for ip in candidate_ips:
                next_actions.append(
                    {
                        "id": f"triage_block_{ip.replace('.', '_')}",
                        "label": f"是否进行IP {ip}进行封禁（进入审批）",
                        "template_id": "alert_triage",
                        "params": {
                            "mode": "block_ip",
                            "ip": ip,
                            "session_id": runtime_context["session_id"],
                        },
                        "style": "danger",
                    }
                )
                next_actions.append(
                    {
                        "id": f"triage_hunt_{ip.replace('.', '_')}",
                        "label": f"生成IP {ip} 的90天活动轨迹",
                        "template_id": "threat_hunting",
                        "params": {"ip": ip},
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
            candidate_ips = params.get("ips")
            if isinstance(candidate_ips, list):
                resolved = _dedup_keep_order(
                    [
                        str(item).strip()
                        for item in candidate_ips
                        if isinstance(item, str) and IPV4_PATTERN.match(str(item).strip())
                    ]
                )
                if resolved:
                    return {"target_ips": resolved}
            candidate_ip = params.get("ip")
            if isinstance(candidate_ip, str) and IPV4_PATTERN.match(candidate_ip):
                return {"target_ips": [candidate_ip]}

            uuids = self._resolve_incident_uuids(params, runtime_context["session_id"])
            resolved_from_events: list[str] = []
            for uid in uuids:
                resp = requester.request("GET", f"/api/xdr/v1/incidents/{uid}/entities/ip")
                entities, _ = extract_entity_items_from_response(resp)
                for entity in entities:
                    ip = entity.get("ip")
                    if isinstance(ip, str) and IPV4_PATTERN.match(ip):
                        resolved_from_events.append(ip)
            resolved_from_events = _dedup_keep_order(resolved_from_events)
            if resolved_from_events:
                return {"target_ips": resolved_from_events[:10], "incident_uuids": uuids}
            raise ValueError("未能解析待封禁IP，请补充 ip/ips 参数。")

        def node_2_build_block_approval(ctx: dict[str, Any]) -> dict[str, Any]:
            target_ips = ctx["nodes"]["node_1_resolve_target_ip"].get("target_ips", [])
            if not target_ips:
                raise ValueError("待封禁IP列表为空。")
            block_skill = skills.get("block_action")
            if not block_skill:
                raise ValueError("系统未加载 block_action 技能。")

            payloads: list[dict[str, Any]] = []
            if len(target_ips) > 1:
                # 批量封禁先进入可编辑参数表单，便于用户按需删减 IP。
                payloads = block_skill.execute(
                    runtime_context["session_id"],
                    {
                        "views": target_ips,
                        "reason": "Playbook深挖建议批量封禁",
                    },
                    f"批量封禁 {','.join(target_ips)}",
                )
                context_manager.update_params(runtime_context["session_id"], {"last_playbook_target_ips": target_ips})
                return {"cards": payloads, "target_ips": target_ips}

            try:
                payloads = block_skill.execute(
                    runtime_context["session_id"],
                    {
                        "block_type": "SRC_IP",
                        "views": target_ips,
                        "time_type": "temporary",
                        "time_value": 24,
                        "time_unit": "h",
                        "reason": "Playbook深度研判建议封禁",
                        "confirm": False,
                    },
                    f"封禁 {','.join(target_ips)}",
                )
            except ConfirmationRequiredException as exc:
                token = f"pending-{runtime_context['session_id']}-block_action"
                pending_params = exc.action_payload.get("params", {"views": target_ips, "confirm": True})
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
            context_manager.update_params(runtime_context["session_id"], {"last_playbook_target_ips": target_ips})
            return {"cards": payloads, "target_ips": target_ips}

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
            ips = node2.get("target_ips") or []
            cards = node2.get("cards", [])
            if ips:
                if len(ips) == 1:
                    summary = f"已为 {ips[0]} 生成封禁审批卡，请确认后执行。"
                else:
                    summary = f"已为 {len(ips)} 个IP生成批量封禁审批卡，请确认后执行。"
            else:
                summary = "已生成封禁审批卡。"
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
        max_scan: int = 10000,
        page_size: int = 200,
        max_store_matches: int = 500,
        extra_filters: dict[str, Any] | None = None,
        require_ip_match: bool = True,
    ) -> dict[str, Any]:
        matched: list[dict[str, Any]] = []
        matched_total = 0
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
            req.update(extra_filters or {})
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
                if (not require_ip_match) or self._incident_match_ip(item, ip):
                    matched_total += 1
                    if len(matched) < max_store_matches:
                        matched.append(self._normalize_event_row(item, len(matched) + 1))
            if len(items) < page_size:
                break
            if scanned >= max_scan:
                truncated = True
                break
            page += 1

        return {
            "matched_events": matched,
            "matched_total": matched_total,
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

    @staticmethod
    def _extract_ipv4_values(value: Any) -> list[str]:
        if value is None:
            return []
        values = value if isinstance(value, list) else [value]
        result: list[str] = []
        for item in values:
            text = str(item or "")
            if not text:
                continue
            for token in re.findall(r"(?:\d{1,3}\.){3}\d{1,3}", text):
                parsed = _parse_ipv4(token)
                if parsed:
                    result.append(parsed)
        return _dedup_keep_order(result)

    @staticmethod
    def _infer_flow_direction(src_ips: list[str], dst_ips: list[str]) -> str:
        if not src_ips or not dst_ips:
            return ""
        src_private = _is_private_ipv4(src_ips[0])
        dst_private = _is_private_ipv4(dst_ips[0])
        if src_private and not dst_private:
            return "内部 -> 外部"
        if (not src_private) and dst_private:
            return "外部 -> 内部"
        if src_private and dst_private:
            return "内部 -> 内部"
        return "外部 -> 外部"

    @staticmethod
    def _direction_from_scan_side(scan_side: str, target_ip: str) -> str:
        side = str(scan_side or "")
        target_is_private = _is_private_ipv4(target_ip)
        if side == "源":
            return "内部 -> 外部" if target_is_private else "外部 -> 内部"
        if side == "目的":
            return "外部 -> 内部" if target_is_private else "内部 -> 外部"
        return "-"

    @classmethod
    def _resolve_hunting_direction(
        cls,
        *,
        target_ip: str,
        scan_side: str,
        src_values: Any,
        dst_values: Any,
    ) -> str:
        src_ips = cls._extract_ipv4_values(src_values)
        dst_ips = cls._extract_ipv4_values(dst_values)
        flow_direction = cls._infer_flow_direction(src_ips, dst_ips)
        if flow_direction:
            return flow_direction

        if target_ip in src_ips and target_ip not in dst_ips:
            return "内部 -> 外部" if _is_private_ipv4(target_ip) else "外部 -> 内部"
        if target_ip in dst_ips and target_ip not in src_ips:
            return "外部 -> 内部" if _is_private_ipv4(target_ip) else "内部 -> 外部"

        return cls._direction_from_scan_side(scan_side, target_ip)

    @staticmethod
    def _normalize_timeline_severity(value: Any) -> str:
        text = str(value or "").strip()
        if "严重" in text:
            return "严重"
        if "高危" in text or text == "高":
            return "高危"
        if "中危" in text or text == "中":
            return "中危"
        if "低危" in text or text == "低":
            return "低危"
        score = _to_int(value, -1)
        if score < 0:
            return "信息"
        if score <= 10:
            return "信息"
        if score <= 30:
            return "低危"
        if score <= 50:
            return "中危"
        if score <= 70:
            return "高危"
        return "严重"

    @staticmethod
    def _normalize_timeline_stage(stage_value: Any, alert_name: str = "") -> str:
        score = _to_int(stage_value, -1)
        if score == 20:
            return "侦察"
        if score in {30, 40}:
            return "利用"
        if score in {50, 60}:
            return "横向"
        if score in {70, 80}:
            return "结果"

        sample = f"{stage_value} {alert_name}".lower()
        if any(token in sample for token in ("扫描", "探测", "侦察", "recon")):
            return "侦察"
        if any(token in sample for token in ("利用", "攻击", "主机异常", "执行", "webshell", "rce")):
            return "利用"
        if any(token in sample for token in ("横向", "扩散", "shell", "c2", "cc", "控制", "通信")):
            return "横向"
        if any(token in sample for token in ("窃取", "外传", "泄露", "牟利", "impact", "结果")):
            return "结果"
        return "未知"

    @staticmethod
    def _timeline_attack_phase(stage_name: str) -> str:
        mapping = {
            "侦察": "ATT&CK Reconnaissance",
            "利用": "ATT&CK Initial Access / Execution",
            "横向": "ATT&CK Lateral Movement / Command and Control",
            "结果": "ATT&CK Exfiltration / Impact",
        }
        return mapping.get(stage_name, "ATT&CK Unknown")

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
            summary = self._emphasize_key_points(
                results.get("node_7_llm_asset_briefing", {}).get("briefing", "核心资产防线透视已完成。")
            )

            stats_rows = [
                {"direction": "入向（目标为资产）", "event_count": node1.get("count", 0), "log_count": node3.get("log_total", 0)},
                {"direction": "出向（源为资产）", "event_count": node2.get("count", 0), "log_count": node4.get("log_total", 0)},
            ]
            intel_rows = [self._localize_intel_row(row) for row in node6.get("intel_rows", [])]
            weekday_labels = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"]
            weekly_labels: list[str] = []
            weekly_values: list[int] = []
            now_dt = utc_now()
            for offset in range(6, -1, -1):
                day_start = (now_dt - timedelta(days=offset)).replace(hour=0, minute=0, second=0, microsecond=0)
                day_end = day_start + timedelta(days=1)
                src_high = self._count_logs(
                    requester,
                    start_ts=to_ts(day_start),
                    end_ts=to_ts(day_end),
                    extra_filters={"srcIps": [asset_ip], "severities": [3, 4]},
                )["total"]
                dst_high = self._count_logs(
                    requester,
                    start_ts=to_ts(day_start),
                    end_ts=to_ts(day_end),
                    extra_filters={"dstIps": [asset_ip], "severities": [3, 4]},
                )["total"]
                weekly_labels.append(weekday_labels[day_start.weekday()])
                weekly_values.append(src_high + dst_high)

            baseline = max(5, int(sum(weekly_values) / max(1, len(weekly_values)) * 1.35))
            peak_days = [
                weekly_labels[idx]
                for idx, value in enumerate(weekly_values)
                if value >= baseline
            ]
            chart_insight = (
                f"AI 透视结论：{'、'.join(peak_days) if peak_days else '近7天'}出现异常流量峰值，"
                f"建议优先审查核心资产 {asset_ip} 的横向扫描与暴露面策略。"
            )
            chart_option = {
                "tooltip": {"trigger": "axis"},
                "xAxis": {"type": "category", "data": weekly_labels},
                "yAxis": {"type": "value"},
                "series": [
                    {
                        "name": "双向高危流量",
                        "type": "bar",
                        "data": weekly_values,
                        "itemStyle": {"color": "#3f7df5"},
                        "markLine": {
                            "symbol": "none",
                            "lineStyle": {"type": "dashed", "color": "#ef4444"},
                            "label": {"formatter": "阈值告警基线"},
                            "data": [{"yAxis": baseline}],
                        },
                    }
                ],
            }
            cards = [
                text_payload(summary, title="核心资产态势结论"),
                echarts_payload(
                    title="流量威胁双向评估（近7天）",
                    option=chart_option,
                    summary=chart_insight,
                ),
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
                    "建议动作：优先对 Top 外部访问实体执行封禁审批；并对封禁前后关联高危告警进行人工复核。",
                    title="建议动作",
                ),
            ]

            next_actions: list[dict[str, Any]] = []
            batch_ips = [
                row.get("ip")
                for row in intel_rows[:5]
                if isinstance(row.get("ip"), str) and IPV4_PATTERN.match(str(row.get("ip")))
            ]
            batch_ips = _dedup_keep_order([str(ip) for ip in batch_ips if ip])
            if batch_ips:
                cards.append(
                    text_payload(
                        "下一步封禁建议涉及以下IP："
                        + "、".join(f"`{ip}`" for ip in batch_ips)
                        + "。点击下方动作后可在审批表单中按需删除不希望封禁的IP。",
                        title="批量封禁目标",
                    )
                )
                next_actions.append(
                    {
                        "id": "asset_guard_block_batch",
                        "label": f"是否批量封禁 Top 外部访问实体（{len(batch_ips)}个IP，进入审批）",
                        "template_id": "alert_triage",
                        "params": {
                            "mode": "block_ip",
                            "ips": batch_ips,
                            "session_id": runtime_context["session_id"],
                        },
                        "style": "danger",
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
            src_scan = self._scan_incidents_for_ip(
                requester,
                ip=target_ip,
                start_ts=start_ts,
                end_ts=end_ts,
                max_scan=params.get("max_scan", 10000),
                page_size=200,
                extra_filters={"srcIps": [target_ip]},
                require_ip_match=False,
            )
            dst_scan = self._scan_incidents_for_ip(
                requester,
                ip=target_ip,
                start_ts=start_ts,
                end_ts=end_ts,
                max_scan=params.get("max_scan", 10000),
                page_size=200,
                extra_filters={"dstIps": [target_ip]},
                require_ip_match=False,
            )
            merged: dict[str, dict[str, Any]] = {}

            def merge_rows(rows: list[dict[str, Any]], direction: str) -> None:
                for row in rows:
                    uid = str(row.get("uuId") or "")
                    key = uid or f"{direction}-{row.get('index', 0)}"
                    existing = merged.get(key)
                    if existing:
                        hits = existing.get("scan_hits")
                        if not isinstance(hits, list):
                            hits = [str(existing.get("direction") or "")]
                        if direction not in hits:
                            hits.append(direction)
                        merged_hits = _dedup_keep_order([item for item in hits if item])
                        existing["scan_hits"] = merged_hits
                        if len(merged_hits) > 1:
                            existing["direction"] = ""
                        continue
                    merged[key] = {**row, "direction": direction, "scan_hits": [direction]}

            merge_rows(src_scan.get("matched_events", []), "源")
            merge_rows(dst_scan.get("matched_events", []), "目的")
            merged_rows = list(merged.values())
            merged_rows.sort(key=lambda item: str(item.get("endTime") or ""), reverse=True)
            for idx, row in enumerate(merged_rows, start=1):
                row["index"] = idx

            uuids = [row["uuId"] for row in merged_rows if row.get("uuId")]
            if uuids:
                context_manager.store_index_mapping(runtime_context["session_id"], "events", uuids)
                context_manager.update_params(
                    runtime_context["session_id"],
                    {"last_event_uuid": uuids[0], "last_event_uuids": uuids, "last_entity_ip": target_ip},
                )
            return {
                "matched_events": merged_rows,
                "matched_total": _to_int(src_scan.get("matched_total"), 0) + _to_int(dst_scan.get("matched_total"), 0),
                "src_alert_total": _to_int(src_scan.get("matched_total"), 0),
                "dst_alert_total": _to_int(dst_scan.get("matched_total"), 0),
                "scanned": _to_int(src_scan.get("scanned"), 0) + _to_int(dst_scan.get("scanned"), 0),
                "pages": _to_int(src_scan.get("pages"), 0) + _to_int(dst_scan.get("pages"), 0),
                "truncated": bool(src_scan.get("truncated") or dst_scan.get("truncated")),
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
                timeline_items = (
                    proof_data.get("alertTimeLine", [])
                    or proof_data.get("incidentTimeLines", [])
                    or []
                )
                timeline_events: list[dict[str, Any]] = []
                incident_direction = "-"
                for timeline in timeline_items[:30]:
                    if not isinstance(timeline, dict):
                        continue
                    alert_name = str(_pick(timeline, "name", "threatSubTypeDesc", default="未知告警"))
                    stage_name = self._normalize_timeline_stage(timeline.get("stage"), alert_name=alert_name)
                    proof_row = timeline.get("proof") if isinstance(timeline.get("proof"), dict) else {}
                    direction_from_timeline = self._resolve_hunting_direction(
                        target_ip=target_ip,
                        scan_side=str(row.get("direction") or ""),
                        src_values=[
                            timeline.get("srcIp"),
                            timeline.get("srcIps"),
                            timeline.get("srcIpDesc"),
                            proof_row.get("srcIp"),
                            proof_row.get("srcIps"),
                            proof_row.get("srcIpDesc"),
                        ],
                        dst_values=[
                            timeline.get("dstIp"),
                            timeline.get("dstIps"),
                            timeline.get("dstIpDesc"),
                            proof_row.get("dstIp"),
                            proof_row.get("dstIps"),
                            proof_row.get("dstIpDesc"),
                        ],
                    )
                    if incident_direction == "-" and direction_from_timeline != "-":
                        incident_direction = direction_from_timeline
                    timeline_events.append(
                        {
                            "uuId": uid,
                            "alert_id": str(_pick(timeline, "alertId", default=uid) or uid),
                            "name": alert_name,
                            "stage_name": stage_name,
                            "attack_phase": self._timeline_attack_phase(stage_name),
                            "last_time": _format_ts(_pick(timeline, "lastTime", default=0)),
                            "last_time_ts": _to_int(_pick(timeline, "lastTime", default=0), 0),
                            "severity": self._normalize_timeline_severity(timeline.get("severity")),
                            "stage_raw": timeline.get("stage"),
                        }
                    )
                return {
                    "uuId": uid,
                    "timeline_count": len(proof_data.get("alertTimeLine", []) or []),
                    "risk_tags": proof_data.get("riskTag", []),
                    "entity_ips": _dedup_keep_order(entity_ips),
                    "ai_result": proof_data.get("gptResultDescription", "暂无"),
                    "timeline_events": timeline_events,
                    "incident_direction": incident_direction,
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

            src_alert_total = _to_int(ctx["nodes"]["node_2_event_scan_paginated"].get("src_alert_total"), 0)
            dst_alert_total = _to_int(ctx["nodes"]["node_2_event_scan_paginated"].get("dst_alert_total"), 0)
            alert_total = src_alert_total + dst_alert_total
            action_decision = "建议继续观察"
            if src_alert_total > 0 or (severity in {"high", "critical"} and alert_total > 0) or alert_total >= 20:
                action_decision = "建议立即封禁"

            fallback = (
                f"风险等级：{risk_level}\n"
                "攻击故事线：\n"
                "1) 侦察：目标IP出现对内通信痕迹。\n"
                "2) 利用：命中可疑告警并关联外部情报标签。\n"
                "3) 横向：在告警时间线上出现多阶段活动痕迹。\n"
                "4) 结果：基于告警与情报综合判断给出处置结论。\n"
                f"处置结论：{action_decision}。"
            )
            prompt = (
                "请按“侦察->利用->横向->结果”输出攻击故事线，每段附关键证据。"
                "最后必须给出一行“处置结论：建议立即封禁”或“处置结论：建议继续观察”。"
                f"\n目标IP: {target_ip}"
                f"\n画像: {json.dumps(profile, ensure_ascii=False)}"
                f"\n命中告警: {json.dumps(matched[:10], ensure_ascii=False)}"
                f"\n举证: {json.dumps(evidence[:10], ensure_ascii=False)}"
                f"\n内部活动: {json.dumps(activity, ensure_ascii=False)}"
                f"\n源IP命中告警数: {src_alert_total}"
                f"\n目的IP命中告警数: {dst_alert_total}"
                f"\n规则建议: {action_decision}"
            )
            story = self._safe_llm_complete(
                prompt,
                system="你是溯源分析专家，输出结构化叙事。",
                fallback=fallback,
            )
            return {"story": story, "risk_level": risk_level, "action_decision": action_decision}

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
            matched_total = _to_int(scan_result.get("matched_total"), len(matched_rows))
            src_alert_total = _to_int(scan_result.get("src_alert_total"), 0)
            dst_alert_total = _to_int(scan_result.get("dst_alert_total"), 0)
            story_result = results.get("node_5_llm_timeline_story", {})
            evidence_items = results.get("node_3_evidence_enrichment_parallel", {}).get("evidence_items", [])
            evidence_errors = results.get("node_3_evidence_enrichment_parallel", {}).get("errors", [])
            summary = (
                f"目标IP {target_ip} 告警轨迹分析完成：命中 {matched_total} 条告警"
                f"（源IP告警 {src_alert_total} / 目的IP告警 {dst_alert_total}），"
                f"扫描 {scan_result.get('scanned', 0)} 条（单向上限 {params.get('max_scan', 10000)}），"
                f"风险等级 {story_result.get('risk_level', '中')}。"
            )
            decision_text = str(story_result.get("action_decision") or "建议继续观察")
            decision_md = self._emphasize_key_points(f"处置结论：{decision_text}。")
            display_limit = 10
            display_rows_raw = matched_rows[:display_limit]
            direction_by_uuid: dict[str, str] = {}
            for evidence in evidence_items:
                if not isinstance(evidence, dict):
                    continue
                uid = str(evidence.get("uuId") or "").strip()
                resolved = str(evidence.get("incident_direction") or "").strip()
                if uid and resolved and resolved != "-":
                    direction_by_uuid[uid] = resolved

            display_rows: list[dict[str, Any]] = []
            alert_table_rows: list[dict[str, Any]] = []
            for row in display_rows_raw:
                uid = str(row.get("uuId") or "-")
                resolved_direction = direction_by_uuid.get(uid) or self._resolve_hunting_direction(
                    target_ip=target_ip,
                    scan_side=str(row.get("direction") or ""),
                    src_values=[row.get("srcIp"), row.get("srcIps"), row.get("srcIpDesc")],
                    dst_values=[row.get("dstIp"), row.get("dstIps"), row.get("dstIpDesc")],
                )
                display_row = {**row, "direction": resolved_direction, "threatId": uid}
                display_rows.append(display_row)
                alert_table_rows.append(
                    {
                        "index": row.get("index"),
                        "recent_time": row.get("endTime", "-"),
                        "direction": resolved_direction,
                        "alert_name": row.get("name", "-"),
                        "threat_id": uid,
                        "alert_id": uid,
                        "severity": row.get("incidentSeverity", "-"),
                        "status": row.get("dealStatus", "-"),
                    }
                )

            stage_order = [
                {"name": "侦察", "title": "初步侦察", "card_title": "扫描与探测脆弱点"},
                {"name": "利用", "title": "漏洞利用", "card_title": "漏洞利用与执行"},
                {"name": "横向", "title": "横向与控制", "card_title": "建立控制与横向移动"},
                {"name": "结果", "title": "结果", "card_title": "影响与结果评估"},
            ]
            events_by_stage: dict[str, list[dict[str, Any]]] = {item["name"]: [] for item in stage_order}
            evidence_by_uuid: dict[str, dict[str, Any]] = {
                str(item.get("uuId") or ""): item for item in evidence_items if isinstance(item, dict)
            }
            seen_timeline_keys: set[tuple[str, str, int]] = set()
            for evidence in evidence_items:
                if not isinstance(evidence, dict):
                    continue
                for timeline in evidence.get("timeline_events", []) or []:
                    if not isinstance(timeline, dict):
                        continue
                    stage_name = str(timeline.get("stage_name") or "未知")
                    if stage_name not in events_by_stage:
                        continue
                    timeline_key = (
                        str(timeline.get("alert_id") or ""),
                        str(timeline.get("uuId") or ""),
                        _to_int(timeline.get("last_time_ts"), 0),
                    )
                    if timeline_key in seen_timeline_keys:
                        continue
                    seen_timeline_keys.add(timeline_key)
                    events_by_stage[stage_name].append(timeline)
            for stage_name in events_by_stage:
                events_by_stage[stage_name].sort(
                    key=lambda item: _to_int(item.get("last_time_ts"), 0),
                    reverse=True,
                )

            kill_chain_stages: list[dict[str, Any]] = []
            stage_evidence_cards: list[dict[str, Any]] = []
            for stage in stage_order:
                stage_name = stage["name"]
                stage_events = events_by_stage.get(stage_name, [])
                observed = bool(stage_events)
                stage_time = stage_events[-1].get("last_time", "-") if observed else "未观测到"
                highlight = stage_events[0].get("name", "-") if observed else "未观测到"
                kill_chain_stages.append(
                    {
                        "stage_name": stage_name,
                        "title": stage["title"],
                        "attack_phase": self._timeline_attack_phase(stage_name),
                        "observed": observed,
                        "time": stage_time,
                        "highlight": highlight,
                        "event_count": len(stage_events),
                    }
                )

                stage_alert_ids = _dedup_keep_order(
                    [str(item.get("alert_id") or "").strip() for item in stage_events if str(item.get("alert_id") or "").strip()]
                )[:6]
                stage_uuids = _dedup_keep_order(
                    [str(item.get("uuId") or "").strip() for item in stage_events if str(item.get("uuId") or "").strip()]
                )
                stage_tags: list[str] = []
                stage_entities: list[str] = []
                for uid in stage_uuids:
                    evidence_row = evidence_by_uuid.get(uid) or {}
                    raw_tags = evidence_row.get("risk_tags")
                    if isinstance(raw_tags, list):
                        for tag in raw_tags:
                            text = str(tag or "").strip()
                            if text:
                                stage_tags.append(text)
                    elif raw_tags:
                        text = str(raw_tags).strip()
                        if text:
                            stage_tags.append(text)
                    for entity_ip in evidence_row.get("entity_ips", []) or []:
                        ip_text = str(entity_ip or "").strip()
                        if ip_text:
                            stage_entities.append(ip_text)
                stage_tags = _dedup_keep_order(stage_tags)[:3]
                stage_entities = _dedup_keep_order(stage_entities)[:2]

                if observed:
                    latest_time = stage_events[0].get("last_time", "-")
                    sample_names = _dedup_keep_order(
                        [str(item.get("name") or "").strip() for item in stage_events if str(item.get("name") or "").strip()]
                    )[:2]
                    sample_text = "、".join(sample_names) if sample_names else "相关攻击行为"
                    summary_text = (
                        f"该阶段命中 {len(stage_events)} 条关联告警，最近发生于 {latest_time}。"
                        f"主要行为：{sample_text}。"
                    )
                else:
                    summary_text = "当前窗口未观测到该阶段的高置信度告警证据。"

                stage_evidence_cards.append(
                    {
                        "stage_name": stage_name,
                        "stage_badge": f"{stage_name}阶段",
                        "title": stage["card_title"],
                        "attack_phase": self._timeline_attack_phase(stage_name),
                        "summary": summary_text,
                        "observed": observed,
                        "alert_ids": stage_alert_ids,
                        "tags": stage_tags,
                        "entities": stage_entities,
                    }
                )

            risk_level = str(story_result.get("risk_level") or "中")
            risk_level_map = {
                "低": {"label": "低风险 (Low)", "detail": "未观察到持续性高危攻击行为"},
                "中": {"label": "中风险 (Medium)", "detail": "存在持续攻击迹象，需要持续关注"},
                "高": {"label": "高风险 (High)", "detail": "已观察到实质性攻击行为，建议尽快处置"},
            }
            risk_profile = risk_level_map.get(risk_level, risk_level_map["中"])
            action_hint = "建议立即执行微隔离/封禁" if "立即封禁" in decision_text else "建议持续观察并保持监测"
            target_type = "内部终端" if _is_private_ipv4(target_ip) else "外部IP"

            cards = [
                text_payload(self._emphasize_key_points(summary), title="攻击者活动轨迹结论"),
                text_payload(decision_md, title="处置结论"),
                table_payload(
                    title="命中告警清单（目标IP源/目的）",
                    columns=[
                        {"key": "index", "label": "序号"},
                        {"key": "direction", "label": "方向"},
                        {"key": "endTime", "label": "时间"},
                        {"key": "threatId", "label": "威胁ID"},
                        {"key": "name", "label": "告警名"},
                        {"key": "incidentSeverity", "label": "等级"},
                        {"key": "dealStatus", "label": "状态"},
                    ],
                    rows=display_rows,
                    namespace="hunting_events",
                ),
                text_payload(self._emphasize_key_points(story_result.get("story", "暂无时间线叙事。")), title="攻击故事线"),
            ]
            if matched_total > len(display_rows):
                cards.append(
                    text_payload(
                        f"命中告警共 {matched_total} 条，当前表格仅展示前 {len(display_rows)} 条以保证可读性与导出稳定性。",
                        title="展示说明",
                    )
                )
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
                    "label": f"执行IP {target_ip}封禁（进入审批）",
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
                "threat_view": {
                    "target_ip": target_ip,
                    "target_type": target_type,
                    "window_days": _to_int(params.get("window_days"), 90),
                    "stats": {
                        "matched_total": matched_total,
                        "src_alert_total": src_alert_total,
                        "dst_alert_total": dst_alert_total,
                        "scanned": _to_int(scan_result.get("scanned"), 0),
                        "max_scan": _to_int(params.get("max_scan"), 10000),
                    },
                    "risk": {
                        "level": risk_level,
                        "level_label": risk_profile["label"],
                        "level_detail": risk_profile["detail"],
                        "action_decision": decision_text,
                        "action_hint": action_hint,
                    },
                    "kill_chain_stages": kill_chain_stages,
                    "stage_evidence_cards": stage_evidence_cards,
                    "alert_table_total": matched_total,
                    "alert_table_rows": alert_table_rows,
                    "story": story_result.get("story", ""),
                },
                "evidence_sources": [
                    "POST /api/xdr/v1/incidents/list (源/目的IP双向过滤)",
                    "GET /api/xdr/v1/incidents/{uuid}/proof",
                    "GET /api/xdr/v1/incidents/{uuid}/entities/ip",
                    "POST /api/xdr/v1/analysislog/networksecurity/count",
                ],
            }

        return nodes, finalizer


playbook_service = PlaybookService()
