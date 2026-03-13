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
ALERT_DEAL_STATUS_LABEL = {1: "待处置", 2: "处置中", 3: "处置完成"}
ALERT_ACCESS_DIRECTION_LABEL = {0: "无", 1: "内对外", 2: "外对内", 3: "内对内"}
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
            normalized["window_days"] = 30
            normalized["max_scan"] = max(200, min(10000, _to_int(normalized.get("max_scan"), 10000)))
            normalized["evidence_limit"] = max(1, min(20, _to_int(normalized.get("evidence_limit"), 20)))
            normalized["adaptive_port_topn"] = max(1, min(20, _to_int(normalized.get("adaptive_port_topn"), 5)))
            raw_ports = normalized.get("pivot_ports")
            if isinstance(raw_ports, str):
                raw_ports = [token.strip() for token in re.split(r"[,\s，]+", raw_ports) if token.strip()]
            if isinstance(raw_ports, list):
                parsed_ports = [port for port in (_to_int(item, -1) for item in raw_ports) if 1 <= port <= 65535]
                normalized["pivot_ports"] = _dedup_keep_order(parsed_ports) or [445, 139, 3389, 22, 5985, 5986, 135]
            else:
                normalized["pivot_ports"] = [445, 139, 3389, 22, 5985, 5986, 135]
            src_only_first_raw = normalized.get("src_only_first")
            if isinstance(src_only_first_raw, bool):
                normalized["src_only_first"] = src_only_first_raw
            elif isinstance(src_only_first_raw, str):
                normalized["src_only_first"] = src_only_first_raw.strip().lower() not in {"0", "false", "no", "off"}
            else:
                normalized["src_only_first"] = True
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
                "node_3_proof_enrich": {"status": "Pending", "depends_on": ["node_2_entity_profile"]},
                "node_4_external_intel": {"status": "Pending", "depends_on": ["node_3_proof_enrich"]},
                "node_5_internal_impact_count_parallel": {
                    "status": "Pending",
                    "depends_on": ["node_4_external_intel"],
                },
                "node_6_asset_profile": {
                    "status": "Pending",
                    "depends_on": ["node_5_internal_impact_count_parallel"],
                },
                "node_7_llm_triage_summary": {
                    "status": "Pending",
                    "depends_on": ["node_6_asset_profile"],
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
            "node_1_attack_surface_recon": {"status": "Pending", "depends_on": []},
            "node_2_breakthrough_identify": {"status": "Pending", "depends_on": ["node_1_attack_surface_recon"]},
            "node_3_victim_lateral_movement": {
                "status": "Pending",
                "depends_on": ["node_2_breakthrough_identify"],
            },
            "node_4_outbound_behavior_analysis": {
                "status": "Pending",
                "depends_on": ["node_3_victim_lateral_movement"],
            },
            "node_5_kill_chain_finalize": {
                "status": "Pending",
                "depends_on": ["node_4_outbound_behavior_analysis"],
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

    @staticmethod
    def _normalize_alert_severity(value: Any) -> str:
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
        if score in SEVERITY_LABEL:
            return SEVERITY_LABEL.get(score, "信息")
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
    def _normalize_alert_deal_status(value: Any) -> str:
        code = _to_int(value, -1)
        if code in ALERT_DEAL_STATUS_LABEL:
            return ALERT_DEAL_STATUS_LABEL[code]
        if code in DEAL_STATUS_LABEL:
            return DEAL_STATUS_LABEL[code]
        text = str(value or "").strip()
        return text or "-"

    @staticmethod
    def _normalize_access_direction(value: Any) -> str:
        code = _to_int(value, -1)
        if code in ALERT_ACCESS_DIRECTION_LABEL:
            return ALERT_ACCESS_DIRECTION_LABEL[code]
        text = str(value or "").strip()
        aliases = {
            "internal_to_external": "内对外",
            "external_to_internal": "外对内",
            "internal_to_internal": "内对内",
            "none": "无",
        }
        return aliases.get(text.lower(), text or "-")

    def _normalize_alert_row(self, item: dict[str, Any], index: int = 0) -> dict[str, Any]:
        uu_id = _pick(item, "uuId", "alertId", "id", default="")
        last_time = _pick(item, "lastTime", "latestTime", "occurTime", "endTime", default=0)
        src_port = _pick(item, "srcPort", default=[])
        dst_port = _pick(item, "dstPort", default=[])
        risk_tag = _pick(item, "riskTag", default=[])
        url = _pick(item, "url", default=[])
        domain = _pick(item, "domain", default=[])
        file_md5 = _pick(item, "fileMd5", default=[])
        return {
            "index": index,
            "uuId": uu_id,
            "name": _pick(item, "name", "alertName", default="未知告警"),
            "incidentSeverity": self._normalize_alert_severity(_pick(item, "severity", "incidentSeverity")),
            "dealStatus": self._normalize_alert_deal_status(_pick(item, "alertDealStatus", "dealStatus", "status")),
            "direction": self._normalize_access_direction(_pick(item, "direction", "accessDirection")),
            "srcIp": _pick(item, "srcIp", "sourceIp", default=[]),
            "dstIp": _pick(item, "dstIp", "destIp", "destinationIp", default=[]),
            "srcPort": src_port if isinstance(src_port, list) else [src_port] if src_port not in (None, "") else [],
            "dstPort": dst_port if isinstance(dst_port, list) else [dst_port] if dst_port not in (None, "") else [],
            "url": url if isinstance(url, list) else [url] if url not in (None, "") else [],
            "domain": domain if isinstance(domain, list) else [domain] if domain not in (None, "") else [],
            "fileMd5": file_md5 if isinstance(file_md5, list) else [file_md5] if file_md5 not in (None, "") else [],
            "stage": _pick(item, "stage", default=0),
            "attackState": _pick(item, "attackState", default=-1),
            "riskTag": risk_tag if isinstance(risk_tag, list) else [risk_tag] if risk_tag not in (None, "") else [],
            "threatSubTypeDesc": _pick(item, "threatSubTypeDesc", default=""),
            "traceBackId": _pick(item, "traceBackId", default=""),
            "hostIp": _pick(item, "hostIp", "assetIp", default="-"),
            "endTime": _format_ts(last_time),
            "lastTimeTs": _to_int(last_time, 0),
        }

    @staticmethod
    def _extract_response_items(response: dict[str, Any]) -> list[dict[str, Any]]:
        if not isinstance(response, dict):
            return []
        data = response.get("data")
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            for key in ("item", "items", "rows", "list"):
                value = data.get(key)
                if isinstance(value, list):
                    return [item for item in value if isinstance(item, dict)]
            if any(key in data for key in ("uuId", "ip", "assetId", "assetName")):
                return [data]
        return []

    @staticmethod
    def _extract_proof_timeline_items(proof_data: dict[str, Any]) -> list[dict[str, Any]]:
        if not isinstance(proof_data, dict):
            return []
        items: list[dict[str, Any]] = []
        for key in ("alertTimeLine", "alertTimeline", "incidentTimeLines", "incidentTimeline"):
            value = proof_data.get(key)
            if isinstance(value, list):
                items.extend([item for item in value if isinstance(item, dict)])
        return items

    @staticmethod
    def _normalize_asset_row(item: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(item, dict):
            return {}
        tags = item.get("tags") if isinstance(item.get("tags"), list) else []
        users = item.get("user") if isinstance(item.get("user"), list) else []
        source_device = item.get("sourceDevice") if isinstance(item.get("sourceDevice"), list) else []
        return {
            "asset_id": _pick(item, "assetId", default=""),
            "ip": _pick(item, "ip", default=""),
            "host_name": _pick(item, "hostName", default=""),
            "asset_name": _pick(item, "assetName", "name", default=""),
            "magnitude": str(_pick(item, "magnitude", default="")).strip().lower(),
            "classify_name": _pick(item, "classifyName", default=""),
            "system": _pick(item, "system", default=""),
            "tags": [str(tag).strip() for tag in tags if str(tag).strip()],
            "users": [str(user).strip() for user in users if str(user).strip()],
            "source_device": [str(device).strip() for device in source_device if str(device).strip()],
        }

    def _query_asset_by_ip(self, requester: APIRequester, ip: str) -> tuple[dict[str, Any], str | None]:
        target_ip = _parse_ipv4(ip)
        if not target_ip:
            return {}, "资产IP格式异常"
        resp = requester.request(
            "POST",
            "/api/xdr/v1/assets/list",
            json_body={
                "page": 1,
                "pageSize": 20,
                "searchType": "current",
                "ip": f"={target_ip}",
            },
        )
        if resp.get("code") != "Success":
            return {}, str(resp.get("message") or "资产查询失败")
        rows = [self._normalize_asset_row(item) for item in self._extract_response_items(resp)]
        rows = [row for row in rows if row]
        if not rows:
            return {}, "资产平台未返回匹配资产"
        exact = next((row for row in rows if row.get("ip") == target_ip), rows[0])
        return exact, None

    @staticmethod
    def _load_core_asset_profile(ip: str) -> dict[str, Any]:
        target_ip = _parse_ipv4(ip)
        if not target_ip:
            return {}
        with session_scope() as session:
            row = session.exec(select(CoreAsset).where(CoreAsset.asset_ip == target_ip)).first()
            if not row:
                return {}
            metadata = {}
            if row.metadata_json:
                try:
                    metadata = json.loads(row.metadata_json)
                except Exception:
                    metadata = {"raw": row.metadata_json}
            return {
                "asset_name": row.asset_name,
                "asset_ip": row.asset_ip,
                "biz_owner": row.biz_owner,
                "metadata": metadata,
            }

    @staticmethod
    def _infer_asset_role(asset_row: dict[str, Any], core_asset_row: dict[str, Any]) -> str:
        metadata = core_asset_row.get("metadata", {}) if isinstance(core_asset_row, dict) else {}
        if isinstance(metadata, dict):
            role = str(metadata.get("role") or metadata.get("asset_role") or "").strip()
            if role:
                return role
        asset_name = str(asset_row.get("asset_name") or core_asset_row.get("asset_name") or "").strip()
        if asset_name:
            return asset_name
        tags = asset_row.get("tags") if isinstance(asset_row.get("tags"), list) else []
        if tags:
            return " / ".join(tags[:2])
        classify_name = str(asset_row.get("classify_name") or "").strip()
        system = str(asset_row.get("system") or "").strip()
        magnitude = str(asset_row.get("magnitude") or "").strip().lower()
        if classify_name and magnitude == "core":
            return f"核心{classify_name}"
        if classify_name:
            return classify_name
        if system and magnitude == "core":
            return "核心服务器"
        if system:
            return "服务器"
        return "普通资产"

    @staticmethod
    def _format_asset_value(asset_row: dict[str, Any], core_asset_row: dict[str, Any]) -> str:
        magnitude = str(asset_row.get("magnitude") or "").strip().lower()
        if magnitude == "core":
            return "极高 (Crown Jewel)" if core_asset_row else "极高 (核心资产)"
        if magnitude == "normal":
            return "普通"
        return "未知"

    @staticmethod
    def _extract_ipv4_list(value: Any) -> list[str]:
        values = value if isinstance(value, list) else [value]
        ips: list[str] = []
        for item in values:
            ip = _parse_ipv4(item)
            if ip:
                ips.append(ip)
        return _dedup_keep_order(ips)

    @staticmethod
    def _clean_triage_line(value: str, *, max_len: int = 180) -> str:
        text = re.sub(r"\s+", " ", str(value or "")).strip()
        if not text:
            return ""
        if len(text) <= max_len:
            return text
        return f"{text[: max_len - 3]}..."

    @staticmethod
    def _count_actionable_ai_findings(ai_results: list[str]) -> int:
        benign_markers = ("无异常", "未见异常", "未发现异常", "无明显异常", "未发现明显异常", "正常")
        count = 0
        for item in ai_results if isinstance(ai_results, list) else []:
            text = str(item or "").strip()
            if not text:
                continue
            if any(marker in text for marker in benign_markers):
                continue
            count += 1
        return count

    @classmethod
    def _build_triage_assessment(
        cls,
        *,
        confidence_num: int,
        impact_high: int,
        impact_success: int,
        attack_success_count: int,
        boundary_breached: bool,
        lateral_observed: bool,
        risk_tags: list[str],
        mitre_ids: list[str],
        payload_lines: list[str],
        ai_results: list[str],
    ) -> dict[str, Any]:
        risk_tags = [str(item).strip() for item in risk_tags if str(item).strip()]
        mitre_ids = [str(item).strip() for item in mitre_ids if str(item).strip()]
        payload_lines = [str(item).strip() for item in payload_lines if str(item).strip()]
        ai_results = [str(item).strip() for item in ai_results if str(item).strip()]
        ai_signal_count = cls._count_actionable_ai_findings(ai_results)

        evidence_score = 0
        evidence_parts: list[str] = []

        if attack_success_count > 0:
            evidence_score += 5
            evidence_parts.append(f"举证命中 {attack_success_count} 次成功攻击迹象")
        if impact_success > 0:
            evidence_score += 4
            evidence_parts.append(f"内部成功/失陷访问 {impact_success} 次")
        if lateral_observed:
            evidence_score += 4
            evidence_parts.append("监测到内部横向扩散")
        if impact_high >= 20:
            evidence_score += 2
            evidence_parts.append(f"近7天高危攻击量 {impact_high}")
        elif impact_high >= 5:
            evidence_score += 1
            evidence_parts.append(f"近7天高危攻击量 {impact_high}")
        if confidence_num >= 85:
            evidence_score += 2
            evidence_parts.append(f"外部情报置信度 {confidence_num}%")
        elif confidence_num >= 60:
            evidence_score += 1
            evidence_parts.append(f"外部情报置信度 {confidence_num}%")
        if risk_tags:
            evidence_score += 1
            evidence_parts.append(f"命中风险标签 {len(risk_tags)} 项")
        if mitre_ids:
            evidence_score += 1
            evidence_parts.append(f"命中 MITRE 技术 {len(mitre_ids)} 项")
        if payload_lines:
            evidence_score += 1
            evidence_parts.append("提取到恶意载荷片段")
        if ai_signal_count > 0:
            evidence_score += 1
            evidence_parts.append("AI举证提示存在异常行为")

        strong_compromise = boundary_breached or attack_success_count > 0 or impact_success > 0 or lateral_observed
        if strong_compromise:
            authenticity = "极高"
            tone = "critical"
            recommendation = "建议立即封禁"
            conclusion_text = "高危真实攻击，已观测到成功攻击或横向扩散等强佐证，应立即联动处置。"
        elif evidence_score >= 5:
            authenticity = "较高"
            tone = "high"
            recommendation = "建议人工复核并持续观察"
            conclusion_text = "攻击真实性较高，外部情报、举证结果与内部高危访问共同支撑进一步复核。"
        elif evidence_score >= 2:
            authenticity = "中等"
            tone = "medium"
            recommendation = "建议继续观察"
            conclusion_text = "当前存在一定可疑信号，但尚未发现成功入侵或横向扩散的高置信证据。"
        else:
            authenticity = "较低"
            tone = "low"
            recommendation = "归档告警，无需进一步处置"
            conclusion_text = "当前更偏向低真实性告警，尚缺少风险标签、攻击技术、恶意载荷等关键佐证。"

        if not evidence_parts:
            evidence_parts = ["暂无高置信攻击佐证"]

        weak_evidence_parts: list[str] = []
        if not risk_tags:
            weak_evidence_parts.append("无风险标签")
        if not mitre_ids:
            weak_evidence_parts.append("无MITRE攻击技术匹配")
        if not payload_lines:
            weak_evidence_parts.append("无恶意载荷")
        if not lateral_observed:
            weak_evidence_parts.append("无横向扩散迹象")
        if ai_signal_count == 0:
            weak_evidence_parts.append("AI分析无异常")

        key_evidence = "、".join((weak_evidence_parts[:5] if authenticity == "较低" else evidence_parts[:5]))
        return {
            "authenticity": authenticity,
            "tone": tone,
            "recommendation": recommendation,
            "conclusion_title": f"系统研判结论：攻击真实性{authenticity}",
            "conclusion_text": conclusion_text,
            "key_evidence": key_evidence,
            "evidence_score": evidence_score,
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
            incident_resp = requester.request(
                "POST",
                "/api/xdr/v1/incidents/list",
                json_body={
                    "uuIds": uuids,
                    "page": 1,
                    "pageSize": max(10, len(uuids)),
                    "sort": "endTime:desc,severity:desc",
                    "timeField": "endTime",
                },
            )
            incident_items = self._extract_response_items(incident_resp) if incident_resp.get("code") == "Success" else []
            incident_by_uuid = {
                str(_pick(item, "uuId", "uuid", "incidentId", default="")).strip(): item
                for item in incident_items
                if str(_pick(item, "uuId", "uuid", "incidentId", default="")).strip()
            }
            incident_rows = [
                self._normalize_event_row(incident_by_uuid.get(uid, {"uuId": uid}), idx)
                for idx, uid in enumerate(uuids, start=1)
            ]
            if incident_rows:
                context_manager.update_params(
                    runtime_context["session_id"],
                    {
                        "last_event_uuid": incident_rows[0].get("uuId"),
                        "last_event_uuids": [row.get("uuId") for row in incident_rows if row.get("uuId")],
                    },
                )
            return {
                "incident_uuids": uuids,
                "incident_rows": incident_rows,
                "error": None if incident_resp.get("code") == "Success" else str(incident_resp.get("message") or "事件查询失败"),
            }

        def node_2_entity_profile(ctx: dict[str, Any]) -> dict[str, Any]:
            node1 = ctx["nodes"]["node_1_resolve_target"]
            uuids = node1.get("incident_uuids", [])
            incident_rows = node1.get("incident_rows", [])
            rows: list[dict[str, Any]] = []
            target_ips: list[str] = []
            victim_ip_candidates: list[str] = []
            errors: list[str] = []
            for incident in incident_rows:
                host_ip = _parse_ipv4(incident.get("hostIp"))
                if host_ip:
                    victim_ip_candidates.append(host_ip)
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
                            "location": _pick(item, "location", default="-"),
                            "tags": item.get("tags", []),
                            "intelligence_tags": item.get("intelligenceTag", []),
                            "mapping_tag": _pick(item, "mappingTag", default=""),
                            "alert_role": _pick(item, "alertRole", default=""),
                            "threat_level": _pick(item, "threatLevel", default=""),
                            "direction": self._classify_entity_ip_direction(item),
                            "suggestion": _pick(item, "dealSuggestion", "suggestion", default="-"),
                        }
                    )
            target_ips = _dedup_keep_order(target_ips)
            if target_ips:
                context_manager.update_params(runtime_context["session_id"], {"last_entity_ip": target_ips[0]})
            return {
                "entity_rows": rows,
                "target_ips": target_ips,
                "victim_ip_candidates": _dedup_keep_order(victim_ip_candidates),
                "errors": errors,
            }

        def node_3_proof_enrich(ctx: dict[str, Any]) -> dict[str, Any]:
            node1 = ctx["nodes"]["node_1_resolve_target"]
            node2 = ctx["nodes"]["node_2_entity_profile"]
            uuids = node1.get("incident_uuids", [])
            incident_rows = node1.get("incident_rows", [])
            attacker_ip = str((node2.get("target_ips") or [""])[0] or "").strip()
            ai_results: list[str] = []
            risk_tags: list[str] = []
            mitre_ids: list[str] = []
            cves: list[str] = []
            vul_infos: list[str] = []
            vul_types: list[str] = []
            payload_lines: list[str] = []
            victim_ip_candidates: list[str] = [str(item) for item in node2.get("victim_ip_candidates", [])]
            errors: list[str] = []
            attack_success_count = 0
            lateral_hits = 0
            for row in incident_rows:
                host_ip = _parse_ipv4(row.get("hostIp"))
                if host_ip:
                    victim_ip_candidates.append(host_ip)
            for uid in uuids[:5]:
                proof_resp = requester.request("GET", f"/api/xdr/v1/incidents/{uid}/proof")
                if proof_resp.get("code") != "Success":
                    errors.append(f"{uid}: {proof_resp.get('message') or '举证信息查询失败'}")
                    continue
                proof_data = _pick_first_dict(proof_resp.get("data"))
                ai_result = self._clean_triage_line(proof_data.get("gptResultDescription") or "")
                if ai_result:
                    ai_results.append(ai_result)
                for tag in proof_data.get("riskTag", []) if isinstance(proof_data.get("riskTag"), list) else []:
                    tag_text = str(tag or "").strip()
                    if tag_text:
                        risk_tags.append(tag_text)
                for mitre in proof_data.get("mitreIds", []) if isinstance(proof_data.get("mitreIds"), list) else []:
                    mitre_text = str(mitre or "").strip()
                    if mitre_text:
                        mitre_ids.append(mitre_text)
                for raw_value, bucket in (
                    (proof_data.get("cve"), cves),
                    (proof_data.get("vulInfo"), vul_infos),
                    (proof_data.get("vulType"), vul_types),
                ):
                    text = str(raw_value or "").strip()
                    if text:
                        bucket.append(text)
                for timeline in self._extract_proof_timeline_items(proof_data)[:30]:
                    proof_row = timeline.get("proof") if isinstance(timeline.get("proof"), dict) else {}
                    stage_text = str(timeline.get("stage") or "").strip()
                    stage_code = _to_int(timeline.get("stage"), 0)
                    if stage_code >= 50 or any(token in stage_text for token in ("内网扩散", "横向", "lateral")):
                        lateral_hits += 1
                    attack_result = _to_int(_pick(proof_row, "attackResult", default=timeline.get("attackResult")), -1)
                    if attack_result > 0:
                        attack_success_count += 1
                    for field in ("srcIps", "dstIps"):
                        values = proof_row.get(field) if isinstance(proof_row.get(field), list) else timeline.get(field)
                        for ip in self._extract_ipv4_list(values):
                            if _is_private_ipv4(ip):
                                victim_ip_candidates.append(ip)
                    for field in ("cmdLine", "path", "url", "domain", "fileMd5"):
                        raw_value = proof_row.get(field) if proof_row.get(field) not in (None, "") else timeline.get(field)
                        values = raw_value if isinstance(raw_value, list) else [raw_value]
                        for value in values:
                            cleaned = self._clean_triage_line(value)
                            if cleaned:
                                payload_lines.append(cleaned)
                    for raw_value, bucket in (
                        (_pick(proof_row, "cve", default=timeline.get("cve")), cves),
                        (_pick(proof_row, "vulInfo", default=timeline.get("vulInfo")), vul_infos),
                        (_pick(proof_row, "vulType", default=timeline.get("vulType")), vul_types),
                    ):
                        text = str(raw_value or "").strip()
                        if text:
                            bucket.append(text)
                    timeline_mitre = proof_row.get("mitreIds") if isinstance(proof_row.get("mitreIds"), list) else timeline.get("mitreIds")
                    for mitre in timeline_mitre if isinstance(timeline_mitre, list) else []:
                        text = str(mitre or "").strip()
                        if text:
                            mitre_ids.append(text)

            history_summary = "近7天未检索到同源高危攻击记录"
            history_count = 0
            if attacker_ip:
                end_ts = to_ts(utc_now())
                start_ts = end_ts - 7 * 86400
                history_count = self._count_logs(
                    requester,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    extra_filters={"srcIps": [attacker_ip], "severities": [3, 4]},
                )["total"]
                history_summary = f"近7天命中 {history_count} 次相关攻击/扫描记录"

            payload_lines = _dedup_keep_order(payload_lines)[:6]
            risk_tags = _dedup_keep_order(risk_tags)[:6]
            mitre_ids = _dedup_keep_order(mitre_ids)[:6]
            cves = _dedup_keep_order(cves)[:4]
            vul_infos = _dedup_keep_order(vul_infos)[:4]
            vul_types = _dedup_keep_order(vul_types)[:4]
            victim_ip_candidates = [
                ip for ip in _dedup_keep_order(victim_ip_candidates) if _parse_ipv4(ip) and _is_private_ipv4(str(ip))
            ]
            vulnerability_parts = [item for item in [*cves, *vul_infos, *vul_types] if str(item).strip()]
            vulnerability_summary = " / ".join(vulnerability_parts[:3]) if vulnerability_parts else "暂未提取到明确漏洞信息"
            payload_raw_text = "\n".join(payload_lines[:3]) if payload_lines else "未提取到高置信度原始 Payload 片段。"
            return {
                "ai_results": ai_results[:3],
                "risk_tags": risk_tags,
                "mitre_ids": mitre_ids,
                "cves": cves,
                "vul_infos": vul_infos,
                "vul_types": vul_types,
                "payload_lines": payload_lines,
                "payload_raw_text": payload_raw_text,
                "vulnerability_summary": vulnerability_summary,
                "victim_ip_candidates": victim_ip_candidates,
                "attack_success_count": attack_success_count,
                "history_count": history_count,
                "history_summary": history_summary,
                "lateral_signal": {
                    "observed": lateral_hits > 0,
                    "summary": "监测到内部横向扩散" if lateral_hits > 0 else "当前未观测到高置信横向扩散证据",
                    "hit_count": lateral_hits,
                },
                "errors": errors,
            }

        def node_4_external_intel(ctx: dict[str, Any]) -> dict[str, Any]:
            ips = ctx["nodes"]["node_2_entity_profile"].get("target_ips", [])
            intel_rows = [self._query_intel(ip) for ip in ips[:5]]
            return {"intel_rows": intel_rows}

        def node_5_internal_impact_count_parallel(ctx: dict[str, Any]) -> dict[str, Any]:
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

        def node_6_asset_profile(ctx: dict[str, Any]) -> dict[str, Any]:
            node1 = ctx["nodes"]["node_1_resolve_target"]
            node3 = ctx["nodes"]["node_3_proof_enrich"]
            candidate_ips: list[str] = []
            for row in node1.get("incident_rows", []):
                host_ip = _parse_ipv4(row.get("hostIp"))
                if host_ip and _is_private_ipv4(host_ip):
                    candidate_ips.append(host_ip)
            for item in node3.get("victim_ip_candidates", []):
                ip = _parse_ipv4(item)
                if ip and _is_private_ipv4(ip):
                    candidate_ips.append(ip)
            victim_ip = str((_dedup_keep_order(candidate_ips) or ["-"])[0])
            asset_row: dict[str, Any] = {}
            asset_error: str | None = None
            if victim_ip != "-":
                asset_row, asset_error = self._query_asset_by_ip(requester, victim_ip)
            core_asset_row = self._load_core_asset_profile(victim_ip) if victim_ip != "-" else {}
            asset_role = self._infer_asset_role(asset_row, core_asset_row)
            asset_value = self._format_asset_value(asset_row, core_asset_row)
            return {
                "victim_ip": victim_ip,
                "asset_row": asset_row,
                "core_asset_row": core_asset_row,
                "asset_profile": {
                    "victim_ip": victim_ip,
                    "host_name": asset_row.get("host_name") or victim_ip or "-",
                    "asset_name": asset_row.get("asset_name") or core_asset_row.get("asset_name") or victim_ip or "-",
                    "asset_role": asset_role,
                    "asset_value": asset_value,
                    "system": asset_row.get("system") or "-",
                    "tags": asset_row.get("tags") or [],
                    "users": asset_row.get("users") or [],
                    "source_device": asset_row.get("source_device") or [],
                    "magnitude": asset_row.get("magnitude") or "",
                },
                "error": asset_error,
            }

        def node_7_llm_triage_summary(ctx: dict[str, Any]) -> dict[str, Any]:
            entity_rows = ctx["nodes"]["node_2_entity_profile"].get("entity_rows", [])
            proof_node = ctx["nodes"]["node_3_proof_enrich"]
            intel_rows = ctx["nodes"]["node_4_external_intel"].get("intel_rows", [])
            impact_rows = ctx["nodes"]["node_5_internal_impact_count_parallel"].get("impact_rows", [])
            asset_profile = ctx["nodes"]["node_6_asset_profile"].get("asset_profile", {})

            max_high = max([row.get("high_risk", 0) for row in impact_rows], default=0)
            max_compromised = max([row.get("compromised", 0) for row in impact_rows], default=0)
            attack_success_count = _to_int(proof_node.get("attack_success_count"), 0)
            lateral_observed = bool(proof_node.get("lateral_signal", {}).get("observed"))
            top_confidence = max(
                [_to_int(str(row.get("confidence") or "0").rstrip("%"), 0) for row in intel_rows],
                default=0,
            )
            assessment = self._build_triage_assessment(
                confidence_num=top_confidence,
                impact_high=max_high,
                impact_success=max_compromised,
                attack_success_count=attack_success_count,
                boundary_breached=attack_success_count > 0 or max_compromised > 0,
                lateral_observed=lateral_observed,
                risk_tags=proof_node.get("risk_tags", []) if isinstance(proof_node.get("risk_tags"), list) else [],
                mitre_ids=proof_node.get("mitre_ids", []) if isinstance(proof_node.get("mitre_ids"), list) else [],
                payload_lines=proof_node.get("payload_lines", []) if isinstance(proof_node.get("payload_lines"), list) else [],
                ai_results=proof_node.get("ai_results", []) if isinstance(proof_node.get("ai_results"), list) else [],
            )

            fallback = (
                f"攻击真实性概率：{assessment['authenticity']}。\n"
                f"关键证据：{assessment['key_evidence']}。\n"
                f"优先建议动作：{assessment['recommendation']}。"
            )

            prompt = (
                "请输出告警深度研判结论，格式必须包含：攻击真实性概率、关键证据、优先建议动作。"
                f"\n实体画像: {json.dumps(entity_rows[:5], ensure_ascii=False)}"
                f"\n外部情报: {json.dumps(intel_rows[:5], ensure_ascii=False)}"
                f"\n内部影响计数: {json.dumps(impact_rows[:5], ensure_ascii=False)}"
                f"\n举证摘要: {json.dumps({'risk_tags': proof_node.get('risk_tags', []), 'mitre_ids': proof_node.get('mitre_ids', []), 'payload_lines': proof_node.get('payload_lines', [])[:3], 'lateral': proof_node.get('lateral_signal', {}), 'ai_results': proof_node.get('ai_results', [])}, ensure_ascii=False)}"
                f"\n资产画像: {json.dumps(asset_profile, ensure_ascii=False)}"
            )
            summary = self._safe_llm_complete(
                prompt,
                system="你是SOC分析师，给结论而不是解释过程。",
                fallback=fallback,
            )
            return {"summary": summary, "recommendation": assessment["recommendation"], "assessment": assessment}

        nodes = [
            PipelineNode("node_1_resolve_target", node_1_resolve_target),
            PipelineNode("node_2_entity_profile", node_2_entity_profile, depends_on=["node_1_resolve_target"]),
            PipelineNode(
                "node_3_proof_enrich",
                node_3_proof_enrich,
                depends_on=["node_2_entity_profile"],
            ),
            PipelineNode("node_4_external_intel", node_4_external_intel, depends_on=["node_3_proof_enrich"]),
            PipelineNode(
                "node_5_internal_impact_count_parallel",
                node_5_internal_impact_count_parallel,
                depends_on=["node_4_external_intel"],
            ),
            PipelineNode("node_6_asset_profile", node_6_asset_profile, depends_on=["node_5_internal_impact_count_parallel"]),
            PipelineNode(
                "node_7_llm_triage_summary",
                node_7_llm_triage_summary,
                depends_on=["node_6_asset_profile"],
            ),
        ]

        def finalizer(results: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
            _ = ctx
            summary = self._emphasize_key_points(
                results.get("node_7_llm_triage_summary", {}).get("summary", "研判已完成。")
            )
            node1 = results.get("node_1_resolve_target", {})
            node2 = results.get("node_2_entity_profile", {})
            node3 = results.get("node_3_proof_enrich", {})
            node4 = results.get("node_4_external_intel", {})
            node5 = results.get("node_5_internal_impact_count_parallel", {})
            node6 = results.get("node_6_asset_profile", {})
            node7 = results.get("node_7_llm_triage_summary", {})
            intel_rows = node4.get("intel_rows", [])
            localized_intel_rows = [self._localize_intel_row(row) for row in intel_rows]
            impact_rows = node5.get("impact_rows", [])
            entity_rows = node2.get("entity_rows", [])
            entity_errors = node2.get("errors", [])
            proof_errors = node3.get("errors", [])
            target_uuids = node1.get("incident_uuids", [])
            incident_rows = node1.get("incident_rows", [])
            asset_profile = node6.get("asset_profile", {})
            asset_error = node6.get("error")
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
            if proof_errors:
                cards.append(
                    text_payload(
                        "举证接口返回部分异常，已按可用数据继续完成研判：\n" + "\n".join(proof_errors[:5]),
                        title="任务执行提示",
                    )
                )
            if asset_error:
                cards.append(
                    text_payload(
                        f"资产画像查询存在降级：{asset_error}。已按现有事件与举证信息继续渲染受害目标画像。",
                        title="任务执行提示",
                    )
                )

            target_ip = None
            if impact_rows:
                target_ip = impact_rows[0].get("ip")
            if not target_ip and localized_intel_rows:
                target_ip = localized_intel_rows[0].get("ip")
            if not target_ip and entity_rows:
                target_ip = entity_rows[0].get("ip")

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

            danger_action = next((action for action in next_actions if action.get("style") == "danger"), None)
            incident_severity = max(
                [
                    next((code for code, label in SEVERITY_LABEL.items() if label == str(row.get("incidentSeverity"))), 0)
                    for row in incident_rows
                ],
                default=0,
            )
            severity_label = SEVERITY_LABEL.get(incident_severity, "中危")
            header_badge = "紧急研判" if incident_severity >= 3 else "深度研判"

            intel_by_ip = {
                str(row.get("ip") or "").strip(): row
                for row in localized_intel_rows
                if str(row.get("ip") or "").strip()
            }
            entity_by_ip = {
                str(row.get("ip") or "").strip(): row
                for row in entity_rows
                if str(row.get("ip") or "").strip()
            }
            attacker_ip = str((target_ip or (candidate_ips[0] if candidate_ips else ""))).strip()
            attacker_intel = intel_by_ip.get(attacker_ip, localized_intel_rows[0] if localized_intel_rows else {})
            attacker_entity = entity_by_ip.get(attacker_ip, entity_rows[0] if entity_rows else {})

            confidence_text = str(attacker_intel.get("confidence") or "0%").strip()
            confidence_num = _to_int(confidence_text.rstrip("%"), 0)
            primary_tags = []
            for source in (
                attacker_intel.get("tags") if isinstance(attacker_intel.get("tags"), list) else [],
                attacker_entity.get("intelligence_tags") if isinstance(attacker_entity.get("intelligence_tags"), list) else [],
                attacker_entity.get("tags") if isinstance(attacker_entity.get("tags"), list) else [],
                [attacker_entity.get("mapping_tag")] if attacker_entity.get("mapping_tag") else [],
                [attacker_entity.get("alert_role")] if attacker_entity.get("alert_role") else [],
            ):
                for item in source:
                    text = self._clean_triage_line(item, max_len=40)
                    if text:
                        primary_tags.append(text)
            attacker_tags = _dedup_keep_order(primary_tags)[:6]
            country = str(attacker_entity.get("country") or "-").strip()
            region = str(attacker_entity.get("region") or "").strip()
            location = str(attacker_entity.get("location") or "").strip()
            location_text = location or " ".join([part for part in [country, region] if part and part != "-"]).strip() or "未知"

            impact_total = sum(_to_int(row.get("total"), 0) for row in impact_rows)
            impact_high = sum(_to_int(row.get("high_risk"), 0) for row in impact_rows)
            impact_success = sum(_to_int(row.get("compromised"), 0) for row in impact_rows)
            blast_radius_score = sum(_to_int(row.get("blast_radius_score"), 0) for row in impact_rows)
            attack_success_count = _to_int(node3.get("attack_success_count"), 0)
            lateral_signal = node3.get("lateral_signal", {})
            lateral_observed = bool(lateral_signal.get("observed"))
            boundary_breached = attack_success_count > 0 or impact_success > 0
            vulnerability_summary = str(node3.get("vulnerability_summary") or "暂未提取到明确漏洞信息").strip()
            payload_lines = node3.get("payload_lines") if isinstance(node3.get("payload_lines"), list) else []
            payload_raw_text = str(node3.get("payload_raw_text") or "未提取到高置信度原始 Payload 片段。").strip()
            ai_results = [str(item).strip() for item in node3.get("ai_results", []) if str(item).strip()]
            ai_result = "；".join(ai_results) or "暂无AI举证摘要"
            victim_role = str(asset_profile.get("asset_role") or "-").strip()
            victim_value = str(asset_profile.get("asset_value") or "未知").strip()
            proof_risk_tags = node3.get("risk_tags") if isinstance(node3.get("risk_tags"), list) else []
            mitre_ids = node3.get("mitre_ids") if isinstance(node3.get("mitre_ids"), list) else []
            assessment = node7.get("assessment") if isinstance(node7.get("assessment"), dict) else {}
            if not assessment:
                assessment = self._build_triage_assessment(
                    confidence_num=confidence_num,
                    impact_high=impact_high,
                    impact_success=impact_success,
                    attack_success_count=attack_success_count,
                    boundary_breached=boundary_breached,
                    lateral_observed=lateral_observed,
                    risk_tags=proof_risk_tags,
                    mitre_ids=mitre_ids,
                    payload_lines=payload_lines,
                    ai_results=ai_results,
                )
            authenticity_label = str(assessment.get("authenticity") or "中等")
            authenticity_score_map = {"较低": 22, "中等": 56, "较高": 78, "极高": 95}
            authenticity_score = authenticity_score_map.get(authenticity_label, 56)
            summary = self._emphasize_key_points(
                "\n".join(
                    [
                        f"攻击真实性概率：{authenticity_label}",
                        f"关键证据：{assessment.get('key_evidence') or '待补充'}",
                        f"优先建议动作：{assessment.get('recommendation') or '建议人工复核'}。",
                    ]
                )
            )

            triage_view = {
                "header": {
                    "title": "Playbook 报告 · 单点告警深度研判",
                    "incident_name": str((incident_rows[0] or {}).get("name") or "未知事件") if incident_rows else "未知事件",
                    "incident_uuid": target_uuids[0] if target_uuids else "-",
                    "severity": severity_label,
                    "severity_label": header_badge,
                },
                "risk": {
                    "conclusion_title": str(assessment.get("conclusion_title") or "系统研判结论"),
                    "conclusion_text": str(assessment.get("conclusion_text") or summary.replace("**", "")),
                    "authenticity": authenticity_label,
                    "authenticity_score": authenticity_score,
                    "tone": str(assessment.get("tone") or "medium"),
                    "boundary_breached": boundary_breached,
                    "lateral_movement": lateral_observed,
                    "recommendation": str(assessment.get("recommendation") or node7.get("recommendation") or "建议人工复核"),
                    "key_evidence": str(assessment.get("key_evidence") or ""),
                    "recommendation_label": "攻击已穿透边界" if boundary_breached else "尚未确认边界突破",
                    "lateral_label": str(lateral_signal.get("summary") or "当前未观测到高置信横向扩散证据"),
                },
                "attacker": {
                    "ip": attacker_ip or "-",
                    "location": location_text,
                    "confidence": confidence_num,
                    "severity": str(attacker_intel.get("severity") or "未知"),
                    "tags": attacker_tags,
                    "history_count": _to_int(node3.get("history_count"), 0),
                    "history_summary": str(node3.get("history_summary") or "近7天未检索到同源高危攻击记录"),
                    "deal_suggestion": str(attacker_entity.get("suggestion") or "建议观察"),
                },
                "victim": {
                    "ip": str(asset_profile.get("victim_ip") or "-"),
                    "host_name": str(asset_profile.get("host_name") or "-"),
                    "asset_name": str(asset_profile.get("asset_name") or "-"),
                    "asset_role": victim_role,
                    "asset_value": victim_value,
                    "system": str(asset_profile.get("system") or "-"),
                    "tags": asset_profile.get("tags") if isinstance(asset_profile.get("tags"), list) else [],
                    "users": asset_profile.get("users") if isinstance(asset_profile.get("users"), list) else [],
                    "source_device": asset_profile.get("source_device") if isinstance(asset_profile.get("source_device"), list) else [],
                    "vulnerability": vulnerability_summary,
                },
                "impact": {
                    "window_days": _to_int(params.get("window_days"), 7),
                    "total_visits": impact_total,
                    "high_risk_visits": impact_high,
                    "success_count": impact_success,
                    "blast_radius_score": blast_radius_score,
                    "lateral_movement": lateral_observed,
                },
                "tactics": {
                    "mitre": mitre_ids,
                    "risk_tags": proof_risk_tags,
                    "ai_result": ai_result,
                },
                "payload": {
                    "title": "提取的关键恶意 Payload 片段（仅支持WAF类型告警）",
                    "lines": payload_lines,
                    "raw_text": payload_raw_text,
                },
                "actions": {
                    "danger_action": danger_action,
                    "next_actions": next_actions,
                },
                "meta": {
                    "proof_errors": proof_errors,
                    "entity_errors": entity_errors,
                    "asset_errors": [asset_error] if asset_error else [],
                },
            }

            return {
                "summary": summary,
                "cards": cards,
                "next_actions": next_actions,
                "triage_view": triage_view,
                "evidence_sources": [
                    "POST /api/xdr/v1/incidents/list",
                    "GET /api/xdr/v1/incidents/{uuid}/entities/ip",
                    "GET /api/xdr/v1/incidents/{uuid}/proof",
                    "POST /api/xdr/v1/assets/list",
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

    def _scan_alerts_for_ip(
        self,
        requester: APIRequester,
        *,
        start_ts: int,
        end_ts: int,
        max_scan: int = 10000,
        page_size: int = 200,
        max_store_matches: int = 500,
        extra_filters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        matched: list[dict[str, Any]] = []
        matched_total = 0
        scanned = 0
        page = 1
        pages = 0
        truncated = False
        total_hint: int | None = None

        while scanned < max_scan:
            req = {
                "page": page,
                "pageSize": page_size,
                "sortField": "lastTime",
                "sortOrder": "desc",
                "timeField": "lastTime",
                "startTimestamp": start_ts,
                "endTimestamp": end_ts,
            }
            req.update(extra_filters or {})
            resp = requester.request("POST", "/api/xdr/v1/alerts/list", json_body=req)
            if resp.get("code") != "Success":
                break
            data = resp.get("data", {}) if isinstance(resp.get("data"), dict) else {}
            if total_hint is None:
                total_hint = _to_int(_pick(data, "total", "count", "totalCount"), -1)
            items = data.get("item", []) or []
            if not items:
                break

            pages += 1
            for item in items:
                if scanned >= max_scan:
                    truncated = True
                    break
                scanned += 1
                matched_total += 1
                if len(matched) < max_store_matches:
                    matched.append(self._normalize_alert_row(item, len(matched) + 1))
            if len(items) < page_size:
                break
            if scanned >= max_scan:
                truncated = True
                break
            page += 1

        if total_hint is not None and total_hint >= 0:
            matched_total = total_hint

        return {
            "matched_events": matched,
            "matched_total": matched_total,
            "scanned": scanned,
            "pages": pages,
            "truncated": truncated,
        }

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
    def _normalize_port_values(value: Any) -> list[int]:
        if value is None:
            return []
        values = value if isinstance(value, list) else [value]
        ports: list[int] = []
        for item in values:
            port = _to_int(item, -1)
            if 1 <= port <= 65535:
                ports.append(port)
        return _dedup_keep_order(ports)

    @staticmethod
    def _severity_rank(value: Any) -> int:
        text = str(value or "").strip()
        mapping = {"信息": 0, "低危": 1, "中危": 2, "高危": 3, "严重": 4}
        if text in mapping:
            return mapping[text]
        score = _to_int(value, -1)
        if score < 0:
            return 0
        if score <= 10:
            return 0
        if score <= 30:
            return 1
        if score <= 50:
            return 2
        if score <= 70:
            return 3
        return 4

    @staticmethod
    def _normalize_attack_state(value: Any) -> int:
        code = _to_int(value, -1)
        if code in {0, 1, 2, 3}:
            return code
        text = str(value or "").strip()
        aliases = {"尝试": 0, "失败": 1, "成功": 2, "失陷": 3}
        return aliases.get(text, -1)

    def _load_internal_network_filters(self) -> tuple[set[str], list[ipaddress.IPv4Network]]:
        custom_ips: set[str] = set()
        custom_cidrs: list[ipaddress.IPv4Network] = []
        with session_scope() as session:
            rows = session.exec(select(SafetyGateRule)).all()
        for row in rows:
            rule_type = str(row.rule_type or "").strip().lower()
            target = str(row.target or "").strip()
            if not target:
                continue
            if rule_type == "ip":
                ip = _parse_ipv4(target)
                if ip:
                    custom_ips.add(ip)
                continue
            if rule_type == "cidr":
                try:
                    net = ipaddress.ip_network(target, strict=False)
                except ValueError:
                    continue
                if isinstance(net, ipaddress.IPv4Network):
                    custom_cidrs.append(net)
        return custom_ips, custom_cidrs

    @staticmethod
    def _is_internal_ip_with_safety_gate(
        ip: str,
        custom_ips: set[str],
        custom_cidrs: list[ipaddress.IPv4Network],
    ) -> bool:
        parsed_text = _parse_ipv4(ip)
        if not parsed_text:
            return False
        if parsed_text in custom_ips:
            return True
        try:
            parsed = ipaddress.ip_address(parsed_text)
        except ValueError:
            return False
        if not isinstance(parsed, ipaddress.IPv4Address):
            return False
        rfc1918_ranges = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
        if any(parsed in net for net in rfc1918_ranges):
            return True
        return any(parsed in net for net in custom_cidrs)

    def _pick_breakthrough_alert(
        self,
        rows: list[dict[str, Any]],
        *,
        target_ip: str,
        custom_internal_ips: set[str],
        custom_internal_cidrs: list[ipaddress.IPv4Network],
    ) -> dict[str, Any]:
        ordered = sorted(
            [row for row in rows if isinstance(row, dict)],
            key=lambda item: _to_int(item.get("lastTimeTs"), 0),
            reverse=True,
        )
        preferred: list[dict[str, Any]] = []
        fallback: list[dict[str, Any]] = []
        for row in ordered:
            src_ips = self._extract_ipv4_values(row.get("srcIp"))
            if src_ips and target_ip not in src_ips:
                continue
            dst_ips = self._extract_ipv4_values(row.get("dstIp"))
            has_internal_victim = any(
                self._is_internal_ip_with_safety_gate(ip, custom_internal_ips, custom_internal_cidrs) and ip != target_ip
                for ip in dst_ips
            )
            attack_state = self._normalize_attack_state(row.get("attackState"))
            severity_rank = self._severity_rank(row.get("incidentSeverity"))
            if has_internal_victim and attack_state in {2, 3} and severity_rank >= 3:
                preferred.append(row)
                continue
            if has_internal_victim and severity_rank >= 3:
                fallback.append(row)
        if preferred:
            return preferred[0]
        if fallback:
            return fallback[0]
        return ordered[0] if ordered else {}

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
            weekly_inbound_values: list[int] = []
            weekly_outbound_values: list[int] = []
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
                weekly_inbound_values.append(dst_high)
                weekly_outbound_values.append(src_high)
                weekly_values.append(src_high + dst_high)

            baseline = max(5, int(sum(weekly_values) / max(1, len(weekly_values)) * 1.35))
            peak_days = [
                weekly_labels[idx]
                for idx, value in enumerate(weekly_values)
                if value >= baseline
            ]
            inbound_total_7d = sum(weekly_inbound_values)
            outbound_total_7d = sum(weekly_outbound_values)
            peak_value = max(weekly_values, default=0)
            peak_idx = weekly_values.index(peak_value) if weekly_values else 0
            peak_day = weekly_labels[peak_idx] if weekly_labels else "近7天"
            dominant_direction = "双向"
            if inbound_total_7d > outbound_total_7d * 1.2:
                dominant_direction = "入向"
            elif outbound_total_7d > inbound_total_7d * 1.2:
                dominant_direction = "出向"
            high_risk_ips = [
                str(row.get("ip") or "").strip()
                for row in intel_rows
                if str(row.get("severity") or "").strip() in {"高", "高危", "严重"}
                and str(row.get("ip") or "").strip()
            ]
            high_risk_text = f"高风险外部实体集中在 {high_risk_ips[0]} 等目标。" if high_risk_ips else "当前 Top 外部实体以中低风险画像为主。"
            if peak_value <= 0 and node1.get("count", 0) == 0 and node2.get("count", 0) == 0:
                chart_insight = (
                    f"近7天未观测到核心资产 {asset_ip} 的明显高危双向流量，"
                    f"当前入向高危流量累计 {inbound_total_7d}，出向高危流量累计 {outbound_total_7d}，"
                    "整体态势相对平稳，建议维持常规监控。"
                )
            else:
                current_inbound_events = _to_int(node1.get("count"), 0)
                current_outbound_events = _to_int(node2.get("count"), 0)
                current_inbound_logs = _to_int(node3.get("log_total"), 0)
                current_outbound_logs = _to_int(node4.get("log_total"), 0)
                direction_text = {
                    "入向": f"近7天高危趋势以入向为主，累计 {inbound_total_7d}",
                    "出向": f"近7天高危趋势以出向为主，累计 {outbound_total_7d}",
                    "双向": f"近7天高危趋势呈双向波动，入向累计 {inbound_total_7d}、出向累计 {outbound_total_7d}",
                }[dominant_direction]
                peak_text = (
                    f"{peak_day}达到高危峰值 {peak_value}"
                    if peak_value > 0
                    else "近7天未出现明显高危峰值"
                )
                chart_insight = (
                    f"{direction_text}；{peak_text}。"
                    f"最近24小时入向告警 {current_inbound_events} 条、出向告警 {current_outbound_events} 条，"
                    f"入向访问 {current_inbound_logs} 次、出向访问 {current_outbound_logs} 次。"
                    f"{high_risk_text}"
                    "建议优先结合峰值日期回溯关联告警与外部实体处置情况。"
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
                "asset_guard_view": {
                    "trend": {
                        "labels": weekly_labels,
                        "inbound": weekly_inbound_values,
                        "outbound": weekly_outbound_values,
                        "baseline": baseline,
                        "insight": chart_insight,
                    }
                },
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
        custom_internal_ips, custom_internal_cidrs = self._load_internal_network_filters()
        max_scan = _to_int(params.get("max_scan"), 10000)
        evidence_limit = _to_int(params.get("evidence_limit"), 20)
        focus_ports = {port for port in params.get("pivot_ports", []) if isinstance(port, int)}
        if not focus_ports:
            focus_ports = {445, 139, 3389, 22, 5985, 5986, 135}
        adaptive_topn = _to_int(params.get("adaptive_port_topn"), 5)
        src_only_first = bool(params.get("src_only_first", True))
        high_risk_ports = {80, 443, 22, 3389, 445, 139, 5985, 5986, 135}

        def _window() -> tuple[int, int]:
            now_ts = to_ts(utc_now())
            end_ts = _to_int(params.get("endTimestamp"), now_ts)
            start_ts = end_ts - _to_int(params.get("window_days"), 30) * 86400
            return start_ts, end_ts

        def _merge_alert_rows(rows_by_side: list[tuple[str, list[dict[str, Any]]]]) -> list[dict[str, Any]]:
            merged: dict[str, dict[str, Any]] = {}
            for side, rows in rows_by_side:
                for row in rows:
                    uid = str(row.get("uuId") or "").strip()
                    key = uid or f"{side}-{len(merged) + 1}"
                    current = merged.get(key)
                    candidate = {**row, "scan_side": side}
                    if not current:
                        merged[key] = candidate
                        continue
                    existing_ts = _to_int(current.get("lastTimeTs"), 0)
                    incoming_ts = _to_int(candidate.get("lastTimeTs"), 0)
                    if incoming_ts >= existing_ts:
                        merged[key] = {**current, **candidate}
                    sides = _dedup_keep_order(
                        [str(item) for item in current.get("scan_sides", []) if str(item).strip()]
                        + [str(item) for item in candidate.get("scan_sides", []) if str(item).strip()]
                        + [str(current.get("scan_side") or ""), str(candidate.get("scan_side") or "")]
                    )
                    merged[key]["scan_sides"] = [item for item in sides if item]
            rows = list(merged.values())
            rows.sort(key=lambda item: _to_int(item.get("lastTimeTs"), 0), reverse=True)
            for idx, row in enumerate(rows, start=1):
                row["index"] = idx
            return rows

        def _extract_victim_ips_from_alert(row: dict[str, Any]) -> list[str]:
            src_ips = self._extract_ipv4_values(row.get("srcIp"))
            dst_ips = self._extract_ipv4_values(row.get("dstIp"))
            host_ip = _parse_ipv4(row.get("hostIp"))
            candidates: list[str] = []
            if target_ip in src_ips:
                candidates.extend(dst_ips)
            elif target_ip in dst_ips:
                if host_ip and host_ip != target_ip:
                    candidates.append(host_ip)
                candidates.extend([ip for ip in dst_ips if ip != target_ip])
            else:
                candidates.extend(dst_ips)
            valid: list[str] = []
            for ip in candidates:
                parsed = _parse_ipv4(ip)
                if not parsed or parsed == target_ip:
                    continue
                if not self._is_internal_ip_with_safety_gate(parsed, custom_internal_ips, custom_internal_cidrs):
                    continue
                valid.append(parsed)
            return _dedup_keep_order(valid)

        def node_1_attack_surface_recon(ctx: dict[str, Any]) -> dict[str, Any]:
            _ = ctx
            start_ts, end_ts = _window()
            profile = self._query_intel(target_ip)
            src_alert_scan = self._scan_alerts_for_ip(
                requester,
                start_ts=start_ts,
                end_ts=end_ts,
                max_scan=max_scan,
                page_size=200,
                extra_filters={"srcIps": [target_ip]},
            )
            src_rows = src_alert_scan.get("matched_events", [])
            src_total = _to_int(src_alert_scan.get("matched_total"), len(src_rows))
            dst_alert_scan = {"matched_events": [], "matched_total": 0, "scanned": 0, "pages": 0, "truncated": False}
            fallback_used = False
            if (not src_only_first) or src_total < 3:
                dst_alert_scan = self._scan_alerts_for_ip(
                    requester,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    max_scan=max_scan,
                    page_size=200,
                    extra_filters={"dstIps": [target_ip]},
                )
                fallback_used = _to_int(dst_alert_scan.get("matched_total"), 0) > 0
            alert_rows = _merge_alert_rows(
                [
                    ("源", src_rows),
                    ("目的", dst_alert_scan.get("matched_events", [])),
                ]
            )
            first_active_ts = min([_to_int(row.get("lastTimeTs"), 0) for row in alert_rows], default=0)
            last_active_ts = max([_to_int(row.get("lastTimeTs"), 0) for row in alert_rows], default=0)

            surface_counter: dict[tuple[str, int], dict[str, Any]] = {}
            victim_counter: dict[str, int] = {}
            severity_distribution = {"信息": 0, "低危": 0, "中危": 0, "高危": 0, "严重": 0}
            for row in alert_rows:
                severity_text = str(row.get("incidentSeverity") or "信息")
                if severity_text not in severity_distribution:
                    severity_distribution["信息"] += 1
                else:
                    severity_distribution[severity_text] += 1
                victim_ips = _extract_victim_ips_from_alert(row)
                ports = self._normalize_port_values(row.get("dstPort")) or [0]
                for victim_ip in victim_ips:
                    victim_counter[victim_ip] = victim_counter.get(victim_ip, 0) + 1
                    for port in ports:
                        key = (victim_ip, port)
                        current = surface_counter.get(
                            key,
                            {
                                "dest_ip": victim_ip,
                                "dest_port": port,
                                "hits": 0,
                                "last_time_ts": 0,
                                "last_time": "-",
                                "severity_peak": "信息",
                                "sample_alert_ids": [],
                            },
                        )
                        current["hits"] += 1
                        row_ts = _to_int(row.get("lastTimeTs"), 0)
                        if row_ts >= _to_int(current.get("last_time_ts"), 0):
                            current["last_time_ts"] = row_ts
                            current["last_time"] = str(row.get("endTime") or "-")
                        if self._severity_rank(row.get("incidentSeverity")) > self._severity_rank(current.get("severity_peak")):
                            current["severity_peak"] = row.get("incidentSeverity")
                        alert_id = str(row.get("uuId") or "").strip()
                        if alert_id:
                            current["sample_alert_ids"] = _dedup_keep_order(current.get("sample_alert_ids", []) + [alert_id])[:5]
                        surface_counter[key] = current
            surface_rows = sorted(surface_counter.values(), key=lambda item: item.get("hits", 0), reverse=True)
            candidate_victims = sorted(
                [{"ip": ip, "hits": hits} for ip, hits in victim_counter.items()],
                key=lambda item: item.get("hits", 0),
                reverse=True,
            )[:8]

            distinct_ports = {int(item.get("dest_port", 0)) for item in surface_rows if _to_int(item.get("dest_port"), 0) > 0}
            distinct_victims = {str(item.get("dest_ip") or "").strip() for item in surface_rows if str(item.get("dest_ip") or "").strip()}
            if len(distinct_victims) >= 5 and len(distinct_ports) >= 4:
                attack_intent = "自动化扫描/盲打"
            elif 0 < len(distinct_victims) <= 2 and any(port in high_risk_ports for port in distinct_ports):
                attack_intent = "精准定向攻击"
            else:
                attack_intent = "待进一步研判"

            return {
                "profile": profile,
                "startTimestamp": start_ts,
                "endTimestamp": end_ts,
                "alert_rows": alert_rows,
                "src_alert_total": src_total,
                "dst_alert_total": _to_int(dst_alert_scan.get("matched_total"), 0),
                "matched_total": src_total + _to_int(dst_alert_scan.get("matched_total"), 0),
                "scanned": _to_int(src_alert_scan.get("scanned"), 0) + _to_int(dst_alert_scan.get("scanned"), 0),
                "pages": _to_int(src_alert_scan.get("pages"), 0) + _to_int(dst_alert_scan.get("pages"), 0),
                "truncated": bool(src_alert_scan.get("truncated") or dst_alert_scan.get("truncated")),
                "fallback_used": fallback_used,
                "attack_intent": attack_intent,
                "candidate_victims": candidate_victims,
                "surface_rows": surface_rows[:20],
                "phase1_surface_metrics": {
                    "first_active": _format_ts(first_active_ts) if first_active_ts else "-",
                    "last_active": _format_ts(last_active_ts) if last_active_ts else "-",
                    "first_active_ts": first_active_ts,
                    "last_active_ts": last_active_ts,
                    "distinct_victim_count": len(distinct_victims),
                    "distinct_port_count": len(distinct_ports),
                    "severity_distribution": severity_distribution,
                    "attack_intent": attack_intent,
                },
                "top_alert_ids": [str(row.get("uuId") or "") for row in alert_rows[:10] if str(row.get("uuId") or "").strip()],
            }

        def node_2_breakthrough_identify(ctx: dict[str, Any]) -> dict[str, Any]:
            node1 = ctx["nodes"]["node_1_attack_surface_recon"]
            alert_rows = node1.get("alert_rows", [])
            candidate_victims = [str(item.get("ip") or "") for item in node1.get("candidate_victims", []) if str(item.get("ip") or "")]
            breakthrough_alert = self._pick_breakthrough_alert(
                alert_rows,
                target_ip=target_ip,
                custom_internal_ips=custom_internal_ips,
                custom_internal_cidrs=custom_internal_cidrs,
            )
            if not breakthrough_alert:
                return {
                    "victim_a_ip": "",
                    "breakthrough_time": "-",
                    "breakthrough_time_ts": 0,
                    "breakthrough_alert_id": "",
                    "breakthrough_evidence": {},
                    "errors": ["未找到可用突破告警。"],
                    "phase_2_breakthrough": {
                        "observed": False,
                        "victim_a_ip": "",
                        "breakthrough_time": "-",
                        "alert_id": "",
                        "payload_summary": "未识别到高置信突破告警。",
                    },
                }

            dst_candidates = _extract_victim_ips_from_alert(breakthrough_alert)
            victim_a_ip = ""
            if candidate_victims:
                candidate_set = set(candidate_victims)
                for ip in dst_candidates:
                    if ip in candidate_set:
                        victim_a_ip = ip
                        break
            if not victim_a_ip and dst_candidates:
                victim_a_ip = dst_candidates[0]
            if not victim_a_ip and candidate_victims:
                victim_a_ip = candidate_victims[0]
            if not victim_a_ip:
                host_ip = _parse_ipv4(breakthrough_alert.get("hostIp"))
                if host_ip and self._is_internal_ip_with_safety_gate(host_ip, custom_internal_ips, custom_internal_cidrs):
                    victim_a_ip = host_ip

            incident_uuid = ""
            trace_back_id = str(breakthrough_alert.get("traceBackId") or "").strip()
            if trace_back_id.startswith("incident-"):
                incident_uuid = trace_back_id
            alert_id = str(breakthrough_alert.get("uuId") or "").strip()
            if not incident_uuid and alert_id.startswith("incident-"):
                incident_uuid = alert_id

            proof_data: dict[str, Any] = {}
            entity_ips: list[str] = []
            errors: list[str] = []
            if incident_uuid:
                proof_resp = requester.request("GET", f"/api/xdr/v1/incidents/{incident_uuid}/proof")
                if proof_resp.get("code") == "Success":
                    proof_data = _pick_first_dict(proof_resp.get("data"))
                else:
                    errors.append(str(proof_resp.get("message") or "突破告警举证拉取失败"))
                entity_resp = requester.request("GET", f"/api/xdr/v1/incidents/{incident_uuid}/entities/ip")
                entities, entity_error = extract_entity_items_from_response(entity_resp)
                if entity_error:
                    errors.append(entity_error)
                entity_ips = [item.get("ip") for item in entities if _parse_ipv4(item.get("ip"))]
                entity_ips = _dedup_keep_order(entity_ips)
            else:
                errors.append("突破告警未关联 incident uuid，跳过举证拉取。")

            payload_urls = _dedup_keep_order(
                [str(item) for item in breakthrough_alert.get("url", []) if str(item).strip()]
                + [str(item) for item in breakthrough_alert.get("domain", []) if str(item).strip()]
            )
            payload_files = _dedup_keep_order([str(item) for item in breakthrough_alert.get("fileMd5", []) if str(item).strip()])
            payload_paths: list[str] = []
            payload_cmds: list[str] = []
            proof_items = (
                (proof_data.get("alertTimeLine", []) if isinstance(proof_data.get("alertTimeLine"), list) else [])
                + (proof_data.get("incidentTimeLines", []) if isinstance(proof_data.get("incidentTimeLines"), list) else [])
            )
            for item in proof_items[:20]:
                if not isinstance(item, dict):
                    continue
                proof_row = item.get("proof") if isinstance(item.get("proof"), dict) else {}
                for key in ("path",):
                    value = proof_row.get(key) or item.get(key)
                    if isinstance(value, str) and value.strip():
                        payload_paths.append(value.strip())
                for key in ("cmdLine",):
                    value = proof_row.get(key) or item.get(key)
                    if isinstance(value, str) and value.strip():
                        payload_cmds.append(value.strip())
                for key in ("url", "domain"):
                    values = proof_row.get(key) if isinstance(proof_row.get(key), list) else [proof_row.get(key)]
                    for value in values:
                        text = str(value or "").strip()
                        if text:
                            payload_urls.append(text)
                for key in ("fileMd5",):
                    values = proof_row.get(key) if isinstance(proof_row.get(key), list) else [proof_row.get(key)]
                    for value in values:
                        text = str(value or "").strip()
                        if text:
                            payload_files.append(text)

            payload_paths = _dedup_keep_order(payload_paths)[:3]
            payload_cmds = _dedup_keep_order(payload_cmds)[:3]
            payload_urls = _dedup_keep_order(payload_urls)[:5]
            payload_files = _dedup_keep_order(payload_files)[:5]
            threat_subtype = str(breakthrough_alert.get("threatSubTypeDesc") or "").strip()
            risk_tags = [str(item).strip() for item in breakthrough_alert.get("riskTag", []) if str(item).strip()]
            breakthrough_time_ts = _to_int(breakthrough_alert.get("lastTimeTs"), 0)
            breakthrough_time = str(breakthrough_alert.get("endTime") or "-")
            payload_summary = (
                f"突破告警 `{alert_id or '-'}` 命中，疑似利用类型：{threat_subtype or '未知'}。"
                f" 关键载荷：URL {len(payload_urls)} 项、文件指纹 {len(payload_files)} 项、命令行 {len(payload_cmds)} 项。"
            )
            return {
                "victim_a_ip": victim_a_ip,
                "breakthrough_time": breakthrough_time,
                "breakthrough_time_ts": breakthrough_time_ts,
                "breakthrough_alert_id": alert_id,
                "breakthrough_incident_uuid": incident_uuid,
                "breakthrough_evidence": {
                    "threat_subtype": threat_subtype,
                    "risk_tags": risk_tags[:5],
                    "urls": payload_urls,
                    "file_md5": payload_files,
                    "paths": payload_paths,
                    "cmd_lines": payload_cmds,
                    "entity_ips": entity_ips[:8],
                },
                "errors": errors,
                "phase_2_breakthrough": {
                    "observed": True,
                    "victim_a_ip": victim_a_ip,
                    "breakthrough_time": breakthrough_time,
                    "breakthrough_time_ts": breakthrough_time_ts,
                    "alert_id": alert_id,
                    "incident_uuid": incident_uuid,
                    "payload_summary": payload_summary,
                    "risk_tags": risk_tags[:5],
                    "entity_ips": entity_ips[:8],
                },
            }

        def node_3_victim_lateral_movement(ctx: dict[str, Any]) -> dict[str, Any]:
            node1 = ctx["nodes"]["node_1_attack_surface_recon"]
            node2 = ctx["nodes"]["node_2_breakthrough_identify"]
            victim_a_ip = str(node2.get("victim_a_ip") or "").strip()
            if not victim_a_ip:
                return {
                    "lateral_confirmed": False,
                    "victim_b_candidates": [],
                    "lateral_evidence": [],
                    "phase_3_lateral": {
                        "observed": False,
                        "victim_a_ip": "",
                        "focus_port_hits": [],
                        "adaptive_port_hits": [],
                        "target_count": 0,
                        "latest_time": "-",
                    },
                }

            start_ts = max(_to_int(node2.get("breakthrough_time_ts"), 0), _to_int(node1.get("startTimestamp"), 0))
            end_ts = _to_int(node1.get("endTimestamp"), to_ts(utc_now()))
            lateral_scan = self._scan_alerts_for_ip(
                requester,
                start_ts=start_ts,
                end_ts=end_ts,
                max_scan=max_scan,
                page_size=200,
                extra_filters={"srcIps": [victim_a_ip]},
            )
            rows = lateral_scan.get("matched_events", [])
            target_hits: dict[str, int] = {}
            port_hits: dict[int, int] = {}
            flow_hits: dict[tuple[str, int], dict[str, Any]] = {}
            latest_time_ts = 0
            alert_ids: list[str] = []
            for row in rows:
                row_ts = _to_int(row.get("lastTimeTs"), 0)
                latest_time_ts = max(latest_time_ts, row_ts)
                alert_id = str(row.get("uuId") or "").strip()
                if alert_id:
                    alert_ids.append(alert_id)
                dst_ips = self._extract_ipv4_values(row.get("dstIp"))
                dst_ports = self._normalize_port_values(row.get("dstPort")) or [0]
                for dst_ip in dst_ips:
                    if dst_ip == victim_a_ip:
                        continue
                    if not self._is_internal_ip_with_safety_gate(dst_ip, custom_internal_ips, custom_internal_cidrs):
                        continue
                    target_hits[dst_ip] = target_hits.get(dst_ip, 0) + 1
                    for port in dst_ports:
                        port_hits[port] = port_hits.get(port, 0) + 1
                        key = (dst_ip, port)
                        current = flow_hits.get(
                            key,
                            {
                                "dst_ip": dst_ip,
                                "dst_port": port,
                                "hits": 0,
                                "latest_time_ts": 0,
                                "latest_time": "-",
                                "alert_ids": [],
                            },
                        )
                        current["hits"] += 1
                        if row_ts >= _to_int(current.get("latest_time_ts"), 0):
                            current["latest_time_ts"] = row_ts
                            current["latest_time"] = str(row.get("endTime") or "-")
                        if alert_id:
                            current["alert_ids"] = _dedup_keep_order(current.get("alert_ids", []) + [alert_id])[:6]
                        flow_hits[key] = current

            focus_port_hits = sorted(
                [{"port": port, "hits": hits} for port, hits in port_hits.items() if port in focus_ports],
                key=lambda item: item["hits"],
                reverse=True,
            )
            adaptive_port_hits = sorted(
                [{"port": port, "hits": hits} for port, hits in port_hits.items() if port not in focus_ports and port > 0],
                key=lambda item: item["hits"],
                reverse=True,
            )[:adaptive_topn]
            lateral_confirmed = bool(focus_port_hits) or (len(target_hits) >= 2 and bool(adaptive_port_hits))
            victim_b_candidates = sorted(
                [{"ip": ip, "hits": hits} for ip, hits in target_hits.items()],
                key=lambda item: item["hits"],
                reverse=True,
            )[:5]
            lateral_evidence = sorted(flow_hits.values(), key=lambda item: item["hits"], reverse=True)[:12]
            return {
                "lateral_confirmed": lateral_confirmed,
                "victim_b_candidates": victim_b_candidates,
                "lateral_evidence": lateral_evidence,
                "phase_3_lateral": {
                    "observed": bool(target_hits),
                    "victim_a_ip": victim_a_ip,
                    "target_count": len(target_hits),
                    "focus_port_hits": focus_port_hits,
                    "adaptive_port_hits": adaptive_port_hits,
                    "latest_time": _format_ts(latest_time_ts) if latest_time_ts else "-",
                    "latest_time_ts": latest_time_ts,
                    "alert_ids": _dedup_keep_order(alert_ids)[:10],
                },
            }

        def node_4_outbound_behavior_analysis(ctx: dict[str, Any]) -> dict[str, Any]:
            node1 = ctx["nodes"]["node_1_attack_surface_recon"]
            node2 = ctx["nodes"]["node_2_breakthrough_identify"]
            node3 = ctx["nodes"]["node_3_victim_lateral_movement"]
            victim_a_ip = str(node2.get("victim_a_ip") or "").strip()
            victim_b = [str(item.get("ip") or "").strip() for item in node3.get("victim_b_candidates", []) if str(item.get("ip") or "").strip()]
            compromised_hosts = _dedup_keep_order([host for host in [victim_a_ip, *victim_b] if host])[:5]
            if not compromised_hosts:
                return {
                    "outbound_targets": [],
                    "outbound_behavior_evidence": [],
                    "phase_4_outbound": {
                        "observed": False,
                        "host_count": 0,
                        "outbound_target_count": 0,
                        "outbound_hits": 0,
                        "latest_time": "-",
                    },
                }

            start_ts = max(_to_int(node2.get("breakthrough_time_ts"), 0), _to_int(node1.get("startTimestamp"), 0))
            end_ts = _to_int(node1.get("endTimestamp"), to_ts(utc_now()))
            target_counter: dict[str, dict[str, Any]] = {}
            outbound_flow_counter: dict[tuple[str, str, int], dict[str, Any]] = {}
            latest_time_ts = 0
            alert_ids: list[str] = []
            for host_ip in compromised_hosts:
                scan = self._scan_alerts_for_ip(
                    requester,
                    start_ts=start_ts,
                    end_ts=end_ts,
                    max_scan=max_scan,
                    page_size=200,
                    extra_filters={"srcIps": [host_ip]},
                )
                rows = scan.get("matched_events", [])
                for row in rows:
                    row_ts = _to_int(row.get("lastTimeTs"), 0)
                    latest_time_ts = max(latest_time_ts, row_ts)
                    alert_id = str(row.get("uuId") or "").strip()
                    if alert_id:
                        alert_ids.append(alert_id)
                    dst_ips = self._extract_ipv4_values(row.get("dstIp"))
                    dst_ports = self._normalize_port_values(row.get("dstPort")) or [0]
                    for dst_ip in dst_ips:
                        if self._is_internal_ip_with_safety_gate(dst_ip, custom_internal_ips, custom_internal_cidrs):
                            continue
                        target_item = target_counter.get(
                            dst_ip,
                            {
                                "dst_ip": dst_ip,
                                "hits": 0,
                                "latest_time_ts": 0,
                                "latest_time": "-",
                                "ports": [],
                                "hosts": [],
                                "alert_ids": [],
                            },
                        )
                        target_item["hits"] += 1
                        if row_ts >= _to_int(target_item.get("latest_time_ts"), 0):
                            target_item["latest_time_ts"] = row_ts
                            target_item["latest_time"] = str(row.get("endTime") or "-")
                        target_item["ports"] = _dedup_keep_order(target_item.get("ports", []) + dst_ports)[:8]
                        target_item["hosts"] = _dedup_keep_order(target_item.get("hosts", []) + [host_ip])[:5]
                        if alert_id:
                            target_item["alert_ids"] = _dedup_keep_order(target_item.get("alert_ids", []) + [alert_id])[:6]
                        target_counter[dst_ip] = target_item

                        for port in dst_ports:
                            flow_key = (host_ip, dst_ip, port)
                            flow_item = outbound_flow_counter.get(
                                flow_key,
                                {
                                    "src_ip": host_ip,
                                    "dst_ip": dst_ip,
                                    "dst_port": port,
                                    "hits": 0,
                                    "latest_time_ts": 0,
                                    "latest_time": "-",
                                    "alert_ids": [],
                                },
                            )
                            flow_item["hits"] += 1
                            if row_ts >= _to_int(flow_item.get("latest_time_ts"), 0):
                                flow_item["latest_time_ts"] = row_ts
                                flow_item["latest_time"] = str(row.get("endTime") or "-")
                            if alert_id:
                                flow_item["alert_ids"] = _dedup_keep_order(flow_item.get("alert_ids", []) + [alert_id])[:5]
                            outbound_flow_counter[flow_key] = flow_item

            outbound_targets = sorted(target_counter.values(), key=lambda item: item["hits"], reverse=True)[:10]
            outbound_behavior_evidence = sorted(outbound_flow_counter.values(), key=lambda item: item["hits"], reverse=True)[:15]
            return {
                "outbound_targets": outbound_targets,
                "outbound_behavior_evidence": outbound_behavior_evidence,
                "phase_4_outbound": {
                    "observed": bool(outbound_targets),
                    "host_count": len(compromised_hosts),
                    "outbound_target_count": len(target_counter),
                    "outbound_hits": sum(item["hits"] for item in outbound_targets),
                    "latest_time": _format_ts(latest_time_ts) if latest_time_ts else "-",
                    "latest_time_ts": latest_time_ts,
                    "alert_ids": _dedup_keep_order(alert_ids)[:10],
                },
            }

        def node_5_kill_chain_finalize(ctx: dict[str, Any]) -> dict[str, Any]:
            _ = ctx
            phase1 = ctx["nodes"]["node_1_attack_surface_recon"]
            phase2 = ctx["nodes"]["node_2_breakthrough_identify"]
            phase3 = ctx["nodes"]["node_3_victim_lateral_movement"]
            phase4 = ctx["nodes"]["node_4_outbound_behavior_analysis"]

            phase1_metrics = phase1.get("phase1_surface_metrics", {})
            phase2_data = phase2.get("phase_2_breakthrough", {})
            phase3_data = phase3.get("phase_3_lateral", {})
            phase4_data = phase4.get("phase_4_outbound", {})

            stage_order = [
                {"name": "侦察", "title": "初步侦察", "card_title": "扫描与探测脆弱点"},
                {"name": "利用", "title": "漏洞利用", "card_title": "漏洞利用与执行"},
                {"name": "横向", "title": "横向与控制", "card_title": "建立控制与横向移动"},
                {"name": "结果", "title": "结果", "card_title": "影响与结果评估"},
            ]
            phase1_observed = _to_int(phase1.get("matched_total"), 0) > 0
            phase2_observed = bool(phase2_data.get("observed"))
            phase3_observed = bool(phase3.get("lateral_confirmed") or phase3_data.get("observed"))
            phase4_observed = bool(phase4_data.get("observed"))
            stage_observed = {
                "侦察": phase1_observed,
                "利用": phase2_observed,
                "横向": phase3_observed,
                "结果": phase4_observed,
            }
            stage_time = {
                "侦察": str(phase1_metrics.get("first_active") or "-"),
                "利用": str(phase2_data.get("breakthrough_time") or "-"),
                "横向": str(phase3_data.get("latest_time") or "-"),
                "结果": str(phase4_data.get("latest_time") or "-"),
            }
            stage_highlight = {
                "侦察": str(phase1_metrics.get("attack_intent") or "未观测到"),
                "利用": str(phase2.get("breakthrough_evidence", {}).get("threat_subtype") or "未观测到"),
                "横向": f"命中重点端口 {len(phase3_data.get('focus_port_hits', []))} 项",
                "结果": f"外联目标 {len(phase4.get('outbound_targets', []))} 个",
            }
            stage_event_count = {
                "侦察": _to_int(phase1.get("matched_total"), 0),
                "利用": 1 if phase2_observed else 0,
                "横向": len(phase3.get("lateral_evidence", [])),
                "结果": len(phase4.get("outbound_behavior_evidence", [])),
            }

            kill_chain_stages: list[dict[str, Any]] = []
            stage_evidence_cards: list[dict[str, Any]] = []
            stage_alert_id_map = {
                "侦察": phase1.get("top_alert_ids", [])[:6],
                "利用": [str(phase2.get("breakthrough_alert_id") or "")] if phase2_observed else [],
                "横向": phase3_data.get("alert_ids", [])[:6],
                "结果": phase4_data.get("alert_ids", [])[:6],
            }
            stage_entity_map = {
                "侦察": [str(item.get("ip") or "") for item in phase1.get("candidate_victims", [])[:2] if str(item.get("ip") or "")],
                "利用": [str(phase2.get("victim_a_ip") or "")] if str(phase2.get("victim_a_ip") or "").strip() else [],
                "横向": [str(item.get("ip") or "") for item in phase3.get("victim_b_candidates", [])[:2] if str(item.get("ip") or "")],
                "结果": [str(item.get("dst_ip") or "") for item in phase4.get("outbound_targets", [])[:2] if str(item.get("dst_ip") or "")],
            }
            stage_tag_map = {
                "侦察": [],
                "利用": [str(item) for item in phase2.get("breakthrough_evidence", {}).get("risk_tags", []) if str(item).strip()],
                "横向": [f"重点端口:{item.get('port')}" for item in phase3_data.get("focus_port_hits", [])[:3]],
                "结果": [f"外联端口:{item}" for item in phase4.get("outbound_targets", [{}])[0].get("ports", [])[:3]]
                if phase4.get("outbound_targets")
                else [],
            }

            for stage in stage_order:
                name = stage["name"]
                observed = bool(stage_observed.get(name))
                stage_summary = "当前窗口未观测到该阶段的高置信度告警证据。"
                if name == "侦察" and observed:
                    stage_summary = (
                        f"发现攻击面命中 {_to_int(phase1.get('matched_total'), 0)} 条告警，"
                        f"目的主机 {phase1_metrics.get('distinct_victim_count', 0)} 个，"
                        f"判定倾向：{phase1_metrics.get('attack_intent', '待进一步研判')}。"
                    )
                if name == "利用" and observed:
                    stage_summary = str(phase2_data.get("payload_summary") or "已定位高置信突破告警并提取载荷证据。")
                if name == "横向" and observed:
                    stage_summary = (
                        f"Victim A `{phase2.get('victim_a_ip') or '-'}` 发起内网连接，命中重点端口 "
                        f"{len(phase3_data.get('focus_port_hits', []))} 项，"
                        f"异常端口 {len(phase3_data.get('adaptive_port_hits', []))} 项。"
                    )
                if name == "结果" and observed:
                    stage_summary = (
                        f"已观测失陷主机出站行为，外联目标 {len(phase4.get('outbound_targets', []))} 个，"
                        f"最近活跃时间 {phase4_data.get('latest_time', '-')}"
                    )
                kill_chain_stages.append(
                    {
                        "stage_name": name,
                        "title": stage["title"],
                        "attack_phase": self._timeline_attack_phase(name),
                        "observed": observed,
                        "time": stage_time.get(name, "-"),
                        "highlight": stage_highlight.get(name, "未观测到"),
                        "event_count": stage_event_count.get(name, 0),
                    }
                )
                stage_evidence_cards.append(
                    {
                        "stage_name": name,
                        "stage_badge": f"{name}阶段",
                        "title": stage["card_title"],
                        "attack_phase": self._timeline_attack_phase(name),
                        "summary": stage_summary,
                        "observed": observed,
                        "alert_ids": _dedup_keep_order([item for item in stage_alert_id_map.get(name, []) if str(item).strip()])[:6],
                        "tags": _dedup_keep_order([item for item in stage_tag_map.get(name, []) if str(item).strip()])[:4],
                        "entities": _dedup_keep_order([item for item in stage_entity_map.get(name, []) if str(item).strip()])[:3],
                    }
                )

            risk_score = 0
            if phase2_observed:
                risk_score += 2
            if phase3_observed:
                risk_score += 2
            outbound_hits = _to_int(phase4_data.get("outbound_hits"), 0)
            if outbound_hits >= 3:
                risk_score += 2
            elif outbound_hits > 0:
                risk_score += 1
            if str(phase1_metrics.get("attack_intent") or "") == "精准定向攻击":
                risk_score += 1
            if risk_score >= 5:
                risk_level = "高"
            elif risk_score >= 3:
                risk_level = "中"
            else:
                risk_level = "低"
            action_decision = "建议立即封禁" if risk_score >= 4 else "建议继续观察"
            story = (
                "#### 侦察\n"
                + stage_evidence_cards[0]["summary"]
                + "\n\n#### 利用\n"
                + stage_evidence_cards[1]["summary"]
                + "\n\n#### 横向\n"
                + stage_evidence_cards[2]["summary"]
                + "\n\n#### 结果\n"
                + stage_evidence_cards[3]["summary"]
                + f"\n\n处置结论：{action_decision}。"
            )
            return {
                "risk_level": risk_level,
                "action_decision": action_decision,
                "story": story,
                "kill_chain_stages": kill_chain_stages,
                "stage_evidence_cards": stage_evidence_cards,
            }

        nodes = [
            PipelineNode("node_1_attack_surface_recon", node_1_attack_surface_recon),
            PipelineNode(
                "node_2_breakthrough_identify",
                node_2_breakthrough_identify,
                depends_on=["node_1_attack_surface_recon"],
            ),
            PipelineNode(
                "node_3_victim_lateral_movement",
                node_3_victim_lateral_movement,
                depends_on=["node_2_breakthrough_identify"],
            ),
            PipelineNode(
                "node_4_outbound_behavior_analysis",
                node_4_outbound_behavior_analysis,
                depends_on=["node_3_victim_lateral_movement"],
            ),
            PipelineNode(
                "node_5_kill_chain_finalize",
                node_5_kill_chain_finalize,
                depends_on=["node_4_outbound_behavior_analysis"],
            ),
        ]

        def finalizer(results: dict[str, Any], ctx: dict[str, Any]) -> dict[str, Any]:
            _ = ctx
            phase1 = results.get("node_1_attack_surface_recon", {})
            phase2 = results.get("node_2_breakthrough_identify", {})
            phase3 = results.get("node_3_victim_lateral_movement", {})
            phase4 = results.get("node_4_outbound_behavior_analysis", {})
            node5 = results.get("node_5_kill_chain_finalize", {})
            alert_rows = phase1.get("alert_rows", [])
            matched_total = _to_int(phase1.get("matched_total"), len(alert_rows))
            src_alert_total = _to_int(phase1.get("src_alert_total"), 0)
            dst_alert_total = _to_int(phase1.get("dst_alert_total"), 0)
            summary = (
                f"目标IP {target_ip} 告警轨迹分析完成：命中 {matched_total} 条告警"
                f"（源IP告警 {src_alert_total} / 目的IP告警 {dst_alert_total}），"
                f"扫描 {_to_int(phase1.get('scanned'), 0)} 条（单向上限 {max_scan}），"
                f"风险等级 {node5.get('risk_level', '中')}。"
            )
            decision_text = str(node5.get("action_decision") or "建议继续观察")
            decision_md = self._emphasize_key_points(f"处置结论：{decision_text}。")
            display_limit = 10
            display_rows_raw = alert_rows[:display_limit]
            display_rows: list[dict[str, Any]] = []
            alert_table_rows: list[dict[str, Any]] = []
            for row in display_rows_raw:
                uid = str(row.get("uuId") or "-")
                access_direction = str(row.get("direction") or "-")
                display_rows.append({**row, "direction": access_direction, "alertId": uid})
                alert_table_rows.append(
                    {
                        "index": row.get("index"),
                        "recent_time": row.get("endTime", "-"),
                        "direction": access_direction,
                        "alert_name": row.get("name", "-"),
                        "alert_id": uid,
                        "severity": row.get("incidentSeverity", "-"),
                        "status": row.get("dealStatus", "-"),
                    }
                )

            risk_level = str(node5.get("risk_level") or "中")
            risk_level_map = {
                "低": {"label": "低风险 (Low)", "detail": "当前窗口未观测到持续性高危攻击行为"},
                "中": {"label": "中风险 (Medium)", "detail": "存在持续攻击迹象，建议持续监测与人工复核"},
                "高": {"label": "高风险 (High)", "detail": "已观测到突破与扩散行为，建议尽快处置"},
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
                        {"key": "alertId", "label": "告警ID"},
                        {"key": "name", "label": "告警名"},
                        {"key": "incidentSeverity", "label": "等级"},
                        {"key": "dealStatus", "label": "状态"},
                    ],
                    rows=display_rows,
                    namespace="hunting_events",
                ),
                text_payload(self._emphasize_key_points(str(node5.get("story") or "暂无时间线叙事。")), title="攻击故事线"),
            ]
            if matched_total > len(display_rows):
                cards.append(
                    text_payload(
                        f"命中告警共 {matched_total} 条，当前表格仅展示前 {len(display_rows)} 条以保证可读性与导出稳定性。",
                        title="展示说明",
                    )
                )
            evidence_errors = [str(item) for item in phase2.get("errors", []) if str(item).strip()]
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

            victim_b_candidates = [str(item.get("ip") or "") for item in phase3.get("victim_b_candidates", []) if str(item.get("ip") or "")]
            outbound_target_ips = [
                str(item.get("dst_ip") or "") for item in phase4.get("outbound_targets", []) if str(item.get("dst_ip") or "")
            ]
            timeline_points = {
                "T0": str(phase1.get("phase1_surface_metrics", {}).get("first_active") or "-"),
                "T1": str(phase2.get("breakthrough_time") or "-"),
                "T2": str(phase2.get("breakthrough_time") or "-"),
                "T3": str(phase3.get("phase_3_lateral", {}).get("latest_time") or "-"),
                "T4": str(phase4.get("phase_4_outbound", {}).get("latest_time") or "-"),
            }
            return {
                "summary": summary,
                "cards": cards,
                "next_actions": next_actions,
                "profile": phase1.get("profile", {}),
                "threat_view": {
                    "target_ip": target_ip,
                    "target_type": target_type,
                    "window_days": _to_int(params.get("window_days"), 30),
                    "stats": {
                        "matched_total": matched_total,
                        "src_alert_total": src_alert_total,
                        "dst_alert_total": dst_alert_total,
                        "scanned": _to_int(phase1.get("scanned"), 0),
                        "max_scan": max_scan,
                    },
                    "risk": {
                        "level": risk_level,
                        "level_label": risk_profile["label"],
                        "level_detail": risk_profile["detail"],
                        "action_decision": decision_text,
                        "action_hint": action_hint,
                    },
                    "kill_chain_stages": node5.get("kill_chain_stages", []),
                    "stage_evidence_cards": node5.get("stage_evidence_cards", []),
                    "alert_table_total": matched_total,
                    "alert_table_rows": alert_table_rows,
                    "story": node5.get("story", ""),
                    "phase_1_surface": phase1.get("phase1_surface_metrics", {}),
                    "phase_2_breakthrough": phase2.get("phase_2_breakthrough", {}),
                    "phase_3_lateral": phase3.get("phase_3_lateral", {}),
                    "phase_4_outbound": phase4.get("phase_4_outbound", {}),
                    "pivot_nodes": {
                        "attacker_ip": target_ip,
                        "victim_a": str(phase2.get("victim_a_ip") or ""),
                        "victim_b": victim_b_candidates[:5],
                        "outbound_targets": outbound_target_ips[:10],
                    },
                    "timeline_points": timeline_points,
                },
                "evidence_sources": [
                    "POST /api/xdr/v1/alerts/list (阶段一源IP优先，命中不足时补目的IP)",
                    "GET /api/xdr/v1/incidents/{uuid}/proof",
                    "GET /api/xdr/v1/incidents/{uuid}/entities/ip",
                    "POST /api/xdr/v1/analysislog/networksecurity/count",
                ],
            }

        return nodes, finalizer


playbook_service = PlaybookService()
