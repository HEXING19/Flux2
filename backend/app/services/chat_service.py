from __future__ import annotations

import json
import re
from typing import Any, Optional

from sqlmodel import Session, select

from app.core.context import context_manager
from app.core.exceptions import ConfirmationRequiredException, MissingParameterException, ValidationGuardException
from app.core.payload import approval_payload, text_payload
from app.core.requester import get_requester_from_credential
from app.llm.router import LLMRouter
from app.models.db_models import AuditAction, PlaybookRun, XDRCredential
from app.pipeline.service import IntentPipeline
from app.skills.registry import SkillRegistry
from app.services.config_service import ConfigService

from .intent_parser import IntentParser


class ChatService:
    def __init__(self, session: Session):
        self.session = session
        credential = session.exec(select(XDRCredential).order_by(XDRCredential.id.desc())).first()
        requester = get_requester_from_credential(credential)
        self.registry = SkillRegistry(requester, context_manager)
        self.pipeline = IntentPipeline(self.registry)
        self.intent_parser = IntentParser()
        self.llm = LLMRouter(session)

    @staticmethod
    def _safe_json_load(raw: str | None, fallback: Any) -> Any:
        if not raw:
            return fallback
        try:
            return json.loads(raw)
        except Exception:
            return fallback

    @staticmethod
    def _extract_run_ips(run: PlaybookRun) -> list[str]:
        result = ChatService._safe_json_load(run.result_json, {})
        next_actions = result.get("next_actions") if isinstance(result, dict) else []
        ips: list[str] = []
        for action in next_actions or []:
            params = action.get("params") if isinstance(action, dict) else {}
            if not isinstance(params, dict):
                continue
            single = params.get("ip")
            if isinstance(single, str) and single.strip():
                ips.append(single.strip())
            for item in params.get("ips") or []:
                text = str(item).strip()
                if text:
                    ips.append(text)
        dedup: list[str] = []
        seen: set[str] = set()
        for ip in ips:
            if ip in seen:
                continue
            seen.add(ip)
            dedup.append(ip)
        return dedup

    def _bind_active_playbook_context(self, session_id: str, active_playbook_run_id: Optional[int]) -> None:
        if not active_playbook_run_id:
            return
        run = self.session.get(PlaybookRun, active_playbook_run_id)
        if not run:
            return
        input_data = self._safe_json_load(run.input_json, {})
        run_session = str(input_data.get("session_id") or "").strip()
        if run_session and run_session != session_id:
            return
        result = self._safe_json_load(run.result_json, {})
        summary = ""
        if isinstance(result, dict):
            summary = str(result.get("summary") or "").strip()
        context_manager.update_params(
            session_id,
            {
                "active_playbook_run_id": run.id,
                "active_playbook_template": run.template,
                "active_playbook_status": run.status,
                "last_playbook_run_id": run.id,
                "last_playbook_template": run.template,
                "last_playbook_summary": summary or context_manager.get_param(session_id, "last_playbook_summary"),
                "last_playbook_target_ips": self._extract_run_ips(run),
            },
        )

    @staticmethod
    def _looks_like_playbook_followup(message: str) -> bool:
        text = message.strip()
        keywords = (
            "深挖",
            "继续分析",
            "继续研判",
            "这个任务",
            "这个报告",
            "上述",
            "这个结果",
            "这些ip",
            "这些IP",
            "这些",
            "它们",
            "批量",
            "全部封禁",
            "上面的",
            "继续问",
            "进一步",
        )
        return any(token in text for token in keywords)

    @staticmethod
    def _is_ambiguous_detail_reference(message: str) -> bool:
        text = message.strip()
        if not any(token in text for token in ("详情", "举证", "时间线")):
            return False
        if any(token in text for token in ("事件", "告警", "incident-", "alert-")):
            return False
        return any(token in text for token in ("第", "前", "刚刚", "那个", "这条", "上一条"))

    def _resolve_detail_intent(self, session_id: str, intent: str, message: str) -> str:
        if intent != "event_detail" or not self._is_ambiguous_detail_reference(message):
            return intent
        if context_manager.get_param(session_id, "last_result_namespace") == "alerts":
            return "alert_detail"
        return intent

    def _inject_playbook_params_if_needed(self, session_id: str, intent: str, params: dict[str, Any], message: str) -> dict[str, Any]:
        merged = dict(params or {})
        if intent != "block_action":
            return merged
        if merged.get("views"):
            return merged
        if not self._looks_like_playbook_followup(message):
            return merged
        candidate_ips = context_manager.get_param(session_id, "last_playbook_target_ips")
        if not isinstance(candidate_ips, list) or not candidate_ips:
            return merged
        views = [str(ip).strip() for ip in candidate_ips if str(ip).strip()]
        if not views:
            return merged
        merged["views"] = views
        merged.setdefault("block_type", "SRC_IP")
        merged.setdefault("reason", "基于Playbook深挖建议执行批量封禁")
        return merged

    def _audit(self, session_id: str, action_name: str, dangerous: bool, status: str, detail: dict[str, Any]) -> None:
        try:
            detail_json = json.dumps(detail, ensure_ascii=False)
        except Exception:
            detail_json = str(detail)
        self.session.add(
            AuditAction(
                session_id=session_id,
                action_name=action_name,
                dangerous=dangerous,
                status=status,
                detail_json=detail_json,
            )
        )
        self.session.commit()

    def _execute_intent(self, session_id: str, intent: str, params: dict[str, Any], message: str) -> list[dict[str, Any]]:
        try:
            result = self.pipeline.run(session_id=session_id, message=message, intent=intent, params=params)
            payloads = result.payloads
            dangerous = any(p.get("data", {}).get("dangerous") for p in payloads) or result.ir.is_dangerous_intent
            status = "blocked" if result.blocked else "executed"
            self._audit(
                session_id,
                intent,
                dangerous,
                status,
                {
                    "params": params,
                    "ir": result.ir.model_dump(),
                    "lint_warnings": result.lint_warnings,
                    "safety_errors": result.safety_errors,
                },
            )
            return payloads
        except MissingParameterException as exc:
            if exc.payloads:
                return exc.payloads
            return [text_payload(exc.question)]
        except ConfirmationRequiredException as exc:
            token = f"pending-{session_id}-{exc.skill_name}"
            context_manager.save_pending_action(
                session_id,
                {
                    "intent": intent,
                    "params": exc.action_payload.get("params", params),
                    "skill": exc.skill_name,
                },
            )
            self._audit(session_id, intent, True, "waiting_confirmation", exc.action_payload)
            return [
                approval_payload(
                    title=f"高危操作确认: {exc.skill_name}",
                    summary=exc.summary,
                    token=token,
                    details=exc.action_payload,
                )
            ]
        except ValidationGuardException as exc:
            return [text_payload(str(exc))]
        except Exception as exc:  # pragma: no cover - 兜底异常
            return [text_payload(f"执行失败: {exc}")]

    def _handle_form_submit(self, session_id: str, message: str) -> list[dict[str, Any]]:
        try:
            payload = json.loads(message[len("__FORM_SUBMIT__:") :].strip())
        except Exception:
            return [text_payload("表单提交格式错误，请重新提交。")]

        token = payload.get("token")
        params = payload.get("params") or {}
        if not token:
            return [text_payload("表单缺少提交令牌，请重新发起操作。")]

        pending = context_manager.peek_pending_form(session_id)
        if not pending or pending.get("token") != token:
            return [text_payload("当前没有可提交的参数表单，请重新发起操作。")]

        context_manager.pop_pending_form(session_id)
        intent = pending.get("intent")
        merged = {**(pending.get("params") or {}), **params}
        return self._execute_intent(session_id, intent, merged, message)

    def _handle_single(self, session_id: str, message: str, active_playbook_run_id: Optional[int] = None) -> list[dict[str, Any]]:
        self._bind_active_playbook_context(session_id, active_playbook_run_id)
        semantic_rules = []
        for row in ConfigService(self.session).list_semantic_rules(enabled_only=True):
            payload = ConfigService.decode_semantic_rule_payload(row)
            semantic_rules.append(
                {
                    "domain": row.domain,
                    "slot_name": row.slot_name,
                    "phrase": row.phrase,
                    "match_mode": row.match_mode,
                    "action_type": payload.get("action_type") or "append",
                    "rule_value": payload.get("rule_value"),
                    "priority": row.priority,
                }
            )
        parsed = self.intent_parser.parse(message, semantic_rules=semantic_rules)
        parsed.intent = self._resolve_detail_intent(session_id, parsed.intent, message)
        parsed.params = self._inject_playbook_params_if_needed(session_id, parsed.intent, parsed.params, message)

        if parsed.intent == "confirm_pending":
            pending = context_manager.pop_pending_action(session_id)
            if not pending and context_manager.peek_pending_form(session_id):
                return [text_payload("请先完成参数表单，再执行确认。")]
            if not pending:
                return [text_payload("当前没有待确认动作。")]
            skill = self.registry.get(pending["intent"])
            if not skill:
                return [text_payload("待确认动作对应的技能不存在。")]
            params = dict(pending["params"])
            params["confirm"] = True
            payloads = skill.execute(session_id, params, message)
            self._audit(session_id, pending["intent"], True, "confirmed", params)
            return payloads

        if parsed.intent == "cancel_pending":
            pending = context_manager.pop_pending_action(session_id)
            form_pending = context_manager.pop_pending_form(session_id)
            if pending:
                self._audit(session_id, pending["intent"], True, "cancelled", pending)
            if form_pending:
                return [text_payload("已取消待提交的参数表单。")]
            return [text_payload("已取消待执行的危险操作。")]

        if parsed.intent == "chat_fallback":
            base_query = parsed.params.get("query", message)
            if self._looks_like_playbook_followup(message):
                summary = str(context_manager.get_param(session_id, "last_playbook_summary") or "").strip()
                playbook_template = str(context_manager.get_param(session_id, "last_playbook_template") or "").strip()
                target_ips = context_manager.get_param(session_id, "last_playbook_target_ips")
                ip_hint = ""
                if isinstance(target_ips, list) and target_ips:
                    ip_hint = "，关联IP：" + "、".join(str(ip) for ip in target_ips[:8])
                if summary:
                    base_query = (
                        f"基于当前会话最近一次Playbook（{playbook_template or 'unknown'}）继续深挖。"
                        f"摘要：{summary}{ip_hint}\n用户问题：{message}"
                    )
            answer = self.llm.complete(base_query, system="你是企业安全运营助手，回答必须简洁并给出可执行步骤。")
            return [text_payload(answer)]

        return self._execute_intent(session_id, parsed.intent, parsed.params, message)

    def handle(self, session_id: str, message: str, active_playbook_run_id: Optional[int] = None) -> list[dict[str, Any]]:
        normalized = message.strip()
        if not normalized:
            return [text_payload("请输入要执行的安全指令。")]

        if normalized.startswith("__FORM_SUBMIT__:"):
            return self._handle_form_submit(session_id, normalized)

        segments = [part.strip() for part in re.split(r"[；;\n]+", normalized) if part.strip()]
        if len(segments) <= 1:
            return self._handle_single(session_id, normalized, active_playbook_run_id=active_playbook_run_id)

        payloads: list[dict[str, Any]] = []
        for segment in segments:
            payloads.extend(self._handle_single(session_id, segment, active_playbook_run_id=active_playbook_run_id))
        return payloads
