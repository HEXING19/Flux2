from __future__ import annotations

import json
import re
from typing import Any

from sqlmodel import Session, select

from app.core.context import context_manager
from app.core.exceptions import ConfirmationRequiredException, MissingParameterException, ValidationGuardException
from app.core.payload import approval_payload, text_payload
from app.core.requester import get_requester_from_credential
from app.llm.router import LLMRouter
from app.models.db_models import AuditAction, XDRCredential
from app.skills.registry import SkillRegistry

from .intent_parser import IntentParser


class ChatService:
    def __init__(self, session: Session):
        self.session = session
        credential = session.exec(select(XDRCredential).order_by(XDRCredential.id.desc())).first()
        requester = get_requester_from_credential(credential)
        self.registry = SkillRegistry(requester, context_manager)
        self.intent_parser = IntentParser()
        self.llm = LLMRouter(session)

    def _audit(self, session_id: str, action_name: str, dangerous: bool, status: str, detail: dict[str, Any]) -> None:
        self.session.add(
            AuditAction(
                session_id=session_id,
                action_name=action_name,
                dangerous=dangerous,
                status=status,
                detail_json=str(detail),
            )
        )
        self.session.commit()

    def _execute_intent(self, session_id: str, intent: str, params: dict[str, Any], message: str) -> list[dict[str, Any]]:
        skill = self.registry.get(intent)
        if not skill:
            return [text_payload("暂不支持该操作，请换一种说法。")]

        try:
            payloads = skill.execute(session_id, params, message)
            if any(p.get("data", {}).get("dangerous") for p in payloads):
                self._audit(session_id, intent, True, "executed", params)
            return payloads
        except MissingParameterException as exc:
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

    def _handle_single(self, session_id: str, message: str) -> list[dict[str, Any]]:
        parsed = self.intent_parser.parse(message)

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
            answer = self.llm.complete(
                parsed.params.get("query", message),
                system="你是企业安全运营助手，回答必须简洁并给出可执行步骤。",
            )
            return [text_payload(answer)]

        return self._execute_intent(session_id, parsed.intent, parsed.params, message)

    def handle(self, session_id: str, message: str) -> list[dict[str, Any]]:
        normalized = message.strip()
        if not normalized:
            return [text_payload("请输入要执行的安全指令。")]

        if normalized.startswith("__FORM_SUBMIT__:"):
            return self._handle_form_submit(session_id, normalized)

        segments = [part.strip() for part in re.split(r"[；;\n]+", normalized) if part.strip()]
        if len(segments) <= 1:
            return self._handle_single(session_id, normalized)

        payloads: list[dict[str, Any]] = []
        for segment in segments:
            payloads.extend(self._handle_single(session_id, segment))
        return payloads
