from __future__ import annotations

from app.pipeline.schemas import IntentExecutionIR

from .base import IntentLinter


class GeneralIntentLinter(IntentLinter):
    def lint(self, ir: IntentExecutionIR, supported_intents: set[str]) -> list[str]:
        warnings: list[str] = []

        if not ir.intent:
            warnings.append("Intent为空，无法路由技能。")
            return warnings

        builtin_intents = {"confirm_pending", "cancel_pending", "chat_fallback", "workflow_trigger", "workflow_approval"}
        if ir.intent not in supported_intents and ir.intent not in builtin_intents:
            warnings.append(f"Intent未注册: {ir.intent}")

        if len(ir.params) > 20:
            warnings.append("解析参数数量异常偏大，建议检查意图提取逻辑。")

        if ir.is_dangerous_intent and "confirm" in ir.params and not isinstance(ir.params.get("confirm"), bool):
            warnings.append("危险动作确认字段类型异常，confirm应为布尔值。")

        return warnings

