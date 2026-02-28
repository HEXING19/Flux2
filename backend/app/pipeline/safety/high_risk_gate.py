from __future__ import annotations

import re

from app.pipeline.schemas import IntentExecutionIR

from .base import IntentSafetyGate


class HighRiskBulkActionGate(IntentSafetyGate):
    """
    Blocks ambiguous bulk dangerous actions before skill execution.
    Skill-level safety/confirmation still applies after this gate.
    """

    _ambiguous_bulk_pattern = re.compile(r"(全部|所有|全都).*(封禁|处置|标记)")

    def enforce(self, ir: IntentExecutionIR) -> list[str]:
        errors: list[str] = []
        if not ir.is_dangerous_intent:
            return errors

        if not self._ambiguous_bulk_pattern.search(ir.raw_message):
            return errors

        has_explicit_scope = any(
            key in ir.params for key in ["uuids", "views", "ref_text", "ips", "keyword"]
        )
        if not has_explicit_scope:
            errors.append("检测到高危批量操作且目标范围不明确，请明确指定序号或目标对象后重试。")

        return errors

