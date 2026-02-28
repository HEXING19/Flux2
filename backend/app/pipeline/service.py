from __future__ import annotations

from app.core.payload import text_payload
from app.pipeline.linter import IntentLinterRunner
from app.pipeline.safety import IntentSafetyRunner
from app.pipeline.schemas import IntentExecutionIR, PipelineRunResult
from app.skills.registry import SkillRegistry


class IntentPipeline:
    def __init__(self, registry: SkillRegistry):
        self.registry = registry
        self.linter = IntentLinterRunner()
        self.safety = IntentSafetyRunner()

    def run(self, session_id: str, message: str, intent: str, params: dict) -> PipelineRunResult:
        ir = IntentExecutionIR(session_id=session_id, raw_message=message, intent=intent, params=dict(params or {}))
        warnings = self.linter.lint(ir, self.registry.supported_intents())
        safety_errors = self.safety.enforce(ir)

        if safety_errors:
            return PipelineRunResult(
                ir=ir,
                lint_warnings=warnings,
                safety_errors=safety_errors,
                payloads=[text_payload("；".join(safety_errors), title="Safety Gate 拦截")],
                blocked=True,
            )

        skill = self.registry.get(ir.intent)
        if not skill:
            return PipelineRunResult(
                ir=ir,
                lint_warnings=warnings,
                safety_errors=safety_errors,
                payloads=[text_payload("暂不支持该操作，请换一种说法。")],
                blocked=True,
            )

        payloads = skill.execute(session_id, ir.params, message)
        return PipelineRunResult(
            ir=ir,
            lint_warnings=warnings,
            safety_errors=safety_errors,
            payloads=payloads,
            blocked=False,
        )

