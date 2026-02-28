from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class IntentExecutionIR(BaseModel):
    session_id: str
    raw_message: str
    intent: str
    params: dict[str, Any] = Field(default_factory=dict)

    @property
    def is_dangerous_intent(self) -> bool:
        return self.intent in {"event_action", "block_action"}


class PipelineRunResult(BaseModel):
    ir: IntentExecutionIR
    lint_warnings: list[str] = Field(default_factory=list)
    safety_errors: list[str] = Field(default_factory=list)
    payloads: list[dict[str, Any]] = Field(default_factory=list)
    blocked: bool = False

