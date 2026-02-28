from __future__ import annotations

from app.pipeline.schemas import IntentExecutionIR

from .general import GeneralIntentLinter


class IntentLinterRunner:
    def __init__(self) -> None:
        self.linters = [GeneralIntentLinter()]

    def lint(self, ir: IntentExecutionIR, supported_intents: set[str]) -> list[str]:
        all_warnings: list[str] = []
        for linter in self.linters:
            all_warnings.extend(linter.lint(ir, supported_intents))
        return all_warnings

