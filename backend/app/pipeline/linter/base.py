from __future__ import annotations

from abc import ABC, abstractmethod

from app.pipeline.schemas import IntentExecutionIR


class IntentLinter(ABC):
    @abstractmethod
    def lint(self, ir: IntentExecutionIR, supported_intents: set[str]) -> list[str]:
        raise NotImplementedError

