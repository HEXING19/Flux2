from __future__ import annotations

from abc import ABC, abstractmethod

from app.pipeline.schemas import IntentExecutionIR


class IntentSafetyGate(ABC):
    @abstractmethod
    def enforce(self, ir: IntentExecutionIR) -> list[str]:
        raise NotImplementedError

