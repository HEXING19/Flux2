from __future__ import annotations

from app.pipeline.schemas import IntentExecutionIR

from .high_risk_gate import HighRiskBulkActionGate


class IntentSafetyRunner:
    def __init__(self) -> None:
        self.gates = [HighRiskBulkActionGate()]

    def enforce(self, ir: IntentExecutionIR) -> list[str]:
        all_errors: list[str] = []
        for gate in self.gates:
            all_errors.extend(gate.enforce(ir))
        return all_errors

