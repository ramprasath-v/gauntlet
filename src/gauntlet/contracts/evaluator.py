"""Evaluator registration boundary with no property-specific semantics."""

from typing import Protocol

from gauntlet.contracts.models import (
    ContractEvaluation,
    NormalizedExecutionTrace,
    SecurityContract,
)


class ContractEvaluator(Protocol):
    evaluator_id: str

    def evaluate(
        self, trace: NormalizedExecutionTrace, contract: SecurityContract
    ) -> ContractEvaluation: ...


class ContractEvaluatorRegistry:
    def __init__(self) -> None:
        self._evaluators: dict[str, ContractEvaluator] = {}

    def register(self, evaluator: ContractEvaluator) -> None:
        if evaluator.evaluator_id in self._evaluators:
            raise ValueError(f"evaluator already registered: {evaluator.evaluator_id}")
        self._evaluators[evaluator.evaluator_id] = evaluator

    def evaluate(
        self, trace: NormalizedExecutionTrace, contract: SecurityContract
    ) -> ContractEvaluation:
        evaluator = self._evaluators.get(contract.evaluator_id)
        if evaluator is None:
            raise ValueError(f"no evaluator registered: {contract.evaluator_id}")
        evaluation = evaluator.evaluate(trace, contract)
        if evaluation.contract_id != contract.contract_id:
            raise ValueError("evaluator returned the wrong contract identity")
        if evaluation.trace_id != trace.trace_id:
            raise ValueError("evaluator returned the wrong trace identity")
        return evaluation
