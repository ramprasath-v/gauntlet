"""Generic security-contract models and evaluation boundary."""

from gauntlet.contracts.evaluator import ContractEvaluator, ContractEvaluatorRegistry
from gauntlet.contracts.effect_authorization import EffectAuthorizationEvaluator
from gauntlet.contracts.models import (
    ContractEvaluation,
    ContractStatus,
    DataClassification,
    EventCondition,
    NormalizedEventType,
    NormalizedExecutionEvent,
    NormalizedExecutionTrace,
    SecurityContract,
    TrustClassification,
    ViolationEvidence,
)

__all__ = [
    "ContractEvaluation",
    "ContractEvaluator",
    "ContractEvaluatorRegistry",
    "ContractStatus",
    "DataClassification",
    "EffectAuthorizationEvaluator",
    "EventCondition",
    "NormalizedEventType",
    "NormalizedExecutionEvent",
    "NormalizedExecutionTrace",
    "SecurityContract",
    "TrustClassification",
    "ViolationEvidence",
]
