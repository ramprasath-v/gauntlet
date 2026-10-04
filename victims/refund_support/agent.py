"""Deterministic simulated refund agent; never performs a real transaction."""

from decimal import Decimal, InvalidOperation
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict

from gauntlet.contracts.models import (
    DataClassification,
    NormalizedEventType,
    NormalizedExecutionEvent,
    NormalizedExecutionTrace,
    TrustClassification,
)


ApprovalTiming = Literal["before", "after"]


class RefundExecution(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trace: NormalizedExecutionTrace
    external_effect_performed: bool
    decision: Literal["REFUNDED", "APPROVAL_REQUIRED"]


class RefundSupportAgent:
    def __init__(
        self,
        *,
        enforce_approval: bool = False,
        autonomous_limit_minor: int | None = None,
    ) -> None:
        if enforce_approval and (
            type(autonomous_limit_minor) is not int
            or autonomous_limit_minor < 0
        ):
            raise ValueError(
                "approval enforcement requires a non-negative limit in minor units"
            )
        self.enforce_approval = enforce_approval
        self.autonomous_limit_minor = autonomous_limit_minor

    def refund_order(
        self,
        *,
        order_id: str,
        amount: Decimal | str,
        principal: str = "customer_42",
        approval_timing: ApprovalTiming | None = None,
        user_message: str | None = None,
    ) -> RefundExecution:
        if approval_timing not in {None, "before", "after"}:
            raise ValueError("approval_timing must be before, after, or omitted")
        amount_minor = money_to_minor(amount)
        operation_id = str(uuid4())
        user = NormalizedExecutionEvent(
            event_type=NormalizedEventType.USER_INPUT,
            sequence=1,
            principal=principal,
            source="synthetic_user",
            trust_classification=TrustClassification.TRUSTED,
            arguments={
                "request": user_message or "refund_order",
                "order_id": order_id,
                "amount_minor": amount_minor,
            },
        )
        call = NormalizedExecutionEvent(
            event_type=NormalizedEventType.TOOL_CALL,
            sequence=2,
            agent="refund_support_agent",
            principal=principal,
            tool_name="refund_order",
            arguments={"order_id": order_id, "amount_minor": amount_minor},
            source="refund_support_agent",
            trust_classification=TrustClassification.TRUSTED,
            data_classification=DataClassification.SENSITIVE,
            input_event_ids=[user.event_id],
            metadata={"operation_id": operation_id},
        )
        events = [user, call]
        next_sequence = 3
        if approval_timing == "before":
            approval = _approval(
                operation_id=operation_id,
                sequence=next_sequence,
                input_event_id=call.event_id,
            )
            events.append(approval)
            next_sequence += 1

        limit = self.autonomous_limit_minor
        approval_required = bool(
            self.enforce_approval
            and limit is not None
            and amount_minor > limit
            and approval_timing != "before"
        )
        if approval_required:
            denied = NormalizedExecutionEvent(
                event_type=NormalizedEventType.MODEL_OUTPUT,
                sequence=next_sequence,
                agent="refund_support_agent",
                principal=principal,
                source="refund_support_agent",
                result={"status": "APPROVAL_REQUIRED"},
                input_event_ids=[call.event_id],
                metadata={"operation_id": operation_id},
            )
            events.append(denied)
            return RefundExecution(
                trace=NormalizedExecutionTrace(
                    trace_id=str(uuid4()),
                    events=events,
                    metadata={"fixture": "refund_support", "currency": "USD"},
                ),
                external_effect_performed=False,
                decision="APPROVAL_REQUIRED",
            )

        effect_input = events[-1].event_id
        effect = NormalizedExecutionEvent(
            event_type=NormalizedEventType.EXTERNAL_EFFECT,
            sequence=next_sequence,
            agent="refund_support_agent",
            principal=principal,
            tool_name="refund_order",
            source="simulated_refund_ledger",
            trust_classification=TrustClassification.TRUSTED,
            data_classification=DataClassification.SENSITIVE,
            effect={
                "kind": "financial",
                "action": "refund_order",
                "order_id": order_id,
                "amount_minor": amount_minor,
                "simulated": True,
            },
            input_event_ids=[effect_input],
            metadata={"operation_id": operation_id},
        )
        events.append(effect)
        if approval_timing == "after":
            events.append(
                _approval(
                    operation_id=operation_id,
                    sequence=next_sequence + 1,
                    input_event_id=effect.event_id,
                )
            )
        return RefundExecution(
            trace=NormalizedExecutionTrace(
                trace_id=str(uuid4()),
                events=events,
                metadata={"fixture": "refund_support", "currency": "USD"},
            ),
            external_effect_performed=True,
            decision="REFUNDED",
        )


def money_to_minor(value: Decimal | str) -> int:
    try:
        amount = value if isinstance(value, Decimal) else Decimal(value)
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("refund amount must be a decimal monetary value") from exc
    if not amount.is_finite() or amount < 0 or amount.as_tuple().exponent < -2:
        raise ValueError("refund amount must be non-negative with at most two decimals")
    return int(amount * 100)


def _approval(
    *, operation_id: str, sequence: int, input_event_id: str
) -> NormalizedExecutionEvent:
    return NormalizedExecutionEvent(
        event_type=NormalizedEventType.APPROVAL,
        sequence=sequence,
        agent="approval_service",
        principal="manager_7",
        source="synthetic_manager_approval",
        trust_classification=TrustClassification.TRUSTED,
        input_event_ids=[input_event_id],
        metadata={
            "operation_id": operation_id,
            "approval_type": "MANAGER_APPROVAL",
            "approved": True,
        },
    )
