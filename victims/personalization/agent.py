"""Deterministic vulnerable personalization agent and framework-owned trace."""

from typing import Literal
from uuid import uuid4

from pydantic import Field, JsonValue

from gauntlet.contracts.models import (
    DataClassification,
    NormalizedEventType,
    NormalizedExecutionEvent,
    NormalizedExecutionTrace,
    StrictModel,
    TrustClassification,
)


class PersonalContextItem(StrictModel):
    context_id: str = Field(min_length=1, max_length=128)
    attribute_id: str = Field(min_length=1, max_length=128)
    subject_id: str = Field(min_length=1, max_length=128)
    value: str = Field(min_length=1, max_length=500)
    provenance_id: str = Field(min_length=1, max_length=128)
    collection_purpose: str = Field(min_length=1, max_length=128)
    policy_id: str = Field(min_length=1, max_length=128)
    personalization_dimension: str = Field(min_length=1, max_length=128)
    source_id: str = Field(
        default="framework_authorized_context", min_length=1, max_length=128
    )
    source_trust: TrustClassification = TrustClassification.TRUSTED
    ingestion_run_id: str = Field(
        default="fixture-seed", min_length=1, max_length=128
    )
    memory_classification: str = Field(
        default="PERSONALIZATION_MEMORY", min_length=1, max_length=128
    )


class ContextAuthorizationGrant(StrictModel):
    authorization_id: str = Field(min_length=1, max_length=128)
    context_id: str = Field(min_length=1, max_length=128)
    attribute_id: str = Field(min_length=1, max_length=128)
    subject_id: str = Field(min_length=1, max_length=128)
    provenance_id: str = Field(min_length=1, max_length=128)
    allowed_purpose: str = Field(min_length=1, max_length=128)
    policy_id: str = Field(min_length=1, max_length=128)
    grant_state: Literal["ACTIVE", "REVOKED"]


class PersonalizationExecution(StrictModel):
    trace: NormalizedExecutionTrace
    response: str


class PersonalizationAgent:
    """Supplies every selected context item without enforcing its purpose grant."""

    def respond(
        self,
        *,
        user_request: str,
        principal: str,
        active_purpose: str,
        run_id: str | None = None,
        request_id: str = "request-unspecified",
        task: str | None = None,
        activated_personalization_dimensions: tuple[str, ...] = (),
        context_items: tuple[PersonalContextItem, ...] = (),
        authorization_grants: tuple[ContextAuthorizationGrant, ...] = (),
        output_text: str = "Harbor Bistro is suitable for a client dinner.",
        model_claims: dict[str, JsonValue] | None = None,
    ) -> PersonalizationExecution:
        if not request_id or not (task or active_purpose) or run_id == "":
            raise ValueError("run_id, request_id, and task must be non-empty")
        if (
            any(not value for value in activated_personalization_dimensions)
            or len(activated_personalization_dimensions)
            != len(set(activated_personalization_dimensions))
        ):
            raise ValueError("activated personalization dimensions must be unique")
        task_name = task or active_purpose
        activated_dimensions = list(activated_personalization_dimensions)
        user = NormalizedExecutionEvent(
            event_type=NormalizedEventType.USER_INPUT,
            sequence=1,
            agent="personalization_agent",
            principal=principal,
            source="synthetic_user",
            trust_classification=TrustClassification.TRUSTED,
            arguments={"request": user_request},
            metadata={
                "request_id": request_id,
                "task": task_name,
                "active_purpose": active_purpose,
                "activated_personalization_dimensions": activated_dimensions,
            },
        )
        events = [user]
        sequence = 2
        for grant in authorization_grants:
            events.append(NormalizedExecutionEvent(
                event_type=NormalizedEventType.APPROVAL,
                sequence=sequence,
                agent="context_policy_service",
                principal=grant.subject_id,
                source="synthetic_context_policy",
                trust_classification=TrustClassification.TRUSTED,
                input_event_ids=[user.event_id],
                metadata={
                    "authorization_type": "CONTEXT_USE",
                    "authorization_id": grant.authorization_id,
                    "context_id": grant.context_id,
                    "attribute_id": grant.attribute_id,
                    "subject_id": grant.subject_id,
                    "provenance_id": grant.provenance_id,
                    "allowed_purpose": grant.allowed_purpose,
                    "policy_id": grant.policy_id,
                    "grant_state": grant.grant_state,
                },
            ))
            sequence += 1

        context_event_ids: list[str] = []
        for item in context_items:
            retrieval = NormalizedExecutionEvent(
                event_type=NormalizedEventType.DATA_READ,
                sequence=sequence,
                agent="personalization_memory_retriever",
                principal=principal,
                source="synthetic_memory_store",
                trust_classification=TrustClassification.TRUSTED,
                result={"context_id": item.context_id},
                input_event_ids=[user.event_id],
                metadata={
                    "selection_step": "retrieved_for_model_context",
                    "context_id": item.context_id,
                    "subject_id": item.subject_id,
                    "provenance_id": item.provenance_id,
                    "personalization_dimension": item.personalization_dimension,
                    "source_id": item.source_id,
                    "source_trust": item.source_trust.value,
                    "ingestion_run_id": item.ingestion_run_id,
                    "memory_classification": item.memory_classification,
                },
            )
            events.append(retrieval)
            sequence += 1
            context = NormalizedExecutionEvent(
                event_type=NormalizedEventType.IDENTITY_CONTEXT,
                sequence=sequence,
                agent="personalization_context_builder",
                principal=item.subject_id,
                source=item.provenance_id,
                trust_classification=TrustClassification.TRUSTED,
                data_classification=DataClassification.SENSITIVE,
                result={"attribute_id": item.attribute_id, "value": item.value},
                input_event_ids=[retrieval.event_id],
                metadata={
                    "lineage_owner": "gauntlet_framework",
                    "context_id": item.context_id,
                    "attribute_id": item.attribute_id,
                    "subject_id": item.subject_id,
                    "provenance_id": item.provenance_id,
                    "collection_purpose": item.collection_purpose,
                    "policy_id": item.policy_id,
                    "personalization_dimension": item.personalization_dimension,
                    "source_id": item.source_id,
                    "source_trust": item.source_trust.value,
                    "ingestion_run_id": item.ingestion_run_id,
                    "memory_classification": item.memory_classification,
                },
            )
            events.append(context)
            context_event_ids.append(context.event_id)
            sequence += 1

        output = NormalizedExecutionEvent(
            event_type=NormalizedEventType.MODEL_OUTPUT,
            sequence=sequence,
            agent="personalization_agent",
            principal=principal,
            source="deterministic_model_adapter",
            trust_classification=TrustClassification.TRUSTED,
            result={"response": output_text},
            input_event_ids=[user.event_id, *context_event_ids],
            metadata={
                "active_purpose": active_purpose,
                "active_agent_subject_id": principal,
                "request_id": request_id,
                "task": task_name,
                "activated_personalization_dimensions": activated_dimensions,
                "model_claims": model_claims or {},
            },
        )
        events.append(output)
        return PersonalizationExecution(
            trace=NormalizedExecutionTrace(
                trace_id=run_id or str(uuid4()),
                events=events,
                metadata={
                    "fixture": "personalization",
                    "active_purpose": active_purpose,
                    "active_agent_subject_id": principal,
                    "request_id": request_id,
                    "task": task_name,
                    "activated_personalization_dimensions": activated_dimensions,
                    "lineage_owner": "gauntlet_framework",
                },
            ),
            response=output_text,
        )

    def recommend_restaurant(self, **kwargs) -> PersonalizationExecution:
        """Compatibility entry point retained for the earlier P400 prototype."""
        return self.respond(**kwargs)
