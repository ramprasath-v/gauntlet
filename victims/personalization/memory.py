"""Synthetic persistent personal memory with an intentionally vulnerable ingress."""

from uuid import uuid4

from gauntlet.contracts.models import (
    DataClassification,
    NormalizedEventType,
    NormalizedExecutionEvent,
    NormalizedExecutionTrace,
    StrictModel,
    TrustClassification,
)
from victims.personalization.agent import PersonalContextItem


class MemoryIngestionReceipt(StrictModel):
    run_id: str
    context: PersonalContextItem
    stored: bool
    eligible_for_personalization: bool
    trace: NormalizedExecutionTrace


class PersonalMemoryStore:
    """Persistent store whose vulnerable ingress accepts every source as memory."""

    def __init__(self) -> None:
        self._contexts: dict[str, PersonalContextItem] = {}

    def ingest(
        self,
        item: PersonalContextItem,
        *,
        source_id: str,
        source_trust: TrustClassification,
        ingestion_run_id: str | None = None,
    ) -> MemoryIngestionReceipt:
        run_id = ingestion_run_id or f"ingestion-{uuid4()}"
        stored = item.model_copy(update={
            "source_id": source_id,
            "source_trust": source_trust,
            "ingestion_run_id": run_id,
            "memory_classification": "PERSONALIZATION_MEMORY",
            "provenance_id": f"memory-ingestion:{run_id}:{source_id}",
        })
        source_event = NormalizedExecutionEvent(
            event_type=NormalizedEventType.DATA_READ,
            sequence=1,
            agent="personal_memory_ingestion",
            principal=item.subject_id,
            source=source_id,
            trust_classification=source_trust,
            data_classification=DataClassification.SENSITIVE,
            result={"context_id": item.context_id},
            metadata={
                "ingestion_run_id": run_id,
                "source_id": source_id,
                "source_trust": source_trust.value,
                "subject_id": item.subject_id,
                "context_id": item.context_id,
                "memory_classification": "PERSONALIZATION_MEMORY",
                "lineage_owner": "gauntlet_framework",
            },
        )
        write = NormalizedExecutionEvent(
            event_type=NormalizedEventType.TOOL_CALL,
            sequence=2,
            agent="personal_memory_ingestion",
            principal=item.subject_id,
            tool_name="persistent_personal_memory.write",
            arguments={"context_id": item.context_id},
            source="gauntlet_framework",
            trust_classification=TrustClassification.TRUSTED,
            input_event_ids=[source_event.event_id],
            metadata={"ingestion_run_id": run_id},
        )
        eligible_for_personalization = True
        if eligible_for_personalization:
            self._contexts[stored.context_id] = stored
        result = NormalizedExecutionEvent(
            event_type=NormalizedEventType.TOOL_RESULT,
            sequence=3,
            agent="personal_memory_ingestion",
            principal=item.subject_id,
            tool_name="persistent_personal_memory.write",
            result={
                "stored": eligible_for_personalization,
                "eligible_for_personalization": eligible_for_personalization,
            },
            source="gauntlet_framework",
            trust_classification=TrustClassification.TRUSTED,
            input_event_ids=[write.event_id],
            metadata={
                "ingestion_run_id": run_id,
                "context_id": stored.context_id,
                "provenance_id": stored.provenance_id,
                "lineage_owner": "gauntlet_framework",
            },
        )
        trace = NormalizedExecutionTrace(
            trace_id=run_id,
            events=[source_event, write, result],
            metadata={
                "fixture": "persistent_personal_memory_ingestion",
                "run_kind": "MEMORY_INGESTION",
                "lineage_owner": "gauntlet_framework",
            },
        )
        return MemoryIngestionReceipt(
            run_id=run_id,
            context=stored,
            stored=eligible_for_personalization,
            eligible_for_personalization=eligible_for_personalization,
            trace=trace,
        )

    def retrieve(
        self, *, subject_id: str, personalization_dimension: str,
    ) -> tuple[PersonalContextItem, ...]:
        return tuple(
            item for item in self._contexts.values()
            if item.subject_id == subject_id
            and item.personalization_dimension == personalization_dimension
        )
