"""M4.2 bounded provider feedback and M4.1 proof orchestration.

Two-call remediation: the provider first generates only the source edit, then
— after the edit validates — only the regression test. Each call carries a
small, focused strict-JSON payload so truncation and malformed output stay
rare. Retries are routed to the specific failing call, and a validated edit is
reused while only the test is retried.
"""
import hashlib
from pathlib import Path
import re
from time import monotonic
from datetime import datetime, timezone
from typing import Callable
from uuid import uuid4

from gauntlet.llm.nebius import NEMOTRON_LIGHTNING_MODEL, QWEN_35_MODEL
from gauntlet.remediation.candidate_artifact import (
    CANDIDATE_ARTIFACT_SCHEMA_VERSION, EDIT_EVIDENCE_SCHEMA_VERSION,
    CandidateArtifactReference, ValidatedEditArtifactReference,
    candidate_artifact_location, persist_candidate_artifact,
    persist_validated_edit_artifact, validated_edit_artifact_location,
)
from gauntlet.remediation.context import build_source_context
from gauntlet.remediation.models import (
    GeneratedEditCandidate, GeneratedRepairCandidate, GeneratedTestCandidate,
    RemediationRequest, RepairContext, RepairFailure, RepairProposal,
    combine_repair_candidate,
)
from gauntlet.remediation.parsing import (
    parse_generated_edit_candidate, parse_generated_test_candidate,
)
from gauntlet.remediation.provider import RetryRemediationProvider
from gauntlet.remediation.retry_models import (
    RepairAttempt, RepairRunFailed, RepairRunResult, RepairRunSucceeded,
    SafeProviderCompletion,
)
from gauntlet.remediation.run_evidence import persist_repair_run
from gauntlet.remediation.validation import (
    combined_candidate_identity, restamp_failure_identity,
    validate_regression_test, validate_source_edit,
)
from gauntlet.sandbox.m4_executor import M41RepairExecutor
from gauntlet.sandbox.m4_models import PatchProof
from gauntlet.sandbox.workspace import repository_digest
from gauntlet.tracing.models import AttackTrace


MAX_PROVIDER_ATTEMPTS = 3
FEEDBACK_FIELD_LIMIT = 8_000
APPROVED_LIVE_REMEDIATION_MODELS = frozenset({
    NEMOTRON_LIGHTNING_MODEL,
    QWEN_35_MODEL,
})
_SECRET = re.compile(
    r"(?i)((?:api[_-]?key|authorization|access[_-]?token|password|secret)"
    r"\s*[=:]\s*['\"]?)[^\s'\"]+"
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _safe_text(value: object, limit: int = FEEDBACK_FIELD_LIMIT) -> str:
    text = str(value)
    text = _SECRET.sub(r"\1[REDACTED]", text)
    text = re.sub(
        r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", text
    )
    return text[:limit]


def _safe_value(value: object) -> object:
    if isinstance(value, str):
        return _safe_text(value)
    if isinstance(value, list):
        return [_safe_value(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _safe_value(item) for key, item in value.items()}
    return value


def _safe_edit_candidate(
    edit: GeneratedEditCandidate | None,
) -> dict[str, object]:
    if edit is None:
        return {
            "rationale": None, "source_edit": None,
            "optional_policy_artifact": None,
        }
    return _safe_value(edit.model_dump(mode="json"))


def _safe_test_candidate(
    test: GeneratedTestCandidate | None,
) -> dict[str, object]:
    if test is None:
        return {"regression_test": None}
    return _safe_value(test.model_dump(mode="json"))


def _truncated(completion: SafeProviderCompletion | None) -> bool:
    return (
        completion is not None
        and completion.finish_reason in {"length", "max_tokens"}
    )


_STAGE_GUIDANCE = {
    "candidate_validation": "Previous candidate content failed deterministic validation.",
    "regression_syntax": "Previous regression test failed Python parsing.",
    "regression_structure": "Previous regression test lacked the required test structure.",
    "patch_format": "Previous patch was not a valid authorized unified diff.",
    "patch_authorization": "Previous patch exceeded or failed the authorized target scope.",
    "source_identity": "Proposal did not match the trusted source revision.",
    "patch_apply": "Previous patch could not be applied to the authorized source revision.",
    "compile": "Previous patch caused compilation failure.",
    "regression_execution": "Generated regression test failed when executed.",
    "security_test": "Patched system still failed the P100 security verification.",
    "utility_test": "Patch broke legitimate P200 behavior.",
    "existing_suite": "Patch caused existing compatible tests to fail.",
}


def build_failure_feedback(
    request: RemediationRequest,
    failure: RepairFailure,
    *,
    failed_call: str,
    attempt: int,
    candidate_digest: str,
) -> dict[str, object]:
    """Create bounded redacted feedback suitable for another model call."""
    diagnostics = {
        key: (_safe_text(value, 2_000) if isinstance(value, str) else value)
        for key, value in failure.diagnostics.items()
    }
    return {
        "failed_call": failed_call,
        "truncated": bool(diagnostics.get("truncated")),
        "security_objective": (
            "Prevent indirect prompt injection across the recorded untrusted "
            "tool-data boundary while preserving legitimate P200 behavior."
        ),
        "authorized_target": request.repair_context.target_path,
        "authorized_symbol": request.repair_context.target_symbol,
        "source_hash": request.repair_context.source_hash,
        "previous_attempt": attempt,
        "previous_candidate_digest": candidate_digest,
        "failure_id": failure.failure_id,
        "failure_stage": failure.failure_stage,
        "failure_code": failure.failure_code,
        "failure_summary": _STAGE_GUIDANCE[failure.failure_stage],
        "message": _safe_text(failure.message, 500),
        "diagnostics": diagnostics,
    }


def _provider_metadata(provider: RetryRemediationProvider) -> SafeProviderCompletion | None:
    getter = getattr(provider, "safe_completion_metadata", None)
    if not callable(getter):
        return None
    value = getter()
    if value is None or isinstance(value, SafeProviderCompletion):
        return value
    return SafeProviderCompletion.model_validate(value)


class M42RepairOrchestrator:
    def __init__(
        self,
        repository_root: Path,
        provider: RetryRemediationProvider,
        *,
        executor_factory: Callable[[Path], M41RepairExecutor] | None = None,
    ):
        self.repository_root = repository_root.resolve(strict=True)
        if provider.model_name not in APPROVED_LIVE_REMEDIATION_MODELS:
            raise ValueError(
                "M4.2 requires an explicitly approved live remediation model"
            )
        self.provider = provider
        self.executor_factory = executor_factory or M41RepairExecutor

    def _request(self, serialized_trace: str) -> RemediationRequest:
        trace = AttackTrace.model_validate_json(serialized_trace)
        source = build_source_context(serialized_trace, self.repository_root)
        context = RepairContext(
            trace_id=source.trace_id,
            boundary_id=source.boundary_id,
            evidence_ids=source.evidence_ids,
            provider=self.provider.provider_name,
            model=self.provider.model_name,
            target_path=source.repository_relative_path,
            target_symbol=source.target_symbol,
            source_hash=source.source_hash,
            failure_type="indirect_prompt_injection",
        )
        return RemediationRequest(
            source_context=source,
            repair_context=context,
            evidence_summary={
                "verdict": trace.verdict,
                "boundary_type": trace.failure_boundary.boundary_type,
                "evidence_strength": trace.evidence.get("strength", "UNKNOWN"),
            },
        )

    def _synthetic_failure(
        self,
        request: RemediationRequest,
        *,
        attempt: int,
        raw: str,
        code: str,
        message: str,
        error: Exception,
        failed_call: str,
        truncated: bool = False,
    ) -> RepairFailure:
        return RepairFailure(
            candidate_digest=_digest(raw),
            candidate_field_digests={},
            candidate_field_lengths={},
            trace_id=request.repair_context.trace_id,
            boundary_id=request.repair_context.boundary_id,
            evidence_ids=request.repair_context.evidence_ids,
            provider=request.repair_context.provider,
            model=request.repair_context.model,
            target_path=request.repair_context.target_path,
            target_symbol=request.repair_context.target_symbol,
            source_hash=request.repair_context.source_hash,
            failure_type=request.repair_context.failure_type,
            failure_stage="candidate_validation",
            failure_code=code,
            message=message,
            diagnostics={
                "error_type": type(error).__name__,
                "detail": _safe_text(error, 2_000),
                "failed_call": failed_call,
                "truncated": truncated,
            },
            attempt=attempt,
        )

    def _duplicate_candidate_failure(
        self,
        request: RemediationRequest,
        combined: GeneratedRepairCandidate,
        *,
        attempt: int,
        failed_call: str,
    ) -> RepairFailure:
        candidate_digest, field_digests, field_lengths = (
            combined_candidate_identity(combined)
        )
        return RepairFailure(
            candidate_digest=candidate_digest,
            candidate_field_digests=field_digests,
            candidate_field_lengths=field_lengths,
            trace_id=request.repair_context.trace_id,
            boundary_id=request.repair_context.boundary_id,
            evidence_ids=request.repair_context.evidence_ids,
            provider=request.repair_context.provider,
            model=request.repair_context.model,
            target_path=request.repair_context.target_path,
            target_symbol=request.repair_context.target_symbol,
            source_hash=request.repair_context.source_hash,
            failure_type=request.repair_context.failure_type,
            failure_stage="candidate_validation",
            failure_code="duplicate_candidate",
            message="Retry returned a previously observed candidate unchanged.",
            diagnostics={
                "candidate_digest": candidate_digest,
                "failed_call": failed_call,
            },
            attempt=attempt,
        )

    async def _edit_phase(
        self, request: RemediationRequest, *, attempt_number: int,
        previous_edit: GeneratedEditCandidate | None,
        previous_failure: RepairFailure | None,
        previous_digest: str | None,
        materialized: dict[str, object],
    ) -> tuple[
        GeneratedEditCandidate | None, str | None, RepairFailure | None,
        str, str, str, SafeProviderCompletion | None,
    ]:
        """Run the source-edit call. Returns (edit, patch, failure, call, decode, validation, completion)."""
        raw = ""
        try:
            if (previous_edit is not None and previous_failure is not None
                    and previous_digest is not None):
                feedback = build_failure_feedback(
                    request, previous_failure, failed_call="edit",
                    attempt=attempt_number - 1, candidate_digest=previous_digest,
                )
                raw = await self.provider.generate_edit_revision(
                    request,
                    previous_edit=_safe_edit_candidate(previous_edit),
                    failure_feedback=feedback,
                )
            else:
                raw = await self.provider.generate_edit(request)
            completion = _provider_metadata(self.provider)
            provider_call = "PASS"
        except Exception as exc:
            completion = _provider_metadata(self.provider)
            return (
                None, None,
                self._synthetic_failure(
                    request, attempt=attempt_number, raw=raw,
                    code="provider_call_failed",
                    message="The remediation edit call failed safely.", error=exc,
                    failed_call="edit",
                    truncated=_truncated(completion),
                ),
                "FAIL", "NOT_RUN", "NOT_RUN", completion,
            )
        try:
            edit = parse_generated_edit_candidate(raw)
        except Exception as exc:
            return (
                None, None,
                self._synthetic_failure(
                    request, attempt=attempt_number, raw=raw,
                    code="candidate_decode_failed",
                    message="Provider edit content did not decode as a repair candidate.",
                    error=exc, failed_call="edit",
                    truncated=_truncated(completion),
                ),
                "PASS", "FAIL", "NOT_RUN", completion,
            )
        validated = validate_source_edit(
            edit, request.repair_context, self.repository_root,
            attempt=attempt_number, materialized_output=materialized,
        )
        if isinstance(validated, RepairFailure):
            return edit, None, validated, "PASS", "PASS", "FAIL", completion
        return edit, validated, None, "PASS", "PASS", "PASS", completion

    async def _test_phase(
        self, request: RemediationRequest, *, attempt_number: int,
        derived_patch: str,
        previous_test: GeneratedTestCandidate | None,
        previous_failure: RepairFailure | None,
        previous_digest: str | None,
        materialized: dict[str, object],
    ) -> tuple[
        GeneratedTestCandidate | None, RepairFailure | None,
        str, str, str, SafeProviderCompletion | None,
    ]:
        """Run the regression-test call. Returns (test, failure, call, decode, validation, completion)."""
        raw = ""
        try:
            if (previous_test is not None and previous_failure is not None
                    and previous_digest is not None):
                feedback = build_failure_feedback(
                    request, previous_failure, failed_call="test",
                    attempt=attempt_number - 1, candidate_digest=previous_digest,
                )
                raw = await self.provider.generate_test_revision(
                    request, derived_patch=derived_patch,
                    previous_test=_safe_test_candidate(previous_test),
                    failure_feedback=feedback,
                )
            else:
                raw = await self.provider.generate_test(
                    request, derived_patch=derived_patch,
                )
            completion = _provider_metadata(self.provider)
            provider_call = "PASS"
        except Exception as exc:
            completion = _provider_metadata(self.provider)
            return (
                None,
                self._synthetic_failure(
                    request, attempt=attempt_number, raw=raw,
                    code="provider_call_failed",
                    message="The remediation test call failed safely.", error=exc,
                    failed_call="test",
                    truncated=_truncated(completion),
                ),
                "FAIL", "NOT_RUN", "NOT_RUN", completion,
            )
        try:
            test = parse_generated_test_candidate(raw)
        except Exception as exc:
            return (
                None,
                self._synthetic_failure(
                    request, attempt=attempt_number, raw=raw,
                    code="candidate_decode_failed",
                    message="Provider test content did not decode as a repair candidate.",
                    error=exc, failed_call="test",
                    truncated=_truncated(completion),
                ),
                "PASS", "FAIL", "NOT_RUN", completion,
            )
        validated = validate_regression_test(
            test, request.repair_context,
            attempt=attempt_number, materialized_output=materialized,
        )
        if isinstance(validated, RepairFailure):
            return test, validated, "PASS", "PASS", "FAIL", completion
        return test, None, "PASS", "PASS", "PASS", completion

    async def run(
        self,
        serialized_trace: str,
        *,
        evidence_path: Path | None = None,
    ) -> RepairRunResult:
        run_id = str(uuid4())
        started_at = datetime.now(timezone.utc)
        started = monotonic()
        original_digest = repository_digest(self.repository_root)
        request = self._request(serialized_trace)
        attempts: list[RepairAttempt] = []

        accepted_edit: GeneratedEditCandidate | None = None
        accepted_patch: str | None = None
        accepted_edit_artifact: ValidatedEditArtifactReference | None = None
        previous_edit: GeneratedEditCandidate | None = None
        previous_test: GeneratedTestCandidate | None = None
        previous_failure: RepairFailure | None = None
        edit_revision_due = False
        test_revision_due = False

        for attempt_number in range(1, MAX_PROVIDER_ATTEMPTS + 1):
            attempt_started_at = datetime.now(timezone.utc)
            attempt_started = monotonic()
            materialized: dict[str, object] = {}
            failure: RepairFailure | None = None
            failed_call: str | None = None
            proposal: RepairProposal | None = None
            proof: PatchProof | None = None
            edit_candidate: GeneratedEditCandidate | None = None
            test_candidate: GeneratedTestCandidate | None = None
            combined: GeneratedRepairCandidate | None = None
            derived_patch: str | None = None

            edit_provider_call = "NOT_RUN"
            edit_decode = "NOT_RUN"
            edit_validation = "NOT_RUN"
            edit_reused = False
            test_provider_call = "NOT_RUN"
            test_decode = "NOT_RUN"
            test_validation = "NOT_RUN"
            proposal_execution = "NOT_RUN"
            patch_proof = "NOT_RUN"
            edit_completion: SafeProviderCompletion | None = None
            test_completion: SafeProviderCompletion | None = None
            edit_artifact = accepted_edit_artifact

            # ---------- EDIT PHASE ----------
            if accepted_edit is not None:
                edit_candidate = accepted_edit
                derived_patch = accepted_patch
                materialized["patch"] = accepted_patch or ""
                edit_provider_call = edit_decode = edit_validation = "PASS"
                edit_reused = True
            else:
                (edit_candidate, derived_patch, failure,
                 edit_provider_call, edit_decode, edit_validation,
                 edit_completion) = await self._edit_phase(
                    request, attempt_number=attempt_number,
                    previous_edit=previous_edit if edit_revision_due else None,
                    previous_failure=previous_failure if edit_revision_due else None,
                    previous_digest=(
                        attempts[-1].candidate_digest if edit_revision_due else None
                    ),
                    materialized=materialized,
                )
                if failure is not None:
                    failed_call = "edit"
                if edit_candidate is not None:
                    previous_edit = edit_candidate
                if failure is None:
                    accepted_edit = edit_candidate
                    accepted_patch = derived_patch
                    if evidence_path is not None:
                        assert edit_candidate is not None
                        assert derived_patch is not None
                        trusted_original_lines = materialized.get(
                            "trusted_original_lines"
                        )
                        assert isinstance(trusted_original_lines, list)
                        assert all(
                            isinstance(line, str) for line in trusted_original_lines
                        )
                        edit_id = str(uuid4())
                        artifact_path, relative_artifact_path = (
                            validated_edit_artifact_location(
                                evidence_path, attempt_number, edit_id
                            )
                        )
                        artifact = persist_validated_edit_artifact(
                            edit_candidate,
                            path=artifact_path,
                            edit_id=edit_id,
                            run_id=run_id,
                            originating_attempt=attempt_number,
                            provider=self.provider.provider_name,
                            model=self.provider.model_name,
                            trace_id=request.repair_context.trace_id,
                            boundary_id=request.repair_context.boundary_id,
                            evidence_ids=request.repair_context.evidence_ids,
                            target_path=request.repair_context.target_path,
                            target_symbol=request.repair_context.target_symbol,
                            source_hash=request.repair_context.source_hash,
                            trusted_original_lines=trusted_original_lines,
                            derived_patch=derived_patch,
                        )
                        edit_artifact = ValidatedEditArtifactReference(
                            schema_version=EDIT_EVIDENCE_SCHEMA_VERSION,
                            edit_id=edit_id,
                            originating_attempt=attempt_number,
                            path=relative_artifact_path,
                            edit_candidate_digest=artifact.edit_candidate_digest,
                            integrity_digest=artifact.integrity_digest,
                        )
                        accepted_edit_artifact = edit_artifact

            # ---------- TEST PHASE ----------
            if failure is None and derived_patch is not None:
                (test_candidate, failure,
                 test_provider_call, test_decode, test_validation,
                 test_completion) = await self._test_phase(
                    request, attempt_number=attempt_number,
                    derived_patch=derived_patch,
                    previous_test=previous_test if test_revision_due else None,
                    previous_failure=previous_failure if test_revision_due else None,
                    previous_digest=(
                        attempts[-1].candidate_digest if test_revision_due else None
                    ),
                    materialized=materialized,
                )
                if test_candidate is not None:
                    previous_test = test_candidate
                if failure is not None:
                    failed_call = "test"

            # ---------- COMBINE + DUPLICATE CHECK ----------
            # Runs whenever both parts decoded, even if one failed validation:
            # a duplicate wins over a validation failure, matching the old
            # decode -> duplicate -> validate precedence.
            if edit_candidate is not None and test_candidate is not None:
                combined = combine_repair_candidate(edit_candidate, test_candidate)
                current_digest, _, _ = combined_candidate_identity(combined)
                if any(item.candidate_digest == current_digest for item in attempts):
                    failed_call = "test" if edit_reused else "edit"
                    if edit_reused:
                        test_validation = "FAIL"
                    else:
                        edit_validation = "FAIL"
                    failure = self._duplicate_candidate_failure(
                        request, combined, attempt=attempt_number,
                        failed_call=failed_call,
                    )
                # else: keep any validation failure already recorded.

            if combined is not None and failure is not None:
                failure = restamp_failure_identity(failure, combined)

            # ---------- EXECUTE ----------
            if failure is None and combined is not None:
                patch = materialized["patch"]
                regression_test = materialized["regression_test"]
                assert isinstance(patch, str)
                assert isinstance(regression_test, str)
                proposal = RepairProposal(
                    repair_id=str(uuid4()),
                    **request.repair_context.model_dump(),
                    rationale=edit_candidate.rationale if edit_candidate else "",
                    patch=patch,
                    regression_test=regression_test,
                    optional_policy_artifact=(
                        edit_candidate.optional_policy_artifact
                        if edit_candidate else None
                    ),
                )
                execution = await self.executor_factory(self.repository_root).run(
                    proposal
                )
                if isinstance(execution, RepairFailure):
                    candidate_digest, field_digests, field_lengths = (
                        combined_candidate_identity(combined)
                    )
                    failure = execution.model_copy(update={
                        "candidate_id": str(uuid4()),
                        "candidate_digest": candidate_digest,
                        "candidate_field_digests": field_digests,
                        "candidate_field_lengths": field_lengths,
                        "attempt": attempt_number,
                    })
                    proposal_execution = "FAIL"
                    patch_proof = "FAIL"
                    if execution.failure_stage == "regression_execution":
                        failed_call = "test"
                    else:
                        failed_call = "edit"
                else:
                    proof = execution
                    proposal_execution = "PASS"
                    patch_proof = "VERIFIED"

            # ---------- ATTEMPT RECORD ----------
            if combined is not None:
                candidate_digest, field_digests, field_lengths = (
                    combined_candidate_identity(combined)
                )
            else:
                assert failure is not None
                candidate_digest = failure.candidate_digest
                field_digests = failure.candidate_field_digests
                field_lengths = failure.candidate_field_lengths
            candidate_id = failure.candidate_id if failure else str(uuid4())
            candidate_artifact = None
            if combined is not None and evidence_path is not None:
                artifact_path, relative_artifact_path = candidate_artifact_location(
                    evidence_path, attempt_number, candidate_id
                )
                artifact = persist_candidate_artifact(
                    combined,
                    path=artifact_path,
                    candidate_id=candidate_id,
                    run_id=run_id,
                    attempt_number=attempt_number,
                    provider=self.provider.provider_name,
                    model=self.provider.model_name,
                    trace_id=request.repair_context.trace_id,
                    boundary_id=request.repair_context.boundary_id,
                    evidence_ids=request.repair_context.evidence_ids,
                    target_path=request.repair_context.target_path,
                    target_symbol=request.repair_context.target_symbol,
                    source_hash=request.repair_context.source_hash,
                    derived_patch=materialized.get("patch"),
                    derived_regression_test=materialized.get("regression_test"),
                )
                candidate_artifact = CandidateArtifactReference(
                    schema_version=CANDIDATE_ARTIFACT_SCHEMA_VERSION,
                    candidate_id=candidate_id,
                    attempt_number=attempt_number,
                    path=relative_artifact_path,
                    candidate_digest=artifact.candidate_digest,
                    integrity_digest=artifact.integrity_digest,
                )
            workspace_id = (
                proof.workspace_id if proof else
                failure.diagnostics.get("workspace_id") if failure else None
            )
            completed_at = datetime.now(timezone.utc)
            attempts.append(RepairAttempt(
                attempt=attempt_number,
                candidate_id=candidate_id,
                previous_failure_id=(
                    previous_failure.failure_id if previous_failure else None
                ),
                provider=self.provider.provider_name,
                model=self.provider.model_name,
                candidate_digest=candidate_digest,
                candidate_field_digests=field_digests,
                candidate_field_lengths=field_lengths,
                candidate_artifact=candidate_artifact,
                edit_artifact=edit_artifact,
                edit_provider_call=edit_provider_call,
                edit_decode=edit_decode,
                edit_validation=edit_validation,
                edit_reused=edit_reused,
                test_provider_call=test_provider_call,
                test_decode=test_decode,
                test_validation=test_validation,
                proposal_execution=proposal_execution,
                patch_proof=patch_proof,
                repair_id=proposal.repair_id if proposal else None,
                failure=failure,
                proof_id=proof.proof_id if proof else None,
                workspace_id=str(workspace_id) if workspace_id else None,
                edit_provider_completion=edit_completion,
                test_provider_completion=test_completion,
                started_at=attempt_started_at,
                completed_at=completed_at,
                duration_seconds=monotonic() - attempt_started,
            ))

            unchanged = repository_digest(self.repository_root) == original_digest
            if proof is not None and unchanged:
                result: RepairRunResult = RepairRunSucceeded(
                    run_id=run_id,
                    trace_id=request.repair_context.trace_id,
                    boundary_id=request.repair_context.boundary_id,
                    evidence_ids=request.repair_context.evidence_ids,
                    provider=self.provider.provider_name,
                    model=self.provider.model_name,
                    total_attempts=attempt_number,
                    successful_attempt=attempt_number,
                    attempts=attempts,
                    final_proposal=proposal,
                    patch_proof=proof,
                    started_at=started_at,
                    completed_at=completed_at,
                    duration_seconds=monotonic() - started,
                    original_repository_unchanged=True,
                )
                if evidence_path is not None:
                    persist_repair_run(result, evidence_path)
                return result

            # ---------- ROUTE NEXT ATTEMPT ----------
            if failed_call == "edit":
                edit_revision_due = True
                test_revision_due = False
                accepted_edit = None
                accepted_patch = None
            elif failed_call == "test":
                edit_revision_due = False
                test_revision_due = True
            else:
                edit_revision_due = False
                test_revision_due = False
            previous_failure = failure

        completed_at = datetime.now(timezone.utc)
        result = RepairRunFailed(
            run_id=run_id,
            trace_id=request.repair_context.trace_id,
            boundary_id=request.repair_context.boundary_id,
            evidence_ids=request.repair_context.evidence_ids,
            provider=self.provider.provider_name,
            model=self.provider.model_name,
            total_attempts=MAX_PROVIDER_ATTEMPTS,
            attempts=attempts,
            final_failure=previous_failure,
            safe_failure_summary=(
                f"{previous_failure.failure_stage}: "
                f"{_safe_text(previous_failure.message, 800)}"
            ),
            started_at=started_at,
            completed_at=completed_at,
            duration_seconds=monotonic() - started,
            original_repository_unchanged=(
                repository_digest(self.repository_root) == original_digest
            ),
        )
        if evidence_path is not None:
            persist_repair_run(result, evidence_path)
        return result
