"""Live M4.2 repair-loop runner (test-only helper, not part of the product).

Runs the full two-call remediation loop against a live Nebius model:
attack -> trace -> edit call -> validate -> test call -> validate ->
sandbox proof, with up to three attempts and per-call retries.

Usage (from the repository root, on the two-call-remediation branch):
    NEBIUS_API_KEY=... NEBIUS_BASE_URL=... NEBIUS_MODEL=... \
        .venv/bin/python scripts/live_m42_repair.py

The model must be one of the explicitly approved live remediation models.
"""
import asyncio
import sys
from pathlib import Path

import httpx

from gauntlet.attacks.indirect_prompt_injection import IndirectPromptInjectionAttack
from gauntlet.core.config import NebiusConfig
from gauntlet.llm.nebius import NebiusTokenFactoryClient
from gauntlet.remediation.provider import NebiusNemotronRemediationProvider
from gauntlet.remediation.retry import M42RepairOrchestrator
from gauntlet.remediation.retry_models import RepairRunFailed, RepairRunSucceeded
from victims.customer_support.app import create_app


async def main() -> int:
    root = Path.cwd().resolve()
    config = NebiusConfig.from_environment().require_complete()
    print(f"Model: {config.model}")

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app()), base_url="http://m2-local"
    ) as client:
        before = await IndirectPromptInjectionAttack(client).run()
    if before.trace is None or not before.succeeded:
        raise ValueError("M4.2 live run requires the confirmed M2 trace")

    provider = NebiusNemotronRemediationProvider(
        NebiusTokenFactoryClient(config)
    )
    evidence_path = root / "evidence" / "live-m42-repair-run.json"
    result = await M42RepairOrchestrator(root, provider).run(
        before.trace.model_dump_json(), evidence_path=evidence_path
    )

    for attempt in result.attempts:
        print(
            f"\nAttempt {attempt.attempt}: "
            f"edit(call={attempt.edit_provider_call}, decode={attempt.edit_decode}, "
            f"validation={attempt.edit_validation}, reused={attempt.edit_reused}) "
            f"test(call={attempt.test_provider_call}, decode={attempt.test_decode}, "
            f"validation={attempt.test_validation}) "
            f"execution={attempt.proposal_execution} proof={attempt.patch_proof}"
        )
        if attempt.failure is not None:
            failure = attempt.failure
            print(
                f"  failed_call={failure.diagnostics.get('failed_call')} "
                f"stage={failure.failure_stage} code={failure.failure_code}"
            )
            print(f"  {failure.message}")

    if isinstance(result, RepairRunSucceeded):
        print(
            f"\nPATCH VERIFIED on attempt {result.successful_attempt} "
            f"({result.total_attempts} attempt(s)). "
            f"Evidence: {evidence_path}"
        )
        return 0
    assert isinstance(result, RepairRunFailed)
    print(
        f"\nREPAIR FAILED after {result.total_attempts} attempts. "
        f"Final: stage={result.final_failure.failure_stage} "
        f"code={result.final_failure.failure_code}. "
        f"Evidence: {evidence_path}"
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
