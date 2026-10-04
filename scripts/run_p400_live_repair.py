#!/usr/bin/env python3
"""Run one explicitly authorized Kimi P400 repair request and trusted proof."""

import argparse
import asyncio
import os
from pathlib import Path

from gauntlet.contracts.p400_live import P400_LIVE_BASE_URL, P400_LIVE_MODEL
from gauntlet.contracts.p400_live_repair import (
    _safe_error_message,
    run_live_p400_repair,
    verify_retained_p400_live_repair,
)
from gauntlet.core.config import NebiusConfig
from gauntlet.llm.nebius import NebiusTokenFactoryClient
from gauntlet.remediation.provider import NebiusNemotronRemediationProvider


ROOT = Path(__file__).resolve().parents[1]


def _local_config_value(name: str) -> str | None:
    configured = os.getenv(name)
    if configured:
        return configured
    path = ROOT / ".env"
    if not path.exists():
        return None
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, value = line.split("=", 1)
        if key.strip() != name:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        return value or None
    return None


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run one no-retry P400 live repair experiment."
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument(
        "--attack-evidence",
        type=Path,
        help="Integrity-bound gauntlet.p400-live-detection.v1 artifact",
    )
    mode.add_argument(
        "--candidate-evidence",
        type=Path,
        help=(
            "Integrity-bound gauntlet.p400-live-repair.v1 artifact to verify "
            "offline without a provider request"
        ),
    )
    return parser.parse_args()


async def main() -> int:
    args = _arguments()
    if args.candidate_evidence is not None:
        evidence_path = (
            args.candidate_evidence
            if args.candidate_evidence.is_absolute()
            else ROOT / args.candidate_evidence
        )
        try:
            assessment = await verify_retained_p400_live_repair(
                evidence_path=evidence_path,
                repository_root=ROOT,
            )
        except Exception as error:
            substage = getattr(error, "substage", "evidence_load")
            original = getattr(error, "original_error", error)
            print("Provider requests: 0")
            print(f"Failure substage: {substage}")
            print(f"Error type: {type(original).__name__}")
            print(f"Error: {_safe_error_message(original, ())}")
            return 1
        print("Provider requests: 0")
        print(f"Verdict: {assessment.verdict}")
        print(f"Patch digest: {assessment.patch_digest}")
        print(f"Cleanup: {assessment.cleanup}")
        print(f"Repository immutability: {assessment.repository_immutability}")
        return 0 if assessment.verdict == "VERIFIED" else 1

    attack_path = (
        args.attack_evidence
        if args.attack_evidence.is_absolute()
        else ROOT / args.attack_evidence
    )
    api_key = _local_config_value("NEBIUS_API_KEY")
    base_url = _local_config_value("NEBIUS_BASE_URL")
    model = _local_config_value("NEBIUS_MODEL")
    missing = [name for name, value in (
        ("NEBIUS_API_KEY", api_key),
        ("NEBIUS_BASE_URL", base_url),
        ("NEBIUS_MODEL", model),
    ) if not value]
    if missing:
        raise ValueError("Missing Nebius configuration: " + ", ".join(missing))
    if base_url != P400_LIVE_BASE_URL:
        raise ValueError("P400 live repair requires the configured Kimi endpoint")
    if model != P400_LIVE_MODEL:
        raise ValueError(f"P400 live repair requires {P400_LIVE_MODEL}")
    client = NebiusTokenFactoryClient(NebiusConfig(
        api_key=api_key, base_url=base_url, model=model,
    ))
    evidence, path = await run_live_p400_repair(
        live_attack_path=attack_path,
        provider=NebiusNemotronRemediationProvider(client),
        repository_root=ROOT,
        evidence_directory=ROOT / "evidence" / "p400-live-repair",
        credential_values=(api_key,),
    )
    print(f"Evidence: {path.relative_to(ROOT)}")
    print(f"Provider requests: {evidence.provider_request_count}")
    print(f"Candidate validation: {evidence.candidate_validation}")
    print(f"Live repair status: {evidence.live_repair_status}")
    print(f"Repository immutability: {evidence.repository_immutability}")
    print(
        "Historical evidence immutability: "
        f"{evidence.historical_evidence_immutability}"
    )
    if evidence.validation_failure:
        print(
            "Failure: "
            f"{evidence.validation_failure.get('failure_stage')} / "
            f"{evidence.validation_failure.get('failure_code')}"
        )
    return 0 if evidence.live_repair_status == "VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
