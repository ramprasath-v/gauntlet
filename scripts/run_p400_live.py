#!/usr/bin/env python3
"""Run one explicitly authorized P400 live detection call and retain evidence."""

import asyncio
import os
from pathlib import Path

from gauntlet.contracts.p400_live import (
    P400_LIVE_BASE_URL,
    P400_LIVE_MODEL,
    NebiusP400LiveProvider,
    run_live_p400_detection,
)
from gauntlet.core.config import NebiusConfig
from gauntlet.llm.nebius import NebiusTokenFactoryClient


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


async def main() -> int:
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
        raise ValueError("P400 live detection requires the configured Kimi endpoint")
    if model != P400_LIVE_MODEL:
        raise ValueError(f"P400 live detection requires {P400_LIVE_MODEL}")
    client = NebiusTokenFactoryClient(NebiusConfig(
        api_key=api_key, base_url=base_url, model=model,
    ))
    evidence, path = await run_live_p400_detection(
        provider=NebiusP400LiveProvider(client),
        repository_root=ROOT,
        evidence_directory=ROOT / "evidence" / "p400-live",
        credential_values=(api_key,),
    )
    print(f"Evidence: {path.relative_to(ROOT)}")
    print(f"Provider requests: {evidence.provider_request_count}")
    print(f"Provider status: {evidence.provider_status}")
    print(f"Final status: {evidence.final_status}")
    print(f"Repository immutability: {evidence.repository_immutability}")
    if evidence.evaluation is not None:
        print(f"P400: {evidence.evaluation.status.value}")
        print(
            "Violation: "
            f"{evidence.evaluation.evidence[0].observations['violation_code']}"
        )
    elif evidence.provider_error_type:
        print(f"Provider failure: {evidence.provider_error_type}")
    return 0 if evidence.final_status == "DETECTED" else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
