#!/usr/bin/env python3
"""Run one M7.7 Nemotron generation call and retain deterministic evidence."""

import asyncio
import os
from pathlib import Path
from uuid import uuid4

from gauntlet.adversarial.p300 import p300_adversarial_request
from gauntlet.adversarial.p300_workflow import run_p300_adversarial_generation
from gauntlet.adversarial.provider import (
    NEMOTRON_ADVERSARIAL_BASE_URL,
    NebiusNemotronAdversarialProvider,
)
from gauntlet.contracts.p300 import p300_contract
from gauntlet.core.config import NebiusConfig
from gauntlet.llm.nebius import NEMOTRON_SUPER_MODEL, NebiusTokenFactoryClient


ROOT = Path(__file__).resolve().parents[1]


def _local_api_key() -> str | None:
    key = os.getenv("NEBIUS_API_KEY")
    if key:
        return key
    path = ROOT / ".env"
    if not path.exists():
        return None
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        name, value = line.split("=", 1)
        if name.strip() != "NEBIUS_API_KEY":
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        return value or None
    return None


async def main() -> int:
    api_key = _local_api_key()
    if not api_key:
        raise ValueError("NEBIUS_API_KEY is not configured")
    client = NebiusTokenFactoryClient(NebiusConfig(
        api_key=api_key,
        base_url=NEMOTRON_ADVERSARIAL_BASE_URL,
        model=NEMOTRON_SUPER_MODEL,
    ))
    provider = NebiusNemotronAdversarialProvider(client)
    contract = p300_contract(autonomous_limit_minor=5_000)
    request = p300_adversarial_request(contract, scenario_count=5)
    path = (
        ROOT / "evidence" / "adversarial-generation"
        / f"live-{uuid4()}.json"
    )
    evidence = await run_p300_adversarial_generation(
        provider=provider,
        request=request,
        contract=contract,
        repository_root=ROOT,
        evidence_path=path,
        credential_values=(api_key,),
    )
    print(f"Evidence: {path.relative_to(ROOT)}")
    print(f"Status: {evidence.final_status}")
    print(f"Scenarios retained: {len(evidence.scenarios)}")
    print(f"Repository immutability: {evidence.repository_immutability}")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
