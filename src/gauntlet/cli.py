import argparse
import asyncio
import ipaddress
import logging
from pathlib import Path
import sys
from urllib.parse import urlsplit
import httpx
from gauntlet.attacks.indirect_prompt_injection import IndirectPromptInjectionAttack
from gauntlet.tracing.renderer import render_trace
from gauntlet.patching.renderer import render_patch_proof
from gauntlet.patching.workflow import legacy_prove_test_double
from gauntlet.patching.planner import plan_patch
from gauntlet.sandbox.orchestrator import SandboxRepairOrchestrator
from gauntlet.sandbox.renderer import render_sandbox_result
from victims.customer_support.app import create_app
from gauntlet.core.config import NebiusConfig
from gauntlet.llm.nebius import NebiusTokenFactoryClient
from gauntlet.remediation.fake import FakeRemediationProvider
from gauntlet.remediation.provider import NebiusNemotronRemediationProvider
from gauntlet.remediation.workflow import generate_repair_proposal

logger = logging.getLogger(__name__)

def local_target(value: str) -> str:
    parsed = urlsplit(value)
    try:
        local = parsed.hostname == "localhost" or ipaddress.ip_address(parsed.hostname or "").is_loopback
        port = parsed.port or 8001
    except ValueError:
        local = False
        port = 8001
    if parsed.scheme != "http" or not local or parsed.username or parsed.password or parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise argparse.ArgumentTypeError("M1 accepts only a loopback HTTP origin for the local demo")
    # Pin localhost to loopback and disable HTTP proxy environment variables below.
    host = "127.0.0.1" if parsed.hostname == "localhost" else parsed.hostname
    if ":" in host:
        host = f"[{host}]"
    return f"http://{host}:{port}"

async def attack(target: str) -> int:
    async with httpx.AsyncClient(base_url=target, timeout=15, trust_env=False, follow_redirects=False) as client:
        result = await IndirectPromptInjectionAttack(client).run()
    print("Target: CustomerSupport.Vulnerable")
    print(f"URL: {target}\nAttack: Indirect Prompt Injection\nModel: deterministic simulator (no live LLM)")
    print("\nEXPLOIT CONFIRMED" if result.succeeded else "\nEXPLOIT NOT CONFIRMED")
    if result.trace is not None:
        print("\n" + render_trace(result.trace))
    return 0 if result.succeeded else 1


async def legacy_prove(target: str, *, run_tests: bool = True) -> int:
    async with httpx.AsyncClient(
        base_url=target, timeout=15, trust_env=False, follow_redirects=False
    ) as client:
        before = await IndirectPromptInjectionAttack(client).run()
    if before.trace is None or not before.succeeded:
        raise ValueError("M3 requires a serialized M2 trace with a confirmed exploit")

    suite_passed = None
    if run_tests:
        process = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "pytest", "-q",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        output, _ = await process.communicate()
        suite_passed = process.returncode == 0
        if not suite_passed:
            logger.error("Regression suite failed:\n%s", output.decode(errors="replace"))

    # Serialization is an intentional boundary: M3 consumes the M2 artifact,
    # rather than diagnosing the victim independently.
    proof = await legacy_prove_test_double(
        before.trace.model_dump_json(), test_suite_passed=suite_passed
    )
    print(render_patch_proof(proof))
    return 0 if proof.verified else 1


async def propose_repair(*, live: bool, repository_root: Path | None = None) -> int:
    root = (repository_root or Path.cwd()).resolve()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app()), base_url="http://m2-local"
    ) as client:
        before = await IndirectPromptInjectionAttack(client).run()
    if before.trace is None or not before.succeeded:
        raise ValueError("M3.1 requires the confirmed M2 trace")
    provider = (
        NebiusNemotronRemediationProvider(
            NebiusTokenFactoryClient(NebiusConfig.from_environment())
        ) if live else FakeRemediationProvider()
    )
    proposal = await generate_repair_proposal(
        before.trace.model_dump_json(), root, provider
    )
    print(proposal.model_dump_json(indent=2))
    return 0


async def sandbox_prove(repository_root: Path | None = None) -> int:
    root = (repository_root or Path.cwd()).resolve()
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app()), base_url="http://m2-local"
    ) as client:
        before = await IndirectPromptInjectionAttack(client).run()
    if before.trace is None or not before.succeeded:
        raise ValueError("M4 requires the confirmed M2 trace")
    plan = plan_patch(before.trace.model_dump_json())
    result = await SandboxRepairOrchestrator(root).run(plan)
    print(render_sandbox_result(result))
    return 0 if result.succeeded else 1

def main() -> int:
    logging.basicConfig(level=logging.WARNING)
    parser = argparse.ArgumentParser(description="Gauntlet local attack and proof harness")
    commands = parser.add_subparsers(dest="command", required=True)
    sub = commands.add_parser("attack")
    sub.add_argument("--target", type=local_target, required=True)
    proof = commands.add_parser("legacy-prove")
    proof.add_argument("--target", type=local_target, required=True)
    commands.add_parser("propose-repair")
    commands.add_parser("nebius-repair-smoke")
    commands.add_parser("sandbox-prove")
    args = parser.parse_args()
    try:
        if args.command == "attack":
            return asyncio.run(attack(args.target))
        if args.command == "legacy-prove":
            return asyncio.run(legacy_prove(args.target))
        if args.command == "propose-repair":
            return asyncio.run(propose_repair(live=False))
        if args.command == "nebius-repair-smoke":
            return asyncio.run(propose_repair(live=True))
        return asyncio.run(sandbox_prove())
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        logger.error("Command could not complete: %s", exc)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
