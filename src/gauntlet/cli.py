import argparse
import asyncio
import ipaddress
import logging
from urllib.parse import urlsplit
import httpx
from gauntlet.attacks.indirect_prompt_injection import IndirectPromptInjectionAttack
from gauntlet.tracing.renderer import render_trace

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

def main() -> int:
    logging.basicConfig(level=logging.WARNING)
    parser = argparse.ArgumentParser(description="Gauntlet local M1 attack harness")
    commands = parser.add_subparsers(dest="command", required=True)
    sub = commands.add_parser("attack")
    sub.add_argument("--target", type=local_target, required=True)
    args = parser.parse_args()
    try:
        return asyncio.run(attack(args.target))
    except (httpx.HTTPError, ValueError, KeyError) as exc:
        logger.error("Attack could not complete: %s", exc)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
