#!/usr/bin/env python3
"""Serve the trusted local M7.2 controller. Does not run until the UI requests it."""
from pathlib import Path

import uvicorn

from gauntlet.core.config import NebiusConfig
from gauntlet.demo.m72_web import create_live_demo_app
from gauntlet.llm.nebius import NebiusTokenFactoryClient
from gauntlet.remediation.provider import NebiusNemotronRemediationProvider


ROOT = Path(__file__).resolve().parents[1]


def provider():
    return NebiusNemotronRemediationProvider(
        NebiusTokenFactoryClient(NebiusConfig.from_environment())
    )


app = create_live_demo_app(ROOT, provider)


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8072)
