#!/usr/bin/env python3
"""Serve the M8 live-and-replay product demo on loopback."""

from pathlib import Path

import uvicorn

from gauntlet.demo.m8_web import create_m8_demo_app


ROOT = Path(__file__).resolve().parents[1]
app = create_m8_demo_app(ROOT)


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8080)
