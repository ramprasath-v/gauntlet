#!/usr/bin/env python3
"""Build the offline M7.1 evidence-replay page."""
import argparse
from pathlib import Path

from gauntlet.demo.m7 import DemoEvidenceError, generate_demo


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", default="demo/gauntlet-m7.html",
        help="Repository-relative or absolute output path",
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        output = generate_demo(root, Path(args.output))
    except DemoEvidenceError as exc:
        parser.exit(1, f"M7.1 evidence validation failed: {exc}\n")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
