#!/usr/bin/env python3
"""Print the canary values for a seed as JSON: python3 canary_values.py --seed SEED"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from otelpii.canary import canary_values  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print canary values for a seed as JSON.")
    parser.add_argument("--seed", required=True, help="per-run seed, e.g. a UUID ([A-Za-z0-9_-]+)")
    args = parser.parse_args(argv)
    try:
        values = canary_values(args.seed)
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(values, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
