#!/usr/bin/env python3
"""Validate the Python versions supported by the pinned runtime stack."""

from __future__ import annotations

import sys


SUPPORTED = {(3, 11), (3, 12), (3, 13)}


def main() -> int:
    current = (sys.version_info.major, sys.version_info.minor)
    rendered = f"{current[0]}.{current[1]}"
    if current not in SUPPORTED:
        allowed = ", ".join(f"{major}.{minor}" for major, minor in sorted(SUPPORTED))
        print(f"ERROR: Python {rendered} is unsupported; use {allowed}.", file=sys.stderr)
        return 1
    print(f"OK: Python {rendered} is supported")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
