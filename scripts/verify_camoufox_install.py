#!/usr/bin/env python3
"""Fail-fast verification for the pinned Camoufox browser installation."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001 - console setup is best effort
        pass


# A SHA suffix is optional. Camoufox publishes a different archive digest per
# OS/architecture, so the shared project spec intentionally pins build only.
_SHA_RE = re.compile(r"^(?P<version>.+)-(?P<sha>[0-9a-fA-F]{8,64})$")


def _read_spec(path: Path) -> tuple[str, str, str | None]:
    lines = [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if len(lines) != 1:
        raise ValueError(f"browser spec must contain exactly one non-empty line: {path}")
    spec = lines[0].lower()
    parts = spec.split("/")
    if len(parts) != 3 or not all(parts):
        raise ValueError(
            "browser spec must be repo/channel/version-build[-sha8], "
            f"got {spec!r}"
        )
    version_build = parts[2]
    match = _SHA_RE.fullmatch(version_build)
    if match:
        version_build = match.group("version")
        expected_sha = match.group("sha").lower()
    else:
        expected_sha = None
    return spec, "/".join(parts[:2] + [version_build]), expected_sha


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--spec-file",
        type=Path,
        default=Path(__file__).resolve().parents[1] / "camoufox-browser-spec.txt",
    )
    args = parser.parse_args()

    try:
        expected_spec, expected_channel_path, expected_sha = _read_spec(args.spec_file)
        from camoufox.multiversion import get_active_path, list_installed
        from camoufox.pkgman import launch_path

        active_path = get_active_path()
        if active_path is None:
            raise RuntimeError("no active Camoufox browser is configured")

        active = next((item for item in list_installed() if item.is_active), None)
        if active is None:
            raise RuntimeError("Camoufox active path is not present in installed metadata")

        actual_channel_path = active.channel_path.lower()
        if actual_channel_path != expected_channel_path:
            raise RuntimeError(
                f"active browser mismatch: expected {expected_channel_path}, "
                f"got {actual_channel_path}"
            )
        if expected_sha:
            actual_sha = (active.sha256 or "").lower()
            if not actual_sha.startswith(expected_sha):
                raise RuntimeError(
                    f"browser SHA mismatch: expected prefix {expected_sha}, "
                    f"got {actual_sha[:16] or '<missing>'}"
                )

        executable = Path(launch_path(active_path))
        if not executable.is_file():
            raise RuntimeError(f"Camoufox executable is missing: {executable}")
    except Exception as exc:  # noqa: BLE001 - convert all setup failures to one clear exit
        print(f"ERROR: Camoufox verification failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    print(f"OK: Camoufox {expected_spec} installed at {executable}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
