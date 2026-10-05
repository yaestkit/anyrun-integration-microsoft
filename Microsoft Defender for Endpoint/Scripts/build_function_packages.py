#!/usr/bin/env python3
"""Build deterministic Function App ZIP files from the checked-in sources."""

from __future__ import annotations

import argparse
import hashlib
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONNECTORS = {
    "sandbox": (
        ROOT / "ANYRUN-Sandbox-MDE" / "src",
        ROOT / "ANYRUN-Sandbox-MDE" / "Function App" / "ANYRUN-Sandbox-MDE-FA.zip",
    ),
    "feeds": (
        ROOT / "ANYRUN-TI-Feeds-MDE" / "src",
        ROOT / "ANYRUN-TI-Feeds-MDE" / "Function App" / "ANYRUN-Feeds-MDE-FA.zip",
    ),
}
FIXED_TIMESTAMP = (2026, 1, 1, 0, 0, 0)


def build(source: Path, destination: Path) -> str:
    files = sorted(
        path
        for path in source.rglob("*")
        if path.is_file() and path.name != ".DS_Store" and "__pycache__" not in path.parts
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in files:
            relative = path.relative_to(source).as_posix()
            info = zipfile.ZipInfo(relative, FIXED_TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, path.read_bytes())
    return hashlib.sha256(destination.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("connectors", nargs="*")
    args = parser.parse_args()
    connectors = args.connectors or list(CONNECTORS)
    unknown = sorted(set(connectors) - set(CONNECTORS))
    if unknown:
        parser.error(f"unknown connector(s): {', '.join(unknown)}")
    for connector in connectors:
        source, destination = CONNECTORS[connector]
        digest = build(source, destination)
        print(f"{connector}: {destination.relative_to(ROOT)} SHA256={digest}")


if __name__ == "__main__":
    main()
