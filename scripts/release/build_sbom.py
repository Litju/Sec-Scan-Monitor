"""Build a deterministic CycloneDX inventory from committed lockfiles."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any
from uuid import UUID


def _python_components(lock_path: Path) -> list[dict[str, Any]]:
    components: list[dict[str, Any]] = []
    for raw_line in lock_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "==" not in line:
            continue
        name, version = (part.strip() for part in line.split("==", 1))
        version = version.split(";", 1)[0].rstrip("\\").strip()
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name) or not version:
            raise ValueError(f"invalid Python lock entry: {line!r}")
        components.append(
            {
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:pypi/{name.casefold().replace('_', '-')}@{version}",
                "scope": "required",
            }
        )
    return components


def _npm_components(lock_path: Path) -> list[dict[str, Any]]:
    payload = json.loads(lock_path.read_text(encoding="utf-8"))
    packages = payload.get("packages")
    if not isinstance(packages, dict):
        raise ValueError(f"npm lockfile has no packages map: {lock_path}")
    components: list[dict[str, Any]] = []
    for package_path, metadata in packages.items():
        if package_path == "" or not isinstance(metadata, dict):
            continue
        name = metadata.get("name")
        version = metadata.get("version")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        components.append(
            {
                "type": "library",
                "name": name,
                "version": version,
                "purl": f"pkg:npm/{name}@{version}",
                "scope": "optional" if metadata.get("dev") else "required",
            }
        )
    return components


def build_bom(repo_root: Path) -> dict[str, Any]:
    components = _python_components(repo_root / "analysis" / "requirements.lock")
    for app in ("web", "tui"):
        components.extend(_npm_components(repo_root / "apps" / app / "package-lock.json"))
    components.sort(key=lambda item: (item["type"], item["name"].casefold(), item["version"], item["purl"]))
    identity = "\n".join(item["purl"] for item in components).encode("utf-8")
    digest = hashlib.sha256(identity).hexdigest()
    serial = f"urn:uuid:{UUID(digest[:32])}"
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "SecScanMonitor",
                "version": "0.3.0",
            },
            "tools": [{"vendor": "SecScanMonitor", "name": "build_sbom.py", "version": "0.2.0"}],
        },
        "components": components,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    lockfiles = [root / "analysis" / "requirements.lock", *(root / "apps" / app / "package-lock.json" for app in ("web", "tui"))]
    if not all(path.is_file() for path in lockfiles):
        raise SystemExit("repository root is missing the committed lockfiles")
    output = args.output if args.output.is_absolute() else root / args.output
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(build_bom(root), indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
