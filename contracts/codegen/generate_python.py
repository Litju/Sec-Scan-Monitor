#!/usr/bin/env python3
"""
FL-001 scaffold placeholder for Python contract model generation.

This file intentionally does not implement downstream code generation logic.
It exists only to establish the approved contracts/codegen package shape for
later milestones.
"""

from __future__ import annotations

from pathlib import Path


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    schemas_dir = repo_root / "contracts" / "schemas"
    print("FL-001 scaffold only.")
    print(f"Schemas directory: {schemas_dir}")
    print("Python code generation begins in FL-002.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
