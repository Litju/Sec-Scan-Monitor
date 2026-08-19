from __future__ import annotations

import ast
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"


def _python_files(directory: Path) -> list[Path]:
    return sorted(directory.rglob("*.py"))


def test_domain_has_no_runtime_adapter_imports() -> None:
    forbidden = {"fastapi", "sqlalchemy", "temporalio", "docker", "subprocess"}
    for path in _python_files(SRC / "secscan" / "platform" / "domain"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert all(alias.name.split(".")[0] not in forbidden for alias in node.names)
            if isinstance(node, ast.ImportFrom) and node.module:
                assert node.module.split(".")[0] not in forbidden


def test_agent_modules_do_not_construct_findings() -> None:
    for path in _python_files(SRC / "secscan" / "platform" / "agents"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        assert not any(isinstance(node, ast.Name) and node.id == "Finding" for node in ast.walk(tree))
