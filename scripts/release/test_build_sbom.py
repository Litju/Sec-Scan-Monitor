from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("build_sbom.py")
SPEC = importlib.util.spec_from_file_location("build_sbom", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class SbomTests(unittest.TestCase):
    def test_uv_lock_continuations_and_markers_are_normalized(self) -> None:
        with tempfile.TemporaryDirectory(prefix="SecScanMonitor-") as raw_root:
            lock_path = Path(raw_root) / "requirements.lock"
            lock_path.write_text(
                """cbor2==6.1.4 \\
    --hash=sha256:fixture
pywin32==312 ; sys_platform == 'win32' \\
    --hash=sha256:fixture
""",
                encoding="utf-8",
            )

            components = MODULE._python_components(lock_path)

            self.assertEqual(
                [(component["name"], component["version"]) for component in components],
                [("cbor2", "6.1.4"), ("pywin32", "312")],
            )

    def test_lockfile_inventory_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory(prefix="SecScanMonitor-") as raw_root:
            root = Path(raw_root)
            (root / "analysis").mkdir()
            (root / "apps" / "web").mkdir(parents=True)
            (root / "analysis" / "requirements.lock").write_text("pydantic==2.0.0\n", encoding="utf-8")
            (root / "apps" / "web" / "package-lock.json").write_text(
                json.dumps({"packages": {"": {}, "node_modules/react": {"name": "react", "version": "1.0.0"}}}),
                encoding="utf-8",
            )
            first = MODULE.build_bom(root)
            second = MODULE.build_bom(root)
            self.assertEqual(first, second)
            self.assertEqual(first["bomFormat"], "CycloneDX")
            self.assertEqual(len(first["components"]), 2)


if __name__ == "__main__":
    unittest.main()
