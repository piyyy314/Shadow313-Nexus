"""Executed outside the source checkout using only installed-wheel modules."""

import importlib
import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from importlib.metadata import version
from importlib.resources import files
from pathlib import Path

PROFILE = os.environ.get("WHEEL_PROFILE", "core")


class InstalledWheelChecks(unittest.TestCase):
    def test_identity_and_all_import_roots_are_in_environment(self):
        self.assertEqual(version("shadow313-nexus"), os.environ["WHEEL_VERSION"])
        for name in ("shadow313", "shadow313_sdk", "shadow313_platform", "nexus_toolkit"):
            module = importlib.import_module(name)
            paths = list(module.__path__)
            self.assertTrue(paths)
            for path in paths:
                self.assertTrue(
                    Path(path).resolve().is_relative_to(Path(sys.prefix).resolve()), path
                )

    def test_packaged_resources(self):
        for package, paths in {
            "shadow313.plugins.custom_ai_threat_analyzer": ["plugin.json", "plugin.shadow313sig"],
            "shadow313.v4.satellite": ["data/advisories.json"],
            "shadow313.v4.pqc_js": ["relay.js"],
        }.items():
            for path in paths:
                self.assertTrue(files(package).joinpath(path).is_file(), f"{package}/{path}")

    def test_installed_console_entrypoint_and_subcommand_parsers(self):
        script = Path(sys.executable).parent / ("shadow313.exe" if os.name == "nt" else "shadow313")
        for args in (
            ["--version"],
            ["--help"],
            ["cicd", "--help"],
            ["network", "--help"],
            ["defense", "--help"],
            ["docs", "--help"],
        ):
            result = subprocess.run(
                [str(script), *args],
                capture_output=True,
                text=True,
                encoding="utf-8",
                timeout=30,
                check=True,
            )
            self.assertIn("shadow313", result.stdout.lower())

    def test_sqlite_handles_close_before_removal(self):
        from shadow313.v2.threat_intel.threat_intel import ThreatIntelDB

        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "test.db"
            with ThreatIntelDB(path) as db:
                self.assertEqual(db.stats()["ioc_ip"], 0)
            path.unlink()
            self.assertFalse(path.exists())

    def test_receipt_roundtrip_tampering_and_explicit_backend(self):
        from shadow313.core.binding_sdk.binder import AppIdentity, Binder313, BindReceipt

        binder = Binder313(AppIdentity(app_id="wheel-fixture", app_name="Wheel fixture"))
        payload = {"fixture": True}
        receipt = binder.bind(payload)
        expected = (
            "SPHINCS+-SHAKE-128f"
            if PROFILE == "pqc"
            else ("HMAC-SHA3-256 (local symmetric authentication)")
        )
        self.assertEqual(receipt.signature_algorithm, expected)
        self.assertTrue(binder.verify(BindReceipt(**receipt.to_dict()), payload)["valid"])
        self.assertFalse(binder.verify(replace(receipt, signature="00"), payload)["valid"])
        # Corrupt a valid hex nibble without changing the signature's shape.
        flipped = "0" if receipt.signature[0] != "0" else "1"
        tampered_signature = flipped + receipt.signature[1:]
        self.assertEqual(len(tampered_signature), len(receipt.signature))
        self.assertNotEqual(tampered_signature, receipt.signature)
        self.assertFalse(
            binder.verify(replace(receipt, signature=tampered_signature), payload)["valid"]
        )
        self.assertFalse(binder.verify(receipt, {"fixture": False})["valid"])

    @unittest.skipUnless(PROFILE == "api", "API extra not selected for this job")
    def test_api_auth_body_limit_and_disabled_scan(self):
        from fastapi.testclient import TestClient

        from shadow313.api.server import create_app

        with TestClient(create_app(api_key="wheel-fixture")) as client:
            self.assertEqual(client.post("/api/scan/recon", json={}).status_code, 401)
            headers = {"X-API-Key": "wheel-fixture"}
            self.assertEqual(
                client.post("/api/scan/recon", json={}, headers=headers).status_code, 503
            )
            self.assertEqual(
                client.post("/api/detect", content=b"x" * 1_048_577, headers=headers).status_code,
                413,
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
