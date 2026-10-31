"""Build only reviewed public files and keep distributable Python resources."""

import json
import subprocess
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class PublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        subprocess.run(
            ["node", "scripts/build-site.cjs"], cwd=ROOT, check=True, capture_output=True
        )
        cls.output = ROOT / "site-dist"

    def test_output_is_exact_allowlist(self):
        config = json.loads((ROOT / "vercel.json").read_text())
        self.assertEqual(config["outputDirectory"], "site-dist")
        self.assertEqual(config["buildCommand"], "node scripts/build-site.cjs")
        expected = set(json.loads((ROOT / "site/public-files.json").read_text())["files"]) | {
            ".nojekyll"
        }
        actual = {str(p.relative_to(self.output)) for p in self.output.rglob("*") if p.is_file()}
        self.assertEqual(actual, expected)
        for part in (
            "docs-archive",
            "local_bundle",
            "notes",
            "audit-results",
            "shadow313",
            "api",
            "server",
            ".github",
        ):
            self.assertFalse((self.output / part).exists())
        for name in (
            "README.md",
            "requirements.txt",
            ".env.example",
            "docs/session-exports",
            "docs/shadow313-file-portal.html",
            "docs/shadow313-analysis.html",
        ):
            self.assertFalse((self.output / name).exists())

    def test_demos_get_notice_and_forms_do_not_fake_success(self):
        self.assertIn(
            "publication-notice", (self.output / "docs/S313-Nexus-Dashboard-v3.html").read_text()
        )
        contact = (self.output / "docs/contact.html").read_text()
        home = (self.output / "index.html").read_text()
        for text in (contact, home):
            self.assertIn("/assets/forms.js", text)
            self.assertIn('name="consent"', text)
        self.assertNotIn("function handleSubmit", contact)
        self.assertNotIn("Your data never leaves your machine.", home)

    def test_package_discovery_and_resource_rules_are_explicit(self):
        settings = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["setuptools"]
        self.assertIn("nexus_toolkit*", settings["packages"]["find"]["include"])
        self.assertIn("shadow313*", settings["packages"]["find"]["include"])
        self.assertIn(
            "plugin.json", settings["package-data"]["shadow313.plugins.custom_ai_threat_analyzer"]
        )
        self.assertNotIn("recursive-include docs", (ROOT / "MANIFEST.in").read_text())
        self.assertIn("prune docs-archive", (ROOT / "MANIFEST.in").read_text())

    def test_workflow_handoff_targets_output_not_repo(self):
        patch = (ROOT / "site/github-pages-isolation.patch").read_text()
        self.assertIn("+          path: site-dist", patch)
        self.assertIn("node scripts/build-site.cjs", patch)


if __name__ == "__main__":
    unittest.main()
