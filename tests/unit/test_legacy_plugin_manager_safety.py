"""Regression tests for the disabled legacy in-process plugin loader."""

import json

from shadow313.core.plugin_manager import PluginManager
from shadow313.modules.plugins.signing import PluginArtifactSigner


def test_legacy_plugin_manager_verifies_full_artifact_and_never_imports(tmp_path):
    plugin_root = tmp_path / "plugins"
    plugin_dir = plugin_root / "legacy-demo"
    plugin_dir.mkdir(parents=True)
    marker = tmp_path / "imported.txt"
    (plugin_dir / "plugin.json").write_text(
        json.dumps({"name": "legacy-demo", "hooks": ["recon.post"]}),
        encoding="utf-8",
    )
    (plugin_dir / "analyzer.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).write_text('executed')\n",
        encoding="utf-8",
    )
    signer = PluginArtifactSigner(tmp_path / "signing.key")
    signer.sign(plugin_dir)
    manager = PluginManager(str(plugin_root), signer=signer)

    assert manager.load("legacy-demo") is True
    result = manager.fire("recon.post", {"target": "example.test"})

    assert result[0]["status"] == "sandbox_unavailable"
    assert not marker.exists()


def test_legacy_plugin_manager_rejects_tampered_artifact(tmp_path):
    plugin_root = tmp_path / "plugins"
    plugin_dir = plugin_root / "legacy-demo"
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "plugin.json").write_text(
        json.dumps({"name": "legacy-demo", "hooks": []}),
        encoding="utf-8",
    )
    signer = PluginArtifactSigner(tmp_path / "signing.key")
    signer.sign(plugin_dir)
    (plugin_dir / "plugin.json").write_text(
        json.dumps({"name": "legacy-demo", "hooks": ["recon.post"]}),
        encoding="utf-8",
    )
    manager = PluginManager(str(plugin_root), signer=signer)

    assert manager.load("legacy-demo") is False
