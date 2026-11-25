"""Regression tests for plugin path containment and fail-closed execution."""

from pathlib import Path

from shadow313.modules.plugins.manifest import PluginManifest
from shadow313.modules.plugins.manager import PluginRegistry
from shadow313.modules.plugins.runner import PluginRunner
from shadow313.modules.plugins.signing import PluginArtifactSigner


def _plugin(path: Path, *, name: str = "safe-plugin", entry: str = "plugin.py") -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / "plugin.yaml").write_text(
        (
            f"name: {name}\nversion: 1.0.0\nhooks:\n  - recon.post\n"
            f"entry: {entry}\nrequires: []\n"
        ),
        encoding="utf-8",
    )
    (path / "plugin.py").write_text("print('{}')\n", encoding="utf-8")
    return path


def test_manifest_rejects_parent_directory_entry(tmp_path):
    plugin = _plugin(tmp_path / "plugin", entry="../outside.py")

    errors = PluginManifest(plugin).validate()

    assert any("unsafe path" in error.lower() for error in errors)


def test_manifest_rejects_absolute_entry(tmp_path):
    plugin = _plugin(tmp_path / "plugin", entry=str(tmp_path / "outside.py"))

    errors = PluginManifest(plugin).validate()

    assert any("relative plugin-local path" in error.lower() for error in errors)


def test_manifest_rejects_plugin_name_path_traversal(tmp_path):
    plugin = _plugin(tmp_path / "plugin", name="../outside")

    errors = PluginManifest(plugin).validate()

    assert any("simple" in error.lower() for error in errors)


def test_manifest_rejects_entry_symlink_escape(tmp_path):
    plugin = _plugin(tmp_path / "plugin")
    outside = tmp_path / "outside.py"
    outside.write_text("print('outside')\n", encoding="utf-8")
    (plugin / "plugin.py").unlink()
    (plugin / "plugin.py").symlink_to(outside)

    errors = PluginManifest(plugin).validate()

    assert errors


def test_install_does_not_overwrite_existing_plugin(tmp_path):
    root = tmp_path / "installed"
    registry = PluginRegistry(str(root))
    source = _plugin(tmp_path / "source")
    existing = root / "safe-plugin"
    existing.mkdir()
    sentinel = existing / "preserve.txt"
    sentinel.write_text("keep", encoding="utf-8")

    ok, message = registry.install(str(source))

    assert not ok
    assert "already exists" in message
    assert sentinel.read_text(encoding="utf-8") == "keep"


def test_remove_rejects_traversal_and_preserves_outside_files(tmp_path):
    root = tmp_path / "installed"
    registry = PluginRegistry(str(root))
    outside = tmp_path / "important.txt"
    outside.write_text("preserve", encoding="utf-8")

    ok, _ = registry.remove("../important")

    assert not ok
    assert outside.read_text(encoding="utf-8") == "preserve"


def test_plugin_runner_fails_closed_without_bubblewrap(tmp_path, monkeypatch):
    plugin = PluginManifest(_plugin(tmp_path / "plugin"))
    monkeypatch.setattr("shadow313.modules.plugins.runner.shutil.which", lambda _: None)

    result = PluginRunner(plugin).execute({"session_id": "test"})

    assert result["status"] == "sandbox_unavailable"
    assert "not executed" in result["reason"]


def test_plugin_dependencies_are_not_installed_into_host_python(tmp_path):
    plugin = _plugin(tmp_path / "plugin")
    manifest_path = plugin / "plugin.yaml"
    manifest_path.write_text(
        "name: safe-plugin\nversion: 1.0.0\nhooks: []\nentry: plugin.py\n"
        "requires:\n  - untrusted-package\n",
        encoding="utf-8",
    )
    runner = PluginRunner(PluginManifest(plugin))

    ok, message = runner.install_requirements()

    assert not ok
    assert "isolated plugin image" in message



def test_plugin_artifact_signature_covers_all_files(tmp_path):
    plugin = _plugin(tmp_path / "plugin")
    signer = PluginArtifactSigner(tmp_path / "signing.key")

    signed = signer.sign(plugin)
    assert signed["valid"] is True
    assert signer.verify(plugin)["valid"] is True

    (plugin / "plugin.py").write_text("print('tampered')\\n", encoding="utf-8")
    verification = signer.verify(plugin)

    assert verification["valid"] is False
    assert "content hash mismatch" in verification["reason"]


def test_require_signed_registry_rejects_unsigned_plugin(tmp_path):
    signer = PluginArtifactSigner(tmp_path / "signing.key")
    registry = PluginRegistry(str(tmp_path / "installed"), require_signed=True, signer=signer)
    source = _plugin(tmp_path / "source")

    ok, message = registry.install(str(source))

    assert not ok
    assert "signature is missing or invalid" in message


def test_require_signed_registry_installs_verified_artifact(tmp_path):
    signer = PluginArtifactSigner(tmp_path / "signing.key")
    registry = PluginRegistry(str(tmp_path / "installed"), require_signed=True, signer=signer)
    source = _plugin(tmp_path / "source")
    signer.sign(source)

    ok, message = registry.install(str(source))

    assert ok
    assert "installed" in message
    assert signer.verify(tmp_path / "installed" / "safe-plugin")["valid"] is True
