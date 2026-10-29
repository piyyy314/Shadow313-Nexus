"""Plugin manifests, registry lifecycle and subprocess protocol from PR #86."""

import json
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from shadow313.modules.plugins.manager import HookDispatcher, PluginRegistry, PluginScaffolder
from shadow313.modules.plugins.manifest import PluginManifest
from shadow313.modules.plugins.runner import PluginRunner


@pytest.fixture
def plugin(tmp_path):
    path = PluginScaffolder(str(tmp_path / "sources")).create("sample", author="tester")
    return PluginManifest(path)


def test_scaffold_loads_valid_manifest_and_generates_entry(plugin):
    assert plugin.validate() == []
    assert plugin.name == "sample"
    assert plugin.author == "tester"
    assert plugin.version == "1.0.0"
    assert plugin.hooks == ["recon.post"]
    assert plugin.requires == []
    assert plugin.to_dict()["path"] == str(plugin.path)
    assert "sample" in (plugin.path / "README.md").read_text()
    compile(plugin.entry_path.read_text(), str(plugin.entry_path), "exec")


def test_manifest_alias_defaults_and_missing_entry(tmp_path):
    (tmp_path / "manifest.yaml").write_text("description: test\n")
    manifest = PluginManifest(tmp_path)
    assert manifest.name == tmp_path.name
    assert manifest.version == "0.0.0"
    assert manifest.author == "unknown"
    assert manifest.entry == "plugin.py"
    assert manifest.hooks == []
    assert manifest.requires == []
    assert len(manifest.validate()) == 1
    assert "Entry file not found" in manifest.validate()[0]


def test_manifest_reports_empty_name_and_invalid_hook(tmp_path):
    (tmp_path / "plugin.yaml").write_text('name: ""\nhooks: [invalid.post]\n')
    (tmp_path / "plugin.py").touch()
    assert PluginManifest(tmp_path).validate() == [
        "Missing 'name' field",
        "Invalid hook 'invalid.post'",
    ]


def test_manifest_fallback_parser_preserves_lists_and_quoted_values(tmp_path, monkeypatch):
    (tmp_path / "plugin.yaml").write_text(
        '# comment\nname: "fallback"\nversion: 2\nhooks:\n  - recon.post\n'
        "  - vuln.post\nrequires:\n  - sample-dependency\n"
    )
    monkeypatch.setattr("shadow313.modules.plugins.manifest._HAS_YAML", False)
    manifest = PluginManifest(tmp_path)
    assert manifest.name == "fallback"
    assert manifest.version == "2"
    assert manifest.hooks == ["recon.post", "vuln.post"]
    assert manifest.requires == ["sample-dependency"]


def test_registry_install_replace_enable_filter_and_remove(plugin, tmp_path):
    registry = PluginRegistry(str(tmp_path / "installed"))
    assert registry.enable("missing") is False
    assert registry.install(str(plugin.path))[0] is True
    assert registry.get_enabled() == []
    assert registry.enable("sample") is True
    assert [p.name for p in registry.get_hooks("recon.post")] == ["sample"]
    assert registry.get_hooks("vuln.post") == []
    assert registry.list_all()[0]["enabled"] is True
    plugin.entry_path.write_text("# replacement\n")
    assert registry.install(str(plugin.path))[0] is True
    assert (registry.plugins_dir / "sample/plugin.py").read_text() == "# replacement\n"
    registry.disable("sample")
    assert registry.get_enabled() == []
    assert registry.remove("sample")[0] is True
    assert not (registry.plugins_dir / "sample").exists()
    assert registry.list_all() == []
    assert registry.remove("sample")[0] is False


def test_registry_rejects_missing_invalid_and_incomplete_plugins(tmp_path):
    registry = PluginRegistry(str(tmp_path / "installed"))
    assert registry.install(str(tmp_path / "missing"))[0] is False
    source = tmp_path / "source"
    source.mkdir()
    assert registry.install(str(source))[0] is False
    (source / "plugin.yaml").write_text("name: incomplete\n")
    ok, message = registry.install(str(source))
    assert ok is False
    assert "Entry file not found" in message
    assert list(registry.plugins_dir.iterdir()) == []


def test_discover_skips_nonplugins_and_broken_yaml(plugin, tmp_path):
    (plugin.path.parent / "ordinary-file").touch()
    invalid = plugin.path.parent / "broken"
    invalid.mkdir()
    (invalid / "plugin.yaml").write_text("name: [unterminated")
    empty = plugin.path.parent / "empty"
    empty.mkdir()
    registry = PluginRegistry(str(plugin.path.parent))
    assert [p.name for p in registry.discover()] == ["sample"]


def test_runner_passes_only_scoped_context_and_configures_process(plugin, monkeypatch):
    run = Mock(return_value=SimpleNamespace(returncode=0, stdout='{"status":"ok"}', stderr=""))
    monkeypatch.setattr("shadow313.modules.plugins.runner.subprocess.run", run)
    context = {
        "session_id": "session-test",
        "hook": "recon.post",
        "module": "recon",
        "target": "example.invalid",
        "module_output": {"ports": [443]},
        "timestamp": "fixed",
        "plugin_config": {"verbose": True},
        "internal_credentials": "must-not-cross-boundary",
    }
    original = context.copy()
    assert PluginRunner(plugin).execute(context) == {"status": "ok"}
    args, kwargs = run.call_args
    assert args[0] == [sys.executable, str(plugin.entry_path)]
    expected = {k: v for k, v in context.items() if k != "internal_credentials"}
    assert json.loads(kwargs["input"]) == expected
    assert context == original
    assert kwargs["cwd"] == str(plugin.path)
    assert kwargs["env"]["SHADOW313_PLUGIN_MODE"] == "1"
    assert kwargs["env"]["PYTHONPATH"] == str(plugin.path)
    assert kwargs["timeout"] == 30
    assert kwargs["check"] is False


@pytest.mark.parametrize(
    ("returncode", "stdout", "stderr", "status", "field"),
    [
        (1, "", "e" * 600, "error", "error"),
        (0, " \n", "", "no_output", None),
        (0, "x" * 600, "", "invalid_output", "raw"),
    ],
)
def test_runner_handles_failed_empty_and_invalid_output(
    plugin,
    monkeypatch,
    returncode,
    stdout,
    stderr,
    status,
    field,
):
    monkeypatch.setattr(
        "shadow313.modules.plugins.runner.subprocess.run",
        Mock(
            return_value=SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr),
        ),
    )
    result = PluginRunner(plugin).execute({})
    assert result["plugin"] == "sample"
    assert result["status"] == status
    if field:
        assert len(result[field]) == 500


@pytest.mark.parametrize("error", [subprocess.TimeoutExpired("plugin", 30), OSError("failed")])
def test_runner_contains_process_exceptions(plugin, monkeypatch, error):
    monkeypatch.setattr("shadow313.modules.plugins.runner.subprocess.run", Mock(side_effect=error))
    result = PluginRunner(plugin).execute({})
    assert result["status"] == (
        "timeout" if isinstance(error, subprocess.TimeoutExpired) else "error"
    )
    assert result["error"]


def test_requirement_installation_is_optional_and_handles_failure(plugin, monkeypatch):
    run = Mock(return_value=SimpleNamespace(returncode=1, stderr="dependency failed"))
    monkeypatch.setattr("shadow313.modules.plugins.runner.subprocess.run", run)
    runner = PluginRunner(plugin)
    assert runner.install_requirements() == (True, "No requirements")
    run.assert_not_called()
    plugin._data["requires"] = ["synthetic-package==1.0"]
    assert runner.install_requirements() == (False, "dependency failed")
    assert run.call_args.args[0][-1] == "synthetic-package==1.0"


def test_dispatcher_fires_only_enabled_matching_hooks(plugin, tmp_path, monkeypatch):
    registry = PluginRegistry(str(tmp_path / "installed"))
    registry.install(str(plugin.path))
    dispatcher = HookDispatcher(registry, "session-test")
    execute = Mock(return_value={"status": "ok"})
    monkeypatch.setattr(PluginRunner, "execute", execute)
    assert dispatcher.fire("recon.post", "recon") == []
    registry.enable("sample")
    assert dispatcher.fire("vuln.post", "vuln") == []
    assert dispatcher.fire("recon.post", "recon", {"ports": [443]}, "example.invalid") == [
        {"status": "ok"},
    ]
    context = execute.call_args.args[0]
    assert context["session_id"] == "session-test"
    assert context["target"] == "example.invalid"
    assert context["module_output"] == {"ports": [443]}
    assert context["hook"] == "recon.post"
