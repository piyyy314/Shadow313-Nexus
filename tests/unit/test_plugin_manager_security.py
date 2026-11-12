"""Security regression tests for the legacy HMAC plugin manager."""

import json

import pytest

from shadow313.core.plugin_manager import PluginManager


KEY = "unit-test-signing-key-" + ("x" * 40)


def _plugin(root, name="sample", hooks=None):
    path = root / name
    path.mkdir(parents=True)
    (path / "plugin.json").write_text(
        json.dumps({"name": name, "hooks": hooks or ["recon.post"]}),
        encoding="utf-8",
    )
    return path


def test_plugin_manager_requires_explicit_strong_key(tmp_path, monkeypatch):
    monkeypatch.delenv("SHADOW313_PLUGIN_SIGNING_KEY", raising=False)
    with pytest.raises(ValueError, match="at least 32 characters"):
        PluginManager(str(tmp_path))


def test_plugin_manager_rejects_unsigned_and_tampered_manifests(tmp_path):
    path = _plugin(tmp_path)
    manager = PluginManager(str(tmp_path), secret=KEY)
    assert manager.load("sample") is False

    manager.sign_plugin("sample")
    assert manager.load("sample") is True

    (path / "plugin.json").write_text('{"name":"tampered","hooks":["recon.post"]}')
    assert manager.load("sample") is False


def test_plugin_manager_dispatches_each_hook_once_with_correct_name(tmp_path, monkeypatch):
    _plugin(tmp_path, hooks=["recon.post", "vuln.post"])
    manager = PluginManager(str(tmp_path), secret=KEY)
    manager.sign_plugin("sample")
    assert manager.load("sample") is True

    calls = []
    monkeypatch.setattr(
        manager, "_dispatch",
        lambda name, hook, data: calls.append((name, hook, data)) or {"ok": True},
    )
    assert manager.fire("recon.post", {"id": 1}) == [{"ok": True}]
    assert manager.fire("vuln.post", {"id": 2}) == [{"ok": True}]
    assert calls == [
        ("sample", "recon.post", {"id": 1}),
        ("sample", "vuln.post", {"id": 2}),
    ]


def test_plugin_manager_rejects_path_traversal_and_missing_directory(tmp_path):
    manager = PluginManager(str(tmp_path / "not-created"), secret=KEY)
    assert manager.load_all() == 0
    assert manager.load("../outside") is False
    assert manager.load("nested/plugin") is False
    with pytest.raises(ValueError, match="Invalid plugin name"):
        manager.sign_plugin("../outside")
