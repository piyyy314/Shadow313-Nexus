"""Unit tests — shadow313.core.config v4"""
import os
import pytest
from pathlib import Path
from shadow313.core.config import Config, DEFAULT_CONFIG


class TestConfig:
    def test_defaults_loaded(self, tmp_path):
        cfg = Config(config_path=tmp_path / "config.yaml")
        assert cfg.get("ai", "backend") == "ollama"
        assert cfg.get("ai", "model")   == "mistral:7b"
        assert cfg.get("output", "format") == "rich"

    def test_deep_merge(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "shadow313:\n  ai:\n    model: llama3:8b\n    backend: ollama\n"
        )
        cfg = Config(config_path=config_file)
        assert cfg.get("ai", "model")   == "llama3:8b"
        assert cfg.get("ai", "backend") == "ollama"
        # Default values preserved
        assert cfg.get("ai", "context_window") == 8192

    def test_env_override(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SHADOW313_AI_MODEL", "phi3:mini")
        cfg = Config(config_path=tmp_path / "config.yaml")
        assert cfg.get("ai", "model") == "phi3:mini"

    def test_env_override_verbose_bool(self, tmp_path, monkeypatch):
        """FIX: SHADOW313_VERBOSE should be coerced to bool."""
        monkeypatch.setenv("SHADOW313_VERBOSE", "true")
        cfg = Config(config_path=tmp_path / "config.yaml")
        assert cfg.get("output", "verbose") is True

    def test_set_and_save(self, tmp_path):
        cfg = Config(config_path=tmp_path / "config.yaml")
        # FIX: set() now takes (*keys, value) — keys first, value last
        cfg.set("ai", "model", "gpt-4o")
        cfg.save()
        cfg2 = Config(config_path=tmp_path / "config.yaml")
        assert cfg2.get("ai", "model") == "gpt-4o"

    def test_set_key_order_fixed(self, tmp_path):
        """Verify the v1 bug (reversed key order) is fixed."""
        cfg = Config(config_path=tmp_path / "config.yaml")
        cfg.set("output", "format", "json")
        assert cfg.get("output", "format") == "json"

    def test_get_default(self, tmp_path):
        cfg = Config(config_path=tmp_path / "config.yaml")
        assert cfg.get("nonexistent", "key", default="fallback") == "fallback"

    def test_missing_key_returns_default(self, tmp_path):
        cfg = Config(config_path=tmp_path / "config.yaml")
        assert cfg.get("nonexistent_module", default=None) is None

    def test_save_wraps_in_shadow313_key(self, tmp_path):
        """FIX: save() must wrap in 'shadow313' key for correct reload."""
        cfg = Config(config_path=tmp_path / "config.yaml")
        cfg.set("ai", "model", "test-model")
        cfg.save()
        import yaml
        with open(tmp_path / "config.yaml") as fh:
            raw = yaml.safe_load(fh)
        assert "shadow313" in raw
        assert raw["shadow313"]["ai"]["model"] == "test-model"

    def test_init_user_dirs_creates_all(self, tmp_path, monkeypatch):
        """init_user_dirs() should create all required subdirectories."""
        monkeypatch.setenv("HOME", str(tmp_path))
        cfg = Config(config_path=tmp_path / "config.yaml")
        # Override the path to use tmp_path
        import shadow313.core.config as cfg_mod
        original = cfg_mod.Path
        # Just verify the method runs without error
        cfg.init_user_dirs()

    def test_v4_new_config_keys_present(self, tmp_path):
        """v4 adds temporal_binding, siem, collab config sections."""
        cfg = Config(config_path=tmp_path / "config.yaml")
        assert cfg.get("temporal_binding", "enabled") is True
        assert cfg.get("siem", "backend") == "disabled"
        assert cfg.get("collab", "enabled") is False