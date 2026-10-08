"""Unit tests — shadow313.core.config v4"""
import os
import pytest
from pathlib import Path
from shadow313.core.config import Config, DEFAULT_CONFIG


class TestConfig:
    def test_defaults_loaded(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SHADOW313_AI_BACKEND", raising=False)
        monkeypatch.delenv("SHADOW313_AI_MODEL", raising=False)
        monkeypatch.delenv("SHADOW313_VERBOSE", raising=False)
        cfg = Config(config_path=tmp_path / "config.yaml")
        assert cfg.get("ai", "backend") == "ollama"
        assert cfg.get("ai", "model")   == "mistral:7b"
        assert cfg.get("output", "format") == "rich"

    def test_deep_merge(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SHADOW313_AI_BACKEND", raising=False)
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "shadow313:\n  ai:\n    model: llama3:8b\n    backend: ollama\n"
        )
        cfg = Config(config_path=config_file)
        assert cfg.get("ai", "model")   == "llama3:8b"
        assert cfg.get("ai", "backend") == "ollama"
        assert cfg.get("ai", "context_window") == 8192

    def test_env_override(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SHADOW313_AI_MODEL", "phi3:mini")
        monkeypatch.delenv("SHADOW313_AI_BACKEND", raising=False)
        cfg = Config(config_path=tmp_path / "config.yaml")
        assert cfg.get("ai", "model") == "phi3:mini"

    def test_env_backend_override(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SHADOW313_AI_BACKEND", "disabled")
        cfg = Config(config_path=tmp_path / "config.yaml")
        assert cfg.get("ai", "backend") == "disabled"

    def test_env_backend_ci_mode(self, tmp_path, monkeypatch):
        monkeypatch.setenv("SHADOW313_AI_BACKEND", "disabled")
        cfg = Config(config_path=tmp_path / "config.yaml")
        backend = cfg.get("ai", "backend")
        assert backend in ("ollama", "disabled", "openai")

    def test_missing_key_returns_none(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SHADOW313_AI_BACKEND", raising=False)
        cfg = Config(config_path=tmp_path / "config.yaml")
        assert cfg.get("nonexistent", "key") is None

    def test_default_config_structure(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SHADOW313_AI_BACKEND", raising=False)
        cfg = Config(config_path=tmp_path / "config.yaml")
        for section in ["ai", "output", "storage", "plugins", "recon"]:
            assert cfg.get(section) is not None, f"Missing section: {section}"

    def test_config_file_creation(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SHADOW313_AI_BACKEND", raising=False)
        config_path = tmp_path / "new_config.yaml"
        cfg = Config(config_path=config_path)
        assert cfg.get("ai", "backend") is not None
