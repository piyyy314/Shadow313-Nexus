"""
tests/unit/v4/test_secrets_manager.py
Tests for SecretsManager — hardened secrets management
Covers: validation, entropy, rotation, Vault config, OIDC strategy
"""
from __future__ import annotations
import os
import pytest

from shadow313.v4.intelligence.secrets_manager import (
    SecretsValidator, SecretsAuditReport, SecretValidationResult,
    SecretClass, SecretSource, SECRET_REGISTRY, VAULT_CONFIG,
    GITHUB_OIDC_STRATEGY, KNOWN_DEFAULTS,
    validate_secrets_at_startup, generate_strong_secret,
    get_secret_rotation_schedule,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def validator():
    return SecretsValidator()

@pytest.fixture
def strong_secret():
    return generate_strong_secret(48)

@pytest.fixture
def env_with_strong_secrets(monkeypatch, strong_secret):
    """Set strong secrets in environment."""
    monkeypatch.setenv("WEBUI_SECRET_KEY", strong_secret)
    monkeypatch.setenv("SHADOW313_API_KEY", generate_strong_secret(48))
    return strong_secret


# ── Secret Registry ───────────────────────────────────────────────────────────

class TestSecretRegistry:
    def test_registry_has_entries(self):
        assert len(SECRET_REGISTRY) >= 7

    def test_all_entries_have_required_fields(self):
        required = ["class", "description", "min_length", "min_entropy",
                    "rotation_h", "required", "env_var"]
        for name, config in SECRET_REGISTRY.items():
            for field in required:
                assert field in config, f"{name} missing field: {field}"

    def test_critical_secrets_present(self):
        assert "WEBUI_SECRET_KEY"   in SECRET_REGISTRY
        assert "SHADOW313_API_KEY"  in SECRET_REGISTRY

    def test_critical_secrets_have_short_rotation(self):
        for name, config in SECRET_REGISTRY.items():
            if config["class"] == SecretClass.CRITICAL:
                assert config["rotation_h"] <= 24, \
                    f"{name} CRITICAL secret rotation > 24h"

    def test_required_secrets_are_critical_or_high(self):
        for name, config in SECRET_REGISTRY.items():
            if config["required"]:
                assert config["class"] in (SecretClass.CRITICAL, SecretClass.HIGH), \
                    f"Required secret {name} should be CRITICAL or HIGH"

    def test_vault_paths_for_critical_secrets(self):
        for name, config in SECRET_REGISTRY.items():
            if config["class"] == SecretClass.CRITICAL and config["required"]:
                assert config.get("vault_path"), \
                    f"Critical required secret {name} must have vault_path"


# ── Secret Validation ─────────────────────────────────────────────────────────

class TestSecretValidation:
    def test_missing_secret_invalid(self, validator, monkeypatch):
        monkeypatch.delenv("WEBUI_SECRET_KEY", raising=False)
        result = validator.validate_secret("WEBUI_SECRET_KEY")
        assert result.present is False
        assert result.valid is False
        assert result.source == SecretSource.MISSING.value

    def test_strong_secret_valid(self, validator, monkeypatch, strong_secret):
        monkeypatch.setenv("WEBUI_SECRET_KEY", strong_secret)
        result = validator.validate_secret("WEBUI_SECRET_KEY")
        assert result.present is True
        assert result.length_ok is True
        assert result.entropy_ok is True
        assert result.not_default is True
        assert result.valid is True

    def test_short_secret_invalid(self, validator, monkeypatch):
        monkeypatch.setenv("WEBUI_SECRET_KEY", "short")
        result = validator.validate_secret("WEBUI_SECRET_KEY")
        assert result.length_ok is False
        assert result.valid is False
        assert any("short" in issue.lower() or "length" in issue.lower()
                   for issue in result.issues)

    def test_default_value_invalid(self, validator, monkeypatch):
        monkeypatch.setenv("WEBUI_SECRET_KEY", "shadow313-nexus-change-me-in-production")
        result = validator.validate_secret("WEBUI_SECRET_KEY")
        assert result.not_default is False
        assert result.valid is False
        assert any("default" in issue.lower() or "placeholder" in issue.lower()
                   for issue in result.issues)

    def test_low_entropy_invalid(self, validator, monkeypatch):
        # All same character = zero entropy
        monkeypatch.setenv("WEBUI_SECRET_KEY", "a" * 40)
        result = validator.validate_secret("WEBUI_SECRET_KEY")
        assert result.entropy_ok is False
        assert result.valid is False

    def test_result_to_dict(self, validator, monkeypatch, strong_secret):
        monkeypatch.setenv("WEBUI_SECRET_KEY", strong_secret)
        result = validator.validate_secret("WEBUI_SECRET_KEY")
        d = result.to_dict()
        assert "name"         in d
        assert "present"      in d
        assert "valid"        in d
        assert "length_ok"    in d
        assert "entropy_ok"   in d
        assert "not_default"  in d
        assert "secret_class" in d
        assert "issues"       in d

    def test_unknown_secret_handled(self, validator):
        result = validator.validate_secret("NONEXISTENT_SECRET_XYZ")
        assert result.present is False
        assert result.valid is False


# ── Full Audit ────────────────────────────────────────────────────────────────

class TestFullAudit:
    def test_audit_with_strong_secrets_passes(self, validator, env_with_strong_secrets):
        report = validator.validate_all(fail_fast=False)
        assert isinstance(report, SecretsAuditReport)
        assert len(report.critical_missing) == 0
        assert len(report.default_values) == 0
        assert report.overall_pass is True

    def test_audit_with_missing_required_fails(self, validator, monkeypatch):
        monkeypatch.delenv("WEBUI_SECRET_KEY", raising=False)
        monkeypatch.delenv("SHADOW313_API_KEY", raising=False)
        report = validator.validate_all(fail_fast=False)
        assert report.overall_pass is False
        assert len(report.critical_missing) >= 1

    def test_fail_fast_raises_on_missing(self, validator, monkeypatch):
        monkeypatch.delenv("WEBUI_SECRET_KEY", raising=False)
        monkeypatch.delenv("SHADOW313_API_KEY", raising=False)
        with pytest.raises(RuntimeError, match="FAIL-FAST"):
            validator.validate_all(fail_fast=True)

    def test_fail_fast_raises_on_defaults(self, validator, monkeypatch):
        monkeypatch.setenv("WEBUI_SECRET_KEY", "shadow313-nexus-change-me-in-production")
        monkeypatch.setenv("SHADOW313_API_KEY", "dev-key-change-in-production")
        with pytest.raises(RuntimeError, match="FAIL-FAST"):
            validator.validate_all(fail_fast=True)

    def test_audit_report_to_dict(self, validator, env_with_strong_secrets):
        report = validator.validate_all(fail_fast=False)
        d = report.to_dict()
        assert "overall_pass"     in d
        assert "critical_missing" in d
        assert "weak_secrets"     in d
        assert "rotation_due"     in d
        assert "total_checked"    in d
        assert "total_valid"      in d
        assert "results"          in d
        assert "timestamp"        in d

    def test_all_secrets_checked(self, validator, env_with_strong_secrets):
        report = validator.validate_all(fail_fast=False)
        checked_names = {r.name for r in report.results}
        for name in SECRET_REGISTRY:
            assert name in checked_names, f"{name} not checked in audit"


# ── Entropy Calculation ───────────────────────────────────────────────────────

class TestEntropyCalculation:
    def test_high_entropy_random_string(self, validator):
        s = generate_strong_secret(48)
        entropy = validator._shannon_entropy(s)
        assert entropy >= 4.0, f"Random secret entropy {entropy:.2f} too low"

    def test_zero_entropy_repeated_char(self, validator):
        entropy = validator._shannon_entropy("aaaaaaaaaa")
        assert entropy == 0.0

    def test_empty_string_zero_entropy(self, validator):
        assert validator._shannon_entropy("") == 0.0

    def test_known_defaults_low_entropy_or_detected(self, validator, monkeypatch):
        for default in list(KNOWN_DEFAULTS)[:3]:
            monkeypatch.setenv("WEBUI_SECRET_KEY", default)
            result = validator.validate_secret("WEBUI_SECRET_KEY")
            assert not result.not_default, f"Default '{default}' not detected"


# ── Secret Generation ─────────────────────────────────────────────────────────

class TestSecretGeneration:
    def test_generate_strong_secret_length(self):
        s = generate_strong_secret(48)
        # URL-safe base64 of 48 bytes = 64 chars
        assert len(s) >= 48

    def test_generate_strong_secret_unique(self):
        secrets = {generate_strong_secret(32) for _ in range(10)}
        assert len(secrets) == 10  # All unique

    def test_generate_strong_secret_high_entropy(self, validator):
        s = generate_strong_secret(48)
        entropy = validator._shannon_entropy(s)
        assert entropy >= 4.0

    def test_validator_generate_method(self, validator):
        s = validator.generate_secret(48)
        assert len(s) >= 48
        assert validator._shannon_entropy(s) >= 4.0


# ── Rotation Policy ───────────────────────────────────────────────────────────

class TestRotationPolicy:
    def test_rotation_schedule_has_all_secrets(self):
        schedule = get_secret_rotation_schedule()
        names = {s["name"] for s in schedule}
        for name in SECRET_REGISTRY:
            assert name in names

    def test_critical_secrets_rotate_fastest(self):
        schedule = get_secret_rotation_schedule()
        critical = [s for s in schedule if s["class"] == SecretClass.CRITICAL.value]
        low = [s for s in schedule if s["class"] == SecretClass.LOW.value]
        if critical and low:
            assert min(s["rotation_h"] for s in critical) < \
                   min(s["rotation_h"] for s in low)

    def test_rotation_due_old_secret(self, validator):
        # Secret rotated 25 hours ago — CRITICAL (24h rotation) should be due
        from datetime import datetime, timezone, timedelta
        old_time = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
        assert validator.check_rotation_due("WEBUI_SECRET_KEY", old_time) is True

    def test_rotation_not_due_fresh_secret(self, validator):
        # Secret rotated 1 hour ago — not due
        from datetime import datetime, timezone, timedelta
        fresh_time = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        assert validator.check_rotation_due("WEBUI_SECRET_KEY", fresh_time) is False

    def test_rotation_due_unknown_time(self, validator):
        # Unknown rotation time → assume due
        assert validator.check_rotation_due("WEBUI_SECRET_KEY", "invalid-date") is True

    def test_vault_rotation_policies_complete(self):
        for cls in SecretClass:
            assert cls.value in VAULT_CONFIG["rotation_policies"], \
                f"No rotation policy for {cls.value}"


# ── Vault Configuration ───────────────────────────────────────────────────────

class TestVaultConfiguration:
    def test_vault_config_has_auth_methods(self):
        assert "github_actions" in VAULT_CONFIG["auth_methods"]
        assert "docker_container" in VAULT_CONFIG["auth_methods"]
        assert "local_dev" in VAULT_CONFIG["auth_methods"]

    def test_vault_config_has_secret_paths(self):
        assert len(VAULT_CONFIG["secret_paths"]) >= 5
        assert "shadow313/webui" in VAULT_CONFIG["secret_paths"]
        assert "shadow313/api"   in VAULT_CONFIG["secret_paths"]

    def test_github_actions_uses_jwt(self):
        gh_auth = VAULT_CONFIG["auth_methods"]["github_actions"]
        assert gh_auth["method"] == "jwt"
        assert "ttl" in gh_auth

    def test_container_uses_approle(self):
        container_auth = VAULT_CONFIG["auth_methods"]["docker_container"]
        assert container_auth["method"] == "approle"

    def test_rotation_policies_have_intervals(self):
        for cls, policy in VAULT_CONFIG["rotation_policies"].items():
            assert "interval" in policy
            assert "auto_rotate" in policy
            assert "notify" in policy


# ── GitHub OIDC Strategy ──────────────────────────────────────────────────────

class TestGitHubOIDCStrategy:
    def test_oidc_strategy_has_providers(self):
        assert "ghcr"  in GITHUB_OIDC_STRATEGY["supported_providers"]
        assert "pypi"  in GITHUB_OIDC_STRATEGY["supported_providers"]
        assert "vault" in GITHUB_OIDC_STRATEGY["supported_providers"]

    def test_oidc_requires_id_token_write(self):
        perms = GITHUB_OIDC_STRATEGY["permissions_required"]
        assert perms.get("id-token") == "write"

    def test_pypi_oidc_no_token_needed(self):
        pypi = GITHUB_OIDC_STRATEGY["supported_providers"]["pypi"]
        assert "token" not in pypi.get("workflow_step", "").lower() or \
               "no password" in pypi.get("workflow_step", "").lower()

    def test_ghcr_uses_github_token(self):
        ghcr = GITHUB_OIDC_STRATEGY["supported_providers"]["ghcr"]
        assert "GITHUB_TOKEN" in ghcr.get("workflow_step", "")


# ── Known Defaults ────────────────────────────────────────────────────────────

class TestKnownDefaults:
    def test_known_defaults_not_empty(self):
        assert len(KNOWN_DEFAULTS) >= 5

    def test_env_example_defaults_in_known_list(self):
        # Values from .env.example should be in KNOWN_DEFAULTS
        env_defaults = [
            "shadow313-nexus-change-me-in-production",
            "dev-key-change-in-production",
        ]
        for default in env_defaults:
            assert default in KNOWN_DEFAULTS, \
                f"'{default}' from .env.example not in KNOWN_DEFAULTS"

    def test_validate_startup_convenience(self, monkeypatch, strong_secret):
        monkeypatch.setenv("WEBUI_SECRET_KEY", strong_secret)
        monkeypatch.setenv("SHADOW313_API_KEY", generate_strong_secret(48))
        report = validate_secrets_at_startup(fail_fast=False)
        assert isinstance(report, SecretsAuditReport)
