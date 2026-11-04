"""Artifact integrity and platform coverage without claiming remote OS execution."""

import importlib.util
import json
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("wheel_ci", ROOT / "scripts/check-wheel.py")
wheel_ci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wheel_ci)


def artifacts(path):
    wheel = path / "shadow313_nexus-4.0.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(
            "shadow313_nexus-4.0.0.dist-info/METADATA", "Name: shadow313-nexus\nVersion: 4.0.0\n"
        )
    (path / "shadow313_nexus-4.0.0.tar.gz").write_bytes(b"fixture")
    wheel_ci.write_manifest(path)
    return wheel


def test_exact_artifact_manifest_roundtrip(tmp_path):
    wheel = artifacts(tmp_path)
    assert wheel_ci.validate_artifacts(tmp_path) == (wheel, "4.0.0")


def test_tampered_wheel_is_rejected(tmp_path):
    wheel = artifacts(tmp_path)
    wheel.write_bytes(wheel.read_bytes() + b"changed")
    with pytest.raises(ValueError, match="hash/path mismatch"):
        wheel_ci.validate_artifacts(tmp_path)


def test_extra_artifacts_are_rejected(tmp_path):
    artifacts(tmp_path)
    (tmp_path / "stale.tar.gz").write_bytes(b"old")
    with pytest.raises(ValueError, match="Artifact list"):
        wheel_ci.validate_artifacts(tmp_path)


def test_missing_wheel_fails_closed(tmp_path):
    with pytest.raises(ValueError, match="exactly one wheel"):
        wheel_ci.write_manifest(tmp_path)


def test_manifest_path_escape_is_rejected(tmp_path):
    artifacts(tmp_path)
    manifest = json.loads((tmp_path / "SHA256SUMS.json").read_text())
    manifest["../elsewhere.whl"] = "bad"
    (tmp_path / "SHA256SUMS.json").write_text(json.dumps(manifest))
    with pytest.raises(ValueError):
        wheel_ci.validate_artifacts(tmp_path)


def test_workflow_reuses_build_artifact_on_all_platforms_and_gates_results():
    workflow = yaml.safe_load((ROOT / "ci/cross-platform-wheel.yml.template").read_text())
    jobs = workflow["jobs"]
    matrix = jobs["installed-wheel"]["strategy"]["matrix"]
    assert set(matrix["os"]) == {"ubuntu-24.04", "windows-2022", "macos-15"}
    assert set(matrix["python"]) == {"3.11", "3.12"}
    assert set(matrix["profile"]) == {"core", "api"}
    assert workflow["permissions"] == {"contents": "read"}
    assert jobs["installed-wheel"]["needs"] == "build"
    assert jobs["native-signing"]["needs"] == "build"
    assert jobs["wheel-gate"]["if"] == "always()"
    for name in ("installed-wheel", "native-signing"):
        steps = jobs[name]["steps"]
        assert any("download-artifact@" in step.get("uses", "") for step in steps)
        assert all("pip install -e" not in step.get("run", "") for step in steps)
        assert "continue-on-error" not in jobs[name]


def test_wrong_distribution_identity_is_rejected(tmp_path):
    wheel = artifacts(tmp_path)
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("other-4.0.0.dist-info/METADATA", "Name: other\nVersion: 4.0.0\n")
    wheel_ci.write_manifest(tmp_path)
    with pytest.raises(ValueError, match="Wrong distribution"):
        wheel_ci.validate_artifacts(tmp_path)


def test_stale_second_wheel_cannot_be_built_or_verified(tmp_path):
    artifacts(tmp_path)
    (tmp_path / "old-3.0.0-py3-none-any.whl").write_bytes(b"old")
    with pytest.raises(ValueError, match="exactly one wheel"):
        wheel_ci.write_manifest(tmp_path)
    with pytest.raises(ValueError, match="exactly one wheel"):
        wheel_ci.validate_artifacts(tmp_path)
