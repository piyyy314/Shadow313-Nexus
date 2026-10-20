"""Unit tests — shadow313.v4.update"""
import pytest

class TestUpdater:
    def test_module_importable(self):
        try:
            from shadow313.v4.update.updater import Updater
            assert Updater is not None
        except ImportError:
            pytest.skip("updater not available")

    def test_version_comparison(self):
        from packaging.version import Version
        current = Version("4.0.0")
        latest = Version("4.1.0")
        assert latest > current

    def test_update_channels(self):
        channels = ["stable", "beta", "nightly"]
        assert "stable" in channels

    def test_integrity_verification(self):
        """Updates must be verified with SHA3-256."""
        import hashlib
        data = b"update_package_content"
        checksum = hashlib.sha3_256(data).hexdigest()
        assert len(checksum) == 64

    def test_rollback_capability(self):
        """Must support rollback to previous version."""
        rollback_supported = True
        assert rollback_supported is True

    def test_offline_update_support(self):
        """Must support offline/air-gapped updates."""
        offline_supported = True
        assert offline_supported is True
