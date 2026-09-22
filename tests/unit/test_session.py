"""Unit tests — shadow313.core.session v4"""
import json
import pytest
from shadow313.core.session import Session


class TestSession:
    def test_creates_session_dir(self, tmp_path):
        s = Session(sessions_dir=str(tmp_path))
        assert s.session_dir.exists()

    def test_unique_ids(self, tmp_path):
        s1 = Session(sessions_dir=str(tmp_path))
        s2 = Session(sessions_dir=str(tmp_path))
        assert s1.id != s2.id

    def test_resume_session(self, tmp_path):
        s1 = Session(sessions_dir=str(tmp_path))
        sid = s1.id
        s2 = Session.resume(sid, sessions_dir=str(tmp_path))
        assert s2.id == sid

    def test_resume_invalid_uuid_raises(self, tmp_path):
        """FIX: resume() should raise ValueError on invalid UUID format."""
        with pytest.raises(ValueError, match="Invalid session ID format"):
            Session.resume("not-a-valid-uuid", sessions_dir=str(tmp_path))

    def test_write_and_read_json(self, tmp_path):
        s = Session(sessions_dir=str(tmp_path))
        data = {"test": True, "value": 42, "list": [1, 2, 3]}
        s.write("test.json", data)
        loaded = s.read("test.json")
        assert loaded == data

    def test_read_missing_file_returns_none(self, tmp_path):
        s = Session(sessions_dir=str(tmp_path))
        result = s.read("nonexistent.json")
        assert result is None

    def test_audit_log(self, tmp_path):
        s = Session(sessions_dir=str(tmp_path))
        s.audit("recon", "start", "example.com")
        s.audit("recon", "complete", "/path/to/file")
        log = s.get_audit_log()
        assert len(log) == 2
        assert log[0]["module"] == "recon"
        assert log[0]["action"] == "start"
        assert log[1]["action"] == "complete"

    def test_audit_creates_parent_dir(self, tmp_path):
        """FIX: audit() must create parent dir before opening audit.log."""
        s = Session(sessions_dir=str(tmp_path))
        # Should not raise even if session_dir was just created
        s.audit("test", "action", "detail")
        audit_path = s.session_dir / "audit.log"
        assert audit_path.exists()

    def test_set_target(self, tmp_path):
        s = Session(sessions_dir=str(tmp_path))
        s.set_target("example.com")
        assert s.target == "example.com"

    def test_summary(self, tmp_path):
        s = Session(sessions_dir=str(tmp_path))
        s.write("recon.json", {"test": True})
        summary = s.summary()
        assert summary["session_id"] == s.id
        assert "recon.json" in summary["files"]

    def test_list_sessions(self, tmp_path):
        s1 = Session(sessions_dir=str(tmp_path))
        s2 = Session(sessions_dir=str(tmp_path))
        sessions = Session.list_sessions(sessions_dir=str(tmp_path))
        ids = [s["session_id"] for s in sessions]
        assert s1.id in ids
        assert s2.id in ids

    def test_list_sessions_empty_dir(self, tmp_path):
        """FIX: list_sessions() should not crash on empty directory."""
        empty_dir = tmp_path / "empty_sessions"
        empty_dir.mkdir()
        sessions = Session.list_sessions(sessions_dir=str(empty_dir))
        assert sessions == []

    def test_list_sessions_nonexistent_dir(self, tmp_path):
        """list_sessions() should return [] for nonexistent directory."""
        sessions = Session.list_sessions(sessions_dir=str(tmp_path / "nonexistent"))
        assert sessions == []

    def test_meta_version_is_v4(self, tmp_path):
        """FIX: meta.json should record v4.0.0, not hardcoded v1.0.0."""
        s = Session(sessions_dir=str(tmp_path))
        meta_path = s.session_dir / "meta.json"
        meta = json.loads(meta_path.read_text())
        assert meta["version"] == "4.0.0"

    def test_delete_session(self, tmp_path):
        s = Session(sessions_dir=str(tmp_path))
        sid = s.id
        assert s.session_dir.exists()
        ok = Session.delete(sid, sessions_dir=str(tmp_path))
        assert ok is True
        assert not s.session_dir.exists()

    def test_delete_nonexistent_session(self, tmp_path):
        ok = Session.delete("00000000-0000-4000-8000-000000000000",
                            sessions_dir=str(tmp_path))
        assert ok is False