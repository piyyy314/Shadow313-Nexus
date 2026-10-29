"""
Comprehensive tests — shadow313.v2.campaign
Covers: _load_targets (inline, text file, JSON file), CampaignTarget dataclass,
        CampaignManager.run_campaign (mocked kernel), state persistence,
        concurrency semaphore, progress callbacks, error handling, resume/list.
"""
from __future__ import annotations
import json
import uuid
import pytest
from pathlib import Path
from unittest.mock import MagicMock, AsyncMock, patch

from shadow313.v2.campaign.campaign import (
    CampaignTarget, CampaignResult, Campaign,
    CampaignManager, CampaignModule, _load_targets,
)


# ── _load_targets ─────────────────────────────────────────────────────────────

class TestLoadTargets:
    def test_inline_comma_separated(self):
        targets = _load_targets("example.com,192.168.1.1,test.org")
        assert len(targets) == 3
        assert targets[0].identifier == "example.com"
        assert targets[1].identifier == "192.168.1.1"
        assert targets[2].identifier == "test.org"

    def test_inline_single_target(self):
        targets = _load_targets("example.com")
        assert len(targets) == 1
        assert targets[0].identifier == "example.com"

    def test_inline_strips_whitespace(self):
        targets = _load_targets("  example.com , test.org  ")
        assert targets[0].identifier == "example.com"
        assert targets[1].identifier == "test.org"

    def test_inline_skips_empty_entries(self):
        targets = _load_targets("example.com,,test.org,")
        identifiers = [t.identifier for t in targets]
        assert "" not in identifiers
        assert len(targets) == 2

    def test_text_file_one_per_line(self, tmp_path):
        f = tmp_path / "targets.txt"
        f.write_text("example.com\n192.168.1.1\ntest.org\n")
        targets = _load_targets(str(f))
        assert len(targets) == 3
        assert targets[0].identifier == "example.com"

    def test_text_file_skips_comments(self, tmp_path):
        f = tmp_path / "targets.txt"
        f.write_text("example.com\n# this is a comment\ntest.org\n")
        targets = _load_targets(str(f))
        identifiers = [t.identifier for t in targets]
        assert "# this is a comment" not in identifiers
        assert len(targets) == 2

    def test_text_file_skips_blank_lines(self, tmp_path):
        f = tmp_path / "targets.txt"
        f.write_text("example.com\n\n\ntest.org\n")
        targets = _load_targets(str(f))
        assert len(targets) == 2

    def test_json_file_list_of_strings(self, tmp_path):
        f = tmp_path / "targets.json"
        f.write_text(json.dumps(["example.com", "192.168.1.1"]))
        targets = _load_targets(str(f))
        assert len(targets) == 2
        assert targets[0].identifier == "example.com"

    def test_json_file_list_of_dicts(self, tmp_path):
        f = tmp_path / "targets.json"
        f.write_text(json.dumps([
            {"identifier": "example.com", "type": "domain"},
            {"identifier": "192.168.1.1", "type": "ip"},
        ]))
        targets = _load_targets(str(f))
        assert len(targets) == 2
        assert targets[0].type == "domain"
        assert targets[1].type == "ip"

    def test_default_target_type_is_domain(self):
        targets = _load_targets("example.com")
        assert targets[0].type == "domain"

    def test_default_target_kwargs_empty(self):
        targets = _load_targets("example.com")
        assert targets[0].kwargs == {}

    def test_default_target_tags_empty(self):
        targets = _load_targets("example.com")
        assert targets[0].tags == []


# ── CampaignTarget / CampaignResult / Campaign dataclasses ───────────────────

class TestCampaignDataclasses:
    def test_campaign_target_defaults(self):
        t = CampaignTarget(identifier="example.com")
        assert t.type   == "domain"
        assert t.tags   == []
        assert t.kwargs == {}

    def test_campaign_target_custom(self):
        t = CampaignTarget(identifier="192.168.1.1", type="ip",
                           tags=["internal"], kwargs={"mode": "passive"})
        assert t.type   == "ip"
        assert t.tags   == ["internal"]
        assert t.kwargs == {"mode": "passive"}

    def test_campaign_result_fields(self):
        r = CampaignResult(
            target="example.com", session_uuid="uuid-1",
            findings_count=5, severity_breakdown={"CRITICAL": 2, "HIGH": 3},
            status="ok", duration=12.5,
        )
        assert r.target          == "example.com"
        assert r.findings_count  == 5
        assert r.status          == "ok"
        assert r.duration        == 12.5
        assert r.error           == ""

    def test_campaign_result_with_error(self):
        r = CampaignResult(
            target="fail.com", session_uuid="uuid-2",
            findings_count=0, severity_breakdown={},
            status="error", duration=0.1, error="Connection refused",
        )
        assert r.status == "error"
        assert r.error  == "Connection refused"

    def test_campaign_defaults(self):
        c = Campaign(
            campaign_id="test-id",
            targets=[CampaignTarget(identifier="example.com")],
            modules=["recon", "vuln"],
        )
        assert c.concurrency == 3
        assert c.state       == "queued"
        assert c.results     == []


# ── CampaignManager ───────────────────────────────────────────────────────────

class TestCampaignManager:
    @pytest.fixture
    def manager_and_kernel(self, tmp_path):
        kernel = MagicMock()
        kernel.out = MagicMock()
        kernel.dispatch.return_value = {
            "findings": [{"cve": "CVE-2021-44228", "severity": "CRITICAL"}]
        }
        manager = CampaignManager(
            kernel,
            campaigns_dir=str(tmp_path / "campaigns"),
            default_concurrency=2,
        )
        return manager, kernel, tmp_path

    def test_run_campaign_single_target(self, manager_and_kernel):
        manager, kernel, tmp_path = manager_and_kernel
        campaign = Campaign(
            campaign_id=str(uuid.uuid4()),
            targets=[CampaignTarget(identifier="example.com")],
            modules=["recon"],
        )
        result = manager.run_campaign(campaign)
        assert result.state == "done"
        assert len(result.results) == 1

    def test_run_campaign_multiple_targets(self, manager_and_kernel):
        manager, kernel, tmp_path = manager_and_kernel
        campaign = Campaign(
            campaign_id=str(uuid.uuid4()),
            targets=[
                CampaignTarget(identifier="example.com"),
                CampaignTarget(identifier="test.org"),
                CampaignTarget(identifier="192.168.1.1"),
            ],
            modules=["recon"],
        )
        result = manager.run_campaign(campaign)
        assert result.state == "done"
        assert len(result.results) == 3

    def test_run_campaign_persists_state(self, manager_and_kernel):
        manager, kernel, tmp_path = manager_and_kernel
        campaign_id = str(uuid.uuid4())
        campaign = Campaign(
            campaign_id=campaign_id,
            targets=[CampaignTarget(identifier="example.com")],
            modules=["recon"],
        )
        manager.run_campaign(campaign)
        # Check state file was written
        state_file = tmp_path / "campaigns" / f"{campaign_id}.json"
        assert state_file.exists()
        data = json.loads(state_file.read_text())
        assert data["campaign_id"] == campaign_id
        assert data["state"]       == "done"

    def test_run_campaign_calls_progress_callback(self, manager_and_kernel):
        manager, kernel, tmp_path = manager_and_kernel
        progress_calls = []
        def cb(result):
            progress_calls.append(result)
        campaign = Campaign(
            campaign_id=str(uuid.uuid4()),
            targets=[CampaignTarget(identifier="example.com")],
            modules=["recon"],
        )
        manager.run_campaign(campaign, progress_cb=cb)
        assert len(progress_calls) == 1
        assert isinstance(progress_calls[0], CampaignResult)

    def test_run_campaign_handles_dispatch_error(self, manager_and_kernel):
        manager, kernel, tmp_path = manager_and_kernel
        kernel.dispatch.side_effect = Exception("module failed")
        campaign = Campaign(
            campaign_id=str(uuid.uuid4()),
            targets=[CampaignTarget(identifier="example.com")],
            modules=["recon"],
        )
        result = manager.run_campaign(campaign)
        assert result.state == "done"
        assert len(result.results) == 1
        assert result.results[0].status == "error"
        assert "module failed" in result.results[0].error

    def test_run_campaign_aggregates_findings_count(self, manager_and_kernel):
        manager, kernel, tmp_path = manager_and_kernel
        kernel.dispatch.return_value = {
            "findings": [
                {"cve": "CVE-1", "severity": "CRITICAL"},
                {"cve": "CVE-2", "severity": "HIGH"},
                {"cve": "CVE-3", "severity": "MEDIUM"},
            ]
        }
        campaign = Campaign(
            campaign_id=str(uuid.uuid4()),
            targets=[CampaignTarget(identifier="example.com")],
            modules=["recon", "vuln"],
        )
        result = manager.run_campaign(campaign)
        # 3 findings × 2 modules = 6 total
        assert result.results[0].findings_count == 6

    def test_run_campaign_empty_targets(self, manager_and_kernel):
        manager, kernel, tmp_path = manager_and_kernel
        campaign = Campaign(
            campaign_id=str(uuid.uuid4()),
            targets=[],
            modules=["recon"],
        )
        result = manager.run_campaign(campaign)
        assert result.state   == "done"
        assert result.results == []

    def test_load_campaign_returns_none_for_unknown_id(self, manager_and_kernel):
        manager, kernel, tmp_path = manager_and_kernel
        assert manager.load("nonexistent-campaign-id") is None

    def test_load_campaign_returns_data_after_run(self, manager_and_kernel):
        manager, kernel, tmp_path = manager_and_kernel
        campaign_id = str(uuid.uuid4())
        campaign = Campaign(
            campaign_id=campaign_id,
            targets=[CampaignTarget(identifier="example.com")],
            modules=["recon"],
        )
        manager.run_campaign(campaign)
        data = manager.load(campaign_id)
        assert data is not None
        assert data["campaign_id"] == campaign_id

    def test_list_campaigns_empty(self, manager_and_kernel):
        manager, kernel, tmp_path = manager_and_kernel
        assert manager.list_campaigns() == []

    def test_list_campaigns_after_run(self, manager_and_kernel):
        manager, kernel, tmp_path = manager_and_kernel
        for i in range(3):
            campaign = Campaign(
                campaign_id=str(uuid.uuid4()),
                targets=[CampaignTarget(identifier=f"target{i}.com")],
                modules=["recon"],
            )
            manager.run_campaign(campaign)
        campaigns = manager.list_campaigns()
        assert len(campaigns) == 3

    def test_list_campaigns_has_required_fields(self, manager_and_kernel):
        manager, kernel, tmp_path = manager_and_kernel
        campaign = Campaign(
            campaign_id=str(uuid.uuid4()),
            targets=[CampaignTarget(identifier="example.com")],
            modules=["recon", "vuln"],
        )
        manager.run_campaign(campaign)
        campaigns = manager.list_campaigns()
        assert len(campaigns) == 1
        c = campaigns[0]
        assert "campaign_id"   in c
        assert "state"         in c
        assert "target_count"  in c
        assert "modules"       in c

    def test_campaign_state_file_has_targets(self, manager_and_kernel):
        manager, kernel, tmp_path = manager_and_kernel
        campaign_id = str(uuid.uuid4())
        campaign = Campaign(
            campaign_id=campaign_id,
            targets=[
                CampaignTarget(identifier="a.com"),
                CampaignTarget(identifier="b.com"),
            ],
            modules=["recon"],
        )
        manager.run_campaign(campaign)
        data = manager.load(campaign_id)
        assert len(data["targets"]) == 2

    def test_target_kwargs_passed_to_dispatch(self, manager_and_kernel):
        manager, kernel, tmp_path = manager_and_kernel
        campaign = Campaign(
            campaign_id=str(uuid.uuid4()),
            targets=[CampaignTarget(identifier="example.com",
                                    kwargs={"mode": "passive"})],
            modules=["recon"],
        )
        manager.run_campaign(campaign)
        call_kwargs = kernel.dispatch.call_args[1]
        assert call_kwargs.get("mode") == "passive"


# ── CampaignModule.run() ──────────────────────────────────────────────────────

class TestCampaignModuleRun:
    def _make_module(self, tmp_path):
        kernel = MagicMock()
        kernel.out = MagicMock()
        kernel.session = MagicMock()
        kernel.session.id = "test-session"
        kernel.config.get.return_value = {
            "default_concurrency": 2,
            "campaigns_dir": str(tmp_path / "campaigns"),
        }
        kernel.dispatch.return_value = {"findings": []}
        return CampaignModule(kernel), kernel

    def test_list_campaigns_empty(self, tmp_path):
        module, _ = self._make_module(tmp_path)
        result = module.run(list_campaigns=True)
        assert "campaigns" in result
        assert result["campaigns"] == []

    def test_no_targets_returns_error(self, tmp_path):
        module, _ = self._make_module(tmp_path)
        result = module.run(targets="")
        assert "error" in result
        assert result["error"] == "no_targets"

    def test_run_with_inline_targets(self, tmp_path):
        module, kernel = self._make_module(tmp_path)
        result = module.run(targets="example.com,test.org", modules="recon")
        assert "campaign_id"   in result
        assert "total_findings" in result
        assert result["target_count"] == 2

    def test_run_with_text_file_targets(self, tmp_path):
        f = tmp_path / "targets.txt"
        f.write_text("example.com\ntest.org\n")
        module, kernel = self._make_module(tmp_path)
        result = module.run(targets=str(f), modules="recon")
        assert result["target_count"] == 2

    def test_resume_nonexistent_campaign(self, tmp_path):
        module, _ = self._make_module(tmp_path)
        result = module.run(resume="nonexistent-id")
        assert "error" in result

    def test_ai_context_returns_module_name(self, tmp_path):
        module, _ = self._make_module(tmp_path)
        ctx = module.ai_context()
        assert ctx["module"] == "campaign"
        assert "campaign_count" in ctx