"""Campaign tests against the file loader and CampaignManager API.

Targets are read from text/JSON files; campaign state is saved by the manager.
Dispatch and session I/O are isolated so unit tests never run live scans.
"""

import json
import uuid
from unittest.mock import MagicMock, patch

import pytest

from shadow313.v2.campaign.campaign import (
    Campaign,
    CampaignManager,
    CampaignModule,
    CampaignResult,
    CampaignTarget,
    _sanitize_id,
)


@pytest.fixture
def manager_and_kernel(tmp_path):
    kernel = MagicMock()
    kernel.config.get.return_value = {"campaigns_dir": str(tmp_path), "default_concurrency": 2}
    manager = CampaignManager(kernel, campaigns_dir=str(tmp_path))
    with patch("shadow313.core.session.Session") as session:
        session.return_value.id = "test-session"
        session.return_value.read.return_value = {"findings": [{"severity": "HIGH"}]}
        yield manager, kernel


@pytest.mark.parametrize(
    "content,expected",
    [
        ("example.com\n\n  test.org  \n", ["example.com", "test.org"]),
        ('["example.com", "192.0.2.1"]', ["example.com", "192.0.2.1"]),
        (
            '[{"target": "example.com", "tags": ["prod"], "kwargs": {"quick": true}}]',
            ["example.com"],
        ),
        ("", []),
    ],
)
def test_load_targets_file(manager_and_kernel, tmp_path, content, expected):
    manager, _ = manager_and_kernel
    path = tmp_path / "targets.txt"
    path.write_text(content)
    targets = manager.load_targets_file(str(path))
    assert [t.target for t in targets] == expected
    if '"tags"' in content:
        assert targets[0].tags == ["prod"]
        assert targets[0].kwargs == {"quick": True}


def test_missing_file(manager_and_kernel, tmp_path):
    manager, _ = manager_and_kernel
    assert manager.load_targets_file(str(tmp_path / "missing")) == []


def test_target_defaults_are_independent():
    first, second = CampaignTarget("one"), CampaignTarget("two")
    assert first.type == "domain" and first.kwargs == {} and first.tags == []
    first.tags.append("prod")
    first.kwargs["quick"] = True
    assert second.tags == [] and second.kwargs == {}


def test_result_defaults():
    result = CampaignResult("example.com")
    assert result.status == "queued" and result.findings_count == 0
    assert result.severity_breakdown == {} and result.error == ""


def make_campaign(targets=None, **kwargs):
    return Campaign(
        str(uuid.uuid4()),
        "test campaign",
        targets if targets is not None else [CampaignTarget("example.com")],
        ["recon", "vuln"],
        **kwargs,
    )


def test_run_campaign_and_persist(manager_and_kernel):
    manager, kernel = manager_and_kernel
    campaign = make_campaign([CampaignTarget("one.example"), CampaignTarget("two.example")])
    result = manager.run_campaign(campaign)
    assert result["targets"] == 2
    assert result["total_findings"] == 2
    assert campaign.state == "complete"
    assert all(r.status == "complete" and r.findings_count == 1 for r in campaign.results)
    assert kernel.dispatch.call_count == 4
    kernel.dispatch.assert_any_call("recon", target="one.example", mode="passive")
    kernel.dispatch.assert_any_call("vuln", target="two.example")
    state = json.loads((manager._campaigns_dir / f"{campaign.campaign_id}.json").read_text())
    assert state["state"] == "complete"
    assert len(state["targets"]) == len(state["results"]) == 2


def test_dispatch_failure_is_recorded(manager_and_kernel):
    manager, kernel = manager_and_kernel
    kernel.dispatch.side_effect = RuntimeError("scan failed")
    campaign = make_campaign()
    manager.run_campaign(campaign)
    assert campaign.results[0].status == "error"
    assert campaign.results[0].error == "scan failed"


def test_target_kwargs_forwarded(manager_and_kernel):
    manager, kernel = manager_and_kernel
    campaign = make_campaign([CampaignTarget("example.com", kwargs={"quick": True})])
    manager.run_campaign(campaign)
    kernel.dispatch.assert_any_call("vuln", target="example.com", quick=True)


def test_empty_campaign(manager_and_kernel):
    manager, kernel = manager_and_kernel
    result = manager.run_campaign(make_campaign([]))
    assert result["targets"] == 0 and result["total_findings"] == 0
    kernel.dispatch.assert_not_called()


def test_campaign_ids_are_sanitized(manager_and_kernel):
    manager, _ = manager_and_kernel
    campaign = make_campaign([])
    campaign.campaign_id = "../../outside"
    manager.run_campaign(campaign)
    assert (manager._campaigns_dir / f"{_sanitize_id(campaign.campaign_id)}.json").exists()
    assert "/" not in _sanitize_id(campaign.campaign_id)
    assert len(_sanitize_id("x" * 200)) == 64


def test_list_campaigns_ignores_malformed_json(manager_and_kernel):
    manager, _ = manager_and_kernel
    assert manager.list_campaigns() == []
    manager.run_campaign(make_campaign([]))
    (manager._campaigns_dir / "bad.json").write_text("not json")
    campaigns = manager.list_campaigns()
    assert len(campaigns) == 1 and campaigns[0]["state"] == "complete"


def test_severity_counts():
    assert CampaignManager._count_severities(
        [
            {"severity": "HIGH"},
            {"severity": "high"},
            {"severity": "LOW"},
            {},
        ]
    ) == {"high": 2, "low": 1, "unknown": 1}


def test_campaign_module(manager_and_kernel, tmp_path):
    _, kernel = manager_and_kernel
    module = CampaignModule(kernel)
    module.register(kernel)
    kernel.register.assert_called_once_with("campaign", module.run)
    assert module.run() == {}
    assert module.run(list_campaigns=True) == {"campaigns": []}
    path = tmp_path / "targets.txt"
    path.write_text("example.com\n")
    result = module.run(targets=str(path), modules="recon", name="file campaign")
    assert result["name"] == "file campaign" and result["targets"] == 1


def test_repeated_campaign_runs_after_event_loop_closes(manager_and_kernel):
    manager, _ = manager_and_kernel
    first, second = make_campaign([]), make_campaign([])
    assert manager.run_campaign(first)["state"] == "complete"
    assert manager.run_campaign(second)["state"] == "complete"


@pytest.mark.asyncio
async def test_campaign_run_inside_running_event_loop(manager_and_kernel):
    manager, _ = manager_and_kernel
    result = manager.run_campaign(make_campaign())
    assert result["state"] == "complete" and result["total_findings"] == 1
