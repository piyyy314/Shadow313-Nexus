"""
shadow313.v2.campaign.campaign  — v4
Asyncio-parallel multi-target scanning campaigns.

BUG FIXES:
  - asyncio.Semaphore used inside non-async context causing RuntimeError —
    wrapped in asyncio.run() with proper event loop management.
  - Campaign state file used campaign_id as filename but didn't sanitize it —
    added path sanitization.
  - _run_target() swallowed all exceptions silently — now records error status.
  - list_campaigns() crashed on malformed JSON files — added try/except.
"""
from __future__ import annotations
import asyncio
import json
import re
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _sanitize_id(s: str) -> str:
    """FIX: sanitize campaign_id for use as filename."""
    return re.sub(r"[^a-zA-Z0-9_\-]", "_", s)[:64]


@dataclass
class CampaignTarget:
    target:  str
    type:    str = "domain"
    tags:    list[str] = field(default_factory=list)
    kwargs:  dict = field(default_factory=dict)


@dataclass
class CampaignResult:
    target:             str
    session_uuid:       str = ""
    findings_count:     int = 0
    severity_breakdown: dict = field(default_factory=dict)
    status:             str = "queued"
    duration:           float = 0.0
    error:              str = ""


@dataclass
class Campaign:
    campaign_id:  str
    name:         str
    targets:      list[CampaignTarget]
    modules:      list[str]
    concurrency:  int = 3
    state:        str = "queued"
    results:      list[CampaignResult] = field(default_factory=list)


class CampaignManager:
    """Asyncio semaphore-controlled multi-target campaign executor."""

    def __init__(self, kernel, campaigns_dir: str = "~/.shadow313/campaigns") -> None:
        self._kernel       = kernel
        self._campaigns_dir = Path(campaigns_dir).expanduser()
        self._campaigns_dir.mkdir(parents=True, exist_ok=True)

    def run_campaign(self, campaign: Campaign) -> dict:
        """Entry point — runs asyncio event loop."""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(asyncio.run, self._execute(campaign))
                    return future.result()
            return asyncio.run(self._execute(campaign))
        except Exception as exc:
            return {"error": str(exc), "campaign_id": campaign.campaign_id}

    async def _execute(self, campaign: Campaign) -> dict:
        campaign.state = "running"
        self._save(campaign)

        sem     = asyncio.Semaphore(campaign.concurrency)
        tasks   = [self._run_target(sem, campaign, t) for t in campaign.targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        campaign.results = []
        for r in results:
            if isinstance(r, CampaignResult):
                campaign.results.append(r)
            elif isinstance(r, Exception):
                campaign.results.append(CampaignResult(
                    target="unknown", status="error", error=str(r)
                ))

        campaign.state = "complete"
        self._save(campaign)

        return self._summarize(campaign)

    async def _run_target(
        self, sem: asyncio.Semaphore, campaign: Campaign, target: CampaignTarget
    ) -> CampaignResult:
        async with sem:
            result = CampaignResult(target=target.target, status="running")
            start  = time.time()
            try:
                from shadow313.core.session import Session
                session = Session()
                result.session_uuid = session.id

                for module in campaign.modules:
                    kwargs = {"target": target.target, **target.kwargs}
                    if module == "recon":
                        kwargs["mode"] = "passive"
                    # Run in thread pool to avoid blocking event loop
                    loop = asyncio.get_event_loop()
                    await loop.run_in_executor(
                        None,
                        lambda m=module, k=kwargs: self._kernel.dispatch(m, **k),
                    )

                findings = (session.read("findings.json") or {}).get("findings", [])
                result.findings_count = len(findings)
                result.severity_breakdown = self._count_severities(findings)
                result.status = "complete"
            except Exception as exc:
                # FIX: record error status instead of silently swallowing
                result.status = "error"
                result.error  = str(exc)
            finally:
                result.duration = round(time.time() - start, 2)
            return result

    @staticmethod
    def _count_severities(findings: list[dict]) -> dict:
        counts: dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "unknown").lower()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _summarize(self, campaign: Campaign) -> dict:
        total_findings = sum(r.findings_count for r in campaign.results)
        return {
            "campaign_id":    campaign.campaign_id,
            "name":           campaign.name,
            "targets":        len(campaign.targets),
            "complete":       sum(1 for r in campaign.results if r.status == "complete"),
            "errors":         sum(1 for r in campaign.results if r.status == "error"),
            "total_findings": total_findings,
            "results":        [asdict(r) for r in campaign.results],
            "state":          campaign.state,
        }

    def _save(self, campaign: Campaign) -> None:
        # FIX: sanitize campaign_id for filename
        safe_id = _sanitize_id(campaign.campaign_id)
        path = self._campaigns_dir / f"{safe_id}.json"
        data = {
            "campaign_id": campaign.campaign_id,
            "name":        campaign.name,
            "state":       campaign.state,
            "modules":     campaign.modules,
            "concurrency": campaign.concurrency,
            "targets":     [asdict(t) for t in campaign.targets],
            "results":     [asdict(r) for r in campaign.results],
            "updated":     datetime.now(timezone.utc).isoformat(),
        }
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)

    def list_campaigns(self) -> list[dict]:
        campaigns = []
        for f in sorted(
            self._campaigns_dir.glob("*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        ):
            try:
                campaigns.append(json.loads(f.read_text()))
            except Exception:
                # FIX: skip malformed JSON files
                pass
        return campaigns

    def load_targets_file(self, path: str) -> list[CampaignTarget]:
        p = Path(path)
        if not p.exists():
            return []
        text = p.read_text().strip()
        if text.startswith("[") or text.startswith("{"):
            try:
                data = json.loads(text)
                if isinstance(data, list):
                    return [CampaignTarget(**item) if isinstance(item, dict)
                            else CampaignTarget(target=str(item)) for item in data]
            except Exception:
                pass
        # Plain text: one target per line
        return [CampaignTarget(target=line.strip())
                for line in text.splitlines() if line.strip()]


class CampaignModule:
    """shadow313.v2.campaign — Multi-target campaigns. Registered: campaign"""

    def __init__(self, kernel) -> None:
        self.kernel  = kernel
        self.out     = kernel.out
        cfg          = kernel.config.get("campaign", default={})
        campaigns_dir= cfg.get("campaigns_dir", "~/.shadow313/campaigns")
        concurrency  = int(cfg.get("default_concurrency", 3))
        self.manager = CampaignManager(kernel, campaigns_dir)
        self._default_concurrency = concurrency

    def register(self, kernel) -> None:
        kernel.register("campaign", self.run)

    def run(
        self,
        targets: str = "",
        modules: str = "recon,vuln",
        concurrency: int = 0,
        resume: str = "",
        list_campaigns: bool = False,
        name: str = "",
    ) -> dict:
        self.out.section("CAMPAIGN MANAGER")

        if list_campaigns:
            campaigns = self.manager.list_campaigns()
            rows = [[c.get("campaign_id","")[:8], c.get("name",""),
                     c.get("state",""), str(len(c.get("targets",[])))]
                    for c in campaigns[:20]]
            self.out.table(["ID","Name","State","Targets"], rows, "Campaigns")
            return {"campaigns": campaigns}

        if not targets:
            self.out.error("--targets required")
            return {}

        target_list = self.manager.load_targets_file(targets)
        if not target_list:
            self.out.error(f"No targets loaded from: {targets}")
            return {}

        module_list = [m.strip() for m in modules.split(",") if m.strip()]
        campaign = Campaign(
            campaign_id = str(uuid.uuid4()),
            name        = name or f"campaign_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}",
            targets     = target_list,
            modules     = module_list,
            concurrency = concurrency or self._default_concurrency,
        )

        self.out.info(f"Starting campaign: {len(target_list)} targets, modules: {module_list}")
        self.out.info(f"Concurrency: {campaign.concurrency}")

        summary = self.manager.run_campaign(campaign)
        self.out.result(summary, "Campaign Summary")
        return summary