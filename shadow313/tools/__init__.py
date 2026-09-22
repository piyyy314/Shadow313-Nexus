"""Shadow313 Proprietary Tools — 35 purpose-built security intelligence tools."""
__version__ = "6.0.0"

TOOL_REGISTRY = {
    # ── Red Team (5) ──────────────────────────────────────────────────────────
    "nexusprobe":              "shadow313.tools.redteam.nexusprobe",
    "phantomscan":             "shadow313.tools.redteam.phantomscan",
    "shadowdns":               "shadow313.tools.redteam.shadowdns",
    "ghosthttp":               "shadow313.tools.redteam.ghosthttp",
    "c2profiler":              "shadow313.tools.redteam.c2profiler",
    # ── Blue Team (9) ─────────────────────────────────────────────────────────
    "sentinelbaseline":        "shadow313.tools.blueteam.sentinelbaseline",
    "logforge":                "shadow313.tools.blueteam.logforge",
    "honeywirenet":            "shadow313.tools.blueteam.honeywirenet",
    "vaultscan":               "shadow313.tools.blueteam.vaultscan",
    "forensictracer":          "shadow313.tools.blueteam.forensictracer",
    "cloudaudit":              "shadow313.tools.blueteam.cloudaudit",
    "kernelintegritymonitor":  "shadow313.tools.blueteam.kernelintegritymonitor",
    "deceptionengine":         "shadow313.tools.blueteam.deceptionengine",
    "zerotrust":               "shadow313.tools.blueteam.zerotrust",
    # ── Purple Team (8) ───────────────────────────────────────────────────────
    "atomicchain":             "shadow313.tools.purpleteam.atomicchain",
    "detectionforge":          "shadow313.tools.purpleteam.detectionforge",
    "coveragematrix":          "shadow313.tools.purpleteam.coveragematrix",
    "threatreplay":            "shadow313.tools.purpleteam.threatreplay",
    "adversaryemulator":       "shadow313.tools.purpleteam.adversaryemulator",
    "supplychainauditor":      "shadow313.tools.purpleteam.supplychainauditor",
    "lateralmovementtracker":  "shadow313.tools.purpleteam.lateralmovementtracker",
    "threathunter":            "shadow313.tools.purpleteam.threathunter",
    # ── AI-Native (13) ────────────────────────────────────────────────────────
    "nexusrag":                "shadow313.tools.ai.nexusrag",
    "threatnarrator":          "shadow313.tools.ai.threatnarrator",
    "rulesmith":               "shadow313.tools.ai.rulesmith",
    "explaincve":              "shadow313.tools.ai.explaincve",
    "threatintelligence":      "shadow313.tools.ai.threatintelligence",
    "malwareanalyzer":         "shadow313.tools.ai.malwareanalyzer",
    "memoryforensics":         "shadow313.tools.ai.memoryforensics",
    "aegishunter":             "shadow313.tools.ai.aegishunter",
    "palantirbridge":          "shadow313.tools.ai.palantirbridge",
    # ── Shadow313-Native Custom Tools (4) ────────────────────────────────────
    "behavioralgraphengine":   "shadow313.tools.ai.behavioralgraphengine",
    "quantumthreatscorer":     "shadow313.tools.ai.quantumthreatscorer",
    "adaptiveruleengine":      "shadow313.tools.ai.adaptiveruleengine",
    "threatdnaprofiler":       "shadow313.tools.ai.threatdnaprofiler",
}

TOOL_CATEGORIES = {
    "red_team":   ["nexusprobe", "phantomscan", "shadowdns", "ghosthttp", "c2profiler"],
    "blue_team":  ["sentinelbaseline", "logforge", "honeywirenet", "vaultscan",
                   "forensictracer", "cloudaudit", "kernelintegritymonitor",
                   "deceptionengine", "zerotrust"],
    "purple_team":["atomicchain", "detectionforge", "coveragematrix", "threatreplay",
                   "adversaryemulator", "supplychainauditor", "lateralmovementtracker",
                   "threathunter"],
    "ai_native":  ["nexusrag", "threatnarrator", "rulesmith", "explaincve",
                   "threatintelligence", "malwareanalyzer", "memoryforensics",
                   "aegishunter", "palantirbridge", "behavioralgraphengine",
                   "quantumthreatscorer", "adaptiveruleengine", "threatdnaprofiler"],
}
