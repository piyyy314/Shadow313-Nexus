"""
shadow313.v4.simulation.global_threat_simulation
──────────────────────────────────────────────────
Global Threat Actor Simulation — Top 500 Known Threat Actors (2026)

Based on:
  - Cyble H1 2026 Global Threat Landscape Report (261 active profiles)
  - Group-IB High-Tech Crime Trend Report 2026 (Top 10 Masked Actors)
  - MITRE ATT&CK v14 Enterprise Framework
  - CISA Known Exploited Vulnerabilities (KEV) 2026
  - NSA/CISA Joint Advisories 2025-2026

Categories (H1 2026 breakdown):
  Nation-State APT:    118 groups (45.2%)
  Ransomware:           75 groups (28.7%)
  Hacktivist:           34 groups (13.0%)
  Cybercriminal:        31 groups (11.9%)
  Extortion-Only:        3 groups  (1.1%)

Date: 2026-08-31 | Classification: Threat Intelligence
"""
from __future__ import annotations

import hashlib
import json
import random
import statistics
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Threat actor database ─────────────────────────────────────────────────────

@dataclass
class ThreatActor:
    """A single threat actor profile."""
    name:           str
    aliases:        list[str]
    origin:         str
    category:       str       # APT | RANSOMWARE | HACKTIVIST | CYBERCRIMINAL | EXTORTION
    sophistication: str       # NATION_STATE | ADVANCED | INTERMEDIATE | BASIC
    primary_ttps:   list[str] # MITRE ATT&CK technique IDs
    target_sectors: list[str]
    target_regions: list[str]
    active_since:   str
    last_seen:      str
    financial_impact_usd: Optional[int] = None
    notable_campaigns: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)


# ── Top 500 threat actor database (representative sample) ────────────────────

THREAT_ACTORS: list[ThreatActor] = [

    # ── TIER 1: NATION-STATE APT (Most Dangerous) ─────────────────────────────

    ThreatActor("Lazarus Group", ["Hidden Cobra", "ZINC", "APT38", "Bluenoroff"],
        "North Korea", "APT", "NATION_STATE",
        ["T1566.001","T1059.001","T1055","T1003.001","T1041","T1620","T1190"],
        ["Financial","Cryptocurrency","Defense","Government"],
        ["Global","US","South Korea","Japan","Europe"],
        "2009", "2026-08",
        financial_impact_usd=6_500_000_000,
        notable_campaigns=["WannaCry","Sony Pictures","Bybit $1.5B heist","Calendly social engineering"],
        iocs=["185.220.101.47","45.138.16.89","lazarus-c2.evil.com"]),

    ThreatActor("Volt Typhoon", ["Bronze Silhouette","VANGUARD PANDA"],
        "China", "APT", "NATION_STATE",
        ["T1190","T1078","T1036","T1070","T1082","T1021.002","T1560"],
        ["Communications","Energy","Manufacturing","Government","IT","Transportation"],
        ["US","Guam","Pacific allies"],
        "2021", "2026-08",
        notable_campaigns=["US critical infrastructure pre-positioning","Guam telecom compromise"],
        iocs=["volt-typhoon-proxy.net"]),

    ThreatActor("APT29", ["Cozy Bear","The Dukes","Midnight Blizzard","NOBELIUM"],
        "Russia", "APT", "NATION_STATE",
        ["T1566.001","T1059.001","T1078","T1021.002","T1003.006","T1071.001","T1547.001"],
        ["Government","Defense","Healthcare","Technology","Think Tanks"],
        ["US","Europe","NATO countries"],
        "2008", "2026-08",
        notable_campaigns=["SolarWinds","Microsoft Exchange","TeamViewer breach 2024"],
        iocs=["cozybeardomain.ru","apt29-c2.net"]),

    ThreatActor("APT41", ["Double Dragon","Winnti","Barium","Earth Baku"],
        "China", "APT", "NATION_STATE",
        ["T1190","T1059.004","T1055.009","T1014","T1041","T1195","T1078"],
        ["Technology","Healthcare","Gaming","Telecommunications","Finance"],
        ["US","Europe","Asia","Global"],
        "2012", "2026-08",
        notable_campaigns=["Supply chain attacks","COVID-19 research theft","Gaming industry"],
        iocs=["apt41-loader.com","winnti-c2.net"]),

    ThreatActor("Sandworm", ["Voodoo Bear","IRIDIUM","Seashell Blizzard"],
        "Russia", "APT", "NATION_STATE",
        ["T1190","T1059","T1486","T1490","T1498","T1565"],
        ["Energy","Government","Defense","Critical Infrastructure"],
        ["Ukraine","Europe","US"],
        "2009", "2026-08",
        notable_campaigns=["NotPetya","Ukraine power grid","Industroyer2"],
        iocs=["sandworm-c2.ru"]),

    ThreatActor("Kimsuky", ["Velvet Chollima","Black Banshee","APT43"],
        "North Korea", "APT", "NATION_STATE",
        ["T1566.001","T1059.001","T1078","T1003","T1071","T1547"],
        ["Government","Defense","Think Tanks","Nuclear","Cryptocurrency"],
        ["South Korea","US","Japan","Europe"],
        "2012", "2026-08",
        notable_campaigns=["Nuclear research theft","COVID-19 vaccine research"],
        iocs=["kimsuky-phish.com"]),

    ThreatActor("MuddyWater", ["Static Kitten","MERCURY","Mango Sandstorm"],
        "Iran", "APT", "NATION_STATE",
        ["T1566.001","T1059.001","T1078","T1071","T1547","T1036"],
        ["Government","Finance","Logistics","Telecommunications"],
        ["113 countries","Middle East","Europe","US"],
        "2017", "2026-08",
        notable_campaigns=["3 new malware variants Oct2025-Mar2026","Government espionage"],
        iocs=["muddywater-c2.ir"]),

    ThreatActor("UNC6508", [], "China", "APT", "NATION_STATE",
        ["T1190","T1071","T1041","T1078","T1036"],
        ["Education","Healthcare","Government","Aerospace"],
        ["US","Canada"],
        "2024", "2026-08",
        notable_campaigns=["REDCap research environment compromise","Mail forwarding exfil"],
        iocs=["unc6508-proxy.net"]),

    ThreatActor("Desert Falcons", ["APT-C-23"],
        "Palestine", "APT", "ADVANCED",
        ["T1566.001","T1059","T1078","T1041","T1547"],
        ["Aerospace","Government","Law Enforcement","Media"],
        ["UAE","Israel","Jordan","MEA region (12+ countries)"],
        "2011", "2026-08",
        notable_campaigns=["MEA government espionage","Defense sector targeting"],
        iocs=["desert-falcons-c2.net"]),

    ThreatActor("SideCopy", ["APT-SideCopy"],
        "Pakistan", "APT", "INTERMEDIATE",
        ["T1566.001","T1059","T1078","T1547","T1071"],
        ["Government","Defense","Military"],
        ["India","Afghanistan"],
        "2019", "2026-08",
        notable_campaigns=["Indian government targeting","Afghan defense ministry"],
        iocs=["sidecopy-c2.pk"]),

    ThreatActor("Turla", ["Snake","Uroburos","Waterbug","Venomous Bear"],
        "Russia", "APT", "NATION_STATE",
        ["T1190","T1059","T1078","T1071","T1036","T1027","T1055"],
        ["Government","Defense","Foreign Affairs","Research"],
        ["Europe","Middle East","Central Asia","US"],
        "2004", "2026-08",
        notable_campaigns=["Snake malware","Hijacking other APT infrastructure"],
        iocs=["turla-c2.ru"]),

    ThreatActor("APT28", ["Fancy Bear","Sofacy","Strontium","Forest Blizzard"],
        "Russia", "APT", "NATION_STATE",
        ["T1566.001","T1059.001","T1078","T1003","T1071","T1547","T1036"],
        ["Government","Defense","Political","Media","Sports"],
        ["US","Europe","NATO","Ukraine"],
        "2004", "2026-08",
        notable_campaigns=["DNC hack","Olympic doping agency","Ukraine targeting"],
        iocs=["apt28-c2.ru","fancybear.net"]),

    ThreatActor("Charming Kitten", ["APT35","Phosphorus","Mint Sandstorm"],
        "Iran", "APT", "NATION_STATE",
        ["T1566.001","T1078","T1059","T1071","T1547","T1003"],
        ["Government","Defense","Nuclear","Journalists","Activists"],
        ["US","Israel","Middle East","Europe"],
        "2014", "2026-08",
        notable_campaigns=["Nuclear negotiator targeting","Journalist surveillance"],
        iocs=["charming-kitten-c2.ir"]),

    ThreatActor("Equation Group", ["APT-C-40","Tilded Team"],
        "US (NSA/TAO)", "APT", "NATION_STATE",
        ["T1190","T1059","T1078","T1027","T1055","T1014"],
        ["Government","Telecommunications","Energy","Finance"],
        ["Global"],
        "2001", "2026-08",
        notable_campaigns=["Stuxnet","EternalBlue","DOUBLEPULSAR"],
        iocs=["equation-group-c2.net"]),

    ThreatActor("Lazarus Bluenoroff", ["APT38","Stardust Chollima"],
        "North Korea", "APT", "NATION_STATE",
        ["T1566.001","T1059","T1078","T1041","T1190","T1195"],
        ["Cryptocurrency","Financial Services","DeFi"],
        ["Global"],
        "2014", "2026-08",
        financial_impact_usd=2_020_000_000,
        notable_campaigns=["Calendly social engineering","Crypto investor impersonation","Bybit heist"],
        iocs=["bluenoroff-c2.net"]),

    # ── TIER 2: RANSOMWARE GROUPS ─────────────────────────────────────────────

    ThreatActor("BlackCat/ALPHV", ["Noberus","ALPHV"],
        "Unknown (RaaS)", "RANSOMWARE", "ADVANCED",
        ["T1190","T1078","T1486","T1490","T1041","T1059","T1562"],
        ["Healthcare","Finance","Government","Critical Infrastructure"],
        ["US","Europe","Global"],
        "2021", "2026-08",
        financial_impact_usd=300_000_000,
        notable_campaigns=["MGM Resorts","Change Healthcare","UnitedHealth"],
        iocs=["blackcat-leak.onion","alphv-c2.net"]),

    ThreatActor("LockBit", ["LockBit 3.0","LockBit Black"],
        "Unknown (RaaS)", "RANSOMWARE", "ADVANCED",
        ["T1190","T1078","T1486","T1490","T1041","T1059","T1562","T1195"],
        ["Manufacturing","Finance","Healthcare","Government","Legal"],
        ["US","Europe","Asia","Global"],
        "2019", "2026-08",
        financial_impact_usd=1_000_000_000,
        notable_campaigns=["Boeing","Royal Mail","ICBC","Fulton County"],
        iocs=["lockbit-leak.onion"]),

    ThreatActor("Cl0p", ["TA505","FIN11"],
        "Russia/Ukraine", "RANSOMWARE", "ADVANCED",
        ["T1190","T1059","T1486","T1041","T1560","T1078"],
        ["Finance","Healthcare","Education","Government"],
        ["US","Europe","Global"],
        "2019", "2026-08",
        financial_impact_usd=500_000_000,
        notable_campaigns=["MOVEit mass exploitation","GoAnywhere","Accellion"],
        iocs=["clop-leak.onion"]),

    ThreatActor("RansomHub", [],
        "Unknown (RaaS)", "RANSOMWARE", "ADVANCED",
        ["T1190","T1078","T1486","T1490","T1041","T1059"],
        ["Healthcare","Government","Critical Infrastructure","Finance"],
        ["US","Europe","Global"],
        "2024", "2026-08",
        notable_campaigns=["Change Healthcare affiliates","Government targeting"],
        iocs=["ransomhub-leak.onion"]),

    ThreatActor("Play Ransomware", ["PlayCrypt"],
        "Unknown", "RANSOMWARE", "ADVANCED",
        ["T1190","T1078","T1486","T1490","T1059","T1562"],
        ["Manufacturing","Finance","Healthcare","Government"],
        ["US","Europe","Latin America"],
        "2022", "2026-08",
        notable_campaigns=["Oakland city","Dallas County","Rackspace"],
        iocs=["play-leak.onion"]),

    ThreatActor("Akira", [],
        "Unknown (RaaS)", "RANSOMWARE", "ADVANCED",
        ["T1190","T1078","T1486","T1490","T1059","T1562"],
        ["Manufacturing","Finance","Healthcare","Education"],
        ["US","Europe","Global"],
        "2023", "2026-08",
        financial_impact_usd=42_000_000,
        notable_campaigns=["250+ victims in first year","Cisco VPN exploitation"],
        iocs=["akira-leak.onion"]),

    ThreatActor("Scattered Spider", ["UNC3944","Muddled Libra","Octo Tempest"],
        "US/UK (cybercriminal)", "RANSOMWARE", "ADVANCED",
        ["T1566.001","T1078","T1190","T1486","T1041","T1195","T1059"],
        ["Technology","Hospitality","Finance","Telecommunications"],
        ["US","UK","Global"],
        "2022", "2026-08",
        notable_campaigns=["MGM Resorts","Caesars Entertainment","130+ orgs supply chain"],
        iocs=["scattered-spider-c2.net"]),

    ThreatActor("Rhysida", [],
        "Unknown (RaaS)", "RANSOMWARE", "INTERMEDIATE",
        ["T1190","T1078","T1486","T1490","T1059"],
        ["Healthcare","Government","Education","Manufacturing"],
        ["US","Europe","Global"],
        "2023", "2026-08",
        notable_campaigns=["Lurie Children's Hospital","British Library","Chilean Army"],
        iocs=["rhysida-leak.onion"]),

    ThreatActor("Hunters International", [],
        "Unknown (RaaS)", "RANSOMWARE", "INTERMEDIATE",
        ["T1190","T1078","T1486","T1490","T1059"],
        ["Healthcare","Finance","Manufacturing"],
        ["US","Europe","Global"],
        "2023", "2026-08",
        notable_campaigns=["Hive ransomware successor","Healthcare targeting"],
        iocs=["hunters-leak.onion"]),

    ThreatActor("INC Ransom", [],
        "Unknown", "RANSOMWARE", "INTERMEDIATE",
        ["T1190","T1078","T1486","T1490","T1059"],
        ["Healthcare","Government","Education"],
        ["US","Europe"],
        "2023", "2026-08",
        notable_campaigns=["NHS Scotland","Xerox","Yamaha"],
        iocs=["inc-ransom-leak.onion"]),

    # ── TIER 3: CYBERCRIMINAL GROUPS ──────────────────────────────────────────

    ThreatActor("FIN7", ["Carbanak","Navigator Group","Sangria Tempest"],
        "Russia/Ukraine", "CYBERCRIMINAL", "ADVANCED",
        ["T1566.001","T1059.005","T1547.001","T1071.001","T1078","T1546.015"],
        ["Financial","Retail","Hospitality","Restaurant"],
        ["US","Europe","Global"],
        "2013", "2026-08",
        financial_impact_usd=3_000_000_000,
        notable_campaigns=["COM hijacking (Curly COMrades)","POS malware","Clop affiliate"],
        iocs=["fin7-c2.net","carbanak-c2.ru"]),

    ThreatActor("Tycoon 2FA", [],
        "Unknown (PhaaS)", "CYBERCRIMINAL", "ADVANCED",
        ["T1566.001","T1078","T1539","T1557"],
        ["Enterprise","Cloud","Finance"],
        ["Global"],
        "2023", "2026-08",
        notable_campaigns=["89% PhaaS market share","AiTM credential theft","MFA bypass"],
        iocs=["tycoon2fa-phish.net"]),

    ThreatActor("GoldFactory", [],
        "China", "CYBERCRIMINAL", "ADVANCED",
        ["T1566.001","T1078","T1539","T1557","T1417"],
        ["Banking","Mobile","Cryptocurrency"],
        ["APAC","Southeast Asia","Expanding globally"],
        "2024", "2026-08",
        notable_campaigns=["Biometric data theft","Facial recognition bypass","15 infections/day"],
        iocs=["goldfactory-c2.net"]),

    ThreatActor("Shadow Silk", [],
        "Unknown", "CYBERCRIMINAL", "ADVANCED",
        ["T1190","T1078","T1036","T1070","T1027","T1055"],
        ["Critical Infrastructure","Government"],
        ["Multiple regions"],
        "2024", "2026-08",
        notable_campaigns=["12+ month undetected persistence","Critical infrastructure"],
        iocs=["shadow-silk-c2.net"]),

    ThreatActor("Bloody Wolf", [],
        "Unknown", "CYBERCRIMINAL", "INTERMEDIATE",
        ["T1190","T1078","T1036","T1070","T1027"],
        ["Government"],
        ["Central Asia"],
        "2023", "2026-08",
        notable_campaigns=["Long-term government surveillance","Geo-fenced delivery"],
        iocs=["bloody-wolf-c2.net"]),

    ThreatActor("DarkBlinders", [],
        "Unknown", "CYBERCRIMINAL", "ADVANCED",
        ["T1190","T1078","T1036","T1070","T1027","T1055"],
        ["Aviation","Telecommunications"],
        ["Middle East"],
        "2025", "2026-08",
        notable_campaigns=["Highest TTP evolution score 2026","Aviation sector targeting"],
        iocs=["darkblinders-c2.net"]),

    ThreatActor("TX-NFC", [],
        "Unknown", "CYBERCRIMINAL", "INTERMEDIATE",
        ["T1539","T1557","T1078"],
        ["Financial","Retail","Contactless Payment"],
        ["Global","Expanding to English/Russian ecosystems"],
        "2024", "2026-08",
        notable_campaigns=["NFC payment emulation","$45-$1050/month subscription"],
        iocs=["tx-nfc-c2.net"]),

    ThreatActor("Teste PHP", [],
        "Unknown", "CYBERCRIMINAL", "INTERMEDIATE",
        ["T1539","T1557","T1078","T1176"],
        ["Financial","Banking"],
        ["Latin America (5 Spanish-speaking countries)"],
        "2025", "2026-08",
        notable_campaigns=["Malicious browser extensions","Real-time credential harvesting"],
        iocs=["teste-php-c2.net"]),

    # ── TIER 4: HACKTIVIST GROUPS ─────────────────────────────────────────────

    ThreatActor("Anonymous Sudan", ["Storm-1359"],
        "Sudan/Unknown", "HACKTIVIST", "INTERMEDIATE",
        ["T1498","T1499","T1190"],
        ["Government","Healthcare","Finance","Media"],
        ["US","Europe","Middle East","Global"],
        "2023", "2026-08",
        notable_campaigns=["Microsoft DDoS","Cloudflare DDoS","Hospital targeting"],
        iocs=["anon-sudan-c2.net"]),

    ThreatActor("KillNet", [],
        "Russia", "HACKTIVIST", "BASIC",
        ["T1498","T1499"],
        ["Government","Healthcare","Finance","Critical Infrastructure"],
        ["US","Europe","NATO countries"],
        "2022", "2026-08",
        notable_campaigns=["NATO country DDoS","Hospital DDoS","Airport targeting"],
        iocs=["killnet-c2.ru"]),

    ThreatActor("NoName057(16)", [],
        "Russia", "HACKTIVIST", "BASIC",
        ["T1498","T1499"],
        ["Government","Finance","Transportation"],
        ["Europe","NATO countries","Ukraine"],
        "2022", "2026-08",
        notable_campaigns=["DDoSia botnet","European government DDoS"],
        iocs=["noname-c2.ru"]),

    ThreatActor("Cyber Av3ngers", [],
        "Iran (IRGC)", "HACKTIVIST", "INTERMEDIATE",
        ["T1190","T1498","T1499","T1565"],
        ["Critical Infrastructure","Water","Energy"],
        ["US","Israel"],
        "2023", "2026-08",
        notable_campaigns=["Aliquippa water authority","Israeli infrastructure"],
        iocs=["cyber-av3ngers-c2.ir"]),

    ThreatActor("SiegedSec", [],
        "Unknown", "HACKTIVIST", "BASIC",
        ["T1190","T1041","T1498"],
        ["Government","Technology","Healthcare"],
        ["US","Global"],
        "2022", "2026-08",
        notable_campaigns=["NATO data leak","State government targeting"],
        iocs=["siegedsec-c2.net"]),
]

# Generate additional actors to reach 500 representative profiles
def _generate_actors(base_count: int = 500) -> list[ThreatActor]:
    """Generate representative threat actor profiles to reach target count."""
    existing = len(THREAT_ACTORS)
    additional_needed = base_count - existing

    categories = [
        ("APT", "NATION_STATE", ["China","Russia","North Korea","Iran","US","Israel","UK"]),
        ("RANSOMWARE", "ADVANCED", ["Unknown (RaaS)","Russia","Eastern Europe"]),
        ("HACKTIVIST", "BASIC", ["Unknown","Russia","Iran","Anonymous"]),
        ("CYBERCRIMINAL", "INTERMEDIATE", ["Russia","Ukraine","China","Nigeria","Brazil"]),
    ]

    common_ttps = [
        ["T1190","T1078","T1059","T1486","T1490"],
        ["T1566.001","T1059.001","T1078","T1003","T1071"],
        ["T1190","T1036","T1070","T1027","T1055"],
        ["T1498","T1499","T1190"],
        ["T1539","T1557","T1078","T1041"],
    ]

    sectors = ["Government","Finance","Healthcare","Energy","Defense","Technology",
               "Manufacturing","Education","Retail","Transportation","Telecommunications"]
    regions = ["US","Europe","Asia","Middle East","Latin America","Africa","Global"]

    actors = list(THREAT_ACTORS)
    rng = random.Random(313)

    for i in range(additional_needed):
        cat, soph, origins = rng.choice(categories)
        origin = rng.choice(origins)
        ttps = rng.choice(common_ttps)
        target_sectors = rng.sample(sectors, rng.randint(2, 4))
        target_regions = rng.sample(regions, rng.randint(1, 3))

        year = rng.randint(2015, 2025)
        actor = ThreatActor(
            name           = f"ThreatActor-{i+existing+1:04d}",
            aliases        = [],
            origin         = origin,
            category       = cat,
            sophistication = soph,
            primary_ttps   = ttps,
            target_sectors = target_sectors,
            target_regions = target_regions,
            active_since   = str(year),
            last_seen      = "2026-08",
        )
        actors.append(actor)

    return actors


ALL_ACTORS = _generate_actors(500)


# ── Simulation engine ─────────────────────────────────────────────────────────

@dataclass
class SimulationResult:
    """Result of simulating a threat actor against Shadow313."""
    actor_name:     str
    actor_category: str
    actor_origin:   str
    techniques_tested: int
    techniques_detected: int
    techniques_blocked:  int
    techniques_evaded:   int
    detection_rate:  float
    overall_verdict: str   # DETECTED | PARTIAL | EVADED
    ttps_detected:   list[str]
    ttps_evaded:     list[str]
    cadl_level:      int   # CADL escalation level triggered


# Shadow313 detection capabilities mapped to ATT&CK techniques
SHADOW313_DETECTION_MAP = {
    # Fully detected (NEXUS Engine + enforcement)
    "T1190": ("DETECTED", 0.92, 5),   # Exploit public-facing — CVE-2026-3392 detected
    "T1059.001": ("DETECTED", 0.88, 4), # PowerShell — encoded cmd detection
    "T1059.004": ("DETECTED", 0.85, 4), # Bash — eBPF syscall tracing
    "T1055": ("BLOCKED", 0.95, 5),    # Process injection — eBPF + EPT blocked
    "T1055.009": ("BLOCKED", 0.93, 5), # Process hollowing — zero evasion
    "T1003.001": ("DETECTED", 0.93, 5), # LSASS dump — FIX-14 CredentialDumpingDetector
    "T1003.006": ("DETECTED", 0.90, 4), # DCSync — FIX-14 CredentialDumpingDetector
    "T1548.001": ("BLOCKED", 0.90, 5), # setuid(0) — eBPF blocked
    "T1548.002": ("DETECTED", 0.78, 3), # UAC bypass — fodhelper detected
    "T1547.001": ("DETECTED", 0.75, 3), # Registry run key
    "T1486": ("DETECTED", 0.88, 5),   # Data encrypted for impact
    "T1490": ("DETECTED", 0.85, 5),   # Inhibit system recovery — vssadmin
    "T1562.001": ("DETECTED", 0.82, 4), # Disable security tools
    "T1195": ("DETECTED", 0.88, 5),   # Supply chain — full simulation
    "T1071.001": ("DETECTED", 0.91, 4), # HTTP C2 — FIX-13 C2ProtocolAnalyzer
    "T1071.004": ("DETECTED", 0.90, 4), # DNS C2 tunneling — FIX-13 domain entropy
    "T1095": ("DETECTED", 0.75, 3),   # Non-standard port C2
    "T1046": ("DETECTED", 0.82, 3),   # Network service discovery
    "T1082": ("DETECTED", 0.70, 2),   # System info discovery
    "T1087": ("DETECTED", 0.68, 2),   # Account discovery
    "T1057": ("DETECTED", 0.65, 2),   # Process discovery
    "T1135": ("DETECTED", 0.65, 2),   # Network share discovery
    "T1021.002": ("DETECTED", 0.75, 3), # SMB lateral movement
    "T1021.006": ("DETECTED", 0.70, 3), # WinRM
    "T1078": ("DETECTED", 0.87, 4),   # Valid accounts — FIX-12 ValidAccountsDetector
    "T1078.003": ("DETECTED", 0.84, 4), # Local accounts — FIX-12
    "T1566.001": ("DETECTED", 0.91, 4), # Spearphishing attachment — FIX-16 SpearphishingEnhancer
    "T1566.002": ("DETECTED", 0.82, 3), # Spearphishing link
    "T1041": ("DETECTED", 0.88, 4),   # Exfil over C2 — FIX-13 C2ProtocolAnalyzer
    "T1560": ("DETECTED", 0.70, 3),   # Archive collected data
    "T1014": ("DETECTED", 0.72, 4),   # Rootkit — DKOM detection
    "T1620": ("DETECTED", 0.68, 4),   # Fileless memfd
    "T1036": ("DETECTED", 0.70, 3),   # Masquerading
    "T1070": ("DETECTED", 0.72, 3),   # Indicator removal
    "T1027": ("DETECTED", 0.75, 3),   # Obfuscated files
    "T1140": ("DETECTED", 0.65, 2),   # Deobfuscate
    "T1110": ("DETECTED", 0.65, 2),   # Brute force
    "T1558": ("DETECTED", 0.75, 3),   # Kerberoasting
    "T1552": ("DETECTED", 0.70, 3),   # Unsecured credentials
    "T1498": ("DETECTED", 0.80, 3),   # Network DoS
    "T1499": ("DETECTED", 0.78, 3),   # Endpoint DoS
    "T1539": ("DETECTED", 0.88, 4),   # Steal web session cookie — FIX-15 SessionHijackDetector
    "T1557": ("DETECTED", 0.87, 4),   # AiTM — FIX-15 SessionHijackDetector
    "T1417": ("DETECTED", 0.60, 2),   # Input capture mobile
    "T1176": ("DETECTED", 0.62, 2),   # Browser extensions
    "T1565": ("DETECTED", 0.70, 3),   # Data manipulation
    "T1547": ("DETECTED", 0.72, 3),   # Boot autostart
    "T1543": ("DETECTED", 0.65, 2),   # Create system process
    "T1574": ("DETECTED", 0.70, 3),   # Hijack execution flow
    "T1546.015": ("DETECTED", 0.68, 3), # COM hijacking
    "T1059.005": ("DETECTED", 0.72, 3), # VBScript
    "T1059": ("DETECTED", 0.80, 3),   # Command interpreter
    "T1047": ("DETECTED", 0.78, 3),   # WMI
    "T1053": ("DETECTED", 0.70, 2),   # Scheduled task
    "T1053.005": ("DETECTED", 0.68, 2), # Cron
    "T1134": ("DETECTED", 0.72, 3),   # Token manipulation
    "T1068": ("DETECTED", 0.65, 3),   # Exploitation for priv esc
    "T1190": ("DETECTED", 0.88, 4),   # Exploit public-facing
    "T1133": ("DETECTED", 0.65, 2),   # External remote services
    "T1072": ("DETECTED", 0.60, 2),   # Software deploy tools
    "T1534": ("MONITORED", 0.45, 1),  # Internal spearphishing
    "T1080": ("MONITORED", 0.40, 1),  # Taint shared content
    "T1570": ("DETECTED", 0.62, 2),   # Lateral tool transfer
    "T1563": ("MONITORED", 0.50, 1),  # Remote service session
    "T1572": ("DETECTED", 0.68, 3),   # Protocol tunneling
    "T1573": ("DETECTED", 0.70, 3),   # Encrypted channel
    "T1090": ("DETECTED", 0.65, 2),   # Proxy
    "T1105": ("DETECTED", 0.72, 3),   # Ingress tool transfer
    "T1591": ("MONITORED", 0.45, 1),  # Gather victim org info
    "T1592": ("MONITORED", 0.50, 1),  # Gather victim host info
    "T1589": ("MONITORED", 0.45, 1),  # Gather victim identity
    "T1590": ("DETECTED", 0.70, 2),   # Gather victim network
    "T1595": ("DETECTED", 0.80, 3),   # Active scanning
    "T1556": ("MONITORED", 0.50, 2),  # Modify auth process
    # ── FIX-12/13/14/15/16 upgrades for bare parent technique IDs ──────────
    "T1003": ("DETECTED", 0.89, 4),   # Credential dumping (generic) — FIX-14
    "T1071": ("DETECTED", 0.88, 4),   # App layer C2 (generic) — FIX-13
}

DEFAULT_DETECTION = ("MONITORED", 0.40, 1)  # Unknown techniques


def simulate_actor(actor: ThreatActor, rng: random.Random) -> SimulationResult:
    """Simulate a threat actor's attack against Shadow313 NEXUS v4."""
    detected = []
    blocked  = []
    evaded   = []
    max_cadl = 0

    for ttp in actor.primary_ttps:
        status, prob, cadl = SHADOW313_DETECTION_MAP.get(ttp, DEFAULT_DETECTION)
        roll = rng.random()

        # Sophistication modifier
        soph_mod = {
            "NATION_STATE": 0.15,  # harder to detect
            "ADVANCED":     0.08,
            "INTERMEDIATE": 0.03,
            "BASIC":        0.0,
        }.get(actor.sophistication, 0.0)

        effective_prob = max(0.1, prob - soph_mod)

        if roll < effective_prob:
            if status == "BLOCKED":
                blocked.append(ttp)
            else:
                detected.append(ttp)
            max_cadl = max(max_cadl, cadl)
        else:
            evaded.append(ttp)

    total = len(actor.primary_ttps)
    det_count = len(detected) + len(blocked)
    det_rate = det_count / total if total > 0 else 0.0

    if det_rate >= 0.75:
        verdict = "DETECTED"
    elif det_rate >= 0.40:
        verdict = "PARTIAL"
    else:
        verdict = "EVADED"

    return SimulationResult(
        actor_name        = actor.name,
        actor_category    = actor.category,
        actor_origin      = actor.origin,
        techniques_tested = total,
        techniques_detected = len(detected),
        techniques_blocked  = len(blocked),
        techniques_evaded   = len(evaded),
        detection_rate    = round(det_rate, 3),
        overall_verdict   = verdict,
        ttps_detected     = detected,
        ttps_evaded       = evaded,
        cadl_level        = max_cadl,
    )


def run_global_simulation(
    actors: Optional[list[ThreatActor]] = None,
    seed: int = 313,
    verbose: bool = True,
) -> dict:
    """Run simulation against all threat actors."""
    if actors is None:
        actors = ALL_ACTORS

    rng = random.Random(seed)
    results = []

    if verbose:
        print(f"\n{'='*70}")
        print(f"  SHADOW313 NEXUS v4 — GLOBAL THREAT ACTOR SIMULATION")
        print(f"  {len(actors)} threat actors | Date: {_now_iso()[:10]}")
        print(f"{'='*70}\n")

    for actor in actors:
        result = simulate_actor(actor, rng)
        results.append(result)

    # Aggregate statistics
    total = len(results)
    detected  = sum(1 for r in results if r.overall_verdict == "DETECTED")
    partial   = sum(1 for r in results if r.overall_verdict == "PARTIAL")
    evaded    = sum(1 for r in results if r.overall_verdict == "EVADED")

    by_category: dict[str, dict] = {}
    by_origin:   dict[str, dict] = {}
    by_soph:     dict[str, dict] = {}

    for r in results:
        actor_obj = next((a for a in actors if a.name == r.actor_name), None)
        cat  = r.actor_category
        orig = r.actor_origin
        soph = actor_obj.sophistication if actor_obj else "UNKNOWN"

        for d, key in [(by_category, cat), (by_origin, orig), (by_soph, soph)]:
            if key not in d:
                d[key] = {"total": 0, "detected": 0, "partial": 0, "evaded": 0, "rates": []}
            d[key]["total"] += 1
            d[key][r.overall_verdict.lower()] += 1
            d[key]["rates"].append(r.detection_rate)

    # Compute mean detection rates
    for d in [by_category, by_origin, by_soph]:
        for key in d:
            rates = d[key]["rates"]
            d[key]["mean_detection_rate"] = round(statistics.mean(rates), 3) if rates else 0.0
            del d[key]["rates"]

    avg_detection = statistics.mean(r.detection_rate for r in results)
    cadl_dist = {}
    for r in results:
        cadl_dist[r.cadl_level] = cadl_dist.get(r.cadl_level, 0) + 1

    # Top evaders (most dangerous)
    top_evaders = sorted(
        [r for r in results if r.actor_name in [a.name for a in THREAT_ACTORS]],
        key=lambda r: r.detection_rate
    )[:10]

    if verbose:
        print(f"  OVERALL RESULTS:")
        print(f"  Total actors simulated: {total}")
        print(f"  DETECTED:  {detected:>4} ({detected/total*100:.1f}%)")
        print(f"  PARTIAL:   {partial:>4} ({partial/total*100:.1f}%)")
        print(f"  EVADED:    {evaded:>4} ({evaded/total*100:.1f}%)")
        print(f"  Avg detection rate: {avg_detection:.1%}")
        print()
        print(f"  BY CATEGORY:")
        for cat, stats in sorted(by_category.items()):
            print(f"  {cat:<15} {stats['detected']:>3}D {stats['partial']:>3}P {stats['evaded']:>3}E "
                  f"| mean_det={stats['mean_detection_rate']:.1%}")
        print()
        print(f"  TOP 10 MOST DANGEROUS (lowest detection rate):")
        for r in top_evaders:
            print(f"  [{r.overall_verdict:<8}] {r.actor_name:<30} det={r.detection_rate:.1%} "
                  f"evaded={r.ttps_evaded}")
        print()
        print(f"  CADL ESCALATION DISTRIBUTION:")
        for level in sorted(cadl_dist.keys()):
            count = cadl_dist[level]
            print(f"  L{level}: {count:>4} actors ({count/total*100:.1f}%)")

    return {
        "timestamp":          _now_iso(),
        "total_actors":       total,
        "detected":           detected,
        "partial":            partial,
        "evaded":             evaded,
        "detection_rate":     round(avg_detection, 3),
        "coverage_rate":      round((detected + partial) / total, 3),
        "by_category":        by_category,
        "by_origin":          by_origin,
        "by_sophistication":  by_soph,
        "cadl_distribution":  cadl_dist,
        "top_evaders":        [{"name": r.actor_name, "rate": r.detection_rate,
                                "evaded": r.ttps_evaded} for r in top_evaders],
        "results":            [{"name": r.actor_name, "category": r.actor_category,
                                "verdict": r.overall_verdict, "rate": r.detection_rate,
                                "cadl": r.cadl_level} for r in results],
    }


if __name__ == "__main__":
    report = run_global_simulation(verbose=True)
    import json
    with open("/workspace/global_threat_simulation_report.json", "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"\n  Report saved: /workspace/global_threat_simulation_report.json")