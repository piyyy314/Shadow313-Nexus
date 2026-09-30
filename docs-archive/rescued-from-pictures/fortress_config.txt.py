# fortress_config.py - Central configuration for Fortress_Command suite

# Defensive Modules
TARPIT_PORT = 9999
CANARY_LISTEN_PORT = 8888
SENTINEL_BLACKLIST = [
    "nc.exe", "netcat", "nmap", "wireshark", "tshark", "mimikatz", "putty", "vnc", "ophcrack"
]

# Networking
INTERNAL_NET = "192.168.1."    # Used by pivot scan, etc.
DASHBOARD_REFRESH = 2          # Seconds between dashboard updates

# Alerting
DISCORD_WEBHOOK = "YOUR_DISCORD_WEBHOOK"
TELEGRAM_BOT_TOKEN = ""
TELEGRAM_CHAT_ID = ""

# Paths
LOG_DEFENSIVE = "sentinel_actions.txt"
LOG_OFFENSIVE = "exfiltration_manifest.txt"
LOG_INTEL = "intel_report.txt"
LOG_MASTER = "fortress_activity.log"

# Threat Intel
ABUSEIPDB_KEY = "YOUR_ABUSEIPDB_KEY"
VIRUSTOTAL_KEY = "YOUR_VT_KEY"
SHODAN_KEY = "YOUR_SHODAN_KEY"