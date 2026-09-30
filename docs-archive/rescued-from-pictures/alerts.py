import requests
import json
from datetime import datetime
from fortress_config import DISCORD_WEBHOOK

def send_alert(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    data = {
        "content": f"🚨 **FORTRESS ALERT** 🚨\n**Time:** {timestamp}\n**Event:** {message}"
    }
    try:
        response = requests.post(
            DISCORD_WEBHOOK,
            data=json.dumps(data),
            headers={'Content-Type': 'application/json'}
        )
        if response.status_code == 204:
            print("[√] Alert sent to Mobile Command.")
        else:
            print(f"[X] Failed to send alert. Status: {response.status_code}")
    except Exception as e:
        print(f"[X] Alerting Error: {e}")