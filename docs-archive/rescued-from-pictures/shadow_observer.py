import requests

# --- Configuration ---
# Uses a service like 'ip-api' or 'AbuseIPDB' 
API_KEY = "YOUR_ABUSEIPDB_KEY" 

def shadow_observe(ip_address):
    """
    Automatically gathers intelligence on a trapped IP.
    """
    print(f"[*] Shadow Observer: Digging into {ip_address}...")
    
    url = f"https://api.abuseipdb.com/api/v2/check"
    params = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }
    headers = {
        'Accept': 'application/json',
        'Key': API_KEY
    }

    try:
        response = requests.get(url, headers=headers, params=params)
        data = response.json()
        
        # Pulling the 'Intel'
        score = data['data']['abuseConfidenceScore']
        usage = data['data']['usageType']
        isp = data['data']['isp']
        
        intel_report = (
            f"--- INTEL REPORT: {ip_address} ---\n"
            f"Abuse Score: {score}%\n"
            f"ISP/Host: {isp}\n"
            f"Usage Type: {usage}\n"
        )
        print(intel_report)
        return intel_report
    except Exception as e:
        return f"[X] Intel Gathering Failed: {e}"

# Integration: This would be called by your Tarpit or Listener.