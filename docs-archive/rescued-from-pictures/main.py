import threading
from core.response_controller import ResponseController
from core.response_actions import (
    block_ip_response, 
    disable_user_response, 
    kill_process_response, 
    quarantine_instance_response)
from sensors.honeypot import honeypot
from sensors.log_monitor import monitor_log
from sensors.cloud_monitor import aws_guardduty_monitor
from web.dashboard import app as dashboard_app

rc = ResponseController(dry_run=False, require_approval=True)
rc.register_response("suspicious_ip", block_ip_response)
rc.register_response("compromised_user", disable_user_response)
rc.register_response("malicious_process", kill_process_response)
rc.register_response("cloud_quarantine", quarantine_instance_response)

# Start honeypot sensor
threading.Thread(target=honeypot, kwargs={'rc': rc}, daemon=True).start()
# Start log monitor
pattern_map = { "compromised_user": (r"Failed password for (\w+)", lambda m: {"username": m.group(1)}) }
threading.Thread(target=monitor_log, args=('/var/log/auth.log', pattern_map, rc), daemon=True).start()
# Start AWS GuardDuty monitor
threading.Thread(target=aws_guardduty_monitor, args=(rc,), daemon=True).start()
# Start Dashboard HTTP server
dashboard_app.run(port=5000)