from defensive_package.honeypot import honeypot
from defensive_package.log_monitor import monitor_log
from defensive_package.alerting import send_alert
import threading

# Start honeypot on port 2222
threading.Thread(target=honeypot, args=('0.0.0.0', 2222, send_alert), daemon=True).start()

# Monitor ssh logs for failed attempts
threading.Thread(target=monitor_log, args=('/var/log/auth.log', ['Failed password'], send_alert), daemon=True).start()

# Main loop
while True:
    pass