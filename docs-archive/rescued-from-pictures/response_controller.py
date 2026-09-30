from .log_util import log_event
from .alerting import send_dashboard_alert, send_slack_alert

class ResponseController:
    def __init__(self, dry_run=False, require_approval=True):
        self.response_map = {}
        self.pending = []
        self.dry_run = dry_run
        self.require_approval = require_approval

    def register_response(self, alert_type, func):
        self.response_map[alert_type] = func

    def handle_alert(self, alert_type, context):
        log_event(f"[ALERT] {alert_type} | {context}")
        if self.require_approval:
            self.pending.append((alert_type, context))
            msg = f"Pending response [{alert_type}] {context}. Approve in dashboard."
            send_dashboard_alert(msg)
            send_slack_alert("YOUR_SLACK_WEBHOOK_URL", msg)
        else:
            self.execute_response(alert_type, context)

    def execute_response(self, alert_type, context):
        if alert_type in self.response_map:
            self.response_map[alert_type](context, dry_run=self.dry_run)
        else:
            log_event(f"No response for {alert_type}")

    def approve_pending(self, idx):
        alert_type, context = self.pending.pop(idx)
        self.execute_response(alert_type, context)