"""Shadow313 NEXUS workflow package with the hardened webhook adapter."""
__version__ = "4.0.0"

# Keep the historical import path while replacing the unsafe urllib delivery
# implementation with the allowlisted, IP-pinned HTTPS adapter.
from . import workflow_engine as _workflow_engine
from .webhook_security import HTTPWebhookDelivery

_workflow_engine.HTTPWebhookDelivery = HTTPWebhookDelivery
