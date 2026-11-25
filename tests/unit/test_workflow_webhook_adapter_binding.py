"""Ensure the workflow engine uses the hardened webhook adapter."""

def test_workflow_engine_uses_hardened_webhook_adapter():
    from shadow313.v4.workflow import webhook_security
    from shadow313.v4.workflow.workflow_engine import HTTPWebhookDelivery

    assert HTTPWebhookDelivery is webhook_security.HTTPWebhookDelivery
