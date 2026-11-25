# NEXUS workflow webhook security

Workflow webhooks are disabled unless both configuration values are present:

- `SHADOW313_WEBHOOK_ALLOWED_HOSTS`: comma-separated exact hostnames or public IP
  literals. Wildcards are not supported.
- `SHADOW313_WEBHOOK_HMAC_SECRET`: a high-entropy secret of at least 32 bytes.

Example configuration (use a secret manager for the HMAC key):

```dotenv
SHADOW313_WEBHOOK_ALLOWED_HOSTS=hooks.example.net,events.example.org
SHADOW313_WEBHOOK_HMAC_SECRET=<managed-secret-of-at-least-32-bytes>
```

Only HTTPS on TCP port 443 is accepted. URL credentials, fragments, unlisted
hosts, non-public IP addresses, and methods other than POST/PUT/PATCH are
rejected. DNS answers are validated and the connection is pinned to a validated
public IP while TLS certificate validation and SNI use the allowlisted hostname.
Redirects are never followed. Reserved transport and signature headers cannot
be overridden by workflow definitions.

The webhook HMAC is calculated over the exact JSON request body. Receivers
must validate the signature using the same secret and should enforce a timestamp
window and execution-ID idempotency.

This control does not replace an outbound firewall or egress proxy policy.
Production deployments should additionally restrict outbound traffic to the
approved webhook destinations.
