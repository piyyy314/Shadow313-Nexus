# Shadow313 NEXUS — Hetzner Infrastructure Plan

**Status: planned — server not yet purchased or provisioned.**

Hetzner is the selected destination for the future Shadow313 backend. Vercel
continues to host the public static website; GitHub remains the source-control
and CI system; Cloudflare manages DNS for `shadow313.com`.

This directory contains early provisioning automation. Review each script and
its side effects before execution. Do not run a bootstrap script against a new
production server until its package, firewall, SSH, database, persistence, and
application assumptions have been checked against the final server plan.

## Intended responsibility

The Hetzner host is expected to run backend components that should not be served
from the static website, such as the authenticated Python API and background
services. The exact service set, database layout, resource size, backup design,
and public API hostname remain to be finalized.

```text
Visitors
  |
Cloudflare DNS (.com) / Vercel DNS (.dev)
  |
Vercel — public static website
  |
  +---- HTTPS API requests (after backend is deployed)
                 |
              Hetzner
              - Python API
              - background workers (if enabled)
              - database / persistent storage (after design review)
              - monitoring and backups
```

## Before ordering

1. Confirm API workload and expected concurrency.
2. Estimate memory, CPU, storage IOPS, database size, and backup capacity.
3. Choose a server region based on latency, data residency, and provider
   availability; do not assume an old example region or price is current.
4. Confirm the selected plan supports required private networking, backups,
   snapshots, and firewall features.
5. Add an SSH public key before server creation.
6. Keep the Hetzner API token in a local environment variable or secret
   manager; never commit it.

## Files in this directory

| File | Current purpose |
|---|---|
| `create_vps.sh` | Creates a Hetzner Cloud server through the API |
| `bootstrap.sh` | Broad host bootstrap path; installs several services and must be reviewed before use |
| `provision.sh` | SSH hardening and WireGuard-focused server provisioning |
| `setup_wireguard_client.sh` | Configures a client tunnel on the operator workstation |

The scripts are not interchangeable. The WireGuard provisioner is not a
complete application deployment. The broad bootstrap script must be audited
for firewall openings, service exposure, secrets, persistence, and compatibility
with the final application architecture.

## Provisioning safeguards

- Use SSH keys; disable password authentication only after verifying key access.
- Keep a second administrative session open while changing SSH configuration.
- Apply a default-deny firewall and open only ports required by the final design.
- Do not expose PostgreSQL, Docker control sockets, or internal dashboards
  publicly.
- Store application secrets outside the repository.
- Configure persistent database volumes and encrypted off-server backups.
- Enable host and application monitoring before public traffic is enabled.
- Test restore procedures; a snapshot alone is not a complete backup strategy.
- Do not point `api.shadow313.com` at the host until TLS, authentication,
  firewall rules, health checks, and monitoring are verified.

## Production acceptance checklist

- [ ] Server plan and region selected for the measured workload.
- [ ] SSH public key installed and access verified.
- [ ] OS patched and host firewall reviewed.
- [ ] SSH hardening verified without locking out administrators.
- [ ] Runtime and application deployment procedure documented.
- [ ] Database persistence and backup restoration tested.
- [ ] Secrets stored outside Git and rotated where necessary.
- [ ] API authentication, rate limits, and request-size limits verified.
- [ ] TLS and DNS configured only after the service is ready.
- [ ] Monitoring, logs, alerting, and recovery procedure tested.
- [ ] Vercel-to-Hetzner integration verified end to end.

Until every required item is verified, the backend status remains **pending**.
