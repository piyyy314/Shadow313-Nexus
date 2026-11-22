# Hosting the Shadow313 NEXUS Python API on Hetzner

The public website and Python API are separate services:

- Vercel serves the static website and the Node.js API gateway.
- Hetzner is the selected destination for the Python API, but the server has
  **not yet been purchased or provisioned**.
- The browser calls same-origin `/api/*` routes. The Vercel gateway forwards
  only explicitly allowlisted routes and adds the API key server-side.

Do not deploy this service to Railway or Render. Do not put
`SHADOW313_API_KEY` or `SHADOW313_BACKEND_API_KEY` in browser JavaScript,
HTML, public configuration, or a `NEXT_PUBLIC_*` variable.

## 1. Prepare the Hetzner host

Follow [the Hetzner infrastructure plan](../infra/hetzner/README.md). Before
creating a public API endpoint:

1. Select server resources using measured API, database, worker, and storage
   requirements; do not assume an archived plan, region, or price.
2. Add an SSH public key and verify access before changing SSH settings.
3. Patch the OS, configure a default-deny firewall, and harden SSH.
4. Decide whether PostgreSQL and workers run on this host or separate private
   services. Define persistent storage and encrypted off-server backups.
5. Configure host monitoring, application logging, alerting, and recovery.
6. Do not expose PostgreSQL, Docker sockets, or internal dashboards publicly.

The scripts under `infra/hetzner/` are provisioning aids, not proof that a
production server exists. Review each script and its side effects before use.

## 2. Deploy the Python API

From a reviewed repository checkout on the host, create a dedicated virtual
environment and install the application dependencies:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[full]"
```

Run the API behind a hardened reverse proxy with TLS. The application command
is:

```sh
uvicorn shadow313.api.server:app --host 127.0.0.1 --port 8313
```

Use a process manager with a dedicated unprivileged service account. Do not
bind the Python process to a public interface when the reverse proxy can reach
it over localhost.

Configure the backend environment:

| Variable | Purpose |
|---|---|
| `SHADOW313_ENV` | Set to `production` |
| `SHADOW313_API_KEY` | Unique random secret of at least 32 characters |
| `SHADOW313_AI_BACKEND` | `ollama`, `gateway`, `openai`, or `disabled` |
| `SHADOW313_AI_MODEL` | Model identifier supported by the selected provider |
| `SHADOW313_AI_ENDPOINT` | Optional provider endpoint reachable from the host |

Only configure provider credentials such as `AI_GATEWAY_API_KEY` or
`OPENAI_API_KEY` when that provider is deliberately enabled. For Ollama, the
backend must be able to reach the configured Ollama endpoint over a private
network or localhost.

Generate a unique key locally and store it in the host's secret environment;
never commit it:

```sh
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Verify the backend directly from a trusted host:

- `GET https://YOUR-API-HOST/health` returns `200` with `status: ok`.
- `GET https://YOUR-API-HOST/api/status` returns `200` with
  `status: operational`.
- Protected endpoints reject missing or incorrect API keys.

## 3. Connect Vercel to Hetzner

Only after the host is hardened, TLS is working, and the API health checks pass,
add these variables to the Vercel project as **server-side** environment
variables for the required environments:

| Variable | Value | Type |
|---|---|---|
| `SHADOW313_BACKEND_URL` | HTTPS origin of the Hetzner API, without `/api`, query, or credentials | Plain |
| `SHADOW313_BACKEND_API_KEY` | Same secret as backend `SHADOW313_API_KEY` | Sensitive |

The gateway rejects remote HTTP URLs, requires a server-side key for protected
operations, caps request and response sizes, and applies a timeout. Redeploy
the Vercel project after changing these variables.

Do not create an API DNS record until TLS, authentication, firewall rules,
health checks, and monitoring are verified. Keep `shadow313.com` DNS in
Cloudflare and preserve the existing `shadow313.dev` DNS configuration.

## 4. Verify the end-to-end connection

After the backend and Vercel environment are configured:

1. `GET https://shadow313.dev/api/health` should report
   `backend_connected: true`.
2. `GET https://shadow313.dev/api/status` should return the Python API version
   and `backend_connected: true`.
3. Test protected endpoints from a trusted API client. Never put the API key
   into browser code.
4. Confirm backend logs and Vercel function logs contain no credentials.
5. Test backup restoration, service restart, TLS renewal, and recovery.

A healthy process does not prove optional integrations are configured.
Reconnaissance workers, vulnerability scan workers, persistence, AI providers,
and mobile services must be independently configured and tested.

## Current state

The gateway implementation and automated tests can be reviewed in this PR.
The Hetzner server, backend deployment, Vercel secrets, and public API hostname
remain pending. No backend service is claimed to be online until deployment
and end-to-end acceptance checks are completed.
