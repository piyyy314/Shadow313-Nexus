# Hosting the Shadow313 NEXUS Python API

The public website and Python security API are separate services:

- Vercel serves the static website and the Node.js API gateway.
- Railway or Render can host `shadow313.api.server:app`.
- Browser code calls same-origin `/api/*` URLs. The Vercel gateway forwards approved routes to the Python service and adds the API key server-side.

Do not put `SHADOW313_API_KEY` or `SHADOW313_BACKEND_API_KEY` in browser JavaScript, HTML, public configuration, or a `NEXT_PUBLIC_*` variable.

## 1. Deploy the Python API

The repository includes both `railway.json` and `render.yaml`. Connect this repository to one Python hosting provider and deploy from the repository root.

The service command is:

```sh
uvicorn shadow313.api.server:app --host 0.0.0.0 --port $PORT
```

The platform health-check path is `/api/health`. The Python API exposes both `/api/health` (platform-compatible) and `/health` (local/Docker compatibility).

Set these variables in the backend host's service environment:

| Variable | Value |
|---|---|
| `SHADOW313_ENV` | `production` |
| `SHADOW313_API_KEY` | A unique random secret of at least 32 characters |
| `SHADOW313_AI_BACKEND` | `ollama`, `gateway`, `openai`, or `disabled`, according to the provider configured |
| `SHADOW313_AI_MODEL` | A model identifier supported by the selected provider |

Only set provider credentials (for example `AI_GATEWAY_API_KEY` or `OPENAI_API_KEY`) if you have configured that provider. For Ollama, the backend must be able to reach the Ollama service at `SHADOW313_AI_ENDPOINT`; a private Docker hostname such as `ollama` is not reachable from a separate hosted service unless the services share a private network.

Generate the API key locally, then put the same value in the backend host and Vercel's server-side environment. Do not paste the secret into GitHub issues or commits:

```sh
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

After deployment, verify the provider's service URL directly:

- `GET https://YOUR-BACKEND-HOST/api/health` should return `200`.
- `GET https://YOUR-BACKEND-HOST/api/status` should return `200` and `status: operational`.

## 2. Connect Vercel to the Python service

In the Vercel project linked to this repository, add the following environment variables to **Production**, **Preview**, and **Development** as appropriate:

| Variable | Value | Type |
|---|---|---|
| `SHADOW313_BACKEND_URL` | The deployed Python service's HTTPS origin, e.g. `https://your-service.example` | Plain |
| `SHADOW313_BACKEND_API_KEY` | The same random key configured as `SHADOW313_API_KEY` on the Python service | Sensitive |

Use the backend origin only: do not include `/api`, a query string, or credentials in the URL. The gateway appends the requested API path. HTTPS is required except for localhost development.

Redeploy the Vercel project after adding or changing these variables. The gateway intentionally reports `static-site-only` when the backend URL is absent, and returns an unavailable/502/504 response if the configured service cannot be reached. It never invents successful scan results.

## 3. Verify the end-to-end connection

After both services are deployed:

1. Open `https://YOUR-WEBSITE/api/health`. Expect `backend_connected: true`.
2. Open `https://YOUR-WEBSITE/api/status`. Expect the Python API's version and `backend_connected: true`.
3. Test a protected route from a trusted API client, not by exposing the API key in the browser. For example, request `GET /api/modules` through the website gateway.
4. Check the backend host's logs and Vercel function logs if a request fails.

The gateway forwards only the routes explicitly allowlisted in `api/index.js`, caps request and response sizes, uses a timeout, requires a server-side key for protected operations, and rejects non-HTTPS remote backend URLs.

## Runtime limitations

A successful health check proves the API process is reachable, not that every optional subsystem is configured. Reconnaissance workers, vulnerability scan workers, persistence, AI providers, and mobile integrations must be configured and tested independently. The `/api/status` response describes API capability separately from the CLI's local module inventory.
