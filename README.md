# SentinelOS & SHADOW313

![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)

Welcome to the official repository for **SentinelOS** and **SHADOW313**.

## Overview
- **SHADOW313**: A Quantum-Ready CLI designed to bridge the gap between classical developer environments and the emerging world of quantum computing. It brings local-first quantum simulation and verification directly to your terminal.
- **SentinelOS**: An advanced, next-generation security command center and dashboard. It visualizes and manages advanced cryptographic protocols, Post-Quantum Cryptography (PQC), swarm defenses, and Zero-Trust architectures.

## Architecture & Tech Stack
These projects are built from the ground up prioritizing speed, security, and aesthetics:
*   **Vanilla HTML5 / CSS3 / JavaScript (ES6+)** - Absolutely zero off-the-shelf frameworks.
*   **Local-First Design** - No forced cloud dependencies.
*   **Canvas & WebGL** - Used for advanced data visualization and real-time defensive monitoring.
*   **Vercel Routing** - Ready for immediate static deployment via edge networks.

## Features
*   **313 Temporal Binding:** Tamper-evident cryptographic logging for quantum experiments.
*   **Post-Quantum Cryptography (PQC) Readiness:** Real-time metrics and simulations for algorithms like CRYSTALS-Dilithium.
*   **Zero-Trust Network Access (ZTNA) Grid:** Granular visualization of node authentication.
*   **Quantum Thought Engine (QTE):** Terminal-based AI agent interface for running local quantum algorithms via Qiskit's AerSimulator protocols.
*   **AEGIS Ultimate Master Deployment:** Includes the AEGIS Python master deployment script for Monte Carlo threat simulations and active defense honeypots.

## Uploading Project Files

This repository now includes tracked placeholder directories for future asset and fixture uploads. See [docs/upload-paths.md](docs/upload-paths.md) for the canonical path map for SentinelOS and SHADOW313 files.

## Getting Started

### Deploy to Vercel
This repository is optimized for Vercel. 
1. Import this repository to a new Vercel Project.
2. The project uses standard HTML, so no build step is required.
3. Configure your domains. The included `vercel.json` will automatically route:
   *   `shadow313.com` ➔ SHADOW313 Terminal Interface
   *   `shadow313.dev` ➔ SentinelOS Advanced Dashboard

### AI providers

`POST /api/chat` uses Vercel AI Gateway with `openai/gpt-5.5` by default in deployed Vercel Functions. Vercel authenticates production requests with its OIDC token; no production API key is required.

For local Ollama development, run Ollama on `http://127.0.0.1:11434` and configure the Vercel development server with the model you have installed:

```bash
export OLLAMA_BASE_URL=http://127.0.0.1:11434
export OLLAMA_MODEL=<your-ollama-model>
vercel dev
```

You can start from `.env.example` when setting local environment variables.

`OLLAMA_BASE_URL` is local-only. Do not set it for Vercel production, because `127.0.0.1` in a Vercel Function is not your computer. Without it, the API uses Vercel AI Gateway. For non-Vercel local development, set `AI_GATEWAY_API_KEY` and optionally `AI_GATEWAY_MODEL` instead.

The standalone FastAPI backend in `/backend` uses `OLLAMA_URL` and `OLLAMA_MODEL` instead.

When running the standalone FastAPI backend from `/backend`, you can also override the local browser allowlist with `CORS_ORIGINS` as a comma-separated list of origins.

### Security notes

- Keep `AI_GATEWAY_API_KEY`, `VERCEL_OIDC_TOKEN`, and `VERCEL_WEBHOOK_SECRET` in the deployment environment only.
- `CORS_ORIGINS` is intentionally a strict localhost allowlist for local development and should not be expanded beyond trusted origins.
- The SentinelOS demo data includes synthetic `DEMO-TOK-*` values only; do not copy them into production secrets or real canary systems.

### API endpoints

- `GET /api/health` returns a lightweight JSON status payload for deployed functions.
- `POST /api/chat` accepts either `{"message":"..."}` or `{"messages":[...]}` and returns `{"reply":"..."}`.
- `POST /api/webhooks/vercel` accepts signed Vercel deployment webhook events.

Common API error responses:

- `400` invalid JSON or invalid chat payload
- `403` invalid webhook signature
- `429` too many requests
- `413` request body too large
- `502` upstream AI/Ollama failure
- `503` missing runtime configuration
- `504` upstream Ollama timeout

### Vercel deployment webhooks

`POST /api/webhooks/vercel` accepts signed deployment webhook events. Set the same random value as `VERCEL_WEBHOOK_SECRET` in the Explorer production environment and in the webhook configuration. Subscribe only to **Deployment Succeeded** and **Deployment Error** events. The handler rejects unsigned or malformed payloads.

Vercel signs the raw webhook body in the `x-vercel-signature` header using the shared webhook secret. The current handler expects Vercel's documented HMAC-SHA1 format.

For GitHub Actions production deploys, also configure `VERCEL_TOKEN`, `VERCEL_PROJECT_ID`, and `VERCEL_ORG_ID` repository secrets so the Vercel CLI can link the correct project non-interactively.

Optional abuse-protection environment variables:

- `RATE_LIMIT_WINDOW_SECONDS`
- `CHAT_RATE_LIMIT_MAX`
- `WEBHOOK_RATE_LIMIT_MAX`
- `WEBHOOK_MAX_BODY_BYTES`

### Run locally

For the dashboard and API together, use Vercel development mode:

```bash
vercel dev
```

Open the local URL printed by the command. The project has no `localhost:8080` configuration.

To run the standalone FastAPI proxy instead, install `/home/runner/work/SentinelOS-Shadow313/SentinelOS-Shadow313/backend/requirements.txt`, set `OLLAMA_URL` and `OLLAMA_MODEL`, then run:

```bash
python /home/runner/work/SentinelOS-Shadow313/SentinelOS-Shadow313/backend/main.py
```

## License
This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
