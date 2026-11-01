# ═══════════════════════════════════════════════════════════════
# Shadow313 NEXUS v4.0.0 — Dockerfile
# Multi-stage build: slim production + full NEXUS image
# ═══════════════════════════════════════════════════════════════
#
# FIX NOTES (Dockerfile:42 / network failure):
#   - Removed `COPY data/ ...` — data/ dir doesn't exist in repo
#   - Consolidated redundant RUN chown calls into one
#   - Added --no-install-recommends everywhere for smaller layers
#   - Added ARG HTTP_PROXY / HTTPS_PROXY for corporate/WSL2 builds
#   - Added apt-get retry logic for flaky network environments
#   - Debian trixie base and direct build/runtime package versions are pinned
#

# ── Build-time proxy args (pass with --build-arg if behind proxy) ──
ARG HTTP_PROXY=""
ARG HTTPS_PROXY=""
ARG NO_PROXY="localhost,127.0.0.1"

# ── Stage 1: Builder ──────────────────────────────────────────────
FROM python:3.15-slim-trixie AS builder

ARG HTTP_PROXY
ARG HTTPS_PROXY
ENV http_proxy=${HTTP_PROXY} https_proxy=${HTTPS_PROXY}

WORKDIR /build

# Install build deps with retry on network failure
RUN apt-get update -o Acquire::Retries=3 \
    && apt-get install -y --no-install-recommends \
        gcc=4:14.2.0-1 g++=4:14.2.0-1 \
        libssl-dev=3.5.7-1~deb13u3 libffi-dev=3.4.8-2 git=1:2.47.3-0+deb13u1 \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY shadow313/ ./shadow313/
COPY shadow313_sdk/ ./shadow313_sdk/
COPY shadow313_platform/ ./shadow313_platform/
COPY nexus_toolkit/ ./nexus_toolkit/
COPY MANIFEST.in LICENSE CHANGELOG.md SECURITY.md requirements.txt ./

RUN pip install --no-cache-dir --upgrade pip==26.2.2 wheel==0.48.0 \
    && pip install --no-cache-dir --prefix=/install .


# ── Stage 2: Production (slim) ────────────────────────────────────
FROM python:3.15-slim-trixie AS production

ARG HTTP_PROXY
ARG HTTPS_PROXY
ENV http_proxy=${HTTP_PROXY} https_proxy=${HTTPS_PROXY}

LABEL org.opencontainers.image.title="Shadow313 NEXUS"
LABEL org.opencontainers.image.description="Local-First AI-Powered Security Intelligence CLI"
LABEL org.opencontainers.image.version="4.0.0"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.url="https://shadow313.dev"

# Install runtime deps with retry
RUN apt-get update -o Acquire::Retries=3 \
    && apt-get install -y --no-install-recommends \
        tcpdump=4.99.5-2 nmap=7.95+dfsg-3 bind9-dnsutils=1:9.20.30-1~deb13u1 \
        iputils-ping=3:20240905-3 libssl3t64=3.5.7-1~deb13u3 \
    && rm -rf /var/lib/apt/lists/*

# Clear proxy env after apt (don't leak into runtime)
ENV http_proxy="" https_proxy=""

COPY --from=builder /install /usr/local

# Create user + all required dirs in ONE RUN layer (was split across 3)
RUN useradd -m -s /bin/bash shadow313 \
    && for directory in sessions plugins wordlists logs data reports receipts campaigns agent_runs; do \
        mkdir -p "/home/shadow313/.shadow313/$directory"; \
       done \
    && chown -R shadow313:shadow313 /home/shadow313/.shadow313

USER shadow313
WORKDIR /home/shadow313

ENV SHADOW313_AI_BACKEND=ollama
ENV SHADOW313_AI_ENDPOINT=http://host.docker.internal:11434
ENV SHADOW313_AI_MODEL=mistral:7b

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import shadow313; print('ok')"]

EXPOSE 8313

ENTRYPOINT ["shadow313"]
CMD ["--help"]


# ── Stage 3: Full NEXUS (all optional deps) ───────────────────────
FROM production AS nexus

ARG HTTP_PROXY
ARG HTTPS_PROXY
ENV http_proxy=${HTTP_PROXY} https_proxy=${HTTPS_PROXY}

USER root

RUN apt-get update -o Acquire::Retries=3 \
    && apt-get install -y --no-install-recommends \
        python3-dev=3.13.5-1 libpcap-dev=1.10.5-2 whois=5.6.3 nmap=7.95+dfsg-3 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    "dnspython>=2.4" \
    "python-whois>=0.8" \
    "cryptography>=41.0" \
    "scapy>=2.5" \
    "fastapi>=0.104" \
    "uvicorn[standard]>=0.24" \
    "jinja2>=3.1" \
    "networkx>=3.2" \
    "scikit-learn>=1.3" \
    "joblib>=1.3"

ENV http_proxy="" https_proxy=""
USER shadow313
