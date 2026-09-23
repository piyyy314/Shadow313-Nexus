# ═══════════════════════════════════════════════════════════════
# Shadow313 NEXUS v4.0.0 — Dockerfile
# Multi-stage build: slim production + full NEXUS image
# ═══════════════════════════════════════════════════════════════

# ── Stage 1: Builder ──────────────────────────────────────────
FROM python:3.14-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc g++ libssl-dev libffi-dev git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml setup.py ./
COPY shadow313/ ./shadow313/

RUN pip install --upgrade pip wheel && \
    pip install --prefix=/install . && \
    pip install --prefix=/install pyyaml rich


# ── Stage 2: Production (slim) ────────────────────────────────
FROM python:3.14-slim AS production

LABEL org.opencontainers.image.title="Shadow313 NEXUS"
LABEL org.opencontainers.image.description="Local-First AI-Powered Security Intelligence CLI"
LABEL org.opencontainers.image.version="4.0.0"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.url="https://shadow313.dev"

RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump nmap dnsutils iputils-ping libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /install /usr/local

RUN useradd -m -s /bin/bash shadow313 && \
    mkdir -p /home/shadow313/.shadow313/{sessions,plugins,wordlists,logs,data,reports,receipts,campaigns,agent_runs} && \
    chown -R shadow313:shadow313 /home/shadow313/.shadow313

COPY data/ /home/shadow313/.shadow313/data/ 2>/dev/null || true
RUN chown -R shadow313:shadow313 /home/shadow313/.shadow313/ 2>/dev/null || true

USER shadow313
WORKDIR /home/shadow313

ENV SHADOW313_AI_BACKEND=ollama
ENV SHADOW313_AI_ENDPOINT=http://host.docker.internal:11434
ENV SHADOW313_AI_MODEL=mistral:7b

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import shadow313; print('ok')" || exit 1

EXPOSE 7313 7314

ENTRYPOINT ["shadow313"]
CMD ["--help"]


# ── Stage 3: Full NEXUS (all optional deps) ───────────────────
FROM production AS nexus

USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-dev libpcap-dev whois nmap \
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

USER shadow313