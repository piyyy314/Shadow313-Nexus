#!/bin/sh
# Runs inside the official Ollama image; do not assume Python/curl are installed.
set -eu
export OLLAMA_HOST="${OLLAMA_HOST:-http://ollama:11434}"
attempt=0
until ollama list >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 40 ]; then echo "Ollama not ready" >&2; exit 1; fi
    sleep 3
done
ollama pull matarmohamad313/shadow313-nexus
ollama pull mistral:7b
ollama pull nomic-embed-text:latest
ollama show matarmohamad313/shadow313-nexus >/dev/null
ollama show mistral:7b >/dev/null
ollama show nomic-embed-text:latest >/dev/null
echo "Required models verified by Ollama CLI"
