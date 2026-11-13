#!/bin/sh
# Runs inside the official Ollama image; do not assume Python/curl are installed.
set -eu
if [ "${SHADOW313_AI_BACKEND:-ollama}" != "ollama" ]; then
    echo "AI backend is not Ollama; skipping local model downloads"
    exit 0
fi

export OLLAMA_HOST="${OLLAMA_HOST:-http://ollama:11434}"
attempt=0
until ollama list >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 40 ]; then echo "Ollama not ready" >&2; exit 1; fi
    sleep 3
done

ensure_model() {
    model="$1"
    if ollama show "$model" >/dev/null 2>&1; then
        echo "Model already available: $model"
    else
        echo "Pulling configured model: $model"
        ollama pull "$model"
    fi
}

default_model="${OLLAMA_DEFAULT_MODEL:-${SHADOW313_AI_MODEL:-mistral:7b}}"
ensure_model "$default_model"
for model in ${OLLAMA_EXTRA_MODELS:-}; do
    ensure_model "$model"
done

echo "Configured Ollama models verified"
