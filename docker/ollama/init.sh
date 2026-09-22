#!/bin/sh
# Shadow313 NEXUS — Ollama model initializer
# Runs once on first startup to pull required models

set -e

OLLAMA_HOST="${OLLAMA_HOST:-http://ollama:11434}"

echo "═══════════════════════════════════════════════"
echo " Shadow313 NEXUS — Ollama Model Init"
echo " Host: $OLLAMA_HOST"
echo "═══════════════════════════════════════════════"

# Wait for Ollama to be ready
echo "[*] Waiting for Ollama to be ready..."
until curl -sf "$OLLAMA_HOST/api/tags" > /dev/null 2>&1; do
    echo "    ... waiting"
    sleep 3
done
echo "[+] Ollama is ready"

# Pull Shadow313 NEXUS model (primary)
echo "[*] Pulling matarmohamad313/shadow313-nexus..."
curl -sf "$OLLAMA_HOST/api/pull" \
    -d '{"name":"matarmohamad313/shadow313-nexus"}' \
    -H "Content-Type: application/json" | tail -1
echo "[+] shadow313-nexus ready"

# Pull llama3.2:3b as fallback (small, fast)
echo "[*] Pulling llama3.2:3b (fallback)..."
curl -sf "$OLLAMA_HOST/api/pull" \
    -d '{"name":"llama3.2:3b"}' \
    -H "Content-Type: application/json" | tail -1
echo "[+] llama3.2:3b ready"

echo ""
echo "═══════════════════════════════════════════════"
echo " ✅ All models ready"
echo "═══════════════════════════════════════════════"

# List available models
curl -sf "$OLLAMA_HOST/api/tags" | python3 -c "
import json,sys
data = json.load(sys.stdin)
models = data.get('models', [])
print(f'  Available models: {len(models)}')
for m in models:
    size_gb = m.get('size', 0) / 1e9
    print(f'    - {m[\"name\"]} ({size_gb:.1f} GB)')
" 2>/dev/null || echo "  (model list unavailable)"
