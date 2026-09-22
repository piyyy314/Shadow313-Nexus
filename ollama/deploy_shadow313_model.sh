#!/bin/bash
# ============================================================
# SHADOW313 NEXUS — Ollama Model Deploy & Test Script
# Run from Ubuntu WSL2 or Linux terminal
# Usage: bash ollama/deploy_shadow313_model.sh
# ============================================================

GREEN='\033[0;32m'
CYAN='\033[0;36m'
AMBER='\033[0;33m'
RED='\033[0;31m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color
BOLD='\033[1m'

MODEL_NAME="matarmohamad313/shadow313-nexus"
BASE_MODEL="llama3.2:3b"
MODELFILE_PATH="ollama/Modelfile"
OLLAMA_API="http://localhost:11434"

print_header() {
    echo ""
    echo -e "${CYAN}${BOLD}============================================================${NC}"
    echo -e "${CYAN}${BOLD}  SHADOW313 NEXUS — Model Deploy Script v4.0.0${NC}"
    echo -e "${CYAN}${BOLD}  Model: ${MODEL_NAME}${NC}"
    echo -e "${CYAN}${BOLD}============================================================${NC}"
    echo ""
}

check_step() {
    if [ $? -eq 0 ]; then
        echo -e "  ${GREEN}✅ $1${NC}"
    else
        echo -e "  ${RED}❌ $1 — FAILED${NC}"
        echo -e "  ${AMBER}Fix the error above before continuing.${NC}"
        exit 1
    fi
}

warn_step() {
    echo -e "  ${AMBER}⚠️  $1${NC}"
}

info_step() {
    echo -e "  ${CYAN}ℹ️  $1${NC}"
}

# ── STEP 0: Pre-flight checks ─────────────────────────────────
print_header

echo -e "${BOLD}[STEP 0] Pre-flight checks...${NC}"

# Check Ollama is installed
if ! command -v ollama &> /dev/null; then
    echo -e "  ${RED}❌ Ollama not found.${NC}"
    echo -e "  ${AMBER}On Windows: winget install Ollama.Ollama${NC}"
    echo -e "  ${AMBER}On Linux:   curl -fsSL https://ollama.com/install.sh | sh${NC}"
    exit 1
fi
echo -e "  ${GREEN}✅ Ollama found: $(ollama --version 2>/dev/null)${NC}"

# Check Ollama API is responding
if curl -s --max-time 3 "${OLLAMA_API}/api/tags" > /dev/null 2>&1; then
    echo -e "  ${GREEN}✅ Ollama API responding on ${OLLAMA_API}${NC}"
else
    echo -e "  ${AMBER}⚠️  Ollama API not responding. Starting Ollama...${NC}"
    # Try to start (Linux/WSL2)
    ollama serve &> /tmp/ollama.log &
    sleep 3
    if curl -s --max-time 3 "${OLLAMA_API}/api/tags" > /dev/null 2>&1; then
        echo -e "  ${GREEN}✅ Ollama started successfully${NC}"
    else
        echo -e "  ${RED}❌ Could not start Ollama. On Windows, open Ollama from Start Menu first.${NC}"
        exit 1
    fi
fi

# Check Modelfile exists
if [ ! -f "$MODELFILE_PATH" ]; then
    echo -e "  ${RED}❌ Modelfile not found at: ${MODELFILE_PATH}${NC}"
    echo -e "  ${AMBER}Make sure you're running from /workspace directory${NC}"
    exit 1
fi
echo -e "  ${GREEN}✅ Modelfile found: ${MODELFILE_PATH}${NC}"

echo ""

# ── STEP 1: Pull base model ───────────────────────────────────
echo -e "${BOLD}[STEP 1] Pulling base model: ${BASE_MODEL}...${NC}"
echo -e "  ${CYAN}This may take a few minutes (2GB download)${NC}"

# Check if already pulled
if ollama list 2>/dev/null | grep -q "llama3.2:3b"; then
    echo -e "  ${GREEN}✅ ${BASE_MODEL} already downloaded — skipping pull${NC}"
else
    ollama pull "$BASE_MODEL"
    check_step "${BASE_MODEL} downloaded successfully"
fi

echo ""

# ── STEP 2: Build Shadow313 model ────────────────────────────
echo -e "${BOLD}[STEP 2] Building Shadow313-Nexus model...${NC}"
echo -e "  ${CYAN}Creating custom model from Modelfile...${NC}"

ollama create "$MODEL_NAME" -f "$MODELFILE_PATH"
check_step "Model '${MODEL_NAME}' created successfully"

echo ""

# ── STEP 3: Verify model exists ──────────────────────────────
echo -e "${BOLD}[STEP 3] Verifying model...${NC}"

if ollama list 2>/dev/null | grep -q "shadow313"; then
    echo -e "  ${GREEN}✅ Model confirmed in local registry:${NC}"
    ollama list 2>/dev/null | grep "shadow313" | while read line; do
        echo -e "     ${CYAN}${line}${NC}"
    done
else
    echo -e "  ${RED}❌ Model not found in registry after creation${NC}"
    exit 1
fi

echo ""

# ── STEP 4: Run smoke tests ───────────────────────────────────
echo -e "${BOLD}[STEP 4] Running smoke tests...${NC}"

# Test 1: Basic response
echo -e "  ${CYAN}Test 1: Basic identity check...${NC}"
RESPONSE=$(ollama run "$MODEL_NAME" "In one sentence, what is Shadow313 NEXUS?" 2>/dev/null)
if [ -n "$RESPONSE" ]; then
    echo -e "  ${GREEN}✅ Model responding${NC}"
    echo -e "  ${PURPLE}Response: ${RESPONSE:0:120}...${NC}"
else
    warn_step "No response received — model may need more time"
fi

echo ""

# Test 2: ATT&CK mapping
echo -e "  ${CYAN}Test 2: ATT&CK technique mapping...${NC}"
RESPONSE2=$(ollama run "$MODEL_NAME" "Map this to ATT&CK: powershell.exe -enc JABjAD0ATgBlAHcA" 2>/dev/null)
if echo "$RESPONSE2" | grep -qi "T1059\|T1027\|execution\|obfuscat"; then
    echo -e "  ${GREEN}✅ ATT&CK mapping working correctly${NC}"
else
    warn_step "ATT&CK mapping response unexpected — check manually"
fi

echo ""

# Test 3: API endpoint
echo -e "  ${CYAN}Test 3: REST API test...${NC}"
API_RESPONSE=$(curl -s --max-time 15 "${OLLAMA_API}/api/generate" \
    -H "Content-Type: application/json" \
    -d "{\"model\":\"${MODEL_NAME}\",\"prompt\":\"What FIPS standard covers SLH-DSA?\",\"stream\":false}" \
    2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('response','')[:80])" 2>/dev/null)

if [ -n "$API_RESPONSE" ]; then
    echo -e "  ${GREEN}✅ REST API working on ${OLLAMA_API}${NC}"
    echo -e "  ${PURPLE}API Response: ${API_RESPONSE}...${NC}"
else
    warn_step "API test inconclusive — try manually after setup"
fi

echo ""

# ── STEP 5: Show model info ───────────────────────────────────
echo -e "${BOLD}[STEP 5] Model information:${NC}"
ollama show "$MODEL_NAME" 2>/dev/null | head -20 | while read line; do
    echo -e "  ${CYAN}${line}${NC}"
done

echo ""

# ── STEP 6: Optional — push to Ollama.com ────────────────────
echo -e "${BOLD}[STEP 6] Push to Ollama.com (optional):${NC}"
echo -e "  ${AMBER}To publish your model publicly, run:${NC}"
echo -e "  ${CYAN}  ollama signin${NC}"
echo -e "  ${CYAN}  ollama push ${MODEL_NAME}${NC}"
echo ""
echo -e "  ${AMBER}Your model page:${NC}"
echo -e "  ${CYAN}  https://ollama.com/matarmohamad313/shadow313-nexus${NC}"

echo ""

# ── STEP 7: Integration commands ─────────────────────────────
echo -e "${BOLD}[STEP 7] Integration commands:${NC}"

echo -e "  ${GREEN}▶ Chat interactively:${NC}"
echo -e "  ${CYAN}    ollama run ${MODEL_NAME}${NC}"
echo ""
echo -e "  ${GREEN}▶ Python integration (Shadow313 modules):${NC}"
echo -e "  ${CYAN}    pip install ollama${NC}"
echo -e "  ${CYAN}    python3 -c \"import ollama; r=ollama.chat(model='${MODEL_NAME}',messages=[{'role':'user','content':'Analyze T1078'}]); print(r['message']['content'])\"${NC}"
echo ""
echo -e "  ${GREEN}▶ REST API (from any app):${NC}"
echo -e "  ${CYAN}    curl ${OLLAMA_API}/api/generate -d '{\"model\":\"${MODEL_NAME}\",\"prompt\":\"your question\",\"stream\":false}'${NC}"
echo ""
echo -e "  ${GREEN}▶ Open WebUI (Docker — ChatGPT interface):${NC}"
echo -e "  ${CYAN}    docker run -d -p 3000:8080 --add-host=host.docker.internal:host-gateway \\${NC}"
echo -e "  ${CYAN}      -v open-webui:/app/backend/data --name open-webui --restart always \\${NC}"
echo -e "  ${CYAN}      ghcr.io/open-webui/open-webui:main${NC}"
echo -e "  ${CYAN}    # Then open: http://localhost:3000${NC}"
echo ""
echo -e "  ${GREEN}▶ Shadow313 .env config:${NC}"
echo -e "  ${CYAN}    OLLAMA_BASE_URL=http://localhost:11434${NC}"
echo -e "  ${CYAN}    OLLAMA_MODEL=${MODEL_NAME}${NC}"
echo -e "  ${CYAN}    SHADOW313_AI_BACKEND=ollama${NC}"

echo ""

# ── FINAL SUMMARY ─────────────────────────────────────────────
echo -e "${CYAN}${BOLD}============================================================${NC}"
echo -e "${GREEN}${BOLD}  ✅ SHADOW313 NEXUS MODEL DEPLOYMENT COMPLETE${NC}"
echo -e "${CYAN}${BOLD}============================================================${NC}"
echo -e "  Model:    ${MODEL_NAME}"
echo -e "  Base:     ${BASE_MODEL}"
echo -e "  API:      ${OLLAMA_API}"
echo -e "  WebUI:    http://localhost:3000 (after Docker step)"
echo -e "  Platform: Shadow313 NEXUS v4.0.0"
echo -e "  Author:   mohamad — Ottawa, ON, Canada"
echo -e "${CYAN}${BOLD}============================================================${NC}"
echo ""