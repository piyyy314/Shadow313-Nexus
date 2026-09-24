# SHA-6: Docker + Open WebUI Setup
## Run these commands on your Windows machine (PowerShell as Admin)

### Step 1: Start Docker Desktop
Make sure Docker Desktop is running (check system tray).

### Step 2: Run Open WebUI
```powershell
docker run -d -p 3000:8080 `
  --add-host=host.docker.internal:host-gateway `
  -v open-webui:/app/backend/data `
  --name open-webui --restart always `
  ghcr.io/open-webui/open-webui:main
```

### Step 3: Open in browser
http://localhost:3000

### Step 4: Connect to your Ollama models
Open WebUI auto-detects Ollama at http://host.docker.internal:11434
Your models available:
- matarmohamad313/shadow313-nexus (your custom model)
- llama3.2:3b
- mistral:7b
- codellama:7b

### Step 5: Select Shadow313 model
In Open WebUI → top dropdown → select matarmohamad313/shadow313-nexus

### Verify Docker is running
```powershell
docker ps
# Should show: open-webui   Up X minutes   0.0.0.0:3000->8080/tcp
```

### If Ollama isn't detected
```powershell
# Set OLLAMA_HOST env var in Docker
docker run -d -p 3000:8080 `
  --add-host=host.docker.internal:host-gateway `
  -e OLLAMA_BASE_URL=http://host.docker.internal:11434 `
  -v open-webui:/app/backend/data `
  --name open-webui --restart always `
  ghcr.io/open-webui/open-webui:main
```
