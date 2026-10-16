#!/usr/bin/env python3
"""
Shadow313 NEXUS — OpenAPI TypeScript Client Generator
Generates typed TypeScript client from FastAPI OpenAPI spec.

Usage:
  python3 scripts/generate-ts-client.py

Requirements:
  pip install httpx
  npm install -g @openapitools/openapi-generator-cli
"""
import json
import subprocess
from pathlib import Path

API_BASE = "http://localhost:8000"
OUTPUT_DIR = "shadow313_sdk/ts-client"

def generate():
    print("Fetching OpenAPI spec from Shadow313 API...")
    try:
        import urllib.request
        with urllib.request.urlopen(f"{API_BASE}/api/openapi.json", timeout=5) as r:
            spec = json.loads(r.read())
        
        spec_path = Path("/tmp/shadow313-openapi.json")
        spec_path.write_text(json.dumps(spec, indent=2))
        print(f"  Spec: {len(spec.get('paths', {}))} endpoints")
        
        Path(OUTPUT_DIR).mkdir(parents=True, exist_ok=True)
        result = subprocess.run([
            "openapi-generator-cli", "generate",
            "-i", str(spec_path),
            "-g", "typescript-fetch",
            "-o", OUTPUT_DIR,
            "--additional-properties=supportsES6=true,npmName=shadow313-client",
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"  TypeScript client generated: {OUTPUT_DIR}/")
        else:
            print(f"  Error: {result.stderr[:200]}")
            print(f"  Tip: Install with: npm install -g @openapitools/openapi-generator-cli")
    except Exception as e:
        print(f"  Error: {e}")
        print(f"  Make sure Shadow313 API is running: shadow313 serve")

if __name__ == "__main__":
    generate()
