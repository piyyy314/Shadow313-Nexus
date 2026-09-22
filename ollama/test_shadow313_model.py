#!/usr/bin/env python3
"""
SHADOW313 NEXUS — Ollama Model Test Suite
Tests the matarmohamad313/shadow313-nexus model across all core domains.
Run: python3 ollama/test_shadow313_model.py
"""

import json
import time
import sys
import urllib.request
import urllib.error

# ── Config ────────────────────────────────────────────────────
OLLAMA_API   = "http://localhost:11434"
MODEL_NAME   = "matarmohamad313/shadow313-nexus"
TIMEOUT      = 60  # seconds per test

GREEN  = "\033[92m"
RED    = "\033[91m"
AMBER  = "\033[93m"
CYAN   = "\033[96m"
PURPLE = "\033[95m"
BOLD   = "\033[1m"
NC     = "\033[0m"

# ── Test definitions ──────────────────────────────────────────
TESTS = [
    {
        "id": "T01",
        "name": "Identity Check",
        "domain": "Core",
        "prompt": "In one sentence, what is Shadow313 NEXUS and who built it?",
        "must_contain": ["shadow313", "mohamad"],
        "must_not_contain": ["openai", "chatgpt", "i am a language model"],
    },
    {
        "id": "T02",
        "name": "ATT&CK Mapping — PowerShell Encoded",
        "domain": "MITRE ATT&CK",
        "prompt": "Map this event to ATT&CK: powershell.exe -nop -w hidden -enc JABjAD0ATgBlAHcA spawned from winword.exe",
        "must_contain": ["T1059", "T1566"],
        "must_not_contain": [],
    },
    {
        "id": "T03",
        "name": "ATT&CK Mapping — LSASS Access",
        "domain": "MITRE ATT&CK",
        "prompt": "What ATT&CK technique is: procdump.exe -ma lsass.exe lsass.dmp",
        "must_contain": ["T1003"],
        "must_not_contain": [],
    },
    {
        "id": "T04",
        "name": "PQC Knowledge — FIPS Standards",
        "domain": "Post-Quantum Crypto",
        "prompt": "What NIST FIPS standard covers SLH-DSA and why is it used in 313-BIND?",
        "must_contain": ["205", "SLH-DSA"],
        "must_not_contain": [],
    },
    {
        "id": "T05",
        "name": "PQC Knowledge — HNDL Threat",
        "domain": "Post-Quantum Crypto",
        "prompt": "Explain the HNDL threat and which Shadow313 cryptographic layer addresses it.",
        "must_contain": ["harvest", "decrypt"],
        "must_not_contain": [],
    },
    {
        "id": "T06",
        "name": "Detector Knowledge — FIX-17",
        "domain": "Shadow313 Detectors",
        "prompt": "What does the ImpossibleTravelDetector (FIX-17) detect and how does it improve on FIX-12?",
        "must_contain": ["T1078", "geo"],
        "must_not_contain": [],
    },
    {
        "id": "T07",
        "name": "CVE Analysis Format",
        "domain": "Vulnerability Analysis",
        "prompt": "Analyze CVE-2026-3392 TR-069 CWMP vulnerability. Include CVSS vector and ATT&CK mapping.",
        "must_contain": ["CVE", "CWMP"],
        "must_not_contain": [],
    },
    {
        "id": "T08",
        "name": "Sigma Rule Generation",
        "domain": "Detection Engineering",
        "prompt": "Write a Sigma rule to detect DCSync attacks (T1003.006) using Windows Event ID 4662.",
        "must_contain": ["title:", "detection:", "4662"],
        "must_not_contain": [],
    },
    {
        "id": "T09",
        "name": "CADL Escalation Knowledge",
        "domain": "Active Defense",
        "prompt": "Describe the CADL L3 Reroute tier and when it should be triggered.",
        "must_contain": ["L3", "reroute"],
        "must_not_contain": [],
    },
    {
        "id": "T10",
        "name": "313-BIND Receipt Format",
        "domain": "Temporal Binding",
        "prompt": "Produce a 313-BIND receipt for a finding: LSASS dump detected on WS-07 at 2026-09-04.",
        "must_contain": ["313-", "SLH-DSA"],
        "must_not_contain": [],
    },
    {
        "id": "T11",
        "name": "Compliance Gap — CMMC",
        "domain": "Compliance",
        "prompt": "What is Shadow313's current CMMC Level 2 coverage percentage and the top Wave 1 priority?",
        "must_contain": ["40", "CA-"],
        "must_not_contain": [],
    },
    {
        "id": "T12",
        "name": "No Hallucination Check",
        "domain": "Accuracy",
        "prompt": "What is the CVE ID for the Apache Log4Shell vulnerability?",
        "must_contain": ["CVE-2021-44228", "log4j"],
        "must_not_contain": ["CVE-2022", "CVE-2020"],
    },
]


def query_ollama(prompt: str, model: str = MODEL_NAME, timeout: int = TIMEOUT) -> str:
    """Send a prompt to Ollama API and return the response text."""
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2,
            "num_ctx": 4096,
        }
    }).encode("utf-8")

    req = urllib.request.Request(
        f"{OLLAMA_API}/api/generate",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data.get("response", "").strip()
    except urllib.error.URLError as e:
        return f"ERROR: {e}"
    except Exception as e:
        return f"ERROR: {e}"


def check_ollama_running() -> bool:
    """Check if Ollama API is reachable."""
    try:
        req = urllib.request.Request(f"{OLLAMA_API}/api/tags")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status == 200
    except Exception:
        return False


def check_model_exists() -> bool:
    """Check if the Shadow313 model is available locally."""
    try:
        req = urllib.request.Request(f"{OLLAMA_API}/api/tags")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            models = [m.get("name", "") for m in data.get("models", [])]
            return any("shadow313" in m.lower() for m in models)
    except Exception:
        return False


def run_test(test: dict) -> dict:
    """Run a single test and return result."""
    print(f"  {CYAN}[{test['id']}] {test['name']}...{NC}", end=" ", flush=True)

    start = time.time()
    response = query_ollama(test["prompt"])
    elapsed = time.time() - start

    response_lower = response.lower()

    # Check must_contain
    passed_contains = all(
        kw.lower() in response_lower
        for kw in test["must_contain"]
    )

    # Check must_not_contain
    passed_not_contains = all(
        kw.lower() not in response_lower
        for kw in test["must_not_contain"]
    )

    passed = passed_contains and passed_not_contains and not response.startswith("ERROR")

    result = {
        "id": test["id"],
        "name": test["name"],
        "domain": test["domain"],
        "passed": passed,
        "elapsed": round(elapsed, 1),
        "response_preview": response[:120] if response else "",
        "missing_keywords": [
            kw for kw in test["must_contain"]
            if kw.lower() not in response_lower
        ],
        "error": response if response.startswith("ERROR") else None,
    }

    if passed:
        print(f"{GREEN}✅ PASS{NC} ({elapsed:.1f}s)")
    else:
        print(f"{RED}❌ FAIL{NC} ({elapsed:.1f}s)")
        if result["missing_keywords"]:
            print(f"     {AMBER}Missing: {result['missing_keywords']}{NC}")
        if result["error"]:
            print(f"     {RED}Error: {result['error'][:80]}{NC}")

    return result


def print_summary(results: list):
    """Print final test summary."""
    passed  = sum(1 for r in results if r["passed"])
    failed  = sum(1 for r in results if not r["passed"])
    total   = len(results)
    avg_t   = sum(r["elapsed"] for r in results) / total if total else 0

    print()
    print(f"{CYAN}{BOLD}{'='*60}{NC}")
    print(f"{CYAN}{BOLD}  SHADOW313 MODEL TEST RESULTS{NC}")
    print(f"{CYAN}{BOLD}{'='*60}{NC}")
    print(f"  Model:   {MODEL_NAME}")
    print(f"  Total:   {total} tests")
    print(f"  {GREEN}Passed:  {passed}{NC}")
    print(f"  {RED if failed else GREEN}Failed:  {failed}{NC}")
    print(f"  Avg RT:  {avg_t:.1f}s per test")
    print()

    # Domain breakdown
    domains = {}
    for r in results:
        d = r["domain"]
        if d not in domains:
            domains[d] = {"pass": 0, "fail": 0}
        if r["passed"]:
            domains[d]["pass"] += 1
        else:
            domains[d]["fail"] += 1

    print(f"  {'Domain':<28} {'Pass':>5} {'Fail':>5}")
    print(f"  {'-'*40}")
    for domain, counts in domains.items():
        color = GREEN if counts["fail"] == 0 else AMBER if counts["pass"] > 0 else RED
        print(f"  {color}{domain:<28} {counts['pass']:>5} {counts['fail']:>5}{NC}")

    print()

    # Failed tests detail
    failed_tests = [r for r in results if not r["passed"]]
    if failed_tests:
        print(f"  {RED}{BOLD}Failed Tests:{NC}")
        for r in failed_tests:
            print(f"  {RED}  [{r['id']}] {r['name']}{NC}")
            if r["missing_keywords"]:
                print(f"  {AMBER}       Missing keywords: {r['missing_keywords']}{NC}")
            if r["response_preview"]:
                print(f"  {PURPLE}       Response: {r['response_preview'][:80]}...{NC}")
        print()

    # Final verdict
    if failed == 0:
        print(f"  {GREEN}{BOLD}✅ ALL TESTS PASSED — Model is fully operational{NC}")
    elif passed / total >= 0.8:
        print(f"  {AMBER}{BOLD}⚠️  {passed}/{total} PASSED — Model mostly working, review failures{NC}")
    else:
        print(f"  {RED}{BOLD}❌ {failed}/{total} FAILED — Model needs attention{NC}")

    print(f"{CYAN}{BOLD}{'='*60}{NC}")
    print()


def main():
    print()
    print(f"{CYAN}{BOLD}{'='*60}{NC}")
    print(f"{CYAN}{BOLD}  SHADOW313 NEXUS — Ollama Model Test Suite{NC}")
    print(f"{CYAN}{BOLD}  Model: {MODEL_NAME}{NC}")
    print(f"{CYAN}{BOLD}{'='*60}{NC}")
    print()

    # Pre-flight
    print(f"{BOLD}Pre-flight checks:{NC}")

    if not check_ollama_running():
        print(f"  {RED}❌ Ollama API not reachable at {OLLAMA_API}{NC}")
        print(f"  {AMBER}Start Ollama first: ollama serve (Linux) or open Ollama app (Windows){NC}")
        sys.exit(1)
    print(f"  {GREEN}✅ Ollama API reachable{NC}")

    if not check_model_exists():
        print(f"  {RED}❌ Model '{MODEL_NAME}' not found locally{NC}")
        print(f"  {AMBER}Build it first: ollama create {MODEL_NAME} -f ollama/Modelfile{NC}")
        sys.exit(1)
    print(f"  {GREEN}✅ Model '{MODEL_NAME}' found{NC}")

    print()
    print(f"{BOLD}Running {len(TESTS)} tests across {len(set(t['domain'] for t in TESTS))} domains:{NC}")
    print()

    results = []
    for test in TESTS:
        result = run_test(test)
        results.append(result)

    print_summary(results)

    # Exit code
    failed = sum(1 for r in results if not r["passed"])
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()