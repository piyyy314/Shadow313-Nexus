# Shadow313 NEXUS — Delivery Artifacts Branch

This orphan branch stores bot-generated delivery artifacts.
It has NO shared history with the master branch.

## Contents
- `dist/manifest.json` — versioned delivery manifest
- `dist/receipts/` — 313-BIND cryptographic receipts

## Why a separate branch?
Isolating bot commits from the agent's working branch eliminates
non-fast-forward rejection cycles. The master branch contains only
human/agent commits. This branch contains only bot commits.

## Querying receipts
```bash
git fetch origin delivery-artifacts
git show origin/delivery-artifacts:dist/manifest.json | python3 -m json.tool
```
