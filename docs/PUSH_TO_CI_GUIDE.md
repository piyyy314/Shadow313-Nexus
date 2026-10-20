# Push to GitHub & CI Guide

## Quick Push
```powershell
cd C:\Users\shiatoali\shadow313-nexus
git pull origin master
git add .
git commit -m "feat: description"
git remote set-url origin "https://piyyy314:TOKEN@github.com/piyyy314/Shadow313-Nexus.git"
git push origin master
git remote set-url origin "https://github.com/piyyy314/Shadow313-Nexus.git"
```

## Get Token: github.com/settings/tokens/new
## Fine-grained -> Shadow313-Nexus -> Contents+Workflows write

## Common Errors
- non-fast-forward: git pull first
- Authentication failed: new token needed
- nothing to commit: already up to date
