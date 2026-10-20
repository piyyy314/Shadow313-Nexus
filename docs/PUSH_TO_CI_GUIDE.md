# Shadow313 NEXUS — Push to GitHub & CI Guide

## Step 1: Get a Fresh GitHub Token
1. Go to: https://github.com/settings/tokens/new
2. Select Fine-grained personal access token
3. Repository: piyyy314/Shadow313-Nexus only
4. Permissions: Contents (Read & Write), Actions (Read), Workflows (Read & Write)

## Step 2: Push from Your Laptop
```powershell
cd C:\Users\shiatoali\shadow313-nexus
git pull origin master
git add .
git commit -m "feat: your description"
git remote set-url origin "https://piyyy314:YOUR_TOKEN@github.com/piyyy314/Shadow313-Nexus.git"
git push origin master
git remote set-url origin "https://github.com/piyyy314/Shadow313-Nexus.git"
```

## Common Errors
| Error | Fix |
|-------|-----|
| non-fast-forward | git pull origin master first |
| Authentication failed | Generate new token |
| BLOCKED: X commits behind | git pull first |
| nothing to commit | No changes — already up to date |

## Token Security
- Never commit a token to a file
- Always remove from remote URL after pushing
- Rotate monthly at github.com/settings/tokens
