# Shadow313 NEXUS — Deployment Guide
## From Zero to Live on shadow313.dev

---

## Step 1: Register Domains (Day 1)

**Go to:** https://dash.cloudflare.com → Domain Registration

Buy these domains simultaneously:
```
shadow313.dev     ~$12/yr  ← PRIMARY (buy this first)
shadow313.com     ~$12/yr  ← DEFENSIVE redirect
```

**Why Cloudflare Registrar:**
- At-cost pricing (no markup)
- Best DNS management UI
- Free DDoS protection
- Automatic HTTPS

---

## Step 2: Set Up Business Email (Day 1)

**Option A — Zoho Mail (Free to start):**
1. Go to https://zoho.com/mail → Free plan
2. Add domain: shadow313.dev
3. Create: ops@shadow313.dev, enterprise@shadow313.dev, security@shadow313.dev
4. Add Zoho MX records to Cloudflare DNS

**Option B — Google Workspace ($6/mo, upgrade when ready):**
1. Go to https://workspace.google.com
2. Add domain: shadow313.dev
3. Add Google MX records to Cloudflare DNS

---

## Step 3: Deploy to Netlify (Day 1)

### Option A — Drag & Drop (fastest)
1. Go to https://app.netlify.com
2. Drag the `shadow313-landing/` folder onto the deploy zone
3. Site goes live instantly at a random `.netlify.app` URL

### Option B — GitHub + Auto-Deploy (recommended)
1. Create GitHub repo: `github.com/shadow313-nexus/shadow313-landing`
2. Push the `shadow313-landing/` folder
3. Connect repo to Netlify → auto-deploys on every push

### Connect Custom Domain
1. In Netlify: Site Settings → Domain Management → Add custom domain
2. Add: `shadow313.dev`
3. Add: `shadow313.com` (set as redirect to shadow313.dev)
4. Netlify provides SSL automatically via Let's Encrypt

---

## Step 4: Configure Cloudflare DNS

After Netlify gives you the IP/CNAME, add these records:

```dns
# shadow313.dev — PRIMARY
Type    Name    Value                           TTL
A       @       [Netlify IP from dashboard]     Auto
CNAME   www     shadow313.dev                   Auto
MX      @       [Zoho or Google MX records]     Auto
TXT     @       v=spf1 include:_spf.zoho.com ~all  Auto
TXT     @       [DKIM record from Zoho/Google]  Auto

# shadow313.com — REDIRECT TO .dev
A       @       [Netlify IP]                    Auto
CNAME   www     shadow313.com                   Auto
```

**In Netlify:** Add redirect rule (already in netlify.toml):
```
shadow313.com/* → https://shadow313.dev/:splat (301)
```

---

## Step 5: Google Search Console

1. Go to https://search.google.com/search-console
2. Add property: shadow313.dev
3. Verify via DNS TXT record (add to Cloudflare)
4. Submit sitemap: https://shadow313.dev/sitemap.xml

---

## Step 6: Create sitemap.xml

Create `shadow313-landing/sitemap.xml`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://shadow313.dev/</loc><priority>1.0</priority></url>
  <url><loc>https://shadow313.dev/tools/</loc><priority>0.9</priority></url>
  <url><loc>https://shadow313.dev/marketplace/</loc><priority>0.9</priority></url>
  <url><loc>https://shadow313.dev/docs/</loc><priority>0.8</priority></url>
  <url><loc>https://shadow313.dev/about/</loc><priority>0.7</priority></url>
  <url><loc>https://shadow313.dev/tools/aegis-nexus</loc><priority>0.8</priority></url>
  <url><loc>https://shadow313.dev/tools/sovereign-shield</loc><priority>0.8</priority></url>
  <url><loc>https://shadow313.dev/marketplace/analytics</loc><priority>0.7</priority></url>
  <url><loc>https://shadow313.dev/marketplace/analytics/live</loc><priority>0.7</priority></url>
</urlset>
```

---

## Step 7: robots.txt

Create `shadow313-landing/robots.txt`:
```
User-agent: *
Allow: /
Sitemap: https://shadow313.dev/sitemap.xml
```

---

## Step 8: First Marketing Steps

### GitHub
1. Create org: github.com/shadow313-nexus
2. Create repo: shadow313 (the CLI tool)
3. Add README with install instructions
4. Add topics: security, quantum, post-quantum, cli, cybersecurity

### Product Hunt
- Prepare launch for when you have 10+ waitlist signups
- Schedule for a Tuesday/Wednesday (highest traffic)

### Hacker News
- Post in "Show HN" when CLI is installable via pip
- Title: "Show HN: Shadow313 – Local-first quantum-ready security CLI with 313 temporal binding"

### Dev.to / Medium
- Write: "Why I built a post-quantum security CLI that runs entirely locally"
- Write: "313 Temporal Binding: cryptographic provenance for every computation"

---

## Deployment Checklist

- [ ] Domains registered (shadow313.dev + shadow313.com)
- [ ] Business email set up (ops@shadow313.dev)
- [ ] Site deployed to Netlify
- [ ] Custom domain connected + SSL active
- [ ] shadow313.com → shadow313.dev redirect working
- [ ] Google Search Console verified
- [ ] sitemap.xml submitted
- [ ] robots.txt in place
- [ ] GitHub repo created
- [ ] Waitlist form connected (Netlify Forms or Formspree)
- [ ] Analytics added (Plausible or Fathom — privacy-first)

---

## Cost Summary (Year 1)

| Item | Cost |
|------|------|
| shadow313.dev domain | ~$12/yr |
| shadow313.com domain | ~$12/yr |
| Netlify (Starter) | Free |
| Zoho Mail (Free tier) | Free |
| Cloudflare (Free tier) | Free |
| **Total** | **~$24/yr** |

Upgrade triggers:
- Netlify Pro ($19/mo): when you need form submissions > 100/mo or bandwidth > 100GB
- Google Workspace ($6/mo): when you need calendar, Meet, or Drive for team
- Plausible Analytics ($9/mo): when you want privacy-first analytics

---

## Domain Evolution Roadmap

| Phase | Domain | Trigger |
|-------|--------|---------|
| Phase 1 (Now) | shadow313.dev | Launch |
| Phase 2 | shadow313.dev + .com acquired | 100+ signups |
| Phase 3 | shadow313.com (primary) | $10K MRR |

See `SHADOW313 NEXUS — Domain Evolution Roadmap.md` for full details.
