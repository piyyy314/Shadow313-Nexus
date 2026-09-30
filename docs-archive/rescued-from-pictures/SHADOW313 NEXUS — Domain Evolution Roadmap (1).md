# SHADOW313 NEXUS — Domain Evolution Roadmap
## A 3-Phase Strategy Modeled on Vercel, Supabase, and Railway

**Version:** 1.0.0 | **Date:** July 9, 2026 | **Owner:** mohamad · Ottawa, ON

---

## Executive Summary

| Phase | Domain | Trigger | Timeline |
|---|---|---|---|
| **Phase 1 — Launch** | `shadow313.dev` (primary) | Today | Month 0–6 |
| **Phase 2 — Traction** | `shadow313.dev` + acquire `.com` | 100+ signups OR first enterprise inquiry | Month 6–18 |
| **Phase 3 — Scale** | `shadow313.com` (primary) | $10K MRR OR Series A prep | Month 18–36 |

**The Supabase Principle:** Launch on the available domain. Plan the migration from day one. Never let domain decisions delay shipping.

---

## PHASE 1 — LAUNCH
### `shadow313.dev` as Primary · Month 0–6

---

### What to Buy on Day 1

```
REQUIRED (buy today):
├── shadow313.dev     ~$12/yr   ← PRIMARY DOMAIN
├── shadow313.com     ~$12/yr   ← DEFENSIVE (redirect to .dev)
└── shadow313.io      ~$40/yr   ← OPTIONAL defensive

TOTAL: ~$24–64/yr depending on .io decision
```

**Where to buy:** Cloudflare Registrar (at-cost, no markup, best DNS)
- Go to: dash.cloudflare.com → Domain Registration
- Search all three simultaneously
- Buy with your business card (tax deductible)

**Why `.dev` as primary (not `.io`):**
- Google Registry ownership — zero geopolitical risk
- HTTPS enforced at registry level — can't load without SSL
- Increasingly the cleanest signal for developer-first tools
- `.io` carries BIOT/Mauritius sovereignty risk discovered in 2024
- $28/yr cheaper than `.io`

---

### Phase 1 DNS Configuration

Set up these records in Cloudflare immediately after purchase:

```dns
# shadow313.dev — PRIMARY
Type    Name    Value                           TTL
A       @       [Netlify/Vercel IP]             Auto
CNAME   www     shadow313.dev                   Auto
MX      @       [Google Workspace MX records]   Auto
TXT     @       google-site-verification=XXX    Auto
TXT     @       v=spf1 include:_spf.google.com ~all

# shadow313.com — REDIRECT TO .dev
Type    Name    Value                           TTL
A       @       [Netlify/Vercel IP]             Auto
CNAME   www     shadow313.com                   Auto

# In Netlify/Vercel: set shadow313.com → 301 redirect → shadow313.dev
```

**301 redirect rule** (add to `netlify.toml` or `vercel.json`):

```toml
# netlify.toml
[[redirects]]
  from = "https://shadow313.com/*"
  to = "https://shadow313.dev/:splat"
  status = 301
  force = true

[[redirects]]
  from = "https://www.shadow313.com/*"
  to = "https://shadow313.dev/:splat"
  status = 301
  force = true

[[redirects]]
  from = "https://www.shadow313.dev/*"
  to = "https://shadow313.dev/:splat"
  status = 301
  force = true
```

---

### Phase 1 Subdomain Architecture

Set up these subdomains from day one — even if they don't have content yet:

```
shadow313.dev           ← Landing page (live)
www.shadow313.dev       ← 301 → shadow313.dev
docs.shadow313.dev      ← Documentation (GitHub Pages or Mintlify)
status.shadow313.dev    ← Status page (Betteruptime free tier)
api.shadow313.dev       ← Future API (reserve now)
app.shadow313.dev       ← Future dashboard (reserve now)
```

**Why reserve subdomains now:** Changing subdomain structure later breaks links, SEO, and user bookmarks. Set the architecture once.

---

### Phase 1 Email Setup

```
Primary:   mohamad@shadow313.dev
Aliases:   hello@shadow313.dev
           security@shadow313.dev      ← CVE disclosures
           support@shadow313.dev
           press@shadow313.dev
           noreply@shadow313.dev       ← Automated emails
```

**Important:** Also configure `shadow313.com` email forwarding → `shadow313.dev`
Anyone who guesses the `.com` email still reaches you.

---

### Phase 1 Success Metrics

Track these — they are your migration triggers for Phase 2:

```
□ Landing page live at https://shadow313.dev
□ SSL certificate active (auto via Cloudflare)
□ shadow313.com redirecting correctly (test with curl -I)
□ Google Search Console verified for shadow313.dev
□ Google Analytics tracking visitors
□ Business email working: mohamad@shadow313.dev
□ GitHub org live: github.com/shadow313-nexus
□ PyPI package published: pip install shadow313
```

---

### Phase 1 What NOT to Do

```
❌ Don't use shadow313.io as primary (geopolitical risk)
❌ Don't skip buying shadow313.com (someone will squat it)
❌ Don't set up complex subdomain structure before you need it
❌ Don't migrate to .com yet (no traction = no SEO to protect)
❌ Don't use different domains for email vs website (confusing)
❌ Don't buy shadow313nexus.com (too long, dilutes brand)
```

---

## PHASE 2 — TRACTION
### Acquire `.com` · Prepare Migration · Month 6–18

---

### Migration Triggers — Any ONE of These Starts Phase 2

```
TRIGGER A: Waitlist / Signups
└── 100+ email signups on shadow313.dev
└── Action: Buy shadow313.com if not already owned, begin migration prep

TRIGGER B: First Enterprise Inquiry
└── Any company with 50+ employees asks about Pro/Enterprise
└── Action: Immediate — enterprise buyers expect .com
└── Accelerate to Phase 3 if this happens before Month 6

TRIGGER C: Hacker News Traction
└── Show HN post gets 100+ upvotes
└── Action: Traffic spike = time to lock in .com before someone squats

TRIGGER D: First Revenue
└── First paying Pro subscriber ($19/mo)
└── Action: You're a real business now — .com signals legitimacy

TRIGGER E: Investor Interest
└── Any VC or angel reaches out
└── Action: Investors expect .com — migrate before first meeting
```

**The Supabase lesson:** They migrated at YC entry. YC's rule:
> "If you don't have the .com version of your name, you should probably change it."

---

### How to Acquire shadow313.com

**Step 1: Check if it's available**
```bash
whois shadow313.com
# If "No match" → register immediately at Cloudflare for ~$9/yr
# If taken → proceed to negotiation steps below
```

**Step 2: If taken — research the owner**
```
Tools to use:
- who.is/whois/shadow313.com
- domaintools.com
- viewdns.info/whois/?domain=shadow313.com

Look for:
- Is it parked? (no real content = likely for sale)
- Is it a squatter? (generic page with ads = definitely for sale)
- Is it an active business? (harder to acquire, may need rebrand)
```

**Step 3: Negotiation approach (the Supabase method)**
```
DO:
✓ Email the registrant contact directly (no broker needed)
✓ Be honest: "We're a startup, we'd like to acquire this domain"
✓ Start low: offer $500–1,500 for a parked domain
✓ Be willing to walk away — don't show desperation
✓ Use Escrow.com for the transaction (protects both parties)

DON'T:
✗ Use a domain broker (they take % and inflate prices)
✗ Reveal your funding status or valuation
✗ Pay more than $5,000 for a parked domain at this stage
✗ Rush — squatters know urgency = higher price
```

**Step 4: Budget for acquisition**
```
Parked/unused domain:     $500 – $2,000    (likely scenario)
Lightly used domain:      $2,000 – $10,000  (negotiate hard)
Actively used domain:     $10,000+          (consider rebrand)
Premium/short domain:     $50,000+          (not worth it at this stage)
```

---

### Phase 2 Migration Preparation (Do Before Switching)

**Do all of this BEFORE changing the primary domain:**

```
□ Verify shadow313.com ownership in Google Search Console
□ Set up Google Analytics property for shadow313.com
□ Audit all backlinks to shadow313.dev (use Ahrefs free tier)
□ Document every URL that exists on shadow313.dev
□ Set up 301 redirects for every URL (not just homepage)
□ Update PyPI package homepage URL
□ Update GitHub org website field
□ Prepare email migration plan
□ Test all redirects in staging before going live
□ Notify waitlist subscribers of domain change
□ Update all social media profiles
□ Update business registration documents
```

**The redirect map you need:**
```
shadow313.dev           → shadow313.com          (301)
shadow313.dev/docs      → docs.shadow313.com     (301)
shadow313.dev/pricing   → shadow313.com/pricing  (301)
shadow313.dev/blog      → shadow313.com/blog     (301)
[every URL you have]    → [same path on .com]    (301)
```

---

### Phase 2 SEO Protection Protocol

Domain migrations are the #1 cause of startup SEO disasters. Follow this exactly:

**Week 1: Preparation**
```bash
# Export all indexed URLs from Search Console
# Download full sitemap
# Screenshot current rankings for top 10 keywords
# Note current organic traffic baseline
```

**Week 2: Implement redirects (don't switch primary yet)**
```bash
# Add shadow313.com to Cloudflare
# Configure all 301 redirects
# Test every redirect with curl:
curl -I https://shadow313.dev/pricing
# Should return: Location: https://shadow313.com/pricing
```

**Week 3: Switch primary in Search Console**
```
Google Search Console → Settings → Change of Address
Select: shadow313.dev → shadow313.com
Google will transfer ranking signals over 6–12 months
```

**Week 4: Monitor**
```
□ Check Search Console daily for crawl errors
□ Verify 301s are being followed (not 302s)
□ Monitor organic traffic — expect 10-20% temporary dip
□ Should recover fully within 3–6 months
□ Any 404 errors = fix immediately
```

**Email migration:**
```
Before:  mohamad@shadow313.dev
After:   mohamad@shadow313.com

Transition period (3 months):
- Keep shadow313.dev email active
- Auto-forward shadow313.dev → shadow313.com
- Add footer to all emails: "Note: Our email has moved to @shadow313.com"
- Update email signature immediately on switch day
```

---

### Phase 2 Subdomain Architecture Update

```
shadow313.com           ← Landing page (new primary)
shadow313.dev           ← 301 → shadow313.com (keep forever)
docs.shadow313.com      ← Documentation
status.shadow313.com    ← Status page
api.shadow313.com       ← API (if launched)
app.shadow313.com       ← Dashboard (if launched)
blog.shadow313.com      ← Blog (if launched)

# Keep these forever as redirects:
shadow313.dev           → shadow313.com
shadow313.io            → shadow313.com (if you bought it)
```

---

## PHASE 3 — SCALE
### `shadow313.com` as Permanent Primary · Month 18–36

---

### Scale Triggers — You're Ready for Phase 3 When:

```
TRIGGER A: Revenue
└── $10,000 MRR (Monthly Recurring Revenue)
└── This funds the .com acquisition and migration costs

TRIGGER B: Enterprise Pipeline
└── 3+ enterprise deals in pipeline (>$10K ACV each)
└── Enterprise procurement requires .com for vendor approval

TRIGGER C: Funding Round
└── Raising seed or Series A
└── Investors will require .com before term sheet
└── Vercel (ZEIT) rebranded entirely at funding milestone

TRIGGER D: Press Coverage
└── TechCrunch, Wired, or major security publication covers you
└── Mainstream press = mainstream audience = .com expected

TRIGGER E: Team Growth
└── Hiring beyond 5 people
└── Employees expect company email on .com
└── HR/legal/compliance systems expect .com
```

---

### Phase 3 Full Domain Portfolio

By Phase 3 you should own and manage:

```
PRIMARY:
shadow313.com           ← Main website, all marketing
app.shadow313.com       ← Pro/Enterprise dashboard
api.shadow313.com       ← Public API
docs.shadow313.com      ← Documentation
status.shadow313.com    ← Status page
blog.shadow313.com      ← Content marketing

PERMANENT REDIRECTS (keep forever, never let expire):
shadow313.dev           → shadow313.com
shadow313.io            → shadow313.com (if owned)
www.shadow313.com       → shadow313.com

DEFENSIVE (own but don't use):
shadow313.net           → shadow313.com
shadow313.org           → shadow313.com
shadow313security.com   → shadow313.com

FUTURE (acquire when relevant):
shadow313.ai            ← If AI features become primary
s313.io                 ← Short form for marketing
```

**Annual domain budget at Phase 3:** ~$150–200/yr for full portfolio

---

### Phase 3 Brand Consolidation

At scale, the Vercel pattern applies — consider whether the brand itself needs evolution:

```
Option A: Keep "SHADOW313 NEXUS" (recommended)
└── Strong brand equity built in Phase 1-2
└── Developer community knows the name
└── shadow313.com is clean and available

Option B: Rebrand (only if forced)
└── Trigger: shadow313.com is owned by an active business
└── Trigger: Legal trademark conflict discovered
└── Trigger: Enterprise buyers can't pronounce/remember it
└── Cost: High — all marketing, docs, code references change
└── Vercel did this successfully (ZEIT → Vercel) but it's expensive
```

---

### Phase 3 Enterprise Domain Requirements

Enterprise procurement teams check these before approving vendor payments:

```
□ Primary domain is .com (many procurement systems reject .io/.dev)
□ SSL certificate valid and not expiring within 90 days
□ DMARC/DKIM/SPF email authentication configured
□ security.txt file at shadow313.com/.well-known/security.txt
□ Privacy policy at shadow313.com/privacy
□ Terms of service at shadow313.com/terms
□ SOC 2 or security documentation linked from main domain
□ Business address verifiable (matches domain registration)
```

---

## DECISION FLOWCHART

```
TODAY
  │
  ▼
Buy shadow313.dev + shadow313.com
  │
  ▼
Launch on shadow313.dev
  │
  ├─── < 100 signups ──────────────────────────────────────────┐
  │                                                             │
  ├─── 100+ signups OR first enterprise inquiry                 │
  │         │                                                   │
  │         ▼                                                   │
  │    PHASE 2: Acquire .com (if not owned)                     │
  │    Prepare migration (4-week process)                       │
  │    Execute 301 redirects                                    │
  │    Monitor SEO for 3 months                                 │
  │         │                                                   │
  │         ├─── < $10K MRR ──────────────────────────────────┐│
  │         │                                                  ││
  │         ├─── $10K MRR OR investor interest                 ││
  │         │         │                                        ││
  │         │         ▼                                        ││
  │         │    PHASE 3: shadow313.com as permanent primary   ││
  │         │    Full domain portfolio                         ││
  │         │    Enterprise-ready infrastructure               ││
  │         │         │                                        ││
  │         │         ▼                                        ││
  │         │    SCALE: Maintain forever                       ││
  │         │                                                  ││
  │         └──────────────────────────────────────────────────┘│
  └─────────────────────────────────────────────────────────────┘
```

---

## COST SUMMARY

### Phase 1 (Year 1)
```
shadow313.dev       $12/yr
shadow313.com       $12/yr
shadow313.io        $40/yr  (optional)
Google Workspace    $72/yr  ($6/mo)
Netlify/Vercel      $0/yr   (free tier)
─────────────────────────────
TOTAL:              $96–136/yr
```

### Phase 2 (Year 1–2)
```
Phase 1 costs       $96–136/yr
shadow313.com acq.  $0–5,000  (one-time, if not already owned)
Migration work      $0        (DIY with this guide)
─────────────────────────────
TOTAL:              $96–5,136 (one-time acquisition + ongoing)
```

### Phase 3 (Year 2–3+)
```
Full domain portfolio   $150–200/yr
Google Workspace Pro    $144/yr ($12/mo, more users)
Hosting (Vercel Pro)    $240/yr ($20/mo)
─────────────────────────────
TOTAL:                  ~$534–584/yr
```

---

## QUICK REFERENCE — The Three Rules

```
RULE 1: Ship on .dev, plan for .com
  Don't let domain decisions delay your launch.
  shadow313.dev is credible enough to get your first 100 users.

RULE 2: Buy .com defensively on day one
  $12/yr is the cheapest insurance you'll ever buy.
  Someone will try to squat it the moment you get press coverage.

RULE 3: Migrate before enterprise, not after
  Enterprise procurement systems often reject non-.com vendors.
  Migrate when you have traction but before you need the deal.
```

---

## WHAT TO ASK ME TO BUILD NEXT

Once you've purchased your domains, come back and I'll build:

```
1. netlify.toml / vercel.json  ← Redirect configuration files
2. security.txt                ← Security disclosure policy
3. sitemap.xml                 ← For Search Console submission
4. robots.txt                  ← SEO configuration
5. README.md                   ← GitHub repo README
6. pyproject.toml              ← pip install shadow313
```

---

*SHADOW313 NEXUS · Ottawa, ON, Canada · Authorized Snyk Partner*
*Domain strategy modeled on: Vercel (ZEIT→Vercel), Supabase (.io→.com), Railway (.app), Fly.io*
