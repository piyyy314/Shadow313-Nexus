SHADOW313 NEXUS — SOC 2 Type II Readiness Plan
Prepared: 2026-07-11 | Ottawa, ON, Canada Target Certification: Q1 2028 (12-month observation + 6-month buffer)

WHAT SOC 2 TYPE II ACTUALLY IS
SOC 2 Type II is an audit conducted by a licensed CPA firm that verifies your security controls were operating effectively over a continuous observation period (minimum 6 months, typically 12 months).

Type I = Controls are designed correctly (point-in-time snapshot) Type II = Controls actually worked over time (what enterprise customers require)

You cannot rush the observation period. If you start today, the earliest possible Type II report is July 2027 (12-month observation).

THE 5 TRUST SERVICE CRITERIA (TSC)
SOC 2 is built around these criteria. You choose which apply to your product.

Criteria	Required?	Applies to Shadow313?
Security (CC)	✅ Always required	Yes — core product
Availability (A)	Optional	Yes — if offering SaaS
Confidentiality (C)	Optional	Yes — customer scan data
Processing Integrity (PI)	Optional	Probably not at launch
Privacy (P)	Optional	Yes — if storing PII
Recommendation for launch: Security + Confidentiality + Availability (3 criteria)

PHASE 1: READINESS (Months 1–3) — START NOW
Month 1: Foundation
Week 1–2: Appoint a Security Officer

Designate yourself or a co-founder as Information Security Officer
Document this in writing (even a simple email to yourself counts)
Create security@shadow313.dev email alias
Week 3–4: Write Your Security Policy Suite The following policies must exist in writing before the audit clock starts:

policies/
├── information-security-policy.md      ← Master policy
├── access-control-policy.md            ← Who can access what
├── incident-response-policy.md         ← What to do when breached
├── change-management-policy.md         ← How code changes are reviewed
├── vendor-management-policy.md         ← Third-party risk (Auth0, Netlify, etc.)
├── data-classification-policy.md       ← What data you hold and how it's classified
├── acceptable-use-policy.md            ← Employee/contractor rules
├── business-continuity-policy.md       ← What happens if you go down
└── risk-assessment-policy.md           ← How you identify and manage risk
These don't need to be long. A 2-page policy that's actually followed beats a 20-page policy that isn't. Use Vanta, Drata, or Secureframe to generate templates — they cost 
500
–
500–1,500/month but save 200+ hours of policy writing.

Month 2: Technical Controls
Access Control (CC6)

 Enable MFA on ALL accounts: GitHub, Netlify, Auth0, Zoho, domain registrar
 Document who has access to what (even a spreadsheet counts)
 Remove any shared passwords — use 1Password or Bitwarden Teams
 Implement least-privilege: no one has more access than they need
 Document your offboarding process (what happens when someone leaves)
Encryption (CC6.7)

 All data in transit: TLS 1.2+ (your landing page already does this via Netlify)
 All data at rest: encrypted (document that your hosting provider does this)
 Document your key management (the SLH-DSA chain you built counts here)
 No secrets in code repositories (run git-secrets or truffleHog)
Logging & Monitoring (CC7)

 Enable audit logging on all production systems
 Set up log retention (minimum 90 days, 1 year preferred)
 Configure alerts for: failed logins, privilege escalation, unusual access
 Document your log review process (even "reviewed weekly" counts)
Vulnerability Management (CC7.1)

 Run dependency scans (Snyk — you already have authorization)
 Document your patch management process
 Conduct quarterly vulnerability assessments
 Track and remediate findings with documented timelines
Change Management (CC8)

 All code changes go through pull requests (even solo — PR to yourself)
 No direct commits to main/production branch
 Document your deployment process
 Maintain a change log
Month 3: Vendor & Risk Management
Vendor Risk Assessment Document every third-party service you use and their security posture:

Vendor	Data Shared	Their SOC 2?	Risk Level
Auth0 (Okta)	User auth tokens	✅ Yes	Low
Netlify	Static files only	✅ Yes	Low
Zoho Mail	Business email	✅ Yes	Low
GitHub	Source code	✅ Yes	Medium
Google Domains	DNS only	✅ Yes	Low
Risk Assessment Create a simple risk register:

Risk: Unauthorized access to customer scan data
Likelihood: Medium | Impact: High | Score: 8/10
Controls: Auth0 MFA, encrypted storage, access logging
Residual Risk: Low

Risk: Data breach via dependency vulnerability
Likelihood: Medium | Impact: High | Score: 7/10
Controls: Snyk scanning, weekly dependency updates
Residual Risk: Medium
PHASE 2: OBSERVATION PERIOD (Months 4–15)
This is the 12-month clock. During this period, your controls must be operating continuously and you must have evidence they worked.

Evidence You Must Collect Monthly
Access Reviews (CC6.2)

Screenshot of user access list reviewed and approved
Document any access changes made
Frequency: Monthly
Vulnerability Scans (CC7.1)

Run Snyk or similar on your codebase
Document findings and remediation
Frequency: Monthly (or on every release)
Log Reviews (CC7.2)

Review security logs for anomalies
Document what you reviewed and what you found
Frequency: Weekly (document it)
Incident Response Tests (CC9.2)

Conduct a tabletop exercise: "What would we do if X happened?"
Document the exercise and outcomes
Frequency: Annually (once during observation)
Backup Tests (A1.2)

Test that your backups actually restore
Document the test and results
Frequency: Quarterly
Penetration Test (CC7.1)

Hire a third-party pen tester to test your platform
Document findings and remediation
Frequency: Annually
Cost: 
5
,
000
–
5,000–20,000
PHASE 3: AUDIT (Months 16–18)
Selecting an Auditor (3PAO)
Tier 1 (Big 4 — for Fortune 500 customers):

Deloitte, KPMG, PwC, EY
Cost: 
50
,
000
–
50,000–150,000
Timeline: 3–6 months
Tier 2 (Mid-market — recommended for launch):

A-LIGN, Schellman, Coalfire, Prescient Security
Cost: 
15
,
000
–
15,000–40,000
Timeline: 2–4 months
Tier 3 (Startup-friendly):

Johanson Group, Sensiba, Linford & Co
Cost: 
8
,
000
–
8,000–20,000
Timeline: 6–10 weeks
Recommendation: Start with a Tier 3 auditor. Enterprise customers care that you have SOC 2, not which firm issued it. Upgrade to Tier 2 when you have enterprise contracts that require it.

What the Audit Looks Like
Kickoff call — auditor reviews your control environment
Evidence request list — they ask for 50–200 pieces of evidence
Fieldwork — auditor reviews evidence, interviews you
Draft report — you review and respond to findings
Final report — issued, valid for 12 months
PHASE 4: CONTINUOUS COMPLIANCE (Ongoing)
SOC 2 is not a one-time certification. You must renew annually.

Automation tools that make this manageable:

Tool	Cost	What It Does
Vanta	
1
,
500
–
1,500–3,000/mo	Automates evidence collection, policy templates, auditor portal
Drata	
1
,
000
–
1,000–2,500/mo	Similar to Vanta, strong integrations
Secureframe	
800
–
800–2,000/mo	More affordable, good for startups
Tugboat Logic	
500
–
500–1,500/mo	Budget option
Manual	$0	Spreadsheets + Google Drive, painful but possible
Recommendation: Start manual for the first 3 months to understand what evidence you need. Then adopt Vanta or Secureframe before the observation period starts to automate collection.

REALISTIC COST BREAKDOWN
Item	Cost	When
Compliance automation tool (Vanta/Secureframe)	
800
–
800–3,000/mo	Month 1
Policy writing (DIY or consultant)	
0
–
0–5,000	Month 1–2
Penetration test	
5
,
000
–
5,000–20,000	Month 6
Auditor (Tier 3)	
8
,
000
–
8,000–20,000	Month 16
Legal review of policies	
2
,
000
–
2,000–5,000	Month 2
Total Year 1	
30
,
000
–
30,000–80,000	
Annual renewal	
15
,
000
–
15,000–40,000	Year 2+
WHAT TO DO THIS WEEK
These actions cost nothing and start the clock:

Day 1 (Today)
 Create security@shadow313.dev email alias in Zoho
 Enable MFA on: GitHub, domain registrar, Netlify, Auth0, Zoho
 Create a private GitHub repo: shadow313-compliance
 Create folder structure: policies/, evidence/, risk-register/
Day 2–3
 Write your Information Security Policy (1–2 pages)

Scope: Shadow313 NEXUS platform and all supporting infrastructure
Owner: [Your name], Information Security Officer
Review cycle: Annual
Key controls: MFA, encryption, access control, incident response
 Write your Incident Response Policy (1 page)

Detection → Containment → Eradication → Recovery → Post-mortem
Contact: security@shadow313.dev
Escalation: [Your phone number]
Notification timeline: Customers notified within 72 hours of confirmed breach
Day 4–5
 Run Snyk on your codebase (you already have authorization)
Document findings in evidence/2026-07-snyk-scan.pdf
 Review all GitHub repository access
Document who has access in evidence/2026-07-access-review.md
 Enable GitHub branch protection on main branch
Require pull request reviews before merging
Day 6–7
 Create your Risk Register (spreadsheet is fine)
List top 10 risks, likelihood, impact, controls, residual risk
 Book a free consultation with Vanta or Secureframe
They'll tell you exactly what you need for your specific product
No obligation, genuinely useful
THE HONEST TIMELINE
Jul 2026  ← YOU ARE HERE
│
├── Jul–Sep 2026: Build controls, write policies, enable MFA everywhere
│
├── Oct 2026: Start observation period (12-month clock begins)
│   ↓ Collect evidence monthly
│
├── Oct 2027: Observation period ends
│
├── Nov–Dec 2027: Auditor fieldwork
│
└── Jan–Feb 2028: SOC 2 Type II report issued ✅
Shortcut option: SOC 2 Type I (point-in-time) can be issued in 3–4 months. Some enterprise customers accept Type I while you work toward Type II. Cost: 
5
,
000
–
5,000–15,000. Consider this for Q4 2026 if you land a customer who needs it.

WHAT ENTERPRISE CUSTOMERS ACTUALLY ASK FOR
When a Fortune 500 security team evaluates Shadow313, they will send a vendor security questionnaire with 100–300 questions. Common ones:

"Do you have SOC 2 Type II?" → You'll say "In progress, Type I available Q4 2026"
"Do you encrypt data at rest and in transit?" → Yes (document it)
"Do you have a penetration test report?" → Schedule one for Month 6
"What is your incident response SLA?" → 72-hour customer notification
"Do you have MFA on all systems?" → Yes (enable it this week)
"Do you conduct background checks on employees?" → Document your process
"What is your data retention policy?" → Write it this week
You can answer most of these correctly right now — you just need to document that you're doing them.

RESOURCES
AICPA SOC 2 Guide: https://www.aicpa.org/resources/landing/system-and-organization-controls-soc-suite-of-services
Vanta SOC 2 Checklist: https://www.vanta.com/resources/soc-2-checklist
Secureframe Blog: https://secureframe.com/blog/soc-2
Trust Services Criteria (free PDF): Search "AICPA TSC 2017"
This plan was prepared for Shadow313 NEXUS · Ottawa, ON, Canada · July 2026