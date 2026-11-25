# Security Policy

## Current project version

The repository package version is **4.0.0**. This identifies the source/package version; it is not a statement that every optional integration or deployment is supported or production-ready. Support commitments for older releases are not currently published.

## Reporting a vulnerability

Please report suspected vulnerabilities privately before publishing exploit details.

- **Email:** pitty313@proton.me
- **Subject:** `[SECURITY] Brief description`
- Include the affected repository/component and version, reproduction steps, impact, and a safe way to contact you.
- Do not include secrets, personal data, or live customer information in an initial report.

We will review reports and coordinate remediation and disclosure where appropriate. No fixed acknowledgement or remediation SLA is currently promised. Good-faith, authorized testing is welcome; this policy does not authorize testing systems you do not own or have permission to assess.

## Scope

This policy covers code and configuration maintained in [Shadow313-Nexus](https://github.com/piyyy314/Shadow313-Nexus), including its Python packages, API, CLI, Docker configuration, static website, and repository workflows.

Third-party services and dependencies are not operated by this project. Report vulnerabilities in those products to their respective maintainers. Do not perform denial-of-service, social-engineering, physical, or other disruptive testing.

## Bounty and rewards

No formal paid bug-bounty program, reward schedule, or guaranteed payout is currently published. Do not assume that a report qualifies for compensation.

## CVE and advisory status

This repository does not use project-internal tracking labels as externally assigned CVE identifiers. A project issue or internal label is not a CVE assignment, a published security advisory, or proof that a fix shipped in a released artifact.

For externally assigned identifiers and public advisories, consult the repository's [GitHub Security Advisories](https://github.com/piyyy314/Shadow313-Nexus/security/advisories). Verify the affected commit and release artifact before describing a vulnerability as fixed.

## Release and deployment verification

A passing CI job is evidence only for the checks that ran on that commit. It does not prove that production systems, optional integrations, external services, or deployed artifacts are secure or operational. Review the current [GitHub Actions runs](https://github.com/piyyy314/Shadow313-Nexus/actions) and deployment records separately.
