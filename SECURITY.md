# Security policy

QuietWard Response is pre-release security software. Phase 1 is designed for local development and investigation workflows; it is not an internet-facing production service.

## Reporting a vulnerability

Please use GitHub's private **Report a vulnerability** / Security Advisories workflow for this repository. Do not open a public issue containing exploit details, credentials, private event data, or host evidence.

Include the affected revision, a minimal reproduction, impact, and any suggested mitigation. Synthetic evidence is preferred.

## Phase 1 boundary

- The API defaults to `127.0.0.1` and CORS permits only the configured local frontend.
- Event envelopes are strictly validated and duplicate UUIDs are rejected and audited.
- Database access uses SQLAlchemy parameter binding.
- Secrets are supplied through environment variables and are never committed.
- There is no shell, process termination, isolation, firewall, quarantine, deletion, or arbitrary action endpoint.
- Recommendations labeled remediation are disabled data, not executable requests.

Authentication, signed sensor enrollment, role-based authorization, approval quorum, and a separately versioned endpoint action protocol are required before production or remote deployment.
