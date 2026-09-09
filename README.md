# QuietWard Response

QuietWard Response is the controlled incident-response companion to QuietWard. QuietWard observes and detects; Response owns analyst-guided investigation and any endpoint mutation authority.

> **Guided Incident Response vNext is under active development on a draft feature branch. It is not release-ready.** The combined QuietWard + Response update is explicitly blocked until every QuietWard finding category has a tested Response resolution path and the final resolution-coverage gate passes.

For the current public release, use the documented stable setup and safety model in this repository. The vNext branch adds guided triage and is building evidence-bound containment without introducing arbitrary shell/PID/path/address execution surfaces.

## vNext development highlights

The draft vNext work currently includes:

- sanitized QuietWard response-context v1.1
- priority, evidence strength and playbook guidance
- one-click bounded incident triage
- endpoint-local opaque evidence handles
- analyst-approved, evidence-bound process containment
- a machine-readable resolution coverage matrix
- a release-blocking gate that fails while any QuietWard category is unresolved or unqualified

Process containment accepts only an opaque endpoint-generated handle, requires same-incident/host/agent triage provenance, and revalidates the process instance at execution time. It does not accept arbitrary PIDs or commands.

Remaining vNext release blockers include file quarantine/restore, persistence remediation, network containment, identity/session recovery, container remediation, vulnerability remediation verification, integrity recovery, operational recovery, and generic fallback resolution.

See `docs/GUIDED_INCIDENT_RESPONSE_VNEXT.md` for the active design and release requirements.

## Safety principles

- QuietWard remains observation-only.
- Response actions are typed and allowlisted.
- High-impact actions require explicit analyst approval.
- No generic remote shell or arbitrary command execution is provided.
- Remediation targets must be evidence-bound rather than free-form where host mutation is involved.
- Endpoint evidence is revalidated before mutation.
- Protected/system-critical targets fail closed.
- Audit and lifecycle records are retained for controlled actions.

## Repository status

This repository contains the Response backend, frontend, endpoint agent, protocols, tests, migration history, and release tooling. Stable-release documentation and historical details remain available in the repository docs and changelog.
