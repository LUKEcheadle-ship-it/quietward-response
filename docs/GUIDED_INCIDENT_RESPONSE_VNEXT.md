# QuietWard Response Guided Incident Response — vNext

This update turns sanitized QuietWard detection context into a safer detection-to-resolution workflow while preserving the architectural separation between QuietWard observation and Response authority.

## Non-negotiable release requirement

The combined QuietWard + QuietWard Response vNext update **must not be released while any QuietWard finding family lacks a tested Response resolution path**.

`scripts/verify_vnext_resolution_coverage.py` is the release-blocking gate. It must return PASS before this combined update can move out of draft/release-candidate status.

A valid resolution path is either a typed, evidence-bound, policy-checked Response action with analyst approval where host mutation is safe and generalizable, or a tested guided escalation/recovery workflow with explicit evidence and closure criteria where automatic mutation would be unsafe or environment-specific. A generic "investigate manually" placeholder does not count.

## Implemented so far

- QuietWard response-context v1.1 with priority, evidence strength, playbook and investigation hints
- backward-compatible optional opaque `resolution_target_handle`
- approval-gated `collect_incident_triage_bundle`
- endpoint-local process evidence handles
- evidence-bound `terminate_evidence_process`
- server policy requiring the process handle to originate from a successful triage result for the same incident/host/agent
- endpoint execution-time process identity revalidation
- protected system-process deny rules
- UI workflow that selects a triage-produced handle rather than accepting free-form PID input
- action-protocol tests rejecting arbitrary PID/command parameters
- machine-readable resolution coverage matrix and hard release gate

The reviewed October 13 candidate underwent Windows and Ubuntu backend/native tests, database migration checks, real multi-analyst browser verification and paired-source checks. The [qualification workflow](https://github.com/LUKEcheadle-ship-it/quietward-response/actions/runs/38439060669) also passed the all-12-category recovery and escalation gate. These source-test receipts are **not** a separately published versioned package or host-by-host installer qualification.

## Automated executor roadmap (not claimed as implemented)

- evidence-bound file quarantine and reversible restore
- evidence-bound persistence disable/removal
- evidence-bound network containment/isolation
- identity/session recovery workflow
- container/workload containment
- vulnerability patch/update verification workflow
- evidence-integrity recovery workflow
- typed operational recovery workflows
- generic-security fallback resolution into a specific actionable family

## Required release gates

Before release:

- QuietWard remains observation-only
- legacy handoffs remain upgrade-compatible
- malformed optional remediation handles fail closed
- action capabilities are signed and explicitly enrolled
- high-impact actions are typed, evidence-bound, approval-bound and audited
- same-incident/host/agent provenance is verified before containment
- mutable targets are revalidated at execution time
- no arbitrary shell, PID, path, address, service name or free-form command surface exists
- protected system targets fail closed
- backend/frontend tests pass
- companion QuietWard tests pass
- joint finding -> handoff -> incident -> triage -> approval -> action -> result -> audit tests pass
- `scripts/verify_vnext_resolution_coverage.py` passes with zero unresolved categories

## Current status

Versioned, evidence-backed **human recovery workflows** cover all 12 declared categories in the October 13 reviewed source, including concrete routing for the generic-security fallback. They require named independent approval, ordered evidence checkpoints, fresh independent verification, and accountable escalation. They add no endpoint mutation authority. See [GUIDED_RECOVERY_WORKFLOWS.md](GUIDED_RECOVERY_WORKFLOWS.md) for the exact implemented behavior and its limits.

The original primary outcomes remain in the coverage matrix. The executable coverage gate runs positive and negative API contracts for every category and refuses skipped or missing cases; it **passed in the reviewed October 13 Windows and Ubuntu qualification**. Full backend, frontend, migration, native and paired verification must still be bound to any later selected formal release revision. The full vNext release is not tagged/published, and the gate's PASS does not mean the automatic-executor roadmap above is implemented.
