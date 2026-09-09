# QuietWard Response Guided Incident Response — vNext

This update turns sanitized QuietWard detection context into a safer detection-to-resolution workflow while preserving the architectural separation between QuietWard observation and Response authority.

## Non-negotiable release requirement

The combined QuietWard + QuietWard Response vNext update **must not be released while any QuietWard finding family lacks a tested Response resolution path**.

`scripts/verify_vnext_resolution_coverage.py` is the release-blocking gate. It must return PASS before this combined update can move out of draft/release-candidate status.

A valid resolution path is either:

1. a typed, evidence-bound, policy-checked Response action with analyst approval where host mutation is safe and generalizable; or
2. a tested guided escalation/recovery workflow with explicit evidence and closure criteria where automatic mutation would be unsafe or environment-specific.

A generic "investigate manually" placeholder does not count as release-ready resolution coverage.

## Phase 1 — Guided QuietWard context

Status: implemented; qualification pending.

Response accepts allowlisted QuietWard response-context v1.1 values while retaining v1.0 compatibility:

- `response_priority`
- `evidence_strength`
- `recommended_playbook`
- `investigation_hints`
- optional opaque `resolution_target_handle`

The opaque handle is not a path, PID, account, address, or command. Raw private targets remain outside the server-visible handoff. Guidance that violates the observation-only contract is rejected.

## Phase 2 — Incident triage bundle

Status: implemented; qualification pending.

`collect_incident_triage_bundle` is an analyst-approved, parameterless Response action that composes:

- bounded host health
- bounded process inventory
- privacy-preserving network snapshot where supported

The bundle is read-only with respect to protected host state. Process entries may receive endpoint-local opaque evidence handles that can later authorize narrowly typed containment after separate analyst approval.

## Phase 3 — Evidence-bound containment

Status: in progress and release-blocking.

### Process containment

Implemented in the feature branch; qualification pending:

- `terminate_evidence_process`
- no arbitrary PID field
- only accepts `qwrp-<opaque handle>`
- handle must originate from a successful triage result for the same incident, host, and agent
- endpoint privately resolves the handle
- process image, parent and start marker are revalidated immediately before action
- critical/system processes and Response's own lineage are protected
- stale, changed, cross-incident, unknown or expired evidence fails closed
- explicit analyst approval remains mandatory
- no shell or arbitrary command execution

### Remaining release-blocking resolution families

Still to be implemented and qualified:

- evidence-bound file quarantine and reversible restore
- evidence-bound persistence disable/removal
- evidence-bound network containment/isolation
- identity/session recovery workflow
- container/workload containment
- vulnerability patch/update verification workflow
- evidence-integrity recovery workflow
- typed operational recovery workflows
- generic-security fallback resolution into a specific actionable family

## Resolution coverage matrix

`backend/app/services/resolution_coverage.py` is the machine-readable coverage inventory. Every QuietWard Response category must exist in this matrix and remain `release_ready=False` until its real resolution path and qualification evidence exist.

Current categories:

- malware
- integrity
- privilege
- persistence
- identity
- network
- container
- vulnerability
- execution
- file_integrity
- operational
- security

The final release gate fails while even one category remains unresolved.

## Phase 4 — Higher-value detection playbooks

After resolution coverage is complete, expand playbooks for:

1. ransomware behavior
2. credential access / infostealers
3. persistence establishment
4. suspicious living-off-the-land activity
5. correlated process + file + network attack chains

New detectors must not expand faster than Response's ability to safely resolve or explicitly escalate them; otherwise they create the same detection/remediation gap this vNext release is intended to close.

## Joint release gates

Before release:

- QuietWard remains observation-only
- legacy v1.0/v1.1 handoffs remain upgrade-compatible
- malformed optional remediation handles fail closed
- Response guidance consumes only allowlisted versioned values
- action capabilities are signed and explicitly enrolled
- mutating actions are typed and parameter-constrained
- evidence-bound actions prove same-incident/host/agent provenance
- endpoints revalidate mutable targets at execution time
- no arbitrary shell, PID, path, address, service name or free-form command surface
- protected system targets are fail-closed
- full backend/frontend tests pass
- companion QuietWard tests pass
- joint finding -> handoff -> incident -> triage -> approval -> action -> result -> audit tests pass
- `scripts/verify_vnext_resolution_coverage.py` passes with zero unresolved categories
