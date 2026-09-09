# QuietWard Response Guided Incident Response — vNext

This update turns sanitized QuietWard detection context into a faster, safer analyst response workflow without introducing autonomous endpoint mutation.

## Goal

When QuietWard produces a strong correlated finding, Response should immediately know the coarse priority, evidence strength, recommended investigation playbook, and safe diagnostic sequence.

Response remains the authority boundary for any future remediation. QuietWard remains observation-only.

## Phase 1 — Consume guided QuietWard context

Status: implementation started on `feature/guided-incident-response-vnext`.

Response accepts only the allowlisted QuietWard response-context v1.1 values and ignores guidance that violates the source safety contract.

Accepted guidance includes:

- `response_priority`
- `evidence_strength`
- `recommended_playbook`
- `investigation_hints`

Response uses the profile to prioritize existing bounded diagnostics and to explain why the investigation sequence was recommended. The profile never grants executable authority.

## Phase 2 — One-click incident triage bundle

Add `collect_incident_triage_bundle` as an analyst-approved, parameterless Response action.

The endpoint agent should compose:

- host health diagnostic
- process diagnostic where supported
- privacy-preserving network diagnostic where supported

The bundle must remain read-only, bounded, capability-aware, replay-safe, signed, and audited. Unsupported diagnostic components should be reported as skipped rather than causing unsafe fallbacks.

## Phase 3 — Evidence-bound containment

After the diagnostic bundle and joint integration gates pass, add narrowly typed remediation actions to Response only.

Initial candidates:

- `quarantine_observed_file`
- `terminate_observed_process`
- `disable_observed_persistence`
- `restore_quarantined_file`

Containment requirements:

- explicit human approval
- deterministic policy validation
- target must originate from previously signed endpoint evidence
- execution-time target revalidation
- stale/mismatched evidence fails closed
- strong allowlists for protected/system-critical processes and files
- no free-form commands or arbitrary shell execution
- complete before/after result and audit record
- reversible action preferred where practical

## Phase 4 — Threat-specific playbooks

Build response playbooks for the highest-value QuietWard detection families:

1. ransomware behavior
2. credential access / infostealer behavior
3. persistence establishment
4. suspicious living-off-the-land activity
5. correlated process + file + network attack chains

Playbooks should guide collection and propose bounded response actions, but should not bypass approval or policy controls.

## Joint release gates

- QuietWard observation-only invariants remain unchanged
- Response guidance parser consumes only allowlisted, versioned values
- malformed or executable-authority handoffs fail closed
- action capabilities are explicitly enrolled and server-validated
- all real endpoint actions remain typed and parameter constrained
- no inbound endpoint listener or remote shell
- joint end-to-end coverage verifies finding -> handoff -> incident -> recommendation -> approval -> action -> signed result -> audit
