# Guided recovery workflows

The guided-response update now supplies a concrete operator recovery path for every declared QuietWard category. This is **human-executed, evidence-attested recovery**, not an automatic quarantine, firewall, account-management, container-management or package-upgrade engine.

## Workflow

Open an incident and use **Guided resolution**. Select a scope from that incident's actual host/category evidence. An unclassified `security` event must be routed to one concrete family; it cannot be closed with a generic "investigate manually" disposition.

The operator provides an existing ticket reference, baseline evidence hash/summary and an owner-approved rollback plan. A different authenticated analyst approves the plan. The operator then records each category-specific checkpoint, in order, with an artifact hash/reference, observation time and an outcome note. Mandatory checkpoints cannot be marked not applicable; a failed checkpoint blocks further work. Only explicitly conditional steps can be waived, with evidence and rationale.

A different named analyst verifies the completed recovery against the playbook's explicit acceptance criteria using a new post-recovery artifact. Every affected host/category must be verified against current incident evidence before the incident can close. Active endpoint actions and unresolved/escalated workflows block closure, including through the older status-change endpoint once a workflow exists.

The older manual status label remains backward-compatible on incidents without workflows. It is **not** a verified recovery record. A workflow's `verified` state always means independent human attestation, never an automated proof that the endpoint is healthy.

## Concrete families

| Family | Required recovery evidence |
|---|---|
| Malware | Preserved process/artifact identity, scoped containment, quarantine custody when applicable, approved recovery and fresh observations |
| Evidence integrity | Preserved original damaged state, trusted recovery source, non-destructive recovery receipt and fresh chain verification |
| Privilege | Effective-privilege baseline, scoped containment, persistence review and least-privilege recovery evidence |
| Persistence | Exact mechanism/content identity, rollback backup, authorized disable/quarantine receipt and fresh inventory/service health |
| Identity | Provider/principal mapping, scoped session containment, supported credential/MFA recovery and fresh sign-in review |
| Network | Host/exposure identity, management-access-safe rollback, scoped management receipt and unwanted/legitimate connectivity tests |
| Container | Immutable workload/controller/image identity, preserved diagnostics, owner-approved containment and desired-state/service checks |
| Vulnerability | Applicable vendor advisory and package inventory, compatibility/rollback approval, trusted update receipt and fresh version/health verification |
| Execution | Instance-bound triage evidence, protected-target/impact review, approved containment receipt and fresh process/service telemetry |
| File integrity | Content/provenance identity, controlled evidence custody, validated restoration and fresh content/permission/function checks |
| Operational | Exact subsystem/collector diagnosis, bounded owner-approved runbook, actual recovery receipt and fresh service/monitoring health |
| Generic security | Explicit routing into a concrete family above, with the same complete workflow and closure requirements |

## Escalation and changed evidence

Unsafe or blocked work can be escalated to another configured named analyst with an existing ticket, explicit assistance request and follow-up deadline within seven days. Only that named recipient can acknowledge it. Acknowledgement does **not** resolve the incident. This product does not create the external ticket or send a notification.

New incident evidence or a changed playbook invalidates prior approval for further work and closure. Rebaseline with a new artifact and obtain fresh approval. Old checkpoints, approvals and evidence remain in immutable audit snapshots. Unclassified security can be rerouted during rebaseline; an already classified finding cannot silently switch families.

## Security and truthfulness boundaries

Configure at least two distinct named analyst credentials using the existing supported analyst setup. Loopback demo mode can show workflows but cannot create/approve/verify them. Caller-supplied actor headers cannot replace authenticated identities. The backend enforces roles, ordering, revisions, scope and timestamps; disabling a button is not the authorization boundary.

Artifact hashes and ticket references are metadata. The server does not fetch their contents, execute their text, validate an external ticket, or cryptographically prove that an operator repaired the endpoint. Approvers/verifiers must inspect the referenced evidence using their organization's authorized tooling. Do not paste credentials, private keys, raw host secrets or sensitive unreviewed logs into notes. The browser renders notes as text.

Workflow projections are checked against their latest hash-chained audit snapshot. Broken audit integrity or altered projections fail closed. The existing single-process API transaction-serialization requirement remains; this is not a multi-worker/distributed audit service.

## Migration and testing

Run the normal Alembic migration before runtime startup. Revision `0004_guided_recovery` adds `resolution_workflows` without replacing the existing incident, action, identity or audit tables. Back up deployment state through the documented process before upgrading; downgrading removes the new workflow table and is not a data-preserving rollback.

`python scripts/verify_vnext_resolution_coverage.py` now executes the actual recovery/negative-path contracts and requires both recovery and acknowledged-but-unresolved escalation cases for **all 12 categories**, with no skipped cases. Static readiness flags alone cannot pass the gate.

`python scripts/verify_guided_recovery_browser.py --output <new-directory>` exercises independent browser sessions, approval, all checkpoints, independent verification, closure and escalation against a temporary database. It requires built frontend dependencies and Chromium/Playwright. It never starts an endpoint agent or creates an endpoint action. The existing native process verifier remains separate and applies only to the existing evidence-bound process action.

These workflows fulfill the existing contract's guided escalation/recovery option where automatic mutation is unsafe or environment-specific. They do not imply that the original roadmap's automated platform-specific remediation executors have been implemented.
