"""Versioned, non-executable operator recovery contracts.

These workflows record accountable human work. They never fetch artifact URLs,
execute instructions, or claim that an attestation is endpoint verification.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass


@dataclass(frozen=True, slots=True)
class Checkpoint:
    key: str
    title: str
    instruction: str
    acceptance: str
    conditional: bool = False


@dataclass(frozen=True, slots=True)
class Playbook:
    family: str
    title: str
    escalation_team: str
    verification: str
    checkpoints: tuple[Checkpoint, ...]
    version: int = 1

    def public(self) -> dict:
        return asdict(self)

    def digest(self) -> str:
        return hashlib.sha256(json.dumps(self.public(), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def step(key: str, title: str, instruction: str, acceptance: str, conditional: bool = False) -> Checkpoint:
    return Checkpoint(key, title, instruction, acceptance, conditional)


PLAYBOOKS = {p.family: p for p in (
    Playbook("malware", "Malware containment and recovery", "Endpoint security owner",
        "Review fresh trusted scanner/EDR results and new process telemetry; confirm preserved evidence, scoped containment, and approved recovery. Record residual uncertainty instead of declaring an unobserved host clean.", (
        step("preserve", "Preserve and identify", "Use the incident's host and event identifiers to identify the process instance and associated artifact hashes. Preserve diagnostics in an approved evidence store before changing the endpoint.", "Evidence manifest identifies the same host, process instance, artifacts, capture time and chain of custody."),
        step("contain", "Contain the identified activity", "After the recorded approval, use the evidence-bound Response action or an authorized endpoint-security console to stop only the confirmed malicious instance. Do not disable protected system processes or general security controls.", "Approved action/EDR receipt identifies the target and records containment outcome and any failure."),
        step("artifact", "Quarantine associated artifacts", "Where an associated artifact exists, use approved endpoint tooling to quarantine that exact content, retaining a restoration receipt. Otherwise document evidence that no associated artifact was found; do not invent a file target.", "Quarantine receipt includes content identity and reversible custody, or an evidence-backed not-applicable rationale.", True),
        step("recover", "Recover and observe", "Restore only approved known-good components using trusted tooling; run a fresh scan and process observation. Escalate if recovery, integrity or containment cannot be confirmed.", "Recovery/change receipt and fresh health/scan observations are available for independent review."))),
    Playbook("integrity", "Evidence-chain integrity recovery", "Evidence custodian",
        "Independently verify the new trusted chain and preserved original hashes. Confirm the historical break remains disclosed and was not rewritten as a valid original history.", (
        step("preserve", "Preserve the damaged evidence", "Stop writes using the documented service procedure. Preserve a read-only copy of the original evidence database and identity material in an access-controlled incident archive.", "Custody manifest records original hashes, affected interval and authorized custodian; no secret material is pasted into Response."),
        step("baseline", "Establish a trusted recovery source", "Have the evidence custodian validate a known-good backup or explicitly authorize a separate fresh evidence state. Do not silently regenerate keys over signed history.", "Backup provenance or a signed fresh-state decision identifies retained old state and disclosed gaps."),
        step("recover", "Recover without rewriting history", "The custodian restores the approved source or provisions the separate state with the supported procedure. Keep the original damaged archive unchanged.", "Recovery receipt links old and new state identities and documents permissions and rollback."),
        step("observe", "Validate new collection", "Run chain verification and supported service diagnostics on the recovered state. Confirm new observations are stored and retain the original failure record.", "Fresh chain/health output and archive hash comparison demonstrate the recovery boundary."))),
    Playbook("privilege", "Privilege incident recovery", "Identity and endpoint administrators",
        "Compare effective privileges with the approved baseline and review fresh authentication/process telemetry. Confirm unauthorized sessions and persistence are addressed without losing authorized recovery access.", (
        step("identify", "Identify the escalation scope", "Tie the finding to its host and process/account evidence. The authorized administrator establishes the legitimate privilege baseline and preserves audit records.", "Baseline and evidence identify the exact affected principal/process without including credentials."),
        step("contain", "Contain escalation activity", "Use authorized endpoint or identity controls to stop the confirmed escalation path. Preserve break-glass access and do not act on a display name alone.", "Approved containment receipt records the identified target, operator and actual outcome."),
        step("persistence", "Remove unauthorized privilege persistence", "The owner compares persistence and privileged memberships with policy, backs up the identified mechanism and disables only unauthorized entries using supported management tools.", "Before/after policy or persistence evidence records the change, or a supported no-persistence finding.", True),
        step("recover", "Restore least privilege", "Restore the approved access policy and review subsequent sign-ins and process state. Escalate mismatches or uncertain account ownership.", "Fresh effective-permission and telemetry reports match the approved policy."))),
    Playbook("persistence", "Persistence removal and recovery", "Endpoint configuration owner",
        "Compare a fresh persistence inventory with the approved baseline and confirm the affected application still functions. Review artifact custody and any reboot requirement.", (
        step("identify", "Bind the persistence mechanism", "Identify the exact scheduled task, startup entry or service configuration from host evidence, including its backing content and legitimate owner. A label alone is insufficient.", "Inventory receipt identifies the precise mechanism and backing artifact hash or explains its absence."),
        step("backup", "Preserve rollback and evidence", "Export the scoped configuration and preserve associated evidence in approved storage. Establish the owner-approved rollback and recovery access before changing the mechanism.", "Backup hash, custody reference and rollback approval cover only the identified mechanism."),
        step("disable", "Disable the unauthorized mechanism", "The authorized administrator uses supported platform management to disable the confirmed entry and approved endpoint tooling to quarantine associated unauthorized content. Never bulk-delete unrelated persistence.", "Change and quarantine receipts identify exact targets; a legitimate/protected target is escalated, not disabled."),
        step("observe", "Check non-recurrence and function", "Collect a fresh persistence inventory, test the affected service and check for recurrence. Perform a reboot only through the owner's approved maintenance procedure.", "Fresh inventory and service-health results show the expected state and disclose any deferred reboot."))),
    Playbook("identity", "Credential and session recovery", "Identity provider administrator",
        "Independently inspect provider audit records, session revocation, MFA/recovery state and post-recovery sign-ins. No secret value is accepted as evidence.", (
        step("identify", "Verify the account and provider", "The identity owner maps the event to an immutable account/provider identity, verifies authorized access, and preserves sign-in and session evidence.", "Provider/account reference and audit export identify the principal without copying secrets."),
        step("contain", "Contain suspicious sessions", "The administrator uses the provider's supported controls to revoke identified sessions or temporarily restrict the account, preserving approved emergency recovery access.", "Provider receipt identifies the scoped principal/sessions and the containment outcome."),
        step("recover", "Recover authentication", "Use the organization's verified recovery process to rotate affected credentials and review MFA, recovery methods, delegated grants and sessions. Do not put passwords or recovery codes in notes.", "Recovery ticket and provider audit references confirm the reviewed controls without exposing credentials."),
        step("observe", "Verify restored access", "The owner validates intended access and examines fresh sign-in activity for recurrence. Escalate ambiguous account identity or failed revocation.", "Fresh provider audit and owner acceptance support the restored account state."))),
    Playbook("network", "Scoped network containment", "Network and service owners",
        "Review fresh flow/firewall evidence and legitimate-service connectivity tests; verify rollback and management access remain available.", (
        step("identify", "Identify the network exposure", "Tie activity to the affected host, owning process or service and time-bounded network evidence. Have the owner distinguish approved exposure from unauthorized traffic.", "Flow/listener/process evidence identifies the scoped exposure and owner-approved baseline."),
        step("rollback", "Protect connectivity and rollback", "Record out-of-band recovery, management exclusions and the exact approved firewall/service change. Do not infer a block target from an unverified address string.", "Reviewed change plan includes bounded scope, recovery access and reversible rollback."),
        step("contain", "Apply the approved containment", "The owner uses a managed firewall, endpoint console or supported service control to restrict only the confirmed exposure; use evidence-bound process containment only when appropriate.", "Management-system receipt identifies the applied rule/service/instance and actual result."),
        step("observe", "Test malicious and legitimate paths", "Collect fresh flows/listeners and test both the unwanted path and required business/management connectivity. Roll back or escalate an adverse result.", "Independent test artifacts document blocked exposure and preserved required connectivity."))),
    Playbook("container", "Container workload containment", "Orchestrator owner",
        "Verify immutable workload/image identity, desired and actual state, fresh runtime telemetry, and service health in the target namespace.", (
        step("identify", "Identify the exact workload", "The orchestrator owner identifies cluster, namespace, controller and immutable workload UID/image digest. Do not stop a workload based only on a reused container name.", "Inventory reference identifies the exact controller, workload and content digest."),
        step("preserve", "Preserve diagnostics and rollback", "Preserve workload logs and configuration, record the approved image/configuration baseline and rollback plan, and assess dependent services.", "Evidence manifest and approved rollback identify affected dependencies without exposing credentials."),
        step("contain", "Contain through the owning controller", "The owner isolates or stops the scoped workload through the supported orchestrator/controller and deploys only an approved replacement when needed.", "Orchestrator change receipt records targeted UID/controller and replacement provenance."),
        step("observe", "Confirm desired state and recovery", "Compare desired/actual state, image digests and fresh security/service telemetry. Escalate uncontrolled restart or unexpected changes outside the target.", "Fresh controller and service reports confirm scoped containment and accepted recovery."))),
    Playbook("vulnerability", "Verified package remediation", "Package and application owner",
        "Check the installed package/version against the applicable vendor advisory and a fresh inventory or scanner result. A successful install command alone is not proof of remediation.", (
        step("identify", "Validate package and advisory", "Bind the finding to an exact installed package/version on the host. The owner validates the applicable vendor advisory and supported fixed version/source.", "Inventory and authoritative advisory references establish applicability and intended fixed version."),
        step("plan", "Approve compatibility and rollback", "The owner checks application/version constraints, tests the proposed update in a safe environment and records backup/rollback and maintenance approval.", "Compatibility test and change-ticket references identify an approved constrained upgrade path."),
        step("update", "Use the supported package manager", "The owner applies the reviewed update using the host's trusted package manager or vendor process. Do not run an unverified downloaded script or an unconstrained bulk upgrade.", "Package-manager/vendor receipt records original/new versions, verified source and actual result."),
        step("observe", "Confirm remediation and health", "Collect fresh installed-version and vulnerability evidence and test dependent application health. Document any restart still required; escalate when the fixed version is unavailable.", "Post-change inventory/scan and health artifacts support the claimed fix with deferred work disclosed."))),
    Playbook("execution", "Evidence-bound process containment", "Endpoint security owner",
        "Verify the original process instance exited, new diagnostic telemetry is available and the incident evidence was retained. PID disappearance alone is insufficient.", (
        step("identify", "Preserve process-instance evidence", "Collect the approved triage bundle and retain its incident/host/agent-bound handle, process creation identity and supporting evidence.", "Triage receipt binds the original instance and provenance without accepting arbitrary PID parameters."),
        step("approve", "Review protection and impact", "The owner checks that the process is not a protected system or Response-lineage process and records affected-service impact and an approved recovery plan.", "Risk/protection review identifies an allowed target and a controlled recovery path."),
        step("contain", "Contain only the bound instance", "After approval, use the existing evidence-bound Response action or authorized endpoint tooling. A stale handle or protected-target refusal requires fresh triage/escalation, not a PID fallback.", "Signed action result or authorized-tool receipt confirms the bound original instance and exit outcome."),
        step("observe", "Check recovery and recurrence", "Collect fresh process and service telemetry, preserve the incident audit chain, and escalate any recurrence or uncertain containment.", "Fresh observations and audit-verification artifacts support scoped containment and service recovery."))),
    Playbook("file_integrity", "File provenance and recovery", "Data and endpoint owners",
        "Compare recovered content and permissions with the trusted baseline and verify preserved evidence/quarantine custody. A filename or modified time alone is not sufficient identity.", (
        step("identify", "Identify exact content and owner", "The authorized owner identifies content hash, filesystem identity, trust baseline and protected-path implications from the incident's host evidence.", "Content/provenance manifest distinguishes trusted baseline from suspect bytes and binds the correct host."),
        step("preserve", "Preserve suspect content safely", "Use approved endpoint/evidence tooling to quarantine or preserve the exact suspect content with controlled custody and reversible recovery; do not follow an unverified link or overwrite the evidence.", "Custody/quarantine receipt records original content hash, protected handling and recovery reference."),
        step("restore", "Restore validated content", "The owner restores an approved, provenance-validated version through supported tooling and preserves the prior suspect artifact. Escalate protected-system or uncertain-origin files.", "Restoration/change receipt identifies validated source, resulting content and permissions."),
        step("observe", "Verify integrity and functionality", "Collect fresh content/permission verification and application checks. Document unsupported or inaccessible targets instead of treating a failed read as success.", "Fresh integrity and functionality artifacts match the approved baseline."))),
    Playbook("operational", "Bounded operational recovery", "Affected service owner",
        "Independently verify current service/resource health and collector freshness; ensure missing observations are not interpreted as healthy state.", (
        step("identify", "Identify the affected subsystem", "Use event evidence and supported diagnostics to identify the exact service/resource, symptom and owner. Distinguish a failed collector from an actual absence of problems.", "Diagnostic and owner references establish the affected component and observable failure."),
        step("plan", "Approve a bounded recovery runbook", "The owner selects a supported runbook with a specific scope, dependencies, recovery access and rollback. Unidentified or critical-system targets are escalated.", "Runbook/change approval records the exact component, risks, acceptance tests and rollback."),
        step("recover", "Perform the scoped recovery", "The authorized owner executes the approved recovery through supported management tools. Record failures and partial outcomes; do not claim that the demo JSON restart repaired an OS service.", "Management/change receipt identifies the actual component, intervention and result."),
        step("observe", "Confirm service and monitoring health", "Run fresh service/resource checks and confirm collector freshness and dependent functionality. Escalate when recovery cannot be confirmed.", "Fresh health, telemetry and dependency checks meet the approved acceptance criteria."))),
)}

SOURCE_CATEGORIES = frozenset(PLAYBOOKS) | {"security"}


def catalog() -> dict:
    return {
        "version": 1,
        "mode": "human_executed_evidence_attested",
        "endpoint_execution": False,
        "artifact_contents_verified_by_server": False,
        "security_fallback": "An unclassified security finding must be routed to one concrete family before a workflow can start.",
        "playbooks": [p.public() | {"digest": p.digest()} for p in PLAYBOOKS.values()],
    }
