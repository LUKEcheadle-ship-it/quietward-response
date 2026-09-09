from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ResolutionCoverage:
    category: str
    resolution_mode: str
    primary_outcome: str
    release_ready: bool
    rationale: str


# This matrix is intentionally release-blocking. A category may be marked ready
# only when Response has a concrete, tested resolution path for it. "Resolution"
# can be a safe automated containment/remediation action or a deliberately human-
# executed workflow when a universal automatic mutation would be unsafe.
#
# The combined QuietWard + Response vNext release MUST NOT ship while any entry is
# release_ready=False.
RESOLUTION_COVERAGE: dict[str, ResolutionCoverage] = {
    "malware": ResolutionCoverage(
        "malware",
        "planned_containment",
        "quarantine observed artifact and/or terminate evidence-bound process",
        False,
        "Requires evidence-bound file/process handles and execution-time revalidation.",
    ),
    "integrity": ResolutionCoverage(
        "integrity",
        "planned_recovery",
        "preserve trusted evidence, replace corrupted evidence state, and re-establish chain health",
        False,
        "Must preserve forensic integrity and cannot silently rewrite evidence history.",
    ),
    "privilege": ResolutionCoverage(
        "privilege",
        "planned_containment",
        "terminate evidence-bound escalation process and revoke unsafe persistence when present",
        False,
        "Needs process identity revalidation and protected-process deny rules.",
    ),
    "persistence": ResolutionCoverage(
        "persistence",
        "planned_remediation",
        "disable the evidence-bound persistence mechanism and quarantine its backing artifact",
        False,
        "Needs typed persistence identities rather than arbitrary registry/task/service names.",
    ),
    "identity": ResolutionCoverage(
        "identity",
        "planned_guided_resolution",
        "contain suspicious account activity and guide credential/session recovery",
        False,
        "Account lock/reset is environment-specific and must not be inferred from a generic username.",
    ),
    "network": ResolutionCoverage(
        "network",
        "planned_containment",
        "block or isolate evidence-bound malicious network activity",
        False,
        "Needs locally resolved network/process evidence handles and safe rollback.",
    ),
    "container": ResolutionCoverage(
        "container",
        "planned_containment",
        "stop/isolate the evidence-bound container or workload and preserve diagnostics",
        False,
        "Needs a typed local workload identity and platform-specific executor.",
    ),
    "vulnerability": ResolutionCoverage(
        "vulnerability",
        "planned_guided_resolution",
        "produce a verified patch/update path and confirm the vulnerable package is remediated",
        False,
        "Blind package upgrades are unsafe; remediation must respect the host package manager and version constraints.",
    ),
    "execution": ResolutionCoverage(
        "execution",
        "planned_containment",
        "terminate an evidence-bound malicious process and preserve its incident evidence",
        False,
        "Needs durable process evidence handles and execution-time identity checks.",
    ),
    "file_integrity": ResolutionCoverage(
        "file_integrity",
        "planned_recovery",
        "quarantine or restore the evidence-bound file after provenance validation",
        False,
        "Needs content identity, protected-path rules, quarantine storage, and reversible restore.",
    ),
    "operational": ResolutionCoverage(
        "operational",
        "planned_guided_resolution",
        "recover the affected service/resource with a bounded typed action or guided operator step",
        False,
        "Operational findings span multiple subsystems and require explicit typed recovery actions.",
    ),
    "security": ResolutionCoverage(
        "security",
        "planned_guided_resolution",
        "complete guided triage and route to the concrete resolution family identified by evidence",
        False,
        "The generic fallback must resolve into a specific response family before closure.",
    ),
}


def unresolved_categories() -> list[str]:
    return sorted(
        category
        for category, coverage in RESOLUTION_COVERAGE.items()
        if not coverage.release_ready
    )


def release_resolution_ready() -> bool:
    return not unresolved_categories()


def public_resolution_coverage() -> list[dict[str, object]]:
    return [
        {
            "category": item.category,
            "resolution_mode": item.resolution_mode,
            "primary_outcome": item.primary_outcome,
            "release_ready": item.release_ready,
            "rationale": item.rationale,
        }
        for item in RESOLUTION_COVERAGE.values()
    ]
