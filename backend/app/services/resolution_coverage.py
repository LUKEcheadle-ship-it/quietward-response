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
        "containment_in_qualification",
        "terminate an evidence-bound malicious process and quarantine evidence-bound artifacts when present",
        False,
        "Evidence-bound process termination is implemented but not yet locally/jointly qualified; file quarantine remains incomplete.",
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
        "containment_in_qualification",
        "terminate an evidence-bound escalation process and revoke unsafe persistence when present",
        False,
        "Evidence-bound process termination is implemented but qualification and persistence remediation remain incomplete.",
    ),
    "persistence": ResolutionCoverage(
        "persistence",
        "partial_containment",
        "disable the evidence-bound persistence mechanism and quarantine its backing artifact",
        False,
        "Process containment exists; typed persistence identities and backing-artifact quarantine are still required.",
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
        "partial_containment",
        "terminate the evidence-bound owning process and/or block evidence-bound malicious network activity",
        False,
        "Owning-process containment is being enabled; direct network containment and safe rollback remain incomplete.",
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
        "containment_in_qualification",
        "terminate an evidence-bound malicious process and preserve its incident evidence",
        False,
        "Implementation exists; local and joint qualification must pass before this category becomes release-ready.",
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
