from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ResolutionCoverage:
    category: str
    resolution_mode: str
    primary_outcome: str
    release_ready: bool
    rationale: str


# A release requires a concrete, tested resolution path for every category.
# These paths are operator-executed recovery with evidence, independent approval
# and independent attestation; they are NOT universal automatic remediation.
# The executable gate additionally runs the real API/state-machine contracts for
# all categories and refuses skipped/missing cases. The original outcomes below
# are retained. Generic security must route to a concrete family before closure.
RESOLUTION_COVERAGE: dict[str, ResolutionCoverage] = {
    'malware': ResolutionCoverage('malware', 'guided_human_recovery',
        'terminate an evidence-bound malicious process and quarantine evidence-bound artifacts when present',
        True, 'Versioned malware operator playbook has four evidence-backed recovery checkpoints, independent named approval and verification, scoped escalation, and fail-closed closure tests. Artifact contents and endpoint outcomes are attested by humans, not verified by the server.'),
    'integrity': ResolutionCoverage('integrity', 'guided_human_recovery',
        'preserve trusted evidence, replace corrupted evidence state, and re-establish chain health',
        True, 'Versioned integrity operator playbook has four evidence-backed recovery checkpoints, independent named approval and verification, scoped escalation, and fail-closed closure tests. Artifact contents and endpoint outcomes are attested by humans, not verified by the server.'),
    'privilege': ResolutionCoverage('privilege', 'guided_human_recovery',
        'terminate an evidence-bound escalation process and revoke unsafe persistence when present',
        True, 'Versioned privilege operator playbook has four evidence-backed recovery checkpoints, independent named approval and verification, scoped escalation, and fail-closed closure tests. Artifact contents and endpoint outcomes are attested by humans, not verified by the server.'),
    'persistence': ResolutionCoverage('persistence', 'guided_human_recovery',
        'disable the evidence-bound persistence mechanism and quarantine its backing artifact',
        True, 'Versioned persistence operator playbook has four evidence-backed recovery checkpoints, independent named approval and verification, scoped escalation, and fail-closed closure tests. Artifact contents and endpoint outcomes are attested by humans, not verified by the server.'),
    'identity': ResolutionCoverage('identity', 'guided_human_recovery',
        'contain suspicious account activity and guide credential/session recovery',
        True, 'Versioned identity operator playbook has four evidence-backed recovery checkpoints, independent named approval and verification, scoped escalation, and fail-closed closure tests. Artifact contents and endpoint outcomes are attested by humans, not verified by the server.'),
    'network': ResolutionCoverage('network', 'guided_human_recovery',
        'terminate the evidence-bound owning process and/or block evidence-bound malicious network activity',
        True, 'Versioned network operator playbook has four evidence-backed recovery checkpoints, independent named approval and verification, scoped escalation, and fail-closed closure tests. Artifact contents and endpoint outcomes are attested by humans, not verified by the server.'),
    'container': ResolutionCoverage('container', 'guided_human_recovery',
        'stop/isolate the evidence-bound container or workload and preserve diagnostics',
        True, 'Versioned container operator playbook has four evidence-backed recovery checkpoints, independent named approval and verification, scoped escalation, and fail-closed closure tests. Artifact contents and endpoint outcomes are attested by humans, not verified by the server.'),
    'vulnerability': ResolutionCoverage('vulnerability', 'guided_human_recovery',
        'produce a verified patch/update path and confirm the vulnerable package is remediated',
        True, 'Versioned vulnerability operator playbook has four evidence-backed recovery checkpoints, independent named approval and verification, scoped escalation, and fail-closed closure tests. Artifact contents and endpoint outcomes are attested by humans, not verified by the server.'),
    'execution': ResolutionCoverage('execution', 'guided_human_recovery',
        'terminate an evidence-bound malicious process and preserve its incident evidence',
        True, 'Versioned execution operator playbook has four evidence-backed recovery checkpoints, independent named approval and verification, scoped escalation, and fail-closed closure tests. Artifact contents and endpoint outcomes are attested by humans, not verified by the server.'),
    'file_integrity': ResolutionCoverage('file_integrity', 'guided_human_recovery',
        'quarantine or restore the evidence-bound file after provenance validation',
        True, 'Versioned file_integrity operator playbook has four evidence-backed recovery checkpoints, independent named approval and verification, scoped escalation, and fail-closed closure tests. Artifact contents and endpoint outcomes are attested by humans, not verified by the server.'),
    'operational': ResolutionCoverage('operational', 'guided_human_recovery',
        'recover the affected service/resource with a bounded typed action or guided operator step',
        True, 'Versioned operational operator playbook has four evidence-backed recovery checkpoints, independent named approval and verification, scoped escalation, and fail-closed closure tests. Artifact contents and endpoint outcomes are attested by humans, not verified by the server.'),
    'security': ResolutionCoverage('security', 'evidence_routed_guided_recovery',
        'complete guided triage and route to the concrete resolution family identified by evidence',
        True, 'Unclassified events must select a concrete recovery family; category/host provenance, independent approval, evidence checkpoints, escalation acknowledgement and independently attested closure are tested.'),
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
