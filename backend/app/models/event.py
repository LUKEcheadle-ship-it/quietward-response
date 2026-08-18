from enum import StrEnum


class Severity(StrEnum):
    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


SEVERITY_RANK = {
    Severity.informational.value: 0,
    Severity.low.value: 1,
    Severity.medium.value: 2,
    Severity.high.value: 3,
    Severity.critical.value: 4,
}


def highest_severity(*values: str) -> str:
    return max(values, key=lambda value: SEVERITY_RANK.get(value, -1))
