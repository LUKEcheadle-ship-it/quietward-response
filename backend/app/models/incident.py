INCIDENT_STATUSES = {"new", "investigating", "contained", "resolved", "dismissed"}


def incident_title(category: str | None, hostname: str, summary: str) -> str:
    titles = {
        "persistence": f"Potential persistence activity on {hostname}",
        "network": f"Unexpected network exposure on {hostname}",
        "operational": f"Operational degradation on {hostname}",
        "malware": f"Potential malicious activity on {hostname}",
        "identity": f"Identity-related activity on {hostname}",
    }
    return titles.get(category or "", summary[:255])
