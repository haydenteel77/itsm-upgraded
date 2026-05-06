"""
History layer — temporal recall for incident management.

Answers: "has this failure pattern happened before, and what was done?"

The history layer feeds two things:
  1. Pattern confirmation — does our KB match align with historical resolutions?
  2. MTTR benchmark — what is the historical resolution time for similar incidents?

The agent uses this to build a richer pre-brief for the on-call engineer,
not to make the classification decision (that belongs to the rules layer).
"""
import json
from pathlib import Path
from agent import relationships

DATA_DIR = Path(__file__).parent.parent / "data"


def _load_incidents() -> list[dict]:
    with open(DATA_DIR / "incidents.json") as f:
        return json.load(f)["incidents"]


def prior_incidents_for_service(service_id: str, k: int = 10) -> dict:
    """
    Return the k most recent resolved incidents for this service.
    Summarizes: count, avg MTTR, any linked known errors.

    Used by the harness to enrich the on-call brief.
    """
    incidents = _load_incidents()
    matches = [
        i for i in incidents
        if service_id in i.get("affected_services", [])
        and i["status"] == "resolved"
    ]
    matches.sort(key=lambda i: i.get("resolved_at", ""), reverse=True)
    matches = matches[:k]

    resolution_times = [i["resolution_time_minutes"] for i in matches if i.get("resolution_time_minutes")]
    avg_mttr = round(sum(resolution_times) / len(resolution_times), 1) if resolution_times else None

    known_errors_seen = list({i["linked_known_error"] for i in matches if i.get("linked_known_error")})

    return {
        "found": len(matches),
        "avg_mttr_minutes": avg_mttr,
        "linked_known_errors": known_errors_seen,
        "most_recent": matches[0] if matches else None,
        "incidents": [i["id"] for i in matches],
    }


def validate_kb_match(ke_id: str, service_id: str) -> dict:
    """
    Check historical incidents to see if the KB match has been confirmed
    as the resolution for this service before.

    Returns a confidence boost — if the same KB article has been the
    resolution for this service in the past, the agent should surface it
    more prominently in the on-call brief.
    """
    incidents = _load_incidents()
    confirmed = [
        i for i in incidents
        if i.get("linked_known_error") == ke_id
        and service_id in i.get("affected_services", [])
        and i["status"] == "resolved"
    ]
    return {
        "confirmed_historically": len(confirmed) > 0,
        "confirmation_count": len(confirmed),
        "last_confirmed": confirmed[0]["resolved_at"] if confirmed else None,
    }


def active_incidents_for_service(service_id: str) -> list[dict]:
    """
    Are there currently active incidents on this service?
    Used to detect incident storms and avoid duplicate triage.
    """
    incidents = _load_incidents()
    return [
        {"id": i["id"], "title": i["title"], "priority": i["priority"], "reported_at": i["reported_at"]}
        for i in incidents
        if service_id in i.get("affected_services", [])
        and i["status"] == "active"
    ]
