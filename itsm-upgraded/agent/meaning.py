"""
Meaning layer — canonical entity resolution for incident management.

Extends the change management meaning layer with incident-specific entities:
  - Incident tickets
  - Known errors / Knowledge Base
  - SLA policies

The same principle applies: resolve ambiguous references into canonical,
typed entities before the agent reasons about them.
"""
import json
from pathlib import Path
from typing import Optional

DATA_DIR = Path(__file__).parent.parent / "data"


def _load(filename: str) -> dict | list:
    with open(DATA_DIR / filename) as f:
        return json.load(f)


# ---------- Service resolution (shared with change layer) ----------

def resolve_service(reference: str) -> Optional[dict]:
    """
    Resolve a service reference (by id or name) to the canonical Service entity.
    Returns None if unresolvable — that is a deliberate signal, not an error.
    """
    services = _load("services.json")["services"]
    ref = reference.strip().lower()
    for svc in services:
        if svc["id"].lower() == ref or svc["name"].lower() == ref:
            return svc
    return None


def all_services() -> list[dict]:
    return _load("services.json")["services"]


# ---------- Incident ticket resolution ----------

def resolve_incident_ticket(ticket_id: str) -> Optional[dict]:
    """
    Resolve an incident ticket ID to its canonical representation.
    Returns None if unknown — agent must refuse to classify unresolvable tickets.
    """
    tickets = _load("incident_tickets.json")["incident_tickets"]
    for t in tickets:
        if t["id"] == ticket_id:
            return t
    return None


def all_incident_tickets() -> list[dict]:
    return _load("incident_tickets.json")["incident_tickets"]


# ---------- Known Error / Knowledge Base resolution ----------

def all_known_errors() -> list[dict]:
    return _load("known_errors.json")["known_errors"]


def resolve_known_error(ke_id: str) -> Optional[dict]:
    for ke in all_known_errors():
        if ke["id"] == ke_id:
            return ke
    return None


# ---------- SLA policy resolution ----------

def resolve_sla(priority: str) -> Optional[dict]:
    """Return the SLA definition for a given priority (P1-P4)."""
    policy = _load("sla_policy.json")
    return policy["priority_definitions"].get(priority)


def all_escalation_rules() -> list[dict]:
    return _load("sla_policy.json")["escalation_rules"]


def on_call_for(team: str) -> Optional[str]:
    schedule = _load("sla_policy.json")["on_call_schedule"]
    return schedule.get(team)
