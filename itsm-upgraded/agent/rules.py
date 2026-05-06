"""
Rules layer — incident management policy-as-code.

Rules are layered, exactly like the change management layer:
  - CLASSIFICATION rules (defeasible) — determine initial priority
  - OVERRIDE rules (non-negotiable) — escalate priority regardless of initial assessment
  - ESCALATION rules — determine who to notify and when

Phase 1 gaps addressed:
  - Hard vs. soft dependency check in blast_radius_escalation (PM conflict):
    only HARD upstream dependencies trigger automatic escalation. Soft
    dependencies are surfaced as informational context in the pre-brief.
  - KB match uncertainty language (FM-2): scores in the "uncertain" band
    (KB_MATCH_UNCERTAIN_FLOOR to KB_MATCH_UNCERTAIN_CEILING) are labelled
    "uncertain" with explicit hedging language, not silently promoted to
    "probable". An engineer following a wrong workaround is worse than
    no workaround.
  - Notification acknowledgment tracking structure (FM-4): mandatory_notifications
    now carries an `ack_required` field and `ack_deadline_minutes` so the
    dispatch layer can implement two-phase commit.
  - DORA False Negative Rate = 0%: the DORA override is hardened — a ticket
    that declares P3 but touches a DORA service is still forced to P1.

In production: Rego policies evaluated by OPA.
Here: Python functions — the structure is what matters.
"""
from datetime import datetime, timezone
from agent import config, meaning

# Symptom → KB keyword scoring threshold
KB_MATCH_THRESHOLD = config.KB_MATCH_THRESHOLD
KB_MATCH_UNCERTAIN_FLOOR = config.KB_MATCH_UNCERTAIN_FLOOR
KB_MATCH_UNCERTAIN_CEILING = config.KB_MATCH_UNCERTAIN_CEILING


# ── Priority classification ────────────────────────────────────────────────────

def classify_priority(ticket: dict, service: dict) -> dict:
    """
    Classify a ticket's priority based on impact and service tier.

    Returns a priority string (P1–P4) with a reasoning trace.
    This result is DEFEASIBLE — DORA and other override rules may escalate it.
    """
    impact = ticket.get("impact", "unknown")
    tier = service.get("tier", "unknown")

    matrix = {
        ("full_outage",        "critical"):      "P1",
        ("full_outage",        "standard"):      "P2",
        ("full_outage",        "non-critical"):  "P2",
        ("partial_degradation","critical"):      "P2",
        ("partial_degradation","standard"):      "P3",
        ("partial_degradation","non-critical"):  "P3",
        ("minor_degradation",  "critical"):      "P3",
        ("minor_degradation",  "standard"):      "P3",
        ("minor_degradation",  "non-critical"):  "P4",
        ("unknown",            "critical"):      "P2",
        ("unknown",            "standard"):      "P3",
        ("unknown",            "non-critical"):  "P3",
    }

    priority = matrix.get((impact, tier), "P3")
    return {
        "priority": priority,
        "reason": f"Impact '{impact}' on tier '{tier}' service → {priority} per impact-tier matrix.",
        "defeasible": True,
    }


# ── Override rules ─────────────────────────────────────────────────────────────

def check_dora_escalation(service: dict, priority: str) -> dict:
    """
    Non-negotiable: any incident on a DORA-regulated service is minimum P1.
    Regulatory accountability cannot be traded for operational convenience.
    DORA False Negative Rate must be 0% — this rule fires unconditionally.
    """
    if service.get("dora_regulated", False):
        escalated = priority != "P1"
        return {
            "override": True,
            "rule": "DORA-INC-ESCALATION",
            "original_priority": priority,
            "forced_priority": "P1",
            "reason": (
                f"Service {service['id']} ({service['name']}) is DORA-regulated. "
                "All incidents on DORA-regulated services are mandatory P1. "
                "Compliance officer must be notified within "
                f"{config.COMPLIANCE_NOTIFICATION_DEADLINE_MINUTES} minutes."
            ),
            "escalated": escalated,
        }
    return {"override": False}


def check_blast_radius_escalation(blast: dict, priority: str) -> dict:
    """
    Escalate only on HARD upstream dependencies to DORA or critical services.

    Phase 1 PM conflict fix: soft upstream links do NOT trigger escalation.
    A notification-service outage that causes payment-api to degrade gracefully
    (soft dependency) is surfaced as context — not as an automatic P1.
    Only hard dependencies, where payment would actually fail, escalate.
    """
    # Only consider hard upstream dependencies for escalation
    hard_upstream = [s for s in blast.get("upstream_impacted", [])
                     if s.get("dependency_type", "hard") == "hard"]

    dora_hard = [s for s in hard_upstream if s["dora_regulated"]]
    critical_hard = [s for s in hard_upstream if s["tier"] == "critical"]

    # Soft upstream — informational only (no escalation triggered here)
    soft_upstream = [s for s in blast.get("upstream_impacted", [])
                     if s.get("dependency_type") == "soft"]

    result: dict = {}

    if dora_hard:
        forced = "P1" if priority in ("P3", "P4") else priority
        result = {
            "override": True,
            "rule": "BLAST-RADIUS-DORA-HARD-UPSTREAM",
            "forced_priority": forced,
            "reason": (
                f"Hard upstream DORA-regulated services affected: "
                f"{[s['name'] for s in dora_hard]}. Escalating."
            ),
            "escalated": forced != priority,
        }
    elif critical_hard and priority in ("P3", "P4"):
        result = {
            "override": True,
            "rule": "BLAST-RADIUS-CRITICAL-HARD-UPSTREAM",
            "forced_priority": "P2",
            "reason": (
                f"Hard upstream critical services at risk: "
                f"{[s['name'] for s in critical_hard]}. Escalating to P2."
            ),
            "escalated": True,
        }
    else:
        result = {"override": False}

    # Always attach soft-dependency informational context even when no escalation fires
    if soft_upstream:
        result["soft_upstream_context"] = {
            "services": [s["name"] for s in soft_upstream],
            "note": (
                "These upstream services have a soft dependency on the affected service. "
                "They may degrade gracefully. No automatic escalation — verify actual impact."
            ),
        }

    return result


# ── Knowledge Base matching ────────────────────────────────────────────────────

def match_known_error(ticket: dict) -> dict:
    """
    Match incident symptoms against the known error KB.

    Phase 1 FM-2 fix: three confidence bands instead of a binary threshold:
      - score >= KB_MATCH_THRESHOLD     → "probable" (or "confirmed" after history check)
      - KB_MATCH_UNCERTAIN_FLOOR <= score < KB_MATCH_THRESHOLD → "uncertain"
        Surfaced with explicit hedging: "KB article partially matches.
        Verify before following — root cause may differ."
      - score < KB_MATCH_UNCERTAIN_FLOOR → no match

    Production: vector similarity search over KB embeddings.
    Here: keyword overlap scoring — the design point (score → threshold → act)
    is what matters, not the scoring function.
    """
    symptoms = [s.lower() for s in ticket.get("symptoms", [])]
    title_words = ticket.get("title", "").lower().split()
    all_terms = set(symptoms + title_words)

    known_errors = meaning.all_known_errors()
    best = {"ke_id": None, "score": 0.0, "known_error": None, "confidence_band": "no_match"}

    for ke in known_errors:
        ke_keywords = [kw.lower() for kw in ke.get("symptoms", [])]
        if not ke_keywords:
            continue
        hits = sum(1 for kw in ke_keywords if any(kw in term or term in kw for term in all_terms))
        score = hits / len(ke_keywords)
        if score > best["score"]:
            if score >= KB_MATCH_THRESHOLD:
                band = "probable"
            elif score >= KB_MATCH_UNCERTAIN_FLOOR:
                band = "uncertain"
            else:
                band = "no_match"
            best = {
                "ke_id": ke["id"],
                "score": round(score, 3),
                "known_error": ke,
                "confidence_band": band,
            }

    return best


# ── SLA assessment ─────────────────────────────────────────────────────────────

def assess_sla_breach(ticket: dict, priority: str) -> dict:
    """
    Determine if an SLA breach is imminent or already occurred.
    """
    sla = meaning.resolve_sla(priority)
    if not sla:
        return {"sla_assessed": False, "reason": f"No SLA definition found for {priority}"}

    now = datetime.now(timezone.utc)
    reported_at = datetime.fromisoformat(ticket["reported_at"].replace("Z", "+00:00"))
    elapsed_minutes = (now - reported_at).total_seconds() / 60

    response_target = sla["initial_response_minutes"]
    resolution_target = sla["resolution_target_minutes"]

    response_breached = elapsed_minutes > response_target
    resolution_breached = elapsed_minutes > resolution_target
    response_pct = min(100, round((elapsed_minutes / response_target) * 100, 1))

    return {
        "sla_assessed": True,
        "priority": priority,
        "elapsed_minutes": round(elapsed_minutes, 1),
        "response_target_minutes": response_target,
        "resolution_target_minutes": resolution_target,
        "response_breached": response_breached,
        "resolution_breached": resolution_breached,
        "response_sla_pct_used": response_pct,
        "requires_war_room": sla["requires_war_room"],
        "notify_stakeholders": sla["notify_stakeholders"],
        "escalation_path": sla["escalation_path"],
    }


# ── Escalation path ────────────────────────────────────────────────────────────

def determine_escalation(service: dict, priority: str, sla_status: dict) -> dict:
    """
    Determine who to notify and how urgently.

    Phase 1 FM-4 fix: mandatory_notifications now carries `ack_required: True`
    and `ack_deadline_minutes` so the dispatch layer can implement a two-phase
    commit pattern (dispatch + acknowledgment). Unacknowledged notifications
    after the timeout must trigger a secondary human alert.
    """
    on_call = meaning.on_call_for(service.get("owner_team", ""))
    sla = meaning.resolve_sla(priority)
    escalation_path = sla["escalation_path"] if sla else ["on-call-engineer"]

    notifications = []
    if service.get("dora_regulated"):
        notifications.append({
            "recipient": "compliance-officer",
            "deadline_minutes": config.COMPLIANCE_NOTIFICATION_DEADLINE_MINUTES,
            "reason": "DORA regulatory requirement — mandatory P1 compliance notification",
            "mandatory": True,
            "ack_required": True,
            "ack_deadline_minutes": config.NOTIFICATION_ACK_TIMEOUT_MINUTES,
            "ack_fallback": "secondary-compliance-contact",
        })
    if sla and sla.get("notify_stakeholders"):
        notifications.append({
            "recipient": "stakeholder-distribution-list",
            "deadline_minutes": 15,
            "reason": f"{priority} incident — stakeholder notification policy",
            "mandatory": True,
            "ack_required": False,
        })
    if sla_status.get("response_breached"):
        next_escalation = escalation_path[1] if len(escalation_path) > 1 else escalation_path[0]
        notifications.append({
            "recipient": next_escalation,
            "deadline_minutes": 0,
            "reason": "SLA response breach — immediate escalation triggered",
            "mandatory": True,
            "ack_required": True,
            "ack_deadline_minutes": 2,
            "ack_fallback": escalation_path[-1],
        })

    return {
        "on_call_engineer": on_call,
        "owner_team": service.get("owner_team"),
        "escalation_path": escalation_path,
        "mandatory_notifications": notifications,
        "requires_war_room": sla.get("requires_war_room", False) if sla else False,
    }


# ── Consolidated evaluation ────────────────────────────────────────────────────

def evaluate_all(ticket: dict, service: dict, blast: dict) -> dict:
    """
    Run every rule for this ticket/service/blast triple and return a consolidated result.

    Rule order (order of firmness):
      1. Declared priority override (human submitter raised priority)
      2. DORA escalation (regulatory, non-negotiable — always fires for DORA services)
      3. Blast radius escalation (hard dependencies only — Phase 1 PM conflict fix)
      4. SLA assessment
      5. KB match
      6. Escalation path determination
    """
    priority_result = classify_priority(ticket, service)
    effective_priority = priority_result["priority"]

    # Human-declared priority: only accept if it's more urgent (lower number)
    declared = ticket.get("priority_declared")
    if declared:
        declared_num = int(declared[1])
        effective_num = int(effective_priority[1])
        if declared_num < effective_num:
            effective_priority = declared
            priority_result["reason"] += f" (Overridden by submitter-declared priority {declared}.)"

    # DORA override — non-negotiable, runs AFTER declared priority check
    dora_override = check_dora_escalation(service, effective_priority)
    if dora_override["override"] and dora_override.get("escalated"):
        effective_priority = dora_override["forced_priority"]

    # Blast radius (hard deps only)
    blast_override = check_blast_radius_escalation(blast, effective_priority)
    if blast_override.get("override") and blast_override.get("escalated"):
        effective_priority = blast_override["forced_priority"]

    kb_match = match_known_error(ticket)
    sla_status = assess_sla_breach(ticket, effective_priority)
    escalation = determine_escalation(service, effective_priority, sla_status)

    return {
        "effective_priority": effective_priority,
        "priority_classification": priority_result,
        "dora_override": dora_override,
        "blast_radius_override": blast_override,
        "kb_match": kb_match,
        "sla_status": sla_status,
        "escalation": escalation,
    }
