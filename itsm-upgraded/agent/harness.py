"""
Incident Management Agent harness — the reasoning loop.

Walks the five-step loop adapted for incident management:

  01 Resolve    — meaning layer resolves ticket to canonical service/CI entities
  02 Traverse   — relationships layer maps blast radius (upstream + downstream)
  03 Evaluate   — rules layer runs: priority classification, DORA override,
                  blast-radius escalation, KB match, SLA assessment
  04 Recall     — history layer retrieves prior incidents + MTTR benchmarks,
                  validates KB match against confirmed resolutions
  05 Act        — triage decision: priority, route, on-call assignment,
                  workaround, SLA breach warning — all with a full trace

Phase 1 gaps addressed:
  - Per-tier confidence and freshness thresholds via config and relationships.
    (FM-3: flat threshold caused critical DORA services to be refused.)
  - Multi-CI refusal ladder: ALL affected CIs evaluated, not just max-confidence.
    A stale sibling CI triggers refusal even if another CI maps cleanly.
    (Phase 1 criterion: "Refusal Rate on Stale CMDB = 100%")
  - triggered_by field on audit log entries. (Phase 1 trigger definition gap.)
  - CMDB refresh auto-ticket filed on refusal. (FM-1 mitigation: refusal without
    remediation creates operational dead ends.)
  - Kill-switch: when config.KILL_SWITCH is True, every ticket is refused.
  - Audit log: every decision appended to config.AUDIT_LOG_PATH as JSONL.

The same non-negotiable property as the change layer:
  Every decision is grounded. The trace says exactly which context item
  fed which step of the reasoning. An agent that can't explain its
  triage decision is worse than no agent.
"""
import json
from datetime import datetime, timezone
from pathlib import Path

from agent import config, history, meaning, relationships, rules

ROOT_DIR = Path(__file__).parent.parent


def triage(ticket: dict, triggered_by: str = "cli") -> dict:
    """
    Triage an incident ticket: assign priority, route it, identify workaround.

    Parameters
    ----------
    ticket      : Incident ticket dict (validated against schemas/incident.json)
    triggered_by: Source that invoked triage — e.g. "cli", "webhook:servicenow",
                  "auto-monitor", "user:alice". Recorded in the audit log for
                  full trigger traceability. (Phase 1 trigger definition gap.)

    Returns a triage decision dict AND a full reasoning trace.
    """
    trace: list[dict] = []

    # ── Kill-switch ───────────────────────────────────────────────────────────
    if config.KILL_SWITCH:
        result = _refuse(trace, "Kill-switch engaged. All auto-triage disabled.")
        return _emit(result, ticket, triggered_by)

    # ── 01 RESOLVE ────────────────────────────────────────────────────────────
    affected = relationships.affected_services(ticket["affected_cis"])
    trace.append({
        "step": "01_resolve",
        "action": f"affected_services({ticket['affected_cis']})",
        "result": affected,
    })

    if not affected or all(a.get("service_id") is None for a in affected):
        result = _refuse(trace, "Could not resolve any affected CIs to known services. Cannot triage.")
        _maybe_file_cmdb_refresh(ticket, affected)
        return _emit(result, ticket, triggered_by)

    # Multi-CI refusal ladder:
    # Walk EVERY CI edge. A stale or low-confidence sibling on the same service
    # disqualifies the whole ticket — partial context is not safe context.
    # (Phase 1 criterion: "Refusal Rate on Stale CMDB = 100%")
    failure = _first_unreliable(affected)
    if failure is not None:
        result = _refuse(trace, failure["reason"])
        _maybe_file_cmdb_refresh(ticket, affected)
        return _emit(result, ticket, triggered_by)

    # All edges reliable. Pick highest-confidence edge as primary service.
    valid = [a for a in affected if a.get("service_id")]
    primary = max(valid, key=lambda a: a["confidence"])

    service = meaning.resolve_service(primary["service_id"])
    trace.append({
        "step": "01_resolve",
        "action": f"resolve_service({primary['service_id']})",
        "result": service,
    })

    # ── 02 TRAVERSE ───────────────────────────────────────────────────────────
    blast = relationships.blast_radius(service["id"])
    trace.append({
        "step": "02_traverse",
        "action": f"blast_radius({service['id']})",
        "result": blast,
    })

    active = history.active_incidents_for_service(service["id"])
    trace.append({
        "step": "02_traverse",
        "action": f"active_incidents_for_service({service['id']})",
        "result": active,
    })

    # ── 03 EVALUATE ───────────────────────────────────────────────────────────
    rule_results = rules.evaluate_all(ticket, service, blast)
    trace.append({
        "step": "03_evaluate",
        "action": f"evaluate_all(ticket={ticket['id']}, service={service['id']})",
        "result": rule_results,
    })

    # ── 04 RECALL ─────────────────────────────────────────────────────────────
    prior = history.prior_incidents_for_service(service["id"])
    trace.append({
        "step": "04_recall",
        "action": f"prior_incidents_for_service({service['id']})",
        "result": prior,
    })

    kb = rule_results["kb_match"]
    kb_validation = {"confirmed_historically": False, "confirmation_count": 0}
    if kb["ke_id"] and kb["score"] >= config.KB_MATCH_THRESHOLD:
        kb_validation = history.validate_kb_match(kb["ke_id"], service["id"])
    trace.append({
        "step": "04_recall",
        "action": f"validate_kb_match({kb['ke_id']}, {service['id']})",
        "result": kb_validation,
    })

    # ── 05 ACT ────────────────────────────────────────────────────────────────
    result = _decide(ticket, service, rule_results, prior, kb_validation, active, trace)
    return _emit(result, ticket, triggered_by)


# ── Decision assembly ──────────────────────────────────────────────────────────

def _decide(
    ticket: dict,
    service: dict,
    rule_results: dict,
    prior: dict,
    kb_validation: dict,
    active_incidents: list,
    trace: list,
) -> dict:
    """Assemble the triage decision from gathered context."""
    priority = rule_results["effective_priority"]
    escalation = rule_results["escalation"]
    kb = rule_results["kb_match"]
    sla = rule_results["sla_status"]

    # Build workaround block with confidence band label.
    # Phase 1 FM-2: "uncertain" band gets explicit hedging language.
    workaround = None
    kb_confidence_label = "no_match"
    if kb["ke_id"] and kb["score"] >= config.KB_MATCH_UNCERTAIN_FLOOR:
        ke = kb["known_error"]
        band = kb.get("confidence_band", "no_match")

        if band == "probable":
            if kb_validation["confirmed_historically"]:
                kb_confidence_label = "confirmed"
            else:
                kb_confidence_label = "probable"
        elif band == "uncertain":
            kb_confidence_label = "uncertain"

        if kb_confidence_label != "no_match":
            workaround = {
                "known_error_id": ke["id"],
                "title": ke["title"],
                "workaround": ke["workaround"],
                "permanent_fix": ke["permanent_fix"],
                "kb_match_score": kb["score"],
                "kb_confidence": kb_confidence_label,
                "historically_confirmed": kb_validation["confirmed_historically"],
                "confirmation_count": kb_validation["confirmation_count"],
            }
            if kb_confidence_label == "uncertain":
                workaround["uncertainty_note"] = (
                    "KB article partially matches (score below threshold). "
                    "Verify symptoms match before following this workaround — "
                    "root cause may differ."
                )

    # Storm / duplicate detection
    storm_warning = None
    if active_incidents:
        storm_warning = {
            "active_incidents": active_incidents,
            "recommendation": (
                "Possible incident storm or duplicate. "
                "Review active incidents before creating a new one."
            ),
        }

    # Route by priority
    route_map = {
        "P1": ("P1_war_room",      "IMMEDIATE — Open war room, page all escalation path"),
        "P2": ("P2_on_call_page",  "URGENT — Page on-call engineer, notify stakeholders"),
        "P3": ("P3_on_call_queue", "NORMAL — Assign to on-call queue, respond within SLA"),
        "P4": ("P4_service_desk",  "LOW — Route to service desk queue"),
    }
    route, route_label = route_map.get(priority, ("P4_service_desk", "LOW — Route to service desk"))

    # SLA warning
    sla_warning = None
    if sla.get("sla_assessed"):
        if sla["response_breached"]:
            overage = round(sla["elapsed_minutes"] - sla["response_target_minutes"], 1)
            sla_warning = (
                f"SLA BREACH — Response SLA already exceeded by {overage} minutes."
            )
        elif sla["response_sla_pct_used"] >= 80:
            sla_warning = (
                f"SLA WARNING — {sla['response_sla_pct_used']}% of response SLA consumed."
            )

    decision = {
        "ticket_id": ticket["id"],
        "priority": priority,
        "route": route,
        "route_label": route_label,
        "on_call_engineer": escalation["on_call_engineer"],
        "owner_team": escalation["owner_team"],
        "escalation_path": escalation["escalation_path"],
        "mandatory_notifications": escalation["mandatory_notifications"],
        "requires_war_room": escalation["requires_war_room"],
        "sla_warning": sla_warning,
        "storm_warning": storm_warning,
        "pre_brief": _build_pre_brief(ticket, service, rule_results, prior, workaround),
    }

    if workaround:
        decision["workaround"] = workaround

    # Soft-dependency informational context (not an escalation — Phase 1 PM fix)
    blast_override = rule_results.get("blast_radius_override", {})
    if blast_override.get("soft_upstream_context"):
        decision["soft_dependency_context"] = blast_override["soft_upstream_context"]

    trace.append({"step": "05_act", "action": "decide", "result": decision})
    return {"decision": decision, "trace": trace}


def _build_pre_brief(
    ticket: dict,
    service: dict,
    rule_results: dict,
    prior: dict,
    workaround: dict | None,
) -> dict:
    """
    Build the structured pre-brief for the on-call engineer.
    This is the human value the agent adds — facts, not a blank screen.
    """
    blast_override = rule_results.get("blast_radius_override", {})
    brief = {
        "service": service["name"],
        "service_tier": service["tier"],
        "dora_regulated": service.get("dora_regulated", False),
        "effective_priority": rule_results["effective_priority"],
        "impact_declared": ticket.get("impact"),
        "symptoms_reported": ticket.get("symptoms", []),
        "sla": {
            "response_target_minutes": rule_results["sla_status"].get("response_target_minutes"),
            "resolution_target_minutes": rule_results["sla_status"].get("resolution_target_minutes"),
            "elapsed_minutes": rule_results["sla_status"].get("elapsed_minutes"),
        },
    }

    if rule_results["dora_override"].get("override"):
        brief["dora_escalation_reason"] = rule_results["dora_override"]["reason"]

    if blast_override.get("override"):
        brief["blast_radius_escalation_reason"] = blast_override.get("reason")

    if blast_override.get("soft_upstream_context"):
        brief["soft_dependency_note"] = blast_override["soft_upstream_context"]["note"]

    if prior["found"] > 0:
        brief["historical_context"] = {
            "prior_incidents": prior["found"],
            "avg_mttr_minutes": prior["avg_mttr_minutes"],
            "linked_known_errors": prior["linked_known_errors"],
        }

    if workaround:
        brief["known_workaround"] = {
            "ke_id": workaround["known_error_id"],
            "title": workaround["title"],
            "workaround_steps": workaround["workaround"],
            "confidence": workaround["kb_confidence"],
        }
        if workaround.get("uncertainty_note"):
            brief["known_workaround"]["uncertainty_note"] = workaround["uncertainty_note"]

    return brief


# ── Refusal ladder ─────────────────────────────────────────────────────────────

def _first_unreliable(affected: list[dict]) -> dict | None:
    """
    Walk EVERY CI→service edge. Return the first failure reason or None if all clear.

    Rung 1: Unknown CI — CI not in CMDB at all.
    Rung 2: Low confidence — mapping exists but confidence is below per-tier threshold.
    Rung 3: Stale data — mapping exists but edge age exceeds per-tier threshold.

    Using per-tier thresholds (from config) means critical services get more
    lenient thresholds (tries harder) while non-critical services get tighter
    ones (fails faster). Flat 0.80 was the original bug. (Phase 1 FM-3.)
    """
    for a in affected:
        if a.get("service_id") is None:
            return {
                "ci_id": a["ci_id"],
                "reason": (
                    f"CI {a['ci_id']} not found in CMDB. "
                    "Refusing to triage on incomplete context."
                ),
            }
        conf_thr = a.get("confidence_threshold", config.MIN_EDGE_CONFIDENCE_DEFAULT)
        if a["confidence"] < conf_thr:
            return {
                "ci_id": a["ci_id"],
                "reason": (
                    f"CI {a['ci_id']} → service mapping confidence {a['confidence']:.2f} "
                    f"is below per-tier threshold {conf_thr} "
                    f"(service tier threshold applies). "
                    "Refusing to triage on unreliable CMDB data. "
                    "Submit a CMDB refresh request first."
                ),
            }
        fresh_thr = a.get("freshness_threshold_days", config.MAX_EDGE_AGE_DAYS_DEFAULT)
        if not a["fresh"]:
            return {
                "ci_id": a["ci_id"],
                "reason": (
                    f"CI {a['ci_id']} → service mapping is {a['age_days']} days old "
                    f"(per-tier threshold: {fresh_thr} days). "
                    "Stale dependency data — cannot determine correct blast radius. "
                    "Submit a CMDB refresh request first."
                ),
            }
    return None


def _refuse(trace: list, reason: str) -> dict:
    """Triage refusal — agent cannot safely assign priority. Always return a trace."""
    decision = {
        "priority": "UNKNOWN",
        "route": "manual_triage_required",
        "route_label": "MANUAL — Agent cannot triage. Human triage required.",
        "reason": reason,
    }
    trace.append({"step": "05_act", "action": "refuse", "result": decision})
    return {"decision": decision, "trace": trace}


# ── Audit log ──────────────────────────────────────────────────────────────────

def _emit(result: dict, ticket: dict, triggered_by: str) -> dict:
    """
    Append triage decision to the audit log. Includes triggered_by.
    (Phase 1 trigger definition gap: agent must record what activated it.)
    """
    if config.AUDIT_LOG_PATH is None:
        return result
    audit_path = ROOT_DIR / config.AUDIT_LOG_PATH
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    d = result["decision"]
    entry = {
        "type": "incident_triaged",
        "ticket_id": ticket.get("id"),
        "priority": d.get("priority"),
        "route": d.get("route"),
        "reason": d.get("reason"),
        "triggered_by": triggered_by,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    with open(audit_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return result


# ── CMDB refresh auto-ticket ───────────────────────────────────────────────────

def _maybe_file_cmdb_refresh(ticket: dict, affected: list[dict]) -> None:
    """
    When the agent refuses due to stale or low-confidence CMDB data, file a
    refresh request automatically so the refusal has a remediation path.

    Phase 1 FM-1 mitigation: "Refusal without remediation creates operational
    dead ends." The platform team owns the CMDB and needs to know when an edge
    is blocking automated triage.

    In production, this would create a ServiceNow Service Request ticket.
    Here, it appends to a JSONL log consumed by the platform team's queue.
    """
    if not config.AUTO_FILE_CMDB_REFRESH_ON_REFUSAL:
        return

    stale_or_low = [
        a for a in affected
        if a.get("service_id") is None
        or a.get("confidence", 1.0) < a.get("confidence_threshold", config.MIN_EDGE_CONFIDENCE_DEFAULT)
        or not a.get("fresh", True)
    ]
    if not stale_or_low:
        return

    refresh_path = ROOT_DIR / config.CMDB_REFRESH_LOG_PATH
    refresh_path.parent.mkdir(parents=True, exist_ok=True)
    for a in stale_or_low:
        entry = {
            "type": "cmdb_refresh_request",
            "triggered_by_ticket": ticket.get("id"),
            "ci_id": a.get("ci_id"),
            "service_id": a.get("service_id"),
            "confidence": a.get("confidence"),
            "age_days": a.get("age_days"),
            "reason": a.get("reason", "stale_or_low_confidence"),
            "requested_at": datetime.now(timezone.utc).isoformat(),
            "priority": "normal",
            "note": (
                "Auto-filed by triage agent on refusal. "
                "Assign to platform-team CMDB queue. SLA: 2 business days."
            ),
        }
        with open(refresh_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
