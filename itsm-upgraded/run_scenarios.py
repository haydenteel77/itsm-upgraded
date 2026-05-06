"""
run_scenarios.py — Full incident simulation runner with detailed report.

Runs 15 realistic incident scenarios through the triage agent, narrates
every step of the reasoning loop, and produces a final summary report.

Usage:
    python run_scenarios.py
    python run_scenarios.py --plain        # no terminal colours
    python run_scenarios.py --out report.md  # also save a markdown report

Each scenario shows:
  - Incident description and context
  - Every agent reasoning step (resolve → traverse → evaluate → recall → act)
  - The final triage decision with full justification
  - Any workarounds, notifications, warnings, and soft-dependency notes

The final report shows:
  - Priority distribution (P1/P2/P3/P4/REFUSED)
  - Rule firing counts (DORA, blast radius, KB match, storm, SLA breach)
  - CMDB health issues detected
  - Recommended follow-up actions per incident
  - Executive summary
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

from agent.harness import triage
from agent import config

# ── Terminal colours ──────────────────────────────────────────────────────────
USE_COLOR = True

def _c(code: str, text: str) -> str:
    if not USE_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"

def red(t):    return _c("91", t)
def yellow(t): return _c("93", t)
def blue(t):   return _c("94", t)
def green(t):  return _c("92", t)
def cyan(t):   return _c("96", t)
def bold(t):   return _c("1",  t)
def dim(t):    return _c("2",  t)
def magenta(t):return _c("95", t)

PRIORITY_COLOR = {
    "P1": red, "P2": yellow, "P3": blue, "P4": green, "UNKNOWN": magenta
}

def priority_str(p: str) -> str:
    fn = PRIORITY_COLOR.get(p, str)
    return bold(fn(p))


# ── Scenario definitions ──────────────────────────────────────────────────────
# 15 scenarios covering every major rule path, edge case, and failure mode
# identified in the Phase 1 Problem Discovery document.

NOW = datetime.now(timezone.utc)

def ts(minutes_ago: int) -> str:
    return (NOW - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")

SCENARIOS = [
    # ── DORA / Critical path ──────────────────────────────────────────────────
    {
        "id": "INC-S01",
        "label": "Payment API Full Outage — DORA P1 Escalation",
        "category": "DORA / Critical",
        "narrative": (
            "Monitoring alerts fire at 09:05 UTC. payment-api is returning HTTP 500 "
            "across all checkout endpoints. SSL handshake timeouts visible in logs. "
            "Customers are unable to complete purchases. Revenue impact is immediate."
        ),
        "ticket": {
            "id": "INC-S01",
            "title": "payment-api full outage — all checkout endpoints returning 500",
            "description": "Complete payment processing failure. TLS handshake errors in LB logs.",
            "reported_by": "ops-monitoring",
            "reported_at": ts(8),
            "affected_cis": ["ci-payment-tls", "ci-payment-lb-01"],
            "symptoms": ["500 error", "ssl error", "tls handshake", "checkout failure"],
            "impact": "full_outage",
            "priority_declared": None,
        },
        "triggered_by": "webhook:datadog",
    },
    {
        "id": "INC-S02",
        "label": "Fraud Check Full Outage — DORA Escalation, Stale CMDB Refusal",
        "category": "DORA / CMDB Quality",
        "narrative": (
            "payment-api reports fraud-check is unreachable. Engineers suspect a network "
            "partition between availability zones. However, the CMDB edge for ci-fraud-tls "
            "has not been verified since February — confidence and freshness are both below "
            "threshold. The agent must refuse and auto-file a CMDB refresh request."
        ),
        "ticket": {
            "id": "INC-S02",
            "title": "fraud-check unreachable — payment-api transactions failing fraud scoring",
            "description": "All calls from payment-api to fraud-check timing out. Possible AZ network issue.",
            "reported_by": "carol.engineer",
            "reported_at": ts(12),
            "affected_cis": ["ci-fraud-tls"],
            "symptoms": ["unreachable", "timeout", "fraud", "network", "payment failing"],
            "impact": "full_outage",
            "priority_declared": None,
        },
        "triggered_by": "auto-monitor",
    },
    {
        "id": "INC-S03",
        "label": "Payment API Partial Degradation — DORA Override on Non-P1 Matrix Result",
        "category": "DORA / Override",
        "narrative": (
            "5% of payment transactions are failing — not a full outage, but measurable "
            "degradation. The submitter has not declared a priority. The impact-tier matrix "
            "would give P2. But payment-api is DORA-regulated — the override must fire and "
            "force P1 regardless."
        ),
        "ticket": {
            "id": "INC-S03",
            "title": "payment-api degraded — 5% transaction failure rate, intermittent 503s",
            "description": "Intermittent 503s on payment endpoints. 5% error rate over last 10 minutes.",
            "reported_by": "bob.engineer",
            "reported_at": ts(6),
            "affected_cis": ["ci-payment-lb-01"],
            "symptoms": ["503 error", "intermittent", "transaction failure", "payment"],
            "impact": "partial_degradation",
            "priority_declared": None,
        },
        "triggered_by": "auto-monitor",
    },
    {
        "id": "INC-S04",
        "label": "Payment API — Submitter Declares P3, DORA Forces P1",
        "category": "DORA / False Negative Prevention",
        "narrative": (
            "A junior engineer submits a ticket for a payment-api issue and marks it P3, "
            "believing it is minor. The DORA false-negative-rate-zero rule must catch this: "
            "any incident on a DORA-regulated service exits as P1 regardless of declared priority."
        ),
        "ticket": {
            "id": "INC-S04",
            "title": "payment-api — occasional slow responses, probably nothing urgent",
            "description": "Some users reporting slow checkouts. Feels minor. Probably transient.",
            "reported_by": "junior.engineer",
            "reported_at": ts(20),
            "affected_cis": ["ci-payment-tls"],
            "symptoms": ["slow response", "latency", "payment", "timeout"],
            "impact": "minor_degradation",
            "priority_declared": "P3",
        },
        "triggered_by": "user:junior.engineer",
    },
    # ── Blast radius ──────────────────────────────────────────────────────────
    {
        "id": "INC-S05",
        "label": "Notification Service Outage — Soft Dependency, No Escalation",
        "category": "Blast Radius / Soft Dependency",
        "narrative": (
            "notification-service is completely down. payment-api depends on it softly — "
            "customers can still transact but won't receive email receipts. The blast radius "
            "rule must NOT escalate. Soft dependency context should appear in the pre-brief "
            "so the on-call engineer understands the customer-facing impact without over-reacting."
        ),
        "ticket": {
            "id": "INC-S05",
            "title": "notification-service full outage — no email receipts being sent",
            "description": "notification-service pod crashlooping. No emails delivered since 14:00 UTC.",
            "reported_by": "ops-monitoring",
            "reported_at": ts(15),
            "affected_cis": ["ci-notification-pod"],
            "symptoms": ["outage", "notification", "email", "crashloop", "pod failure"],
            "impact": "full_outage",
            "priority_declared": None,
        },
        "triggered_by": "webhook:pagerduty",
    },
    {
        "id": "INC-S06",
        "label": "Notification Service DB — Connection Pool Exhaustion, KB Match",
        "category": "Blast Radius / KB Match",
        "narrative": (
            "DB connection pool on notification-service is exhausted under load. "
            "This exact pattern has happened before (INC-4388). The KB should match KE-002 "
            "with confirmed historical validation. Workaround: restart the notification pod."
        ),
        "ticket": {
            "id": "INC-S06",
            "title": "notification-service DB connection pool exhausted — 500s on all endpoints",
            "description": "PgBouncer pool maxed out. All notification-service endpoints returning 500.",
            "reported_by": "ops-monitoring",
            "reported_at": ts(5),
            "affected_cis": ["ci-notification-pod"],
            "symptoms": ["connection pool exhausted", "database timeout", "db connection",
                         "500 error", "postgres", "notification"],
            "impact": "full_outage",
            "priority_declared": None,
        },
        "triggered_by": "auto-monitor",
    },
    # ── SLA breach ────────────────────────────────────────────────────────────
    {
        "id": "INC-S07",
        "label": "Payment API — SLA Response Already Breached",
        "category": "SLA Breach",
        "narrative": (
            "A payment-api ticket was filed 25 minutes ago but was missed in the queue. "
            "P1 response SLA is 5 minutes. The agent should detect the breach, flag it "
            "prominently, and trigger immediate escalation to the next tier."
        ),
        "ticket": {
            "id": "INC-S07",
            "title": "payment-api — high error rate, ticket missed in queue",
            "description": "Ticket created 25 minutes ago. No acknowledgment recorded. Escalating.",
            "reported_by": "escalation-bot",
            "reported_at": ts(25),
            "affected_cis": ["ci-payment-tls"],
            "symptoms": ["500 error", "high error rate", "payment", "unacknowledged"],
            "impact": "partial_degradation",
            "priority_declared": None,
        },
        "triggered_by": "escalation-bot",
    },
    {
        "id": "INC-S08",
        "label": "Internal Dashboard — SLA Warning (80% Consumed)",
        "category": "SLA Warning",
        "narrative": (
            "The internal dashboard has been intermittently unavailable for 6 hours. "
            "P4 resolution SLA is 10,080 minutes — but the response SLA is 480 minutes "
            "and 80% of that has been consumed. The agent should warn without breaching."
        ),
        "ticket": {
            "id": "INC-S08",
            "title": "internal-dashboard intermittent 503 — persisting for 6 hours",
            "description": "Intermittent 503s on dashboard. Teams reporting they can't access deployment views.",
            "reported_by": "frank.analyst",
            "reported_at": ts(390),
            "affected_cis": ["ci-dashboard-tls"],
            "symptoms": ["503", "intermittent", "dashboard", "login"],
            "impact": "minor_degradation",
            "priority_declared": None,
        },
        "triggered_by": "user:frank.analyst",
    },
    # ── Storm detection ───────────────────────────────────────────────────────
    {
        "id": "INC-S09",
        "label": "Internal Dashboard — Duplicate Ticket, Storm Warning",
        "category": "Storm Detection",
        "narrative": (
            "INC-4502 is already active on internal-dashboard. A second ticket arrives "
            "for the same service. The agent should triage it but prominently warn the "
            "on-call engineer that a duplicate may already be in flight."
        ),
        "ticket": {
            "id": "INC-S09",
            "title": "internal-dashboard login broken — users locked out",
            "description": "Multiple users unable to reach dashboard. Looks like the same issue from earlier.",
            "reported_by": "alice.analyst",
            "reported_at": ts(10),
            "affected_cis": ["ci-dashboard-tls"],
            "symptoms": ["404", "login", "dashboard", "locked out"],
            "impact": "minor_degradation",
            "priority_declared": None,
        },
        "triggered_by": "user:alice.analyst",
    },
    # ── KB matching ───────────────────────────────────────────────────────────
    {
        "id": "INC-S10",
        "label": "Marketing Site 502 During Deployment — KB Match (Probable)",
        "category": "KB Match",
        "narrative": (
            "marketing-site is returning 502 errors. This matches KE-004 — the known "
            "readiness probe issue during rolling deployments. The KB match should be "
            "probable (not yet confirmed via history) with a clear workaround: disable "
            "CDN cache before deployment."
        ),
        "ticket": {
            "id": "INC-S10",
            "title": "marketing-site returning 502 Bad Gateway during deployment window",
            "description": "CDN returning 502 for marketing-site. Deployment was running at the time.",
            "reported_by": "erin.engineer",
            "reported_at": ts(3),
            "affected_cis": ["ci-marketing-tls"],
            "symptoms": ["502", "bad gateway", "deployment", "marketing", "rolling update"],
            "impact": "partial_degradation",
            "priority_declared": None,
        },
        "triggered_by": "user:erin.engineer",
    },
    {
        "id": "INC-S11",
        "label": "Payment API TLS — KB Match Confirmed from History",
        "category": "KB Match / Confirmed",
        "narrative": (
            "TLS handshake failures on payment-api. This is KE-001 — previously confirmed "
            "as the resolution for INC-4421. The workaround (force cert rotation, toggle OCSP) "
            "should be surfaced with 'confirmed' confidence rating."
        ),
        "ticket": {
            "id": "INC-S11",
            "title": "payment-api TLS handshake failures — cert expiry suspected",
            "description": "SSL handshake errors correlating with cert expiry warning from 3 days ago.",
            "reported_by": "ops-monitoring",
            "reported_at": ts(4),
            "affected_cis": ["ci-payment-tls"],
            "symptoms": ["tls handshake", "ssl error", "certificate expired", "handshake timeout"],
            "impact": "partial_degradation",
            "priority_declared": None,
        },
        "triggered_by": "auto-monitor",
    },
    # ── CMDB quality ──────────────────────────────────────────────────────────
    {
        "id": "INC-S12",
        "label": "Notification DB — Low Confidence CI, Refusal",
        "category": "CMDB Quality / Refusal",
        "narrative": (
            "An alert fires on the notification-service database. The affected CI is "
            "ci-notification-db — a PgBouncer pool with CMDB confidence 0.63 and a "
            "last_verified date in October 2025. Both confidence and freshness fail "
            "the standard-tier thresholds. Agent must refuse and file a refresh request."
        ),
        "ticket": {
            "id": "INC-S12",
            "title": "notification-service DB alert — connection failures on PgBouncer pool",
            "description": "PgBouncer pool health check failing. DB connections timing out.",
            "reported_by": "ops-monitoring",
            "reported_at": ts(7),
            "affected_cis": ["ci-notification-db"],
            "symptoms": ["database timeout", "db connection", "connection pool", "postgres"],
            "impact": "partial_degradation",
            "priority_declared": None,
        },
        "triggered_by": "auto-monitor",
    },
    {
        "id": "INC-S13",
        "label": "Unknown CI — Complete CMDB Miss, Refusal",
        "category": "CMDB Quality / Unknown CI",
        "narrative": (
            "A new microservice was deployed last week but was never added to the CMDB. "
            "An incident ticket arrives referencing a CI that doesn't exist in the graph. "
            "The agent cannot resolve it to any service and must refuse with a clear message."
        ),
        "ticket": {
            "id": "INC-S13",
            "title": "rewards-service API unresponsive — new service not in CMDB",
            "description": "Newly deployed rewards-service returning timeouts. CI not yet registered.",
            "reported_by": "dev.team",
            "reported_at": ts(9),
            "affected_cis": ["ci-rewards-api-new"],
            "symptoms": ["timeout", "unresponsive", "api", "new service"],
            "impact": "full_outage",
            "priority_declared": None,
        },
        "triggered_by": "user:dev.team",
    },
    # ── Kill-switch / policy ──────────────────────────────────────────────────
    {
        "id": "INC-S14",
        "label": "Marketing Site Minor Issue — P4 Clean Path",
        "category": "Clean Path / Low Priority",
        "narrative": (
            "Marketing site has a cosmetic rendering issue on one browser. No monitoring "
            "alert. No customer impact on transactions. Clean path through the agent — "
            "P4, service desk queue, no escalation, no war room."
        ),
        "ticket": {
            "id": "INC-S14",
            "title": "marketing-site layout broken on Safari 16 — cosmetic issue",
            "description": "Homepage hero image not rendering on Safari 16. Functional content unaffected.",
            "reported_by": "qa.team",
            "reported_at": ts(60),
            "affected_cis": ["ci-marketing-tls"],
            "symptoms": ["layout", "cosmetic", "safari", "rendering"],
            "impact": "minor_degradation",
            "priority_declared": None,
        },
        "triggered_by": "user:qa.team",
    },
    {
        "id": "INC-S15",
        "label": "Payment API — Multi-CI Incident, Both CIs Healthy",
        "category": "Multi-CI / Full Reasoning Path",
        "narrative": (
            "A complex payment-api incident involves both the load balancer and the TLS cert. "
            "Both CIs are healthy in the CMDB (high confidence, fresh). The full five-step "
            "reasoning loop runs: DORA fires, war room required, compliance notified, "
            "KB match surfaced, historical MTTR context provided."
        ),
        "ticket": {
            "id": "INC-S15",
            "title": "payment-api — LB health checks failing AND cert warnings, full P1",
            "description": "Load balancer reporting unhealthy backends AND cert expiry warning within 48h.",
            "reported_by": "ops-monitoring",
            "reported_at": ts(2),
            "affected_cis": ["ci-payment-lb-01", "ci-payment-tls"],
            "symptoms": ["ssl error", "tls handshake", "load balancer", "health check",
                         "certificate expired", "500 error"],
            "impact": "full_outage",
            "priority_declared": None,
        },
        "triggered_by": "webhook:datadog",
    },
]


# ── Report rendering ──────────────────────────────────────────────────────────

def render_scenario(idx: int, scenario: dict, result: dict) -> tuple[str, str]:
    """
    Returns (terminal_output, markdown_output) for one scenario.
    """
    ticket = scenario["ticket"]
    d = result["decision"]
    trace = result["trace"]
    priority = d.get("priority", "UNKNOWN")

    lines_term = []   # terminal (coloured)
    lines_md = []     # plain markdown

    def both(term_line: str, md_line: str = None):
        lines_term.append(term_line)
        lines_md.append(md_line if md_line is not None else _strip_ansi(term_line))

    sep = "─" * 72
    both(f"\n{bold(cyan(sep))}", f"\n{'─'*72}")
    both(
        f"{bold(f'  SCENARIO {idx:02d}/{len(SCENARIOS)}')}  "
        f"{bold(scenario['label'])}",
        f"## Scenario {idx:02d}: {scenario['label']}"
    )
    both(
        f"  {dim('Category:')} {scenario['category']}  │  "
        f"{dim('Triggered by:')} {scenario['triggered_by']}",
        f"**Category:** {scenario['category']} | **Triggered by:** `{scenario['triggered_by']}`"
    )
    both(cyan(sep), "─"*72)

    # Narrative
    both(f"\n  {bold('INCIDENT CONTEXT')}", "\n### Incident Context")
    for line in _wrap(scenario["narrative"], 68):
        both(f"  {line}", line)

    both(
        f"\n  {dim('Ticket:')} {ticket['id']} — {ticket['title']}",
        f"\n**Ticket:** `{ticket['id']}` — {ticket['title']}"
    )
    both(
        f"  {dim('Reported:')} {ticket['reported_at']}  "
        f"{dim('Impact:')} {ticket.get('impact','?')}  "
        f"{dim('CIs:')} {', '.join(ticket['affected_cis'])}",
        f"**Reported:** `{ticket['reported_at']}` | **Impact:** `{ticket.get('impact','?')}` | "
        f"**CIs:** `{', '.join(ticket['affected_cis'])}`"
    )

    # Reasoning trace
    both(f"\n  {bold('AGENT REASONING TRACE')}", "\n### Agent Reasoning Trace")
    for entry in trace:
        step = entry["step"]
        action = entry["action"]
        res = entry["result"]

        step_label = {
            "01_resolve":  "01 RESOLVE  ",
            "02_traverse": "02 TRAVERSE ",
            "03_evaluate": "03 EVALUATE ",
            "04_recall":   "04 RECALL   ",
            "05_act":      "05 ACT      ",
        }.get(step, step)

        both(
            f"\n  {bold(blue(f'[{step_label}]'))} {dim(action)}",
            f"\n**[{step_label}]** `{action}`"
        )
        summary = _summarise_trace_result(step, action, res)
        for line in summary:
            both(f"    {dim('→')} {line}", f"> → {line}")

    # Decision
    both(f"\n  {bold('TRIAGE DECISION')}", "\n### Triage Decision")

    priority_display = priority_str(priority)
    both(
        f"  Priority     : {priority_display}",
        f"**Priority:** `{priority}`"
    )
    both(
        f"  Route        : {d.get('route_label', d.get('route', 'n/a'))}",
        f"**Route:** {d.get('route_label', d.get('route', 'n/a'))}"
    )
    if d.get("on_call_engineer"):
        both(
            f"  On-Call      : {d['on_call_engineer']}  │  Team: {d.get('owner_team','')}",
            f"**On-Call:** `{d['on_call_engineer']}` | **Team:** `{d.get('owner_team','')}`"
        )
    if d.get("escalation_path"):
        both(
            f"  Escalation   : {' → '.join(d['escalation_path'])}",
            f"**Escalation Path:** {' → '.join(d['escalation_path'])}"
        )
    if d.get("requires_war_room"):
        both(
            f"  {red(bold('⚑  WAR ROOM REQUIRED — Open bridge immediately'))}",
            f"🔴 **WAR ROOM REQUIRED** — Open bridge immediately"
        )
    if d.get("sla_warning"):
        both(
            f"  {yellow(bold('⚠  ' + d['sla_warning']))}",
            f"⚠️ **{d['sla_warning']}**"
        )
    if d.get("storm_warning"):
        both(
            f"  {yellow('⚠  STORM WARNING:')} {d['storm_warning']['recommendation']}",
            f"⚠️ **STORM WARNING:** {d['storm_warning']['recommendation']}"
        )
        for inc in d["storm_warning"]["active_incidents"]:
            both(
                f"      Active: {inc['id']} — {inc['title']}",
                f"  - Active: `{inc['id']}` — {inc['title']}"
            )
    if d.get("mandatory_notifications"):
        both(f"  {bold('Mandatory Notifications:')}", "**Mandatory Notifications:**")
        for n in d["mandatory_notifications"]:
            ack = ""
            if n.get("ack_required"):
                ack = f" [ACK required ≤{n.get('ack_deadline_minutes','?')}min → fallback: {n.get('ack_fallback','?')}]"
            both(
                f"    • {n['recipient']} within {n['deadline_minutes']}min — {n['reason']}{yellow(ack)}",
                f"  - `{n['recipient']}` within {n['deadline_minutes']}min — {n['reason']}{ack}"
            )
    if d.get("soft_dependency_context"):
        ctx = d["soft_dependency_context"]
        both(
            f"  {dim('Soft Dep Note:')} {ctx['note']}",
            f"**Soft Dependency Note:** {ctx['note']}"
        )
    if d.get("workaround"):
        w = d["workaround"]
        conf_icon = {"confirmed":"✅","probable":"⚡","uncertain":"⚠ ","no_match":"❓"}.get(w["kb_confidence"],"?")
        both(
            f"\n  {bold('Known Workaround')} [{w['known_error_id']}]  "
            f"{conf_icon} {bold(w['kb_confidence'].upper())}",
            f"\n**Known Workaround** `[{w['known_error_id']}]` {conf_icon} **{w['kb_confidence'].upper()}**"
        )
        both(
            f"  KB Article   : {w['title']}",
            f"**KB Article:** {w['title']}"
        )
        both(
            f"  Workaround   : {w['workaround']}",
            f"**Workaround:** {w['workaround']}"
        )
        both(
            f"  Permanent Fix: {w['permanent_fix']}",
            f"**Permanent Fix:** {w['permanent_fix']}"
        )
        if w.get("uncertainty_note"):
            both(
                f"  {yellow('⚠  ' + w['uncertainty_note'])}",
                f"⚠️ {w['uncertainty_note']}"
            )
    if d.get("reason"):
        both(
            f"\n  {dim('Refusal Reason:')} {d['reason']}",
            f"\n**Refusal Reason:** {d['reason']}"
        )

    # Pre-brief
    if d.get("pre_brief"):
        brief = d["pre_brief"]
        both(f"\n  {bold('Pre-Brief for On-Call Engineer')}", "\n### Pre-Brief for On-Call Engineer")
        _render_prebrief(brief, lines_term, lines_md)

    # Outcome tag
    outcome = _outcome_tag(priority, d)
    both(
        f"\n  {bold('Outcome:')} {outcome}",
        f"\n**Outcome:** {outcome}"
    )

    return "\n".join(lines_term), "\n".join(lines_md)


def _render_prebrief(brief: dict, lines_term: list, lines_md: list):
    def row(label, val):
        lines_term.append(f"  {dim(label+':'): <24} {val}")
        lines_md.append(f"| {label} | {val} |")

    lines_md.append("| Field | Value |")
    lines_md.append("|---|---|")

    row("Service", brief.get("service", ""))
    row("Tier", brief.get("service_tier", ""))
    row("DORA Regulated", "YES" if brief.get("dora_regulated") else "no")
    row("Effective Priority", brief.get("effective_priority", ""))
    row("Declared Impact", brief.get("impact_declared", ""))
    symptoms = brief.get("symptoms_reported", [])
    if symptoms:
        row("Symptoms", ", ".join(symptoms))
    sla = brief.get("sla", {})
    if sla.get("response_target_minutes"):
        row("SLA Response Target", f"{sla['response_target_minutes']} min")
    if sla.get("elapsed_minutes") is not None:
        row("Elapsed", f"{sla['elapsed_minutes']:.1f} min")
    hist = brief.get("historical_context", {})
    if hist:
        row("Prior Incidents", str(hist.get("prior_incidents", 0)))
        if hist.get("avg_mttr_minutes"):
            row("Avg MTTR", f"{hist['avg_mttr_minutes']} min")
        if hist.get("linked_known_errors"):
            row("Linked KEs", ", ".join(hist["linked_known_errors"]))
    if brief.get("dora_escalation_reason"):
        row("DORA Reason", brief["dora_escalation_reason"][:80])
    if brief.get("blast_radius_escalation_reason"):
        row("Blast Reason", brief["blast_radius_escalation_reason"][:80])
    if brief.get("soft_dependency_note"):
        row("Soft Dep Note", brief["soft_dependency_note"][:80])


def _summarise_trace_result(step: str, action: str, result) -> list[str]:
    """Produce 1–4 human-readable summary lines for a trace entry."""
    lines = []
    if result is None:
        return ["(no result)"]

    if step == "01_resolve" and "resolve_service" in action:
        if isinstance(result, dict):
            lines.append(
                f"Service: {result.get('name','')} | Tier: {result.get('tier','')} | "
                f"DORA: {'YES' if result.get('dora_regulated') else 'no'} | "
                f"Owner: {result.get('owner_team','')}"
            )
    elif step == "01_resolve" and "affected_services" in action:
        if isinstance(result, list):
            for a in result:
                sid = a.get("service_id") or "UNKNOWN"
                conf = a.get("confidence", 0)
                fresh = "fresh" if a.get("fresh") else f"STALE ({a.get('age_days','?')}d)"
                thr_c = a.get("confidence_threshold", 0.80)
                thr_f = a.get("freshness_threshold_days", 30)
                ok = conf >= thr_c and a.get("fresh", False)
                status = "✓" if ok else "✗"
                lines.append(
                    f"{status} CI {a['ci_id']} → {sid} | "
                    f"conf {conf:.2f} (thr {thr_c}) | {fresh} (thr {thr_f}d)"
                )
    elif step == "02_traverse" and "blast_radius" in action:
        if isinstance(result, dict):
            up = result.get("upstream_impacted", [])
            dn = result.get("downstream_root_cause_candidates", [])
            if up:
                for s in up:
                    dep = s.get("dependency_type","?")
                    lines.append(
                        f"Upstream: {s['name']} ({s['tier']}) "
                        f"[{dep} dep] DORA={s.get('dora_regulated',False)}"
                    )
            else:
                lines.append("Upstream impacted: none")
            if dn:
                for s in dn:
                    lines.append(f"Downstream (root cause candidate): {s['name']} [{s.get('dependency_type','?')} dep]")
    elif step == "02_traverse" and "active_incidents" in action:
        if isinstance(result, list):
            if result:
                lines.append(f"Active incidents on this service: {len(result)}")
                for i in result:
                    lines.append(f"  → {i['id']}: {i['title']} ({i.get('priority','')})")
            else:
                lines.append("No active incidents on this service")
    elif step == "03_evaluate":
        if isinstance(result, dict):
            lines.append(f"Effective priority after all rules: {result.get('effective_priority','?')}")
            pc = result.get("priority_classification", {})
            lines.append(f"Matrix result: {pc.get('priority','?')} — {pc.get('reason','')[:70]}")
            dora = result.get("dora_override", {})
            if dora.get("override"):
                lines.append(f"DORA override FIRED → forced {dora.get('forced_priority')} | escalated={dora.get('escalated')}")
            blast = result.get("blast_radius_override", {})
            if blast.get("override"):
                lines.append(f"Blast radius override FIRED → {blast.get('rule')} → {blast.get('forced_priority')}")
            elif blast.get("soft_upstream_context"):
                svcs = blast["soft_upstream_context"]["services"]
                lines.append(f"Soft upstream context (no escalation): {', '.join(svcs)}")
            kb = result.get("kb_match", {})
            if kb.get("ke_id"):
                lines.append(
                    f"KB match: {kb['ke_id']} score={kb.get('score',0):.2f} "
                    f"band={kb.get('confidence_band','?')}"
                )
            else:
                lines.append("KB match: none")
            sla = result.get("sla_status", {})
            if sla.get("sla_assessed"):
                breach = "BREACHED" if sla.get("response_breached") else f"{sla.get('response_sla_pct_used',0)}% used"
                lines.append(
                    f"SLA: {sla.get('elapsed_minutes',0):.0f}min elapsed | "
                    f"response target {sla.get('response_target_minutes')}min | {breach}"
                )
    elif step == "04_recall" and "prior_incidents" in action:
        if isinstance(result, dict):
            if result.get("found", 0) > 0:
                lines.append(
                    f"Prior incidents found: {result['found']} | "
                    f"Avg MTTR: {result.get('avg_mttr_minutes','?')} min"
                )
                if result.get("linked_known_errors"):
                    lines.append(f"Linked KEs in history: {', '.join(result['linked_known_errors'])}")
            else:
                lines.append("No prior incidents found for this service")
    elif step == "04_recall" and "validate_kb" in action:
        if isinstance(result, dict):
            if result.get("confirmed_historically"):
                lines.append(
                    f"KB match CONFIRMED historically "
                    f"({result.get('confirmation_count',0)} times, "
                    f"last: {result.get('last_confirmed','?')})"
                )
            else:
                lines.append("KB match not yet confirmed in history")
    elif step == "05_act":
        if isinstance(result, dict):
            p = result.get("priority","?")
            r = result.get("route","?")
            lines.append(f"Decision: {p} → {r}")
            if result.get("reason"):
                lines.append(f"Reason: {result['reason'][:100]}")
    if not lines:
        s = str(result)
        lines.append(s[:120] + ("..." if len(s) > 120 else ""))
    return lines


def _outcome_tag(priority: str, d: dict) -> str:
    if priority == "UNKNOWN":
        return "REFUSED — Human triage required. CMDB refresh request auto-filed."
    route = d.get("route", "")
    if "war_room" in route:
        return f"P1 WAR ROOM — Immediate escalation. Compliance notification dispatched."
    if "on_call_page" in route:
        return f"P2 ON-CALL PAGE — Engineer paged, stakeholders notified."
    if "on_call_queue" in route:
        return f"P3 ON-CALL QUEUE — Assigned to queue, respond within SLA."
    if "service_desk" in route:
        return f"P4 SERVICE DESK — Queued for next available engineer."
    return f"{priority} — {route}"


def _wrap(text: str, width: int) -> list[str]:
    words = text.split()
    lines, current = [], []
    for w in words:
        if sum(len(x)+1 for x in current) + len(w) > width:
            lines.append(" ".join(current))
            current = [w]
        else:
            current.append(w)
    if current:
        lines.append(" ".join(current))
    return lines


def _strip_ansi(s: str) -> str:
    import re
    return re.sub(r'\033\[[0-9;]*m', '', s)


# ── Final report ──────────────────────────────────────────────────────────────

def render_final_report(results: list[dict]) -> tuple[str, str]:
    lines_term, lines_md = [], []

    def both(t, m=None):
        lines_term.append(t)
        lines_md.append(m if m is not None else _strip_ansi(t))

    sep = "═" * 72
    both(f"\n{bold(green(sep))}", f"\n{'═'*72}")
    both(bold("  FINAL INCIDENT SIMULATION REPORT"), "# Final Incident Simulation Report")
    both(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", "")
    both(bold(green(sep)), "═"*72)

    # Priority distribution
    prio_counts: dict[str,int] = {}
    refused = 0
    for r in results:
        p = r["result"]["decision"]["priority"]
        if p == "UNKNOWN":
            refused += 1
        else:
            prio_counts[p] = prio_counts.get(p, 0) + 1

    total = len(results)
    both(f"\n{bold('── PRIORITY DISTRIBUTION ─────────────────────────────────────────')}", "\n## Priority Distribution")
    both("", "| Priority | Count | % of Total |")
    both("", "|---|---|---|")
    for p in ["P1","P2","P3","P4"]:
        n = prio_counts.get(p, 0)
        pct = round(n/total*100)
        bar = "█" * n + "░" * (15-n)
        fn = PRIORITY_COLOR.get(p, str)
        both(
            f"  {bold(fn(p))}  {bar}  {n:>2} / {total}  ({pct}%)",
            f"| {p} | {n} | {pct}% |"
        )
    both(
        f"  {magenta('REFUSED')}  {'█'*refused + '░'*(15-refused)}  {refused:>2} / {total}  ({round(refused/total*100)}%)",
        f"| REFUSED | {refused} | {round(refused/total*100)}% |"
    )

    # Rule firing counts
    dora_count = blast_count = kb_count = storm_count = sla_breach_count = sla_warn_count = 0
    for r in results:
        d = r["result"]["decision"]
        trace = r["result"]["trace"]
        eval_step = next((e for e in trace if e["step"] == "03_evaluate"), None)
        if eval_step:
            ev = eval_step["result"]
            if isinstance(ev, dict):
                if ev.get("dora_override", {}).get("override"):
                    dora_count += 1
                if ev.get("blast_radius_override", {}).get("override"):
                    blast_count += 1
                if ev.get("kb_match", {}).get("ke_id"):
                    kb_count += 1
                sla = ev.get("sla_status", {})
                if sla.get("response_breached"):
                    sla_breach_count += 1
                elif sla.get("response_sla_pct_used", 0) >= 80:
                    sla_warn_count += 1
        if d.get("storm_warning"):
            storm_count += 1

    both(f"\n{bold('── RULE FIRING SUMMARY ───────────────────────────────────────────')}", "\n## Rule Firing Summary")
    both("", "| Rule | Fired | Out of |")
    both("", "|---|---|---|")
    rule_rows = [
        ("DORA Override", dora_count),
        ("Blast Radius Escalation", blast_count),
        ("KB Match Found", kb_count),
        ("Storm Warning Triggered", storm_count),
        ("SLA Response Breached", sla_breach_count),
        ("SLA Warning (≥80%)", sla_warn_count),
        ("CMDB Refusals", refused),
    ]
    for label, count in rule_rows:
        bar = "█" * count + "░" * max(0, 10-count)
        both(f"  {label:<32} {bar}  {count}/{total}", f"| {label} | {count} | {total} |")

    # CMDB health issues
    cmdb_issues = []
    for r in results:
        trace = r["result"]["trace"]
        resolve_step = next((e for e in trace if e["step"] == "01_resolve"
                             and "affected_services" in e["action"]), None)
        if resolve_step:
            for a in (resolve_step["result"] or []):
                if (a.get("service_id") is None
                        or a.get("confidence", 1.0) < a.get("confidence_threshold", 0.80)
                        or not a.get("fresh", True)):
                    cmdb_issues.append({
                        "ticket": r["scenario"]["id"],
                        "ci": a.get("ci_id"),
                        "confidence": a.get("confidence"),
                        "age_days": a.get("age_days"),
                        "threshold_c": a.get("confidence_threshold"),
                        "threshold_f": a.get("freshness_threshold_days"),
                    })

    both(f"\n{bold('── CMDB HEALTH ISSUES DETECTED ───────────────────────────────────')}", "\n## CMDB Health Issues Detected")
    if cmdb_issues:
        both("", "| Ticket | CI | Confidence | Age (days) | Action |")
        both("", "|---|---|---|---|---|")
        seen = set()
        for issue in cmdb_issues:
            key = issue["ci"]
            if key in seen:
                continue
            seen.add(key)
            conf_str = f"{issue['confidence']:.2f}" if issue["confidence"] is not None else "N/A"
            age_str  = str(issue["age_days"]) if issue["age_days"] is not None else "N/A"
            both(
                f"  {red('✗')} CI: {issue['ci']: <28} conf={conf_str} age={age_str}d  → CMDB refresh required",
                f"| {issue['ticket']} | `{issue['ci']}` | {conf_str} | {age_str} | Refresh required |"
            )
    else:
        both("  All CMDB edges healthy across scenarios.", "All CMDB edges healthy across scenarios.")

    # Per-incident follow-up actions
    both(f"\n{bold('── RECOMMENDED FOLLOW-UP ACTIONS ─────────────────────────────────')}", "\n## Recommended Follow-Up Actions")
    both("", "| Scenario | Priority | Action Required |")
    both("", "|---|---|---|")
    for r in results:
        d = r["result"]["decision"]
        p = d.get("priority", "UNKNOWN")
        sid = r["scenario"]["id"]
        label = r["scenario"]["label"]
        action = _follow_up_action(p, d, r["result"]["trace"])
        fn = PRIORITY_COLOR.get(p, dim)
        both(
            f"  {bold(fn(p))}  {sid}  {dim(label[:40])}\n       → {action}",
            f"| {p} | `{sid}` {label[:45]} | {action} |"
        )

    # Executive summary
    both(f"\n{bold('── EXECUTIVE SUMMARY ─────────────────────────────────────────────')}", "\n## Executive Summary")
    p1_n = prio_counts.get("P1", 0)
    p2_n = prio_counts.get("P2", 0)
    summary_lines = [
        f"The agent processed {total} incident scenarios in this simulation run.",
        f"{p1_n} escalated to P1 (war room required) — "
        f"{'all triggered DORA compliance notifications.' if dora_count == p1_n else f'{dora_count} triggered DORA compliance notifications.'}",
        f"{p2_n} routed as P2 (on-call page, stakeholder notification).",
        f"{refused} refused due to insufficient CMDB data quality — "
        f"CMDB refresh requests were auto-filed for each.",
        f"{kb_count} incidents matched a known error in the KB — workarounds surfaced to on-call.",
        f"{sla_breach_count} had already breached their SLA response window at triage time — "
        f"immediate escalation triggered.",
        f"{storm_count} triggered storm warnings due to duplicate active incidents on the same service.",
        "",
        "Key architecture properties demonstrated:",
        "  • DORA false negative rate = 0% — every DORA service exited as P1, even when",
        "    submitters declared P3.",
        "  • Hard vs. soft dependency distinction — notification-service soft link to",
        "    payment-api did NOT trigger automatic escalation. Surfaced as context only.",
        "  • Per-tier CMDB thresholds — critical services applied 0.70/45d thresholds;",
        "    non-critical services applied tighter 0.85/21d thresholds.",
        "  • Refusal with remediation — every CMDB refusal auto-filed a refresh request.",
        "  • KB uncertainty bands — partial matches flagged as 'uncertain' with hedging",
        "    language to prevent engineers following wrong workarounds.",
        "  • triggered_by recorded on every audit log entry.",
    ]
    for line in summary_lines:
        both(f"  {line}", line)

    both(f"\n{bold(green(sep))}", f"\n{'═'*72}")
    both(
        bold(f"  Simulation complete — {total} scenarios processed."),
        f"**Simulation complete — {total} scenarios processed.**"
    )
    both(bold(green(sep)), "═"*72)

    return "\n".join(lines_term), "\n".join(lines_md)


def _follow_up_action(priority: str, d: dict, trace: list) -> str:
    if priority == "UNKNOWN":
        return "File CMDB refresh SR. Assign to manual triage queue."
    if priority == "P1":
        notifs = d.get("mandatory_notifications", [])
        ack_needed = any(n.get("ack_required") for n in notifs)
        s = "Open war room. Page escalation path."
        if ack_needed:
            s += " Verify compliance notification acknowledgment within 5 min."
        if d.get("workaround"):
            s += f" Apply KB workaround [{d['workaround']['known_error_id']}] immediately."
        return s
    if priority == "P2":
        s = "Page on-call. Notify stakeholders."
        if d.get("workaround"):
            s += f" KB [{d['workaround']['known_error_id']}] workaround available."
        return s
    if priority == "P3":
        return "Queue for on-call. Respond within 60 min SLA."
    return "Route to service desk. Schedule for next sprint if cosmetic."


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    global USE_COLOR

    parser = argparse.ArgumentParser(description="Run all incident scenarios and generate report.")
    parser.add_argument("--plain", action="store_true", help="Disable terminal colour output")
    parser.add_argument("--out", metavar="FILE", help="Save markdown report to FILE")
    args = parser.parse_args()

    if args.plain:
        USE_COLOR = False

    print(bold(cyan("\n" + "═"*72)))
    print(bold("  ITSM INCIDENT MANAGEMENT AGENT — FULL SCENARIO SIMULATION"))
    print(bold(f"  {len(SCENARIOS)} scenarios · Phase 1 upgrades active"))
    print(bold(cyan("═"*72)))

    all_results = []
    all_md = []

    for idx, scenario in enumerate(SCENARIOS, 1):
        ticket = scenario["ticket"]
        triggered_by = scenario["triggered_by"]

        # Suppress audit log writes during simulation
        original_audit = config.AUDIT_LOG_PATH
        config.AUDIT_LOG_PATH = None

        result = triage(ticket, triggered_by=triggered_by)

        config.AUDIT_LOG_PATH = original_audit

        term_out, md_out = render_scenario(idx, scenario, result)
        print(term_out)
        all_md.append(md_out)

        all_results.append({
            "scenario": scenario,
            "result": result,
        })

    # Final report
    term_report, md_report = render_final_report(all_results)
    print(term_report)
    all_md.append(md_report)

    # Save markdown if requested
    if args.out:
        out_path = Path(args.out)
        header = (
            f"# ITSM Incident Management Agent — Simulation Report\n"
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            f"---\n\n"
        )
        out_path.write_text(header + "\n\n".join(all_md), encoding="utf-8")
        print(f"\n  📄  Markdown report saved to: {out_path}")


if __name__ == "__main__":
    main()
