"""
triage.py — run the incident management agent against an incident ticket.

Usage:
    python triage.py INC-4510              # P1 payment-api outage
    python triage.py INC-4511              # P2 notification-service degradation
    python triage.py INC-4512              # P4 dashboard intermittent 404
    python triage.py INC-4513              # CMDB refusal — stale data, refresh ticket filed
    python triage.py INC-4510 --triggered-by webhook:servicenow

The agent walks a five-step reasoning loop and prints the full trace
so you can follow exactly which context item drove each decision.

Phase 1 upgrades visible here:
  - --triggered-by flag records the activation source in the audit log
  - Soft-dependency context printed separately from escalation triggers
  - KB uncertainty band ("uncertain") shown with hedging language
  - CMDB refresh auto-ticket notice shown on refusal
"""
import json
import sys
from pathlib import Path
from agent.harness import triage

DATA_DIR = Path(__file__).parent / "data"

PRIORITY_COLOR = {
    "P1": "\033[91m",
    "P2": "\033[93m",
    "P3": "\033[94m",
    "P4": "\033[92m",
    "UNKNOWN": "\033[95m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


def load_ticket(ticket_id: str) -> dict:
    with open(DATA_DIR / "incident_tickets.json") as f:
        tickets = json.load(f)["incident_tickets"]
    for t in tickets:
        if t["id"] == ticket_id:
            return t
    raise SystemExit(f"Ticket {ticket_id} not found in data/incident_tickets.json")


def _fmt(val) -> str:
    s = json.dumps(val, default=str, indent=2)
    if len(s) <= 300:
        return s.replace("\n", " ").replace("  ", " ")
    lines = s.splitlines()
    if len(lines) > 20:
        return "\n    ".join(lines[:20]) + f"\n    ... ({len(lines)-20} more lines)"
    return "\n    ".join(lines)


def print_trace(result: dict, triggered_by: str = "cli") -> None:
    print()
    print("=" * 72)
    print(f"{BOLD}  INCIDENT MANAGEMENT AGENT — REASONING TRACE{RESET}")
    print(f"{DIM}  triggered_by: {triggered_by}{RESET}")
    print("=" * 72)

    for entry in result["trace"]:
        print(f"\n[{entry['step']}] {entry['action']}")
        formatted = _fmt(entry["result"])
        print(f"  → {formatted}")

    d = result["decision"]
    priority = d.get("priority", "UNKNOWN")
    color = PRIORITY_COLOR.get(priority, "")

    print()
    print("=" * 72)
    print(f"{BOLD}  TRIAGE DECISION{RESET}")
    print("=" * 72)
    print(f"  Priority       : {color}{BOLD}{priority}{RESET}")
    print(f"  Route          : {d.get('route_label', d.get('route', 'n/a'))}")
    print(f"  On-Call Eng.   : {d.get('on_call_engineer', 'n/a')}")
    print(f"  Owner Team     : {d.get('owner_team', 'n/a')}")

    if d.get("escalation_path"):
        print(f"  Escalation     : {' → '.join(d['escalation_path'])}")

    if d.get("sla_warning"):
        print(f"\n  ⚠  {BOLD}{d['sla_warning']}{RESET}")

    if d.get("storm_warning"):
        print(f"\n  ⚠  STORM WARNING: {d['storm_warning']['recommendation']}")
        for inc in d["storm_warning"]["active_incidents"]:
            print(f"      Active: {inc['id']} — {inc['title']}")

    if d.get("requires_war_room"):
        print(f"\n  🔴 {BOLD}WAR ROOM REQUIRED{RESET} — Open bridge immediately.")

    if d.get("mandatory_notifications"):
        print(f"\n  Mandatory Notifications:")
        for n in d["mandatory_notifications"]:
            ack_note = ""
            if n.get("ack_required"):
                ack_note = f" [ACK required within {n.get('ack_deadline_minutes', '?')} min → fallback: {n.get('ack_fallback', '?')}]"
            print(f"    • {n['recipient']} — within {n['deadline_minutes']} min — {n['reason']}{ack_note}")

    if d.get("soft_dependency_context"):
        ctx = d["soft_dependency_context"]
        print(f"\n  Soft Dependency Note:")
        print(f"    Services: {', '.join(ctx['services'])}")
        print(f"    {ctx['note']}")

    if d.get("workaround"):
        w = d["workaround"]
        confidence_display = {
            "confirmed": "✅  Confirmed (historically validated)",
            "probable":  "⚡  Probable (KB match, not yet historically confirmed)",
            "uncertain": "⚠   Uncertain (partial KB match — verify before following)",
            "no_match":  "❓  No KB match",
        }.get(w["kb_confidence"], w["kb_confidence"])
        print(f"\n  Known Workaround [{w['known_error_id']}] — {confidence_display}")
        print(f"  KB Article      : {w['title']}")
        print(f"  Workaround      : {w['workaround']}")
        print(f"  Permanent Fix   : {w['permanent_fix']}")
        if w.get("uncertainty_note"):
            print(f"\n  ⚠  {w['uncertainty_note']}")

    if "reason" in d:
        print(f"\n  Reason         : {d['reason']}")
        # Check if a CMDB refresh was auto-filed
        from pathlib import Path
        from agent import config
        refresh_log = Path(__file__).parent / config.CMDB_REFRESH_LOG_PATH
        if refresh_log.exists():
            with open(refresh_log) as f:
                lines = [json.loads(l) for l in f if l.strip()]
            ticket_id = d.get("ticket_id") or ""
            relevant = [l for l in lines if l.get("triggered_by_ticket") == ticket_id]
            if relevant:
                print(f"\n  📋  CMDB Refresh auto-filed for {len(relevant)} CI(s):")
                for req in relevant:
                    print(f"      CI: {req.get('ci_id')} — {req.get('note', '')[:80]}")

    if d.get("pre_brief"):
        print(f"\n  Pre-Brief (for on-call engineer):")
        print("  " + json.dumps(d["pre_brief"], indent=4, default=str).replace("\n", "\n  "))

    print("=" * 72)
    print()


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        raise SystemExit(1)

    ticket_id = args[0]
    triggered_by = "cli"
    if "--triggered-by" in args:
        idx = args.index("--triggered-by")
        if idx + 1 < len(args):
            triggered_by = args[idx + 1]

    ticket = load_ticket(ticket_id)
    print(f"\n{BOLD}Triaging {ticket['id']} — {ticket['title']}{RESET}")
    result = triage(ticket, triggered_by=triggered_by)
    print_trace(result, triggered_by)


if __name__ == "__main__":
    main()
