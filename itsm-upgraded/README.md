# Incident Management Context Layer

**ITSM · Senior Track · Lab 02**

A context-layer agent that triages incoming incident tickets for a fintech company.
Walks a five-step reasoning loop, assigns priority (P1–P4), routes to the correct
escalation path, surfaces KB workarounds, and produces a full audit trace for every
decision — including refusals.

---

## What this is

The agent classifies every incoming incident ticket as it transitions to *In Progress*:

```
01 Resolve   → map affected CIs to canonical services (via CMDB graph)
02 Traverse  → compute blast radius (upstream/downstream, hard vs. soft)
03 Evaluate  → priority matrix · DORA override · KB match · SLA assessment
04 Recall    → prior incidents · MTTR benchmark · KB historical confirmation
05 Act       → emit: priority · route · on-call · notifications · workaround · pre-brief
```

Every decision is **grounded** — the trace says exactly which data item drove each step.

---

## Phase 1 improvements (from Problem Discovery)

| Gap identified | What changed | Where |
|---|---|---|
| Flat CMDB confidence threshold (FM-3) | Per-service-tier thresholds: critical=0.70, standard=0.80, non-critical=0.85. DORA/critical services try harder before refusing. | `agent/config.py`, `agent/relationships.py` |
| Stale CMDB threshold also flat (FM-3) | Per-tier freshness: critical=45d, standard=30d, non-critical=21d | `agent/config.py`, `agent/relationships.py` |
| Multi-CI partial-context gap | ALL affected CIs evaluated — a stale sibling CI triggers refusal even if another CI maps cleanly | `agent/harness.py` |
| Refusal without remediation (FM-1) | Agent auto-files a CMDB refresh request on every confidence/freshness refusal | `agent/harness.py`, `data/cmdb_refresh_requests.jsonl` |
| No notification acknowledgment loop (FM-4) | `mandatory_notifications` now carries `ack_required`, `ack_deadline_minutes`, `ack_fallback` | `agent/rules.py` |
| Hard vs. soft dependency conflation (PM conflict) | `dependency_type` field on CMDB edges. Blast radius escalation only fires for **hard** upstreams. Soft upstreams surface as informational context. | `data/cmdb.json`, `agent/relationships.py`, `agent/rules.py` |
| No triggered_by audit field | Every audit log entry records `triggered_by` (cli / webhook:servicenow / auto-monitor / user:X) | `agent/harness.py` |
| KB match over-confidence (FM-2) | Three confidence bands: `confirmed` · `probable` · `uncertain`. Uncertain scores get explicit hedging language in the workaround block. | `agent/rules.py`, `agent/harness.py` |
| No kill-switch | `config.KILL_SWITCH = True` forces every ticket to manual triage instantly | `agent/config.py`, `agent/harness.py` |
| DORA false negative risk | Adversarial test: submitter-declared P3 on DORA service is still forced to P1 | `tests/test_scenarios.py` |

---

## Scenarios

| Ticket | Service | What fires | Result |
|---|---|---|---|
| **INC-4510** | payment-api | Full outage + DORA override + KB match (KE-001, confirmed) | **P1** — war room, compliance notification (ack required), workaround surfaced |
| **INC-4511** | notification-service | Soft blast radius context (not escalation) + KB match (KE-002) | **P2** — submitter-declared, soft dep context in pre-brief |
| **INC-4512** | internal-dashboard | Low impact, non-critical + storm warning (INC-4502 active) | **P4** — service desk queue |
| **INC-4513** | fraud-check | CMDB confidence 0.72 (below critical tier threshold 0.70) + stale | **REFUSED** — human triage required, CMDB refresh ticket auto-filed |

---

## Quick start

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Run all four scenarios
python triage.py INC-4510   # P1 — DORA escalation, war room, confirmed workaround
python triage.py INC-4511   # P2 — declared priority, soft dep context
python triage.py INC-4512   # P4 — low priority, storm warning
python triage.py INC-4513   # REFUSED — stale CMDB, refresh ticket auto-filed

# Run tests (18 passing)
pytest -v
```

---

## Design decisions

| Decision | Rationale |
|---|---|
| **Per-tier CMDB thresholds** | A flat 0.80 threshold is too blunt. DORA-regulated critical services should have a lower refusal bar (try harder before refusing) — a DORA P1 refused because CI confidence dipped to 0.79 destroys trust permanently. Non-critical services can afford a tighter bar. |
| **Hard vs. soft dependencies** | `notification-service → payment-api` is a soft dependency (payments succeed without email receipts). Escalating to P1 because of it is systematic over-escalation. Only hard dependencies (fraud-check → payment-api: transactions cannot complete) trigger automatic escalation. |
| **Notification `ack_required`** | DORA requires compliance notification within 30 minutes. "We dispatched the notification" is not "they received it." Every mandatory notification now carries `ack_required`, `ack_deadline_minutes`, and `ack_fallback` so the dispatch layer can implement two-phase commit. |
| **CMDB refresh auto-ticket** | Refusal without remediation is an operational dead end. When the agent refuses due to stale or low-confidence data, it files a refresh request automatically so the platform team's CMDB queue picks it up. |
| **KB uncertainty band** | A score between 0.15 and 0.30 is genuinely ambiguous. Silently promoting it to "probable" and having an engineer follow the wrong workaround is worse than flagging it as "uncertain" with explicit hedging. |
| **Refusal over wrong answer** | The agent refuses when data quality is insufficient. Silence is safer than a confidently wrong triage. |

---

## Policy knobs (`agent/config.py`)

| Knob | Default | What it gates |
|---|---|---|
| `MIN_EDGE_CONFIDENCE_DEFAULT` | `0.80` | Default confidence threshold (overridden per tier) |
| `MAX_EDGE_AGE_DAYS_DEFAULT` | `30` | Default freshness threshold (overridden per tier) |
| `TIER_CONFIDENCE_THRESHOLDS` | `{critical: 0.70, standard: 0.80, non-critical: 0.85}` | Per-tier confidence floor |
| `TIER_FRESHNESS_THRESHOLDS` | `{critical: 45, standard: 30, non-critical: 21}` | Per-tier max edge age |
| `KB_MATCH_THRESHOLD` | `0.30` | Minimum score for "probable" KB match |
| `KB_MATCH_UNCERTAIN_FLOOR` | `0.15` | Score floor for "uncertain" KB band |
| `KILL_SWITCH` | `False` | `True` → refuse every ticket, route to manual triage |
| `AUTO_FILE_CMDB_REFRESH_ON_REFUSAL` | `True` | Auto-file refresh request on CMDB refusal |
| `NOTIFICATION_ACK_TIMEOUT_MINUTES` | `5` | Time before marking a required ack as missed |
| `COMPLIANCE_NOTIFICATION_DEADLINE_MINUTES` | `30` | DORA hard notification deadline |
| `STORM_DETECTION_WINDOW_SECONDS` | `60` | Window for incident storm grouping |
| `AUDIT_LOG_PATH` | `"data/audit_log.jsonl"` | Set `None` to disable audit emission |

---

## File map

```
agent/
  config.py         # All policy knobs and thresholds in one place (new)
  meaning.py        # Resolve IDs/names → canonical entities (services, KEs, SLAs)
  relationships.py  # NetworkX graph: CI→Service (per-tier thresholds), Service→Service
                    #   (hard/soft dependency_type), invalidate_graph() hook
  rules.py          # Policy-as-code: priority matrix, DORA override, KB match (3 bands),
                    #   blast radius (hard deps only), SLA, escalation (ack_required)
  history.py        # Temporal recall: prior incidents, MTTR, KB validation
  harness.py        # Five-step loop: multi-CI refusal ladder, triggered_by,
                    #   kill-switch, audit log, CMDB refresh auto-ticket

data/
  services.json              # Service catalog
  cmdb.json                  # CIs, CI→Service edges, service dependencies (with dependency_type)
  incident_tickets.json      # Incoming incident tickets (input)
  incidents.json             # Historical + active incident log
  known_errors.json          # Knowledge Base — workarounds + permanent fixes
  sla_policy.json            # Priority definitions, escalation rules, on-call schedule
  cmdb_refresh_requests.jsonl  # Auto-filed CMDB refresh requests (generated)
  audit_log.jsonl            # Triage audit trail (generated, gitignored)

schemas/
  incident.json     # JSON Schema for IncidentTicket
  service.json      # JSON Schema for Service

tests/
  test_scenarios.py  # 18 tests: 4 scenarios + Phase 1 upgrade coverage + groundedness

triage.py          # CLI entry point
```

---

## Where production would differ

- Replace `_build_graph()` with a Neo4j or ServiceNow CMDB query. The `invalidate_graph()` hook is already wired — attach a Kafka subscriber.
- Replace keyword KB matching with a vector similarity search over embeddings.
- Replace `_maybe_file_cmdb_refresh()` with a real ServiceNow Service Request API call.
- Implement the two-phase commit pattern for `ack_required` notifications — dispatch + poll for acknowledgment; fire secondary alert on timeout.
- Replace `config.KILL_SWITCH` with a centralized feature-flag service (LaunchDarkly, etc.).
- Wire `triggered_by` to a real event source (ServiceNow webhook, PagerDuty threshold, Datadog alert).
- Add a priority-accuracy eval harness over a labeled holdout set of 100+ historical incidents (Phase 1 Success Criterion: Priority Accuracy ≥ 90%).
