"""
config.py — Central policy knobs for the Incident Management Agent.

All thresholds, flags, and policy parameters live here so they can be
changed in one place and picked up everywhere.

Phase 1 Problem Discovery gaps addressed:
  - Per-service-tier confidence and freshness thresholds (FM-3: flat 0.80
    threshold was too blunt — DORA-regulated critical services should be
    harder to refuse, not easier).
  - Intake throttle window for incident-storm detection.
  - Notification acknowledgment timeout.
  - CMDB refresh auto-ticket flag.
  - Audit log path and triggered_by tracking.
"""
from pathlib import Path

# ── Data directory ────────────────────────────────────────────────────────────
DATA_DIR = Path(__file__).parent.parent / "data"

# ── CMDB edge quality thresholds ─────────────────────────────────────────────
# These are the defaults. Per-tier overrides below take precedence.
# Raising the bar for non-critical services keeps alert quality high.
# Lowering the bar for DORA-critical services prevents the pathological case
# where a DORA P1 incident is refused because a CI confidence dipped to 0.79.
# (Phase 1 FM-3: "Refusal During Maximum Criticality")

# Default thresholds (applied when no tier-specific override matches)
MIN_EDGE_CONFIDENCE_DEFAULT: float = 0.80
MAX_EDGE_AGE_DAYS_DEFAULT: int = 30

# Per-tier overrides — key is service tier string
TIER_CONFIDENCE_THRESHOLDS: dict[str, float] = {
    "critical":     0.70,   # DORA + critical: try harder before refusing
    "standard":     0.80,   # standard: default
    "non-critical": 0.85,   # non-critical: higher bar; imprecise data matters less
}

TIER_FRESHNESS_THRESHOLDS: dict[str, int] = {
    "critical":     45,     # critical: allow slightly stale edges rather than refusing P1
    "standard":     30,     # standard: default 30-day window
    "non-critical": 21,     # non-critical: tighter freshness required
}

# ── KB match ──────────────────────────────────────────────────────────────────
KB_MATCH_THRESHOLD: float = 0.30
# Scores in this range surface as "probable" with explicit uncertainty language
# (Phase 1 FM-2: "KB Keyword Matching Produces Confident Wrong Workarounds")
KB_MATCH_UNCERTAIN_FLOOR: float = 0.15
KB_MATCH_UNCERTAIN_CEILING: float = 0.30

# ── Precedent / history ───────────────────────────────────────────────────────
PRECEDENT_MIN_SAMPLE: int = 3           # minimum prior incidents before MTTR is meaningful
MTTR_BENCHMARK_WINDOW: int = 10         # number of most-recent incidents to average

# ── Notification acknowledgment ───────────────────────────────────────────────
# Phase 1 FM-4: DORA notification gap — dispatch is not delivery.
# If an ack is not received within this window, a secondary human alert fires.
NOTIFICATION_ACK_TIMEOUT_MINUTES: int = 5   # time before marking notification as unacknowledged
COMPLIANCE_NOTIFICATION_DEADLINE_MINUTES: int = 30  # DORA hard deadline

# ── Incident storm / intake throttle ─────────────────────────────────────────
# Phase 1 FM-5: storm detection must fire before 50 duplicate pages go out.
# Tickets from the same service within this window are flagged as a storm.
STORM_DETECTION_WINDOW_SECONDS: int = 60
STORM_TICKET_COUNT_THRESHOLD: int = 3   # ≥ N tickets in window → storm warning

# ── CMDB refresh auto-ticket ─────────────────────────────────────────────────
# Phase 1 FM-1 mitigation: when the agent refuses due to stale/low-confidence
# CMDB data, it should file a refresh request automatically rather than leaving
# an operational dead end.
AUTO_FILE_CMDB_REFRESH_ON_REFUSAL: bool = True
CMDB_REFRESH_LOG_PATH: str = "data/cmdb_refresh_requests.jsonl"

# ── Audit log ────────────────────────────────────────────────────────────────
AUDIT_LOG_PATH: str = "data/audit_log.jsonl"

# ── Kill-switch ───────────────────────────────────────────────────────────────
# Set to True to force every ticket to manual_triage_required.
KILL_SWITCH: bool = False
