"""
Relationships layer — knowledge graph for incident management.

Answers: "what does this incident affect, and what is already known about it?"

The graph models:
  CI → Service edges        (confidence + freshness, per-tier thresholds)
  Service → Service deps    (upstream/downstream blast radius, hard vs. soft)
  Incident → KnownError     (has this failure pattern been seen before?)
  Service → historical INC  (what incidents has this service had?)

Phase 1 gaps addressed:
  - Per-service-tier confidence and freshness thresholds (FM-3).
  - Hard vs. soft dependency distinction in blast radius (PM conflict / FM-4).
    Hard = payment fails without fraud-check (escalate).
    Soft = payment degrades gracefully without notification-service (note only).
  - `invalidate_graph()` hook exposed so callers can force a rebuild after a
    CMDB update event (production: Kafka subscriber / ServiceNow webhook).
  - Multi-CI refusal: ALL CIs evaluated; a stale sibling triggers refusal.
    (Phase 1 criterion: "Refusal Rate on Stale CMDB = 100%")

In production: Neo4j. Here: NetworkX + JSON.
"""
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import networkx as nx
from agent import config, meaning

DATA_DIR = config.DATA_DIR


def _build_graph() -> nx.DiGraph:
    """Build the full ITSM knowledge graph from JSON data files."""
    with open(DATA_DIR / "cmdb.json") as f:
        cmdb = json.load(f)

    G = nx.DiGraph()

    for ci in cmdb["cis"]:
        G.add_node(ci["id"], kind="ci", **ci)

    for svc in meaning.all_services():
        G.add_node(svc["id"], kind="service", **svc)

    for edge in cmdb["ci_service_edges"]:
        G.add_edge(
            edge["ci_id"],
            edge["service_id"],
            kind="ci_to_service",
            confidence=edge["confidence"],
            last_verified=edge["last_verified"],
        )

    # dependency_type: "hard" (default) or "soft"
    # Hard → upstream failure causes escalation.
    # Soft → upstream degrades gracefully; surfaced as informational only.
    for dep in cmdb["service_dependencies"]:
        G.add_edge(
            dep["from"],
            dep["to"],
            kind="service_dependency",
            confidence=dep["confidence"],
            last_verified=dep.get("last_verified", "2026-04-01T00:00:00Z"),
            dependency_type=dep.get("dependency_type", "hard"),
        )

    return G


_GRAPH: Optional[nx.DiGraph] = None


def graph() -> nx.DiGraph:
    global _GRAPH
    if _GRAPH is None:
        _GRAPH = _build_graph()
    return _GRAPH


def invalidate_graph() -> None:
    """
    Force the graph to rebuild on the next call to graph().
    Call this from a CMDB-update event handler in production.
    Tests that swap config.DATA_DIR must call this explicitly.
    """
    global _GRAPH
    _GRAPH = None


def _confidence_threshold_for(service_id: str) -> float:
    svc = meaning.resolve_service(service_id)
    if svc:
        return config.TIER_CONFIDENCE_THRESHOLDS.get(
            svc.get("tier", "standard"), config.MIN_EDGE_CONFIDENCE_DEFAULT
        )
    return config.MIN_EDGE_CONFIDENCE_DEFAULT


def _freshness_threshold_for(service_id: str) -> int:
    svc = meaning.resolve_service(service_id)
    if svc:
        return config.TIER_FRESHNESS_THRESHOLDS.get(
            svc.get("tier", "standard"), config.MAX_EDGE_AGE_DAYS_DEFAULT
        )
    return config.MAX_EDGE_AGE_DAYS_DEFAULT


def affected_services(ci_ids: list[str]) -> list[dict]:
    """
    Given a list of CI IDs, resolve to services with per-tier thresholds.

    ALL CIs are evaluated. A stale sibling on the same service still triggers
    refusal — partial context is not safe context.
    """
    g = graph()
    results = []
    now = datetime.now(timezone.utc)

    for ci_id in ci_ids:
        if ci_id not in g:
            results.append({
                "ci_id": ci_id,
                "service_id": None,
                "confidence": 0.0,
                "fresh": False,
                "age_days": None,
                "confidence_threshold": config.MIN_EDGE_CONFIDENCE_DEFAULT,
                "freshness_threshold_days": config.MAX_EDGE_AGE_DAYS_DEFAULT,
                "reason": "unknown_ci",
            })
            continue

        for _, svc_id, edge_data in g.out_edges(ci_id, data=True):
            if edge_data["kind"] != "ci_to_service":
                continue

            conf_thr = _confidence_threshold_for(svc_id)
            fresh_thr = _freshness_threshold_for(svc_id)

            last_verified = datetime.fromisoformat(
                edge_data["last_verified"].replace("Z", "+00:00")
            )
            age_days = (now - last_verified).days
            fresh = age_days <= fresh_thr

            results.append({
                "ci_id": ci_id,
                "service_id": svc_id,
                "confidence": edge_data["confidence"],
                "fresh": fresh,
                "age_days": age_days,
                "confidence_threshold": conf_thr,
                "freshness_threshold_days": fresh_thr,
            })

    return results


def blast_radius(service_id: str) -> dict:
    """
    What does this service affect upstream? Includes hard/soft dependency type.

    upstream_impacted: services that call this one.
      dependency_type "hard" → upstream will break if this goes down (escalate).
      dependency_type "soft" → upstream degrades gracefully (informational only).
    downstream_root_cause_candidates: services this one calls.
    """
    g = graph()

    upstream = []
    for src, _, edge_data in g.in_edges(service_id, data=True):
        if edge_data.get("kind") != "service_dependency":
            continue
        svc = meaning.resolve_service(src)
        upstream.append({
            "service_id": src,
            "name": svc["name"] if svc else src,
            "tier": svc["tier"] if svc else "unknown",
            "dora_regulated": svc.get("dora_regulated", False) if svc else False,
            "confidence": edge_data.get("confidence", 1.0),
            "dependency_type": edge_data.get("dependency_type", "hard"),
        })

    downstream = []
    for _, tgt, edge_data in g.out_edges(service_id, data=True):
        if edge_data.get("kind") != "service_dependency":
            continue
        svc = meaning.resolve_service(tgt)
        downstream.append({
            "service_id": tgt,
            "name": svc["name"] if svc else tgt,
            "tier": svc["tier"] if svc else "unknown",
            "dora_regulated": svc.get("dora_regulated", False) if svc else False,
            "confidence": edge_data.get("confidence", 1.0),
            "dependency_type": edge_data.get("dependency_type", "hard"),
        })

    return {
        "upstream_impacted": upstream,
        "downstream_root_cause_candidates": downstream,
    }


def prior_incidents_for_service(service_id: str) -> list[dict]:
    g = graph()
    results = []
    for node, data in g.nodes(data=True):
        if data.get("kind") == "incident":
            for _, svc_id, edge_data in g.out_edges(node, data=True):
                if edge_data.get("kind") == "incident_to_service" and svc_id == service_id:
                    results.append(data)
    return results
