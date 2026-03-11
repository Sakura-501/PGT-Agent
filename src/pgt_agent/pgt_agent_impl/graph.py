from __future__ import annotations

import json
from typing import Any

from pgt_agent.pgt_agent_impl.helpers import (
    as_dict,
    as_list,
    edge_time,
    extract_edges,
    is_alert_edge,
    node_detail,
    node_id,
    node_label,
    safe_int,
    skeleton_node,
    text,
)


def prepare_graph_payload(
    raw_graph: str,
    large_graph_char_threshold: int,
    prompt_graph_char_limit: int,
    alert_detail_limit: int,
) -> tuple[str, str, dict[str, Any], dict[str, Any] | None]:
    raw_len = len(raw_graph)
    try:
        parsed = json.loads(raw_graph)
    except json.JSONDecodeError:
        parsed = None

    if raw_len <= large_graph_char_threshold:
        return raw_graph, "full", {"raw_chars": raw_len}, parsed

    if parsed is None:
        return (
            raw_graph[:prompt_graph_char_limit],
            "truncated-invalid-json",
            {"raw_chars": raw_len, "kept_chars": prompt_graph_char_limit},
            None,
        )

    compressed = build_compressed_context(parsed, alert_detail_limit)
    compressed_text = json.dumps(compressed, ensure_ascii=False, indent=2)

    if len(compressed_text) > prompt_graph_char_limit:
        compressed = shrink_compressed_context(
            compressed=compressed,
            target_chars=prompt_graph_char_limit,
        )
        compressed_text = json.dumps(compressed, ensure_ascii=False, indent=2)

    return (
        compressed_text,
        "compressed",
        {
            "raw_chars": raw_len,
            "compressed_chars": len(compressed_text),
            "edge_count": compressed.get("summary", {}).get("edge_count", 0),
            "alert_edge_count": compressed.get("summary", {}).get("alert_edge_count", 0),
            "node_count": compressed.get("summary", {}).get("node_count", 0),
        },
        parsed,
    )


def build_compressed_context(
    graph: dict[str, Any],
    alert_detail_limit: int,
) -> dict[str, Any]:
    edges = extract_edges(graph)
    nodes: dict[str, dict[str, Any]] = {}
    skeleton_edges: list[dict[str, Any]] = []
    alert_edge_details: list[dict[str, Any]] = []
    timeline: list[dict[str, Any]] = []

    for edge in edges:
        parent = as_dict(edge.get("parent_node"))
        child = as_dict(edge.get("child_node"))
        parent_current_id = node_id(parent)
        child_current_id = node_id(child)

        if parent_current_id:
            nodes[parent_current_id] = skeleton_node(parent)
        if child_current_id:
            nodes[child_current_id] = skeleton_node(child)

        alert = is_alert_edge(edge)
        skeleton_edges.append(
            {
                "from": parent_current_id,
                "to": child_current_id,
                "class_name": text(edge.get("class_name")),
                "activity_name": text(edge.get("activity_name")),
                "event_time": edge_time(edge),
                "is_alert": alert,
            }
        )

        timeline.append(
            {
                "event_time": edge_time(edge),
                "class_name": text(edge.get("class_name")),
                "activity_name": text(edge.get("activity_name")),
                "parent": node_label(parent),
                "child": node_label(child),
                "is_alert": alert,
            }
        )

        if alert and len(alert_edge_details) < alert_detail_limit:
            alert_edge_details.append(
                {
                    "event_time": edge_time(edge),
                    "class_name": text(edge.get("class_name")),
                    "activity_name": text(edge.get("activity_name")),
                    "parent": node_detail(parent),
                    "child": node_detail(child),
                }
            )

    timeline.sort(key=lambda item: safe_int(item.get("event_time"), 0))

    summary = {
        "machine_id": text(graph.get("machine_id")),
        "incident_uuid": text(graph.get("incident_uuid") or graph.get("insight_id")),
        "edge_count": len(skeleton_edges),
        "alert_edge_count": sum(1 for item in skeleton_edges if item.get("is_alert")),
        "node_count": len(nodes),
    }

    return {
        "summary": summary,
        "skeleton": {
            "nodes": list(nodes.values()),
            "edges": skeleton_edges,
        },
        "alert_edge_details": alert_edge_details,
        "timeline": timeline[:80],
    }


def shrink_compressed_context(
    compressed: dict[str, Any],
    target_chars: int,
) -> dict[str, Any]:
    output = json.loads(json.dumps(compressed, ensure_ascii=False))
    while len(json.dumps(output, ensure_ascii=False)) > target_chars:
        details = output.get("alert_edge_details", [])
        if details:
            details.pop()
            continue

        timeline = output.get("timeline", [])
        if timeline:
            timeline.pop()
            continue

        skeleton = as_dict(output.get("skeleton"))
        edges = as_list(skeleton.get("edges"))
        nodes = as_list(skeleton.get("nodes"))

        if len(edges) > 200:
            skeleton["edges"] = edges[: len(edges) // 2]
            continue

        if len(nodes) > 200:
            skeleton["nodes"] = nodes[: len(nodes) // 2]
            continue

        break

    return output
