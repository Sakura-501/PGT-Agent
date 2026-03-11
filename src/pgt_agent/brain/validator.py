"""
Validator for PGT-Agent report quality.

This module provides validation functions to check:
1. Schema completeness - required fields are present
2. Evidence grounding - claims reference valid edge_ids
3. Data integrity - values match expected types
"""

import json
import re
from typing import Any


def _get_nested(data: dict[str, Any] | None, path: tuple[str, ...]) -> Any:
    """Get nested value from dict using tuple path."""
    if data is None:
        return None
    current = data
    for key in path:
        if isinstance(current, dict):
            current = current.get(key)
        else:
            return None
        if current is None:
            return None
    return current


def _extract_edge_ids_from_graph(graph: dict[str, Any]) -> set[str]:
    """Extract all edge IDs from the graph for validation."""
    edge_ids: set[str] = set()
    edges = graph.get("provenance_graph_edges", [])
    if isinstance(edges, list):
        for edge in edges:
            if isinstance(edge, dict):
                edge_id = edge.get("id")
                if edge_id and isinstance(edge_id, str):
                    edge_ids.add(edge_id)
    return edge_ids


def validate_report(
    report: dict[str, Any] | None,
    graph: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate a PGT report against schema and evidence requirements.

    Args:
        report: The parsed report JSON to validate
        graph: Optional original graph for evidence validation

    Returns:
        Dict with keys:
        - "ok": bool - True if validation passed
        - "issues": list[str] - List of specific issues found
    """
    issues: list[str] = []

    if report is None:
        return {"ok": False, "issues": ["报告JSON缺失或解析失败"]}

    # Extract edge IDs from graph for evidence validation
    valid_edge_ids: set[str] = set()
    if graph:
        valid_edge_ids = _extract_edge_ids_from_graph(graph)

    # Check metadata section
    metadata = report.get("metadata")
    if not isinstance(metadata, dict):
        issues.append("缺少metadata字段或格式错误")
    else:
        if not metadata.get("machine_id"):
            issues.append("metadata缺少machine_id字段")
        if not metadata.get("insight_id"):
            issues.append("metadata缺少insight_id字段")

    # Check report_data section
    report_data = report.get("report_data")
    if not isinstance(report_data, dict):
        issues.append("缺少report_data字段或格式错误")
    else:
        # Check title and date
        if not report_data.get("title"):
            issues.append("report_data缺少title字段")
        if not report_data.get("date"):
            issues.append("report_data缺少date字段")

        # Check sections
        sections = report_data.get("sections")
        if not isinstance(sections, dict):
            issues.append("report_data缺少sections字段")
        else:
            # Check event_summary
            event_summary = sections.get("event_summary")
            if not isinstance(event_summary, dict):
                issues.append("sections缺少event_summary字段")
            else:
                required_summary_fields = [
                    "event_brief",
                    "threat_level",
                    "initial_access_method",
                    "initial_access_evidence",
                    "event_purpose",
                ]
                for field in required_summary_fields:
                    if not event_summary.get(field):
                        issues.append(f"event_summary缺少{field}字段")

                # Validate threat_level values
                valid_threat_levels = ["高", "中", "低", "误报", "溯源失败"]
                threat_level = event_summary.get("threat_level")
                if threat_level and threat_level not in valid_threat_levels:
                    issues.append(
                        f"threat_level值无效: {threat_level}，"
                        f"应为: {', '.join(valid_threat_levels)}"
                    )

            # Check attack_timeline
            attack_timeline = sections.get("attack_timeline")
            if not isinstance(attack_timeline, list):
                issues.append("sections缺少attack_timeline字段或格式错误")
            elif len(attack_timeline) == 0:
                issues.append("attack_timeline为空列表")

            # Check attack_graph
            attack_graph = sections.get("attack_graph")
            if not attack_graph:
                issues.append("sections缺少attack_graph字段")

            # Check future_behavior
            future_behavior = sections.get("future_behavior")
            if not isinstance(future_behavior, list):
                issues.append("sections缺少future_behavior字段或格式错误")

        # Check appendix
        appendix = report_data.get("appendix")
        if not isinstance(appendix, dict):
            issues.append("report_data缺少appendix字段")
        else:
            iocs = appendix.get("iocs")
            if not isinstance(iocs, list):
                issues.append("appendix缺少iocs字段或格式错误")

    # Check for evidence grounding (only if graph is provided)
    if valid_edge_ids:
        issues.extend(_validate_evidence_references(report, valid_edge_ids))

    return {"ok": len(issues) == 0, "issues": issues}


def _validate_evidence_references(
    report: dict[str, Any],
    valid_edge_ids: set[str],
) -> list[str]:
    """Validate that any edge_id references in the report are valid."""
    issues: list[str] = []

    # Check attack_timeline for evidence references
    report_data = report.get("report_data", {})
    sections = report_data.get("sections", {})
    attack_timeline = sections.get("attack_timeline", [])

    if isinstance(attack_timeline, list):
        for idx, event in enumerate(attack_timeline):
            if isinstance(event, dict):
                # If the event has an edge_id reference, validate it
                edge_id = event.get("edge_id")
                if edge_id and edge_id not in valid_edge_ids:
                    issues.append(
                        f"attack_timeline[{idx}]引用了无效的edge_id: {edge_id}"
                    )

                # Check technique field - it should reference actual graph content
                technique = event.get("technique")
                if technique and isinstance(technique, str):
                    # Look for potential edge_id patterns in technique description
                    # Format: edge_id:xxx
                    import re

                    edge_refs = re.findall(r"edge_id[：:]\s*(\w+)", technique)
                    for ref in edge_refs:
                        if ref not in valid_edge_ids:
                            issues.append(
                                f"attack_timeline[{idx}].technique引用了无效的edge_id: {ref}"
                            )

    return issues


def validate_report_json_format(raw_output: str) -> dict[str, Any]:
    """Validate that the raw output contains valid JSON.

    Args:
        raw_output: Raw LLM output string

    Returns:
        Dict with keys:
        - "ok": bool - True if valid JSON found
        - "issues": list[str] - List of issues
        - "preview": str - Preview of the output
    """
    issues: list[str] = []

    if not raw_output or not raw_output.strip():
        return {
            "ok": False,
            "issues": ["LLM输出为空"],
            "preview": "",
        }

    # Check for JSON code block
    json_match = re.search(r"```json\s*(.*?)```", raw_output, re.DOTALL | re.IGNORECASE)
    if json_match:
        # Found JSON code block
        json_content = json_match.group(1).strip()
        try:
            json.loads(json_content)
            return {
                "ok": True,
                "issues": [],
                "preview": json_content[:500] + "..."
                if len(json_content) > 500
                else json_content,
            }
        except json.JSONDecodeError as e:
            issues.append(f"JSON代码块解析失败: {e}")

    # Try to find any JSON object
    try:
        parsed = json.loads(raw_output.strip())
        if isinstance(parsed, dict):
            return {
                "ok": True,
                "issues": [],
                "preview": raw_output[:500] + "..."
                if len(raw_output) > 500
                else raw_output,
            }
    except json.JSONDecodeError:
        pass

    # Check if output contains any JSON-like structure
    if "{" in raw_output and "}" in raw_output:
        issues.append("输出包含大括号但未能解析为有效JSON")
    else:
        issues.append("输出未找到JSON格式")

    return {
        "ok": False,
        "issues": issues,
        "preview": raw_output[:200] + "..." if len(raw_output) > 200 else raw_output,
    }
