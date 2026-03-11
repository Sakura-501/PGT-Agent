from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from harbor_ext.pgt_agent_impl.helpers import (
    as_dict,
    as_list,
    class_to_mitre,
    class_to_tactic,
    extract_edges,
    is_alert_edge,
    md_cell,
    node_label,
    normalize_ioc_type,
    text,
)


def json_to_markdown(report: dict[str, Any]) -> str:
    metadata = as_dict(report.get("metadata"))
    report_data = as_dict(report.get("report_data"))
    sections = as_dict(report_data.get("sections"))
    event_summary = as_dict(sections.get("event_summary"))

    title = text(report_data.get("title")) or "溯源图安全分析报告"
    date = text(report_data.get("date")) or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    machine_id = text(metadata.get("machine_id")) or "未知"
    insight_id = text(metadata.get("insight_id")) or "未知"

    lines: list[str] = [
        f"# {title}",
        "",
        f"**生成日期:** {date}",
        f"**机器ID:** `{machine_id}`",
        f"**事件ID:** `{insight_id}`",
        "",
        "## 1. 事件摘要",
        f"**事件简述:** {text(event_summary.get('event_brief')) or 'N/A'}",
        f"**威胁等级:** {text(event_summary.get('threat_level')) or 'N/A'}",
        f"**初始访问方式:** {text(event_summary.get('initial_access_method')) or 'N/A'}",
        f"**初始访问证据:** {text(event_summary.get('initial_access_evidence')) or 'N/A'}",
        f"**事件目的:** {text(event_summary.get('event_purpose')) or 'N/A'}",
        "",
        "## 2. 攻击时间线",
    ]

    timeline = as_list(sections.get("attack_timeline"))
    if timeline:
        lines.append("| 时间 | 战术 | 技术 | 攻击作用 | MITRE 映射 |")
        lines.append("|---|---|---|---|---|")
        for item in timeline:
            row = as_dict(item)
            lines.append(
                "| "
                + " | ".join(
                    [
                        md_cell(text(row.get("timestamp"))),
                        md_cell(text(row.get("tactic"))),
                        md_cell(text(row.get("technique"))),
                        md_cell(text(row.get("attack_effect"))),
                        md_cell(text(row.get("mitre_attck_mappings"))),
                    ]
                )
                + " |"
            )
    else:
        lines.append("无时间线数据。")

    lines.extend(["", "## 3. 攻击流程图"])
    attack_graph = text(sections.get("attack_graph"))
    if attack_graph:
        if "```mermaid" not in attack_graph.lower():
            attack_graph = f"```mermaid\n{attack_graph}\n```"
        lines.append(attack_graph)
    else:
        lines.append("```mermaid\ngraph TD\nA[\"未提供流程图\"]\n```")

    lines.extend(["", "## 4. 行为预测"])
    future_behavior = as_list(sections.get("future_behavior"))
    if future_behavior:
        lines.append("| ID | 关键词 | 行为描述 |")
        lines.append("|---|---|---|")
        for item in future_behavior:
            row = as_dict(item)
            lines.append(
                "| "
                + " | ".join(
                    [
                        md_cell(text(row.get("id"))),
                        md_cell(text(row.get("key_word"))),
                        md_cell(text(row.get("behavior_description"))),
                    ]
                )
                + " |"
            )
    else:
        lines.append("无后续行为预测。")

    lines.extend(["", "## 附录：入侵指标 (IOCs)"])
    appendix = as_dict(report_data.get("appendix"))
    iocs = as_list(appendix.get("iocs"))
    if iocs:
        lines.append("| 类型 | 值 | 描述 | 风险等级 |")
        lines.append("|---|---|---|---|")
        for item in iocs:
            row = as_dict(item)
            lines.append(
                "| "
                + " | ".join(
                    [
                        md_cell(text(row.get("type"))),
                        md_cell(text(row.get("value"))),
                        md_cell(text(row.get("description"))),
                        md_cell(text(row.get("risk_level"))),
                    ]
                )
                + " |"
            )
    else:
        lines.append("未发现 IOC。")

    return "\n".join(lines).strip() + "\n"


def build_fallback_markdown(
    instruction: str,
    source_graph_path: str,
    raw_graph: str,
    parsed_graph: dict[str, Any] | None,
    llm_output: str,
) -> str:
    graph = parsed_graph
    if graph is None:
        try:
            graph = json.loads(raw_graph)
        except json.JSONDecodeError:
            graph = {}

    edges = extract_edges(graph)
    machine_id = text(graph.get("machine_id")) or "未知"
    insight_id = text(graph.get("incident_uuid")) or "未知"
    date = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    lines = [
        "# 溯源图安全分析报告（降级输出）",
        "",
        f"**生成日期:** {date}",
        f"**机器ID:** `{machine_id}`",
        f"**事件ID:** `{insight_id}`",
        "",
        "## 1. 事件摘要",
        f"**事件简述:** 任务指令要求分析 `{source_graph_path}`，本次使用降级模板输出。",
        f"**威胁等级:** {'高' if any(is_alert_edge(item) for item in edges) else '中'}",
        "**初始访问方式:** 溯源失败（模型输出不可解析，需人工复核）",
        "**初始访问证据:** 参考攻击时间线中的首个关键行为。",
        f"**事件目的:** 结合任务语义，疑似与终端异常行为分析相关。指令片段：{md_cell(instruction[:120])}",
        "",
        "## 2. 攻击时间线",
        "| 时间 | 战术 | 技术 | 攻击作用 | MITRE 映射 |",
        "|---|---|---|---|---|",
    ]

    for edge in edges[:8]:
        class_name = text(edge.get("class_name")) or "CLASS_UNKNOWN"
        activity = text(edge.get("activity_name")) or "Unknown"
        parent = node_label(as_dict(edge.get("parent_node")))
        child = node_label(as_dict(edge.get("child_node")))
        timestamp = text(edge.get("event_time"))
        lines.append(
            "| "
            + " | ".join(
                [
                    md_cell(timestamp),
                    md_cell(class_to_tactic(class_name)),
                    md_cell(activity),
                    md_cell(f"{parent} -> {child}"),
                    md_cell(class_to_mitre(class_name)),
                ]
            )
            + " |"
        )

    lines.extend(["", "## 3. 攻击流程图", "```mermaid", "graph TD"])
    for idx, edge in enumerate(edges[:6], start=1):
        parent = node_label(as_dict(edge.get("parent_node"))) or "unknown"
        child = node_label(as_dict(edge.get("child_node"))) or "unknown"
        lines.append(
            f'    N{idx}["{md_cell(parent)}"] --> N{idx + 1}["{md_cell(child)}"]'
        )
    if not edges:
        lines.append('    A["无可用边信息"]')

    lines.extend(
        [
            "```",
            "",
            "## 4. 行为预测",
            "| ID | 关键词 | 行为描述 |",
            "|---|---|---|",
            "| 1 | 后续执行 | 可能继续触发同类进程/脚本执行行为。 |",
            "| 2 | 防御规避 | 可能通过混淆命令行或注入方式规避检测。 |",
            "| 3 | 凭据与横向 | 如存在权限条件，可能进一步进行凭据获取或横向移动。 |",
            "",
            "## 附录：入侵指标 (IOCs)",
            "| 类型 | 值 | 描述 | 风险等级 |",
            "|---|---|---|---|",
        ]
    )

    iocs = _collect_iocs_from_graph(graph, edges)
    for ioc in iocs[:10]:
        lines.append(
            "| "
            + " | ".join(
                [
                    md_cell(ioc.get("type", "文件路径")),
                    md_cell(ioc.get("value", "")),
                    md_cell(ioc.get("description", "提取自溯源图")),
                    md_cell(ioc.get("risk_level", "中")),
                ]
            )
            + " |"
        )

    if not iocs:
        lines.append("| 文件路径 | /app/source_graph.json | 输入样本 | 低 |")

    if llm_output:
        lines.extend(
            [
                "",
                "## 附注",
                "以下是模型原始输出摘要（用于排障）：",
                "",
                "```text",
                llm_output[:2000],
                "```",
            ]
        )

    return "\n".join(lines).strip() + "\n"


def build_error_markdown(title: str, message: str) -> str:
    return (
        f"# {title}\n\n"
        "## 1. 事件摘要\n"
        f"- 事件简述: {message}\n"
        "- 威胁等级: 误报\n"
        "- 初始访问方式: 溯源失败\n"
        "- 初始访问证据: 无\n"
        "- 事件目的: 无法分析\n\n"
        "## 2. 攻击时间线\n无时间线数据。\n\n"
        "## 3. 攻击流程图\n```mermaid\ngraph TD\nA[\"读取失败\"]\n```\n\n"
        "## 4. 行为预测\n无后续行为预测。\n\n"
        "## 附录：入侵指标 (IOCs)\n未发现 IOC。\n"
    )


def _collect_iocs_from_graph(
    graph: dict[str, Any],
    edges: list[dict[str, Any]],
) -> list[dict[str, str]]:
    output: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(ioc_type: str, value: str, description: str, risk_level: str) -> None:
        value_text = text(value)
        if not value_text:
            return

        normalized_type = normalize_ioc_type(ioc_type, value_text)
        key = (normalized_type, value_text.lower())
        if key in seen:
            return

        seen.add(key)
        output.append(
            {
                "type": normalized_type,
                "value": value_text,
                "description": description,
                "risk_level": risk_level,
            }
        )

    for ioc in as_list(graph.get("iocs")):
        row = as_dict(ioc)
        value = text(row.get("value") or row.get("file_path"))
        description = text(row.get("context")) or "来自图顶层 IOC"
        add(text(row.get("type")), value, description, "中")

    for edge in edges:
        risk_level = "高" if is_alert_edge(edge) else "中"
        for node_key in ("parent_node", "child_node"):
            node = as_dict(edge.get(node_key))

            for ioc in as_list(node.get("iocs")):
                row = as_dict(ioc)
                value = text(row.get("value") or row.get("file_path"))
                add(text(row.get("type")), value, "来自节点IOC", risk_level)

            entity = as_dict(node.get("entity"))
            file_obj = as_dict(entity.get("file"))
            path = text(file_obj.get("path"))
            if path:
                add("文件路径", path, "节点文件路径", risk_level)

            for file_hash in as_list(file_obj.get("hashes")):
                row = as_dict(file_hash)
                add(text(row.get("algorithm")), text(row.get("value")), "文件哈希", risk_level)

    return output
