"""
Prompts for PGT-Agent ReAct + Reflection framework.

This module defines system prompts and prompt builders for:
- ReAct: Agent's main reasoning loop
- Critic: Reflection and quality validation
"""

import json
from typing import Any


# ============================================================================
# System Prompts
# ============================================================================

REACT_SYSTEM_PROMPT = """你是一位精通终端威胁检测与响应（TDR）的高级安全分析专家。

## 分析流程（SOP）

请按照以下步骤分析溯源图：

1. **拓扑分解** - 识别关键节点、边和攻击链路
2. **IOC提取** - 从溯源图中提取IP、域名、文件哈希等威胁指标
3. **原子行为解释** - 解释每个关键边的行为和作用
4. **意图分析** - 推断攻击者目的和TTP映射
5. **报告生成** - 输出符合schema的结构化报告

## 关键要求

- 所有结论必须基于证据，引用edge_id
- 证据不足时明确标注"溯源失败"，禁止臆测
- 输出JSON格式，符合要求的schema
- 当有历史反思时，请在本次生成中针对性改进

## 输出格式

请直接输出JSON对象，可以包裹在```json代码块中，也可以直接输出。
确保JSON符合提供的schema结构。
"""


CRITIC_SYSTEM_PROMPT = """你是一位严格的安全报告评审专家。

## 评审标准

1. **事实依据** - 所有结论必须有evidence支持
2. **完整性** - 检查schema必需字段是否齐全
3. **逻辑性** - 攻击链是否连贯，TTP映射是否合理
4. **无臆测** - 标记任何缺乏证据的推断

## 返回格式

请返回JSON对象，包含以下字段：
```json
{
  "verdict": "pass|fail",
  "issues": ["具体问题描述列表"],
  "reflection": "本次问题的总结，用于下一轮改进"
}
```

- `verdict`: "pass"表示报告合格，"fail"表示需要改进
- `issues`: 列出具体的问题点，帮助定位需要改进的地方
- `reflection`: 总结性的反思，指导下一轮如何改进
"""


# ============================================================================
# Report Schema (for reference in prompts)
# ============================================================================

PGT_REPORT_SCHEMA = {
    "metadata": {
        "machine_id": "机器ID",
        "insight_id": "事件ID",
    },
    "report_data": {
        "title": "事件标题（简明扼要）",
        "date": "报告生成时间",
        "sections": {
            "event_summary": {
                "event_brief": "事件简述",
                "threat_level": "高/中/低/误报",
                "initial_access_method": "初始访问方式（文件下载/漏洞利用/弱口令爆破/安全Agent远程执行/溯源失败）",
                "initial_access_evidence": "初始访问方式的证据",
                "event_purpose": "攻击者的最终目的",
            },
            "attack_timeline": [
                {
                    "timestamp": "具体时间",
                    "tactic": "攻击环节",
                    "technique": "具体攻击手法",
                    "attack_effect": "攻击作用",
                    "mitre_attck_mappings": "T1234,T1059等",
                }
            ],
            "attack_graph": "```mermaid```格式的攻击流程图",
            "future_behavior": [
                {
                    "id": "步骤id",
                    "key_word": "关键词",
                    "behavior_description": "后续攻击行为推断",
                }
            ],
        },
        "appendix": {
            "iocs": [
                {
                    "type": "IP/域名/URL/文件哈希/文件路径",
                    "value": "IOC值",
                    "description": "描述",
                    "risk_level": "风险等级",
                }
            ]
        },
    },
}


# ============================================================================
# Prompt Builders
# ============================================================================


def build_user_prompt(
    instruction: str,
    graph_payload: dict[str, Any],
    mode: str,
    mode_stats: dict[str, Any],
    reflections: list[str] | None = None,
) -> str:
    """Build user prompt for the main analysis agent.

    Args:
        instruction: Task instruction from Harbor (instruction.md content)
        graph_payload: Compressed provenance graph data
        mode: Graph compression mode ("full", "slim", "skeleton")
        mode_stats: Statistics about the graph (edge counts, etc.)
        reflections: Previous reflections for improvement

    Returns:
        Formatted user prompt string
    """
    parts = [
        "# 任务",
        instruction,
        "",
        f"# 溯源图数据 (模式: {mode})",
        f"**统计信息**: {json.dumps(mode_stats, ensure_ascii=False)}",
        "",
        "```json",
        json.dumps(graph_payload, ensure_ascii=False, indent=2),
        "```",
        "",
        "# 要求的输出格式",
        "```json",
        json.dumps(PGT_REPORT_SCHEMA, ensure_ascii=False, indent=2),
        "```",
    ]

    if reflections:
        parts.extend(
            [
                "",
                "# 历史反思 (请在本次生成中针对性改进)",
                "",
                "\n".join(f"- {r}" for r in reflections[-3:]),
            ]
        )

    return "\n".join(parts)


def build_reflection_prompt(
    report: dict[str, Any] | None,
    report_raw: str | None,
    validation: dict[str, Any],
) -> str:
    """Build prompt for the Critic to reflect on the report.

    Args:
        report: Parsed report JSON (may be None if parsing failed)
        report_raw: Raw LLM output (for debugging if parsing failed)
        validation: Validation result from validator

    Returns:
        Formatted reflection prompt string
    """
    payload = {
        "report": report,
        "report_raw_preview": (report_raw or "")[:1000] if report_raw else None,
        "validation": validation,
    }

    return "请评审以下安全分析报告，检查事实依据、完整性、逻辑性。\n\n" + json.dumps(
        payload, ensure_ascii=False, indent=2
    )
