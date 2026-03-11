from __future__ import annotations

import json
from typing import Any


def build_user_prompt(
    instruction: str,
    graph_payload: str,
    mode: str,
    mode_stats: dict[str, Any],
    report_schema: dict[str, Any],
) -> str:
    schema_text = json.dumps(report_schema, ensure_ascii=False, indent=2)
    return (
        "你是一名溯源图分析工程师。请基于输入数据生成高质量安全报告。\n"
        "严格要求：\n"
        "1. 最终输出必须是纯 JSON 对象，不要 markdown 包裹，不要解释文字。\n"
        "2. 内容需要完整覆盖：事件摘要、攻击时间线、攻击流程图、行为预测、IOC。\n"
        "3. attack_graph 字段必须为 mermaid 代码块。\n"
        "4. 对推断结论要体现证据依据。\n\n"
        f"运行模式: {mode}\n"
        f"模式统计: {json.dumps(mode_stats, ensure_ascii=False)}\n\n"
        f"任务指令:\n{instruction.strip()}\n\n"
        f"输出 Schema:\n{schema_text}\n\n"
        f"溯源图数据:\n{graph_payload}"
    )
