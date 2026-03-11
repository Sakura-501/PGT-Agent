"""
Reflector for PGT-Agent quality improvement.

This module provides the Critic reflection functionality:
- Analyzes report quality
- Identifies specific issues
- Generates actionable reflections for improvement
"""

import json
import re
from typing import Any

from openai import AsyncOpenAI

from pgt_agent.brain.prompts import CRITIC_SYSTEM_PROMPT


def _extract_first_json_object(text: str) -> str:
    """Extract the first top-level JSON object ({...}) from text."""
    if not text:
        return ""
    s = text.strip()
    start = s.find("{")
    if start == -1:
        return ""
    depth = 0
    in_string = False
    escape = False
    for idx in range(start, len(s)):
        ch = s[idx]
        if in_string:
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
                continue
            if ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return s[start : idx + 1].strip()
    return ""


def _extract_json_block(text: str) -> str:
    """Extract JSON from markdown code blocks or direct JSON."""
    # Prefer ```json fenced blocks
    if "```" in text:
        match = re.search(r"```json\s*(.*?)```", text, flags=re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()
        # Try any fenced block
        match = re.search(r"```\w*\s*(.*?)```", text, flags=re.IGNORECASE | re.DOTALL)
        if match:
            candidate = match.group(1).strip()
            if candidate.startswith("{") and candidate.endswith("}"):
                return candidate
    # Check if text is direct JSON
    text = text.strip()
    if text.startswith("{") and text.endswith("}"):
        return text
    return ""


def extract_json(text: str) -> tuple[dict[str, Any] | None, str | None]:
    """Extract and parse JSON from text.

    Args:
        text: String potentially containing JSON

    Returns:
        Tuple of (parsed_dict_or_None, error_message_or_None)
    """
    if not text:
        return None, "Empty input"

    # Try JSON block first
    block = _extract_json_block(text)
    if not block:
        # Fallback to first JSON object
        block = _extract_first_json_object(text)
        if not block:
            return None, "No JSON found in output"

    try:
        return json.loads(block), None
    except json.JSONDecodeError as e:
        return None, f"Invalid JSON: {e}"


async def reflect_critic(
    client: AsyncOpenAI,
    model_name: str,
    report: dict[str, Any] | None,
    report_raw: str | None,
    validation: dict[str, Any],
    temperature: float = 0.2,
) -> dict[str, Any]:
    """Call Critic LLM to reflect on report quality.

    Args:
        client: OpenAI async client
        model_name: Model to use for reflection
        report: Parsed report JSON (may be None if parsing failed)
        report_raw: Raw LLM output
        validation: Validation result from validator
        temperature: Temperature for generation

    Returns:
        Dict with keys:
        - "verdict": "pass" | "fail"
        - "issues": list[str]
        - "reflection": str
    """
    # Prepare the prompt for the Critic
    prompt = _build_reflection_prompt(report, report_raw, validation)

    messages = [
        {"role": "system", "content": CRITIC_SYSTEM_PROMPT},
        {"role": "user", "content": prompt},
    ]

    try:
        response = await client.chat.completions.create(
            model=model_name,
            messages=messages,
            temperature=temperature,
        )
        content = response.choices[0].message.content or ""
    except Exception as e:
        # Return a default fail response if LLM call fails
        return {
            "verdict": "fail",
            "issues": [f"Critic反思调用失败: {e}"],
            "reflection": "LLM调用失败，无法生成反思",
        }

    # Parse the Critic's response
    review, error = extract_json(content)

    if review is None:
        # Failed to parse, return default response
        return {
            "verdict": "fail",
            "issues": [error or "Critic输出格式错误"],
            "reflection": f"Critic输出解析失败: {content[:200] if content else ''}",
        }

    # Ensure required fields exist
    if "verdict" not in review:
        review["verdict"] = "fail"
    if "issues" not in review:
        review["issues"] = []
    if "reflection" not in review:
        review["reflection"] = "无反思内容"

    return review


def _build_reflection_prompt(
    report: dict[str, Any] | None,
    report_raw: str | None,
    validation: dict[str, Any],
) -> str:
    """Build the reflection prompt for the Critic.

    Args:
        report: Parsed report JSON
        report_raw: Raw LLM output
        validation: Validation result

    Returns:
        Formatted prompt string
    """
    parts = [
        "## 验证结果",
        f"```json\n{json.dumps(validation, ensure_ascii=False, indent=2)}\n```",
        "",
    ]

    if report is not None:
        parts.extend(
            [
                "## 报告内容",
                f"```json\n{json.dumps(report, ensure_ascii=False, indent=2)}\n```",
                "",
            ]
        )
    else:
        parts.extend(
            [
                "## 报告解析失败",
                "报告未能解析为有效JSON。",
                "",
            ]
        )
        if report_raw:
            preview = report_raw[:1000]
            parts.extend(
                [
                    "原始输出预览:",
                    f"```\n{preview}\n```",
                    "",
                ]
            )

    parts.extend(
        [
            "请评审上述报告，返回JSON格式：",
            "```json",
            "{",
            '  "verdict": "pass|fail",',
            '  "issues": ["问题1", "问题2"],',
            '  "reflection": "本次问题的总结，用于下一轮改进"',
            "}",
            "```",
        ]
    )

    return "\n".join(parts)


async def reflect_with_rules(
    report: dict[str, Any] | None,
    validation: dict[str, Any],
) -> dict[str, Any]:
    """Generate reflection based on validation rules (no LLM call).

    This is a fallback method that generates reflection without calling LLM.
    Useful when LLM is unavailable or for faster validation.

    Args:
        report: Parsed report JSON
        validation: Validation result

    Returns:
        Dict with verdict, issues, reflection
    """
    issues = list(validation.get("issues", []))

    # Rule-based verdict
    if validation.get("ok"):
        verdict = "pass"
    else:
        verdict = "fail"

    # Generate reflection based on issues
    if verdict == "pass":
        reflection = "报告验证通过，结构完整，证据充分。"
    else:
        if len(issues) == 0:
            reflection = "报告质量未知，请重新检查。"
        elif len(issues) <= 3:
            reflection = f"报告存在{len(issues)}个问题，请修复: {issues[0]}"
        else:
            reflection = (
                f"报告存在{len(issues)}个问题，请重点检查: {', '.join(issues[:3])}"
            )

    return {
        "verdict": verdict,
        "issues": issues,
        "reflection": reflection,
    }


def should_continue_iteration(
    validation: dict[str, Any],
    review: dict[str, Any],
    current_attempt: int,
    max_attempts: int,
) -> bool:
    """Determine if we should continue to the next iteration.

    Args:
        validation: Validation result
        review: Critic review result
        current_attempt: Current attempt number (0-indexed)
        max_attempts: Maximum allowed attempts

    Returns:
        True if should continue, False if should stop
    """
    # Check if we've reached max attempts
    if current_attempt >= max_attempts - 1:
        return False

    # Check if validation passed
    validation_ok = validation.get("ok", False)

    # Check if critic passed
    verdict = review.get("verdict", "fail")

    # Continue only if either validation or review failed
    return not (validation_ok and verdict == "pass")
