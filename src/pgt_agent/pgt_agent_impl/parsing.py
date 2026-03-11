from __future__ import annotations

import json
import re
from typing import Any


def extract_report_json(text: str) -> dict[str, Any] | None:
    candidate = _extract_json_block(text)
    if not candidate:
        candidate = _extract_first_json_object(text)
    if not candidate:
        return None

    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        return None

    if isinstance(parsed, dict):
        return parsed
    return None


def _extract_json_block(text: str) -> str:
    if "```" not in text:
        return ""

    match = re.search(r"```json\s*(.*?)```", text, flags=re.I | re.S)
    if match:
        return match.group(1).strip()

    match = re.search(r"```\w*\s*(.*?)```", text, flags=re.I | re.S)
    if match:
        candidate = match.group(1).strip()
        if candidate.startswith("{") and candidate.endswith("}"):
            return candidate

    return ""


def _extract_first_json_object(text: str) -> str:
    source = text.strip()
    start = source.find("{")
    if start < 0:
        return ""

    depth = 0
    in_string = False
    escaped = False

    for idx in range(start, len(source)):
        char = source[idx]
        if in_string:
            if escaped:
                escaped = False
                continue
            if char == "\\":
                escaped = True
                continue
            if char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
            continue

        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start : idx + 1].strip()

    return ""
