from __future__ import annotations

import re
from typing import Any


def text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default


def md_cell(value: str) -> str:
    return text(value).replace("|", "/").replace("\n", " ").strip()


def extract_edges(graph: dict[str, Any]) -> list[dict[str, Any]]:
    raw_edges = graph.get("provenance_graph_edges")
    if isinstance(raw_edges, list):
        return [e for e in raw_edges if isinstance(e, dict)]
    return []


def is_alert_edge(edge: dict[str, Any]) -> bool:
    if edge.get("is_alert") is True:
        return True
    if as_list(edge.get("alerts")):
        return True
    return False


def edge_time(edge: dict[str, Any]) -> int:
    return safe_int(edge.get("event_time"), 0)


def class_to_tactic(class_name: str) -> str:
    mapping = {
        "CLASS_PROCESS_ACTIVITY": "执行/进程活动",
        "CLASS_SCRIPT_ACTIVITY": "脚本执行",
        "CLASS_NETWORK_ACTIVITY": "网络通信",
        "CLASS_FILE_ACTIVITY": "文件操作",
        "CLASS_API_ACTIVITY": "防御规避/API调用",
    }
    return mapping.get(class_name, "可疑行为")


def class_to_mitre(class_name: str) -> str:
    mapping = {
        "CLASS_PROCESS_ACTIVITY": "TA0002, T1059",
        "CLASS_SCRIPT_ACTIVITY": "TA0002, T1059.001",
        "CLASS_NETWORK_ACTIVITY": "TA0011, T1071",
        "CLASS_FILE_ACTIVITY": "TA0005, T1070",
        "CLASS_API_ACTIVITY": "TA0005, T1106",
    }
    return mapping.get(class_name, "TA0005")


def node_label(node: dict[str, Any]) -> str:
    name = text(node.get("name"))
    if name:
        return name
    entity = as_dict(node.get("entity"))
    file_obj = as_dict(entity.get("file"))
    return text(file_obj.get("path") or file_obj.get("name") or "unknown")


def node_id(node: dict[str, Any]) -> str:
    current_id = text(node.get("id"))
    if current_id:
        return current_id
    return node_label(node)


def skeleton_node(node: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": node_id(node),
        "type": text(node.get("type")) or "unknown",
        "name": node_label(node),
        "is_alert": bool(node.get("is_alert") is True),
    }


def node_detail(node: dict[str, Any]) -> dict[str, Any]:
    entity = as_dict(node.get("entity"))
    file_obj = as_dict(entity.get("file"))
    return {
        "id": node_id(node),
        "type": text(node.get("type")),
        "name": node_label(node),
        "is_alert": bool(node.get("is_alert") is True),
        "cmd_line": text(entity.get("cmd_line"))[:500],
        "path": text(file_obj.get("path"))[:500],
        "pid": entity.get("pid"),
    }


def normalize_ioc_type(ioc_type: str, value: str) -> str:
    normalized_type = text(ioc_type).lower()
    ioc_value = text(value)
    if normalized_type in {"ip", "ipv4", "ipv6"} or re.fullmatch(
        r"(?:\d{1,3}\.){3}\d{1,3}", ioc_value
    ):
        return "IP"
    if normalized_type in {"domain", "domain_name", "域名"} or re.fullmatch(
        r"[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", ioc_value
    ):
        return "域名"
    if normalized_type in {"url", "uri"} or ioc_value.lower().startswith(
        ("http://", "https://")
    ):
        return "URL"
    if normalized_type in {
        "md5",
        "sha1",
        "sha256",
        "hash",
        "file_hash",
        "文件哈希",
    } or re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", ioc_value):
        return "文件哈希"
    return "文件路径"
