from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from openai import AsyncOpenAI

from harbor.agents.base import BaseAgent
from harbor.environments.base import BaseEnvironment
from harbor.models.agent.context import AgentContext
from harbor.utils.env import resolve_env_vars

from pgt_agent.pgt_agent_impl.graph import prepare_graph_payload
from pgt_agent.pgt_agent_impl.parsing import extract_report_json
from pgt_agent.pgt_agent_impl.prompting import build_user_prompt
from pgt_agent.pgt_agent_impl.reporting import (
    build_error_markdown,
    build_fallback_markdown,
    json_to_markdown,
)
from pgt_agent.pgt_agent_impl.schema import REPORT_SCHEMA


class PGTAgent(BaseAgent):
    DEFAULT_SOURCE_GRAPH_PATH = "/app/source_graph.json"
    DEFAULT_REPORT_MD_PATH = "/logs/artifacts/report.md"
    DEFAULT_REPORT_JSON_PATH = "/logs/artifacts/report.json"
    DEFAULT_RAW_OUTPUT_PATH = "/logs/artifacts/report.raw.txt"

    @staticmethod
    def name() -> str:
        return "pgt-agent"

    def __init__(
        self,
        logs_dir: Path,
        model_name: str | None = None,
        source_graph_path: str = DEFAULT_SOURCE_GRAPH_PATH,
        report_md_path: str = DEFAULT_REPORT_MD_PATH,
        report_json_path: str = DEFAULT_REPORT_JSON_PATH,
        report_raw_path: str = DEFAULT_RAW_OUTPUT_PATH,
        large_graph_char_threshold: int = 220000,
        prompt_graph_char_limit: int = 180000,
        alert_detail_limit: int = 40,
        extra_env: dict[str, str] | None = None,
        **kwargs,
    ):
        super().__init__(logs_dir=logs_dir, model_name=model_name, **kwargs)
        self.source_graph_path = source_graph_path
        self.report_md_path = report_md_path
        self.report_json_path = report_json_path
        self.report_raw_path = report_raw_path
        self.large_graph_char_threshold = large_graph_char_threshold
        self.prompt_graph_char_limit = prompt_graph_char_limit
        self.alert_detail_limit = alert_detail_limit
        self.extra_env = dict(extra_env or {})

    def version(self) -> str:
        return "0.1.0"

    async def setup(self, environment: BaseEnvironment) -> None:
        await environment.exec(command="mkdir -p /logs/artifacts")

    async def run(
        self,
        instruction: str,
        environment: BaseEnvironment,
        context: AgentContext,
    ) -> None:
        await environment.exec(command="mkdir -p /logs/artifacts")

        try:
            raw_graph = await self._download_remote_text(
                environment=environment,
                remote_path=self.source_graph_path,
                local_name="source_graph.json",
            )
        except Exception as exc:  # noqa: BLE001
            error_report = build_error_markdown(
                title="读取溯源图失败",
                message=f"无法读取 {self.source_graph_path}: {exc}",
            )
            await self._write_reports(
                environment=environment,
                markdown=error_report,
                report_json={"error": str(exc)},
                raw_output=str(exc),
            )
            context.metadata = {"error": str(exc), "mode": "read-failed"}
            return

        prompt_payload, mode, mode_stats, parsed_graph = prepare_graph_payload(
            raw_graph=raw_graph,
            large_graph_char_threshold=self.large_graph_char_threshold,
            prompt_graph_char_limit=self.prompt_graph_char_limit,
            alert_detail_limit=self.alert_detail_limit,
        )

        messages = [
            {
                "role": "system",
                "content": (
                    "你是一位精通终端威胁检测与响应（TDR）的高级安全专家。"
                    "你擅长从溯源图中提炼攻击链、MITRE映射、IOC，并输出结构化报告。"
                ),
            },
            {
                "role": "user",
                "content": build_user_prompt(
                    instruction=instruction,
                    graph_payload=prompt_payload,
                    mode=mode,
                    mode_stats=mode_stats,
                    report_schema=REPORT_SCHEMA,
                ),
            },
        ]

        model_output = ""
        report_json: dict[str, Any] | None = None
        usage: dict[str, int] | None = None

        try:
            client = self._build_openai_client()
            model_output, usage = await self._chat_completion(
                client=client,
                model_name=self.model_name or "glm-4.7",
                messages=messages,
            )
            report_json = extract_report_json(model_output)

            if report_json is None:
                fix_messages = messages + [
                    {"role": "assistant", "content": model_output},
                    {
                        "role": "user",
                        "content": (
                            "你刚才的输出不是可解析的 JSON。"
                            "请仅输出符合 schema 的 JSON 对象，"
                            "不要输出 markdown、不要解释。"
                        ),
                    },
                ]
                repaired_output, repaired_usage = await self._chat_completion(
                    client=client,
                    model_name=self.model_name or "glm-4.7",
                    messages=fix_messages,
                )
                model_output = repaired_output
                report_json = extract_report_json(repaired_output)
                usage = self._merge_usage(usage, repaired_usage)

        except Exception as exc:  # noqa: BLE001
            self.logger.exception("LLM call failed: %s", exc)
            report_json = None
            model_output = f"[llm_error] {exc}"

        if report_json is not None:
            markdown = json_to_markdown(report_json)
            final_json = report_json
        else:
            markdown = build_fallback_markdown(
                instruction=instruction,
                source_graph_path=self.source_graph_path,
                raw_graph=raw_graph,
                parsed_graph=parsed_graph,
                llm_output=model_output,
            )
            final_json = {"raw_model_output": model_output, "mode": "fallback"}

        await self._write_reports(
            environment=environment,
            markdown=markdown,
            report_json=final_json,
            raw_output=model_output,
        )

        context.metadata = {
            "mode": mode,
            "mode_stats": mode_stats,
            "report_md_path": self.report_md_path,
            "report_json_path": self.report_json_path,
            "raw_output_path": self.report_raw_path,
        }
        if usage:
            context.n_input_tokens = usage.get("prompt_tokens")
            context.n_output_tokens = usage.get("completion_tokens")

    def _get_env(self, key: str) -> str | None:
        if key in self.extra_env:
            value = self.extra_env.get(key)
            if value:
                try:
                    resolved = resolve_env_vars({key: value})
                    resolved_value = resolved.get(key)
                    if resolved_value:
                        return resolved_value
                except Exception:
                    is_template = value.strip().startswith("${") and value.strip().endswith("}")
                    if value.strip() and not is_template:
                        return value

        value = os.environ.get(key)
        return value if value else None

    def _build_openai_client(self) -> AsyncOpenAI:
        api_key = self._get_env("OPENAI_API_KEY")
        if not api_key:
            raise ValueError(
                "OPENAI_API_KEY is required for PGTAgent. "
                "Please export it in host environment."
            )

        base_url = self._get_env("OPENAI_BASE_URL")
        if base_url:
            return AsyncOpenAI(api_key=api_key, base_url=base_url)

        return AsyncOpenAI(api_key=api_key)

    async def _chat_completion(
        self,
        client: AsyncOpenAI,
        model_name: str,
        messages: list[dict[str, str]],
    ) -> tuple[str, dict[str, int] | None]:
        response = await client.chat.completions.create(
            model=model_name,
            messages=messages,
            temperature=0.2,
        )
        content = response.choices[0].message.content or ""

        usage_payload = None
        usage = getattr(response, "usage", None)
        if usage is not None:
            usage_payload = {
                "prompt_tokens": int(getattr(usage, "prompt_tokens", 0) or 0),
                "completion_tokens": int(getattr(usage, "completion_tokens", 0) or 0),
            }

        return content, usage_payload

    def _merge_usage(
        self,
        first: dict[str, int] | None,
        second: dict[str, int] | None,
    ) -> dict[str, int] | None:
        if first is None and second is None:
            return None

        first_payload = dict(first or {})
        second_payload = dict(second or {})
        return {
            "prompt_tokens": int(first_payload.get("prompt_tokens", 0))
            + int(second_payload.get("prompt_tokens", 0)),
            "completion_tokens": int(first_payload.get("completion_tokens", 0))
            + int(second_payload.get("completion_tokens", 0)),
        }

    async def _download_remote_text(
        self,
        environment: BaseEnvironment,
        remote_path: str,
        local_name: str,
    ) -> str:
        local_path = self.logs_dir / local_name
        local_path.parent.mkdir(parents=True, exist_ok=True)
        await environment.download_file(source_path=remote_path, target_path=local_path)
        return local_path.read_text(encoding="utf-8", errors="ignore")

    async def _write_reports(
        self,
        environment: BaseEnvironment,
        markdown: str,
        report_json: dict[str, Any],
        raw_output: str,
    ) -> None:
        self.logs_dir.mkdir(parents=True, exist_ok=True)

        md_local = self.logs_dir / "report.md"
        json_local = self.logs_dir / "report.json"
        raw_local = self.logs_dir / "report.raw.txt"

        md_local.write_text(markdown, encoding="utf-8")
        json_local.write_text(
            json.dumps(report_json, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        raw_local.write_text(raw_output or "", encoding="utf-8")

        await environment.exec(command="mkdir -p /logs/artifacts")
        await environment.upload_file(source_path=md_local, target_path=self.report_md_path)
        await environment.upload_file(source_path=json_local, target_path=self.report_json_path)
        await environment.upload_file(source_path=raw_local, target_path=self.report_raw_path)
