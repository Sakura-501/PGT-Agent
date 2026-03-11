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

from pgt_agent.brain import (
    REACT_SYSTEM_PROMPT,
    build_user_prompt,
    reflect_critic,
    should_continue_iteration,
    validate_report,
)
from pgt_agent.pgt_agent_impl.graph import prepare_graph_payload
from pgt_agent.pgt_agent_impl.parsing import extract_report_json
from pgt_agent.pgt_agent_impl.reporting import (
    build_error_markdown,
    build_fallback_markdown,
    json_to_markdown,
)


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
        max_attempts: int = 2,
        reflection_enabled: bool = True,
        reflect_model: str | None = None,
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
        self.max_attempts = max_attempts
        self.reflection_enabled = reflection_enabled
        self.reflect_model = reflect_model

    def version(self) -> str:
        return "0.2.0"  # ReAct + Reflection framework

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

        # ReAct + Reflection loop
        client = self._build_openai_client()
        reflections: list[str] = []
        max_attempts = int(self._get_env("MAX_ATTEMPTS") or str(self.max_attempts))
        reflect_enabled = self.reflection_enabled and self._truthy(
            self._get_env("REFLECTION_ENABLED")
        )

        report_json: dict[str, Any] | None = None
        model_output = ""
        total_usage: dict[str, int] = {}
        final_validation: dict[str, Any] = {}
        final_review: dict[str, Any] = {}

        for attempt in range(max_attempts):
            self.logger.info(f"Attempt {attempt + 1}/{max_attempts}")

            # Build prompt with historical reflections
            user_prompt = build_user_prompt(
                instruction=instruction,
                graph_payload=prompt_payload,
                mode=mode,
                mode_stats=mode_stats,
                reflections=reflections,
            )

            messages = [
                {"role": "system", "content": REACT_SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ]

            # LLM call
            try:
                output, usage = await self._chat_completion(
                    client=client,
                    model_name=self.model_name or "glm-4.7",
                    messages=messages,
                )
                model_output = output
                if usage:
                    total_usage = self._merge_usage(total_usage, usage)

            except Exception as exc:  # noqa: BLE001
                self.logger.exception("LLM call failed: %s", exc)
                model_output = f"[llm_error] {exc}"
                report_json = None
                break

            # Parse report
            report_json = extract_report_json(model_output)

            # Validate report
            final_validation = validate_report(
                report=report_json,
                graph=parsed_graph,
            )

            # Reflection
            if reflect_enabled and should_continue_iteration(
                validation=final_validation,
                review={},
                current_attempt=attempt,
                max_attempts=max_attempts,
            ):
                reflect_model = self.reflect_model or self.model_name or "glm-4.7"
                final_review = await reflect_critic(
                    client=client,
                    model_name=reflect_model,
                    report=report_json,
                    report_raw=model_output,
                    validation=final_validation,
                )

                reflection = final_review.get("reflection", "")
                if reflection:
                    reflections.append(reflection)
                    self.logger.info(f"Added reflection: {reflection[:100]}...")

                # Check if should continue
                if not should_continue_iteration(
                    validation=final_validation,
                    review=final_review,
                    current_attempt=attempt,
                    max_attempts=max_attempts,
                ):
                    self.logger.info(f"Success on attempt {attempt + 1}")
                    break
            else:
                # No reflection, break after validation check
                if final_validation.get("ok"):
                    break
                # If not ok and no more attempts, continue
                if attempt >= max_attempts - 1:
                    break

        # Generate final report
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
            final_json = {
                "raw_model_output": model_output,
                "mode": "fallback",
                "validation": final_validation,
                "review": final_review,
            }

        # Add validation and review to final output
        if final_validation:
            final_json["_validation"] = final_validation
        if final_review:
            final_json["_review"] = final_review
        if reflections:
            final_json["_reflections"] = reflections

        await self._write_reports(
            environment=environment,
            markdown=markdown,
            report_json=final_json,
            raw_output=model_output,
        )

        context.metadata = {
            "mode": mode,
            "mode_stats": mode_stats,
            "attempts": len(reflections) + 1,
            "validation_ok": final_validation.get("ok", False),
            "verdict": final_review.get("verdict", "unknown"),
            "report_md_path": self.report_md_path,
            "report_json_path": self.report_json_path,
            "raw_output_path": self.report_raw_path,
        }
        if total_usage:
            context.n_input_tokens = total_usage.get("prompt_tokens")
            context.n_output_tokens = total_usage.get("completion_tokens")

    def _truthy(self, value: str | None) -> bool:
        if not value:
            return False
        return value.strip().lower() in ("1", "true", "yes", "on")

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
                    is_template = value.strip().startswith(
                        "${"
                    ) and value.strip().endswith("}")
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
        await environment.upload_file(
            source_path=md_local, target_path=self.report_md_path
        )
        await environment.upload_file(
            source_path=json_local, target_path=self.report_json_path
        )
        await environment.upload_file(
            source_path=raw_local, target_path=self.report_raw_path
        )
