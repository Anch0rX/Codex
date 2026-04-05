"""CAPE reporting module: LLM-based structured assessment."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict

from lib.cuckoo.common.llm import LLMClient, build_error_stub, build_prompts, normalize_results, parse_and_validate_llm_output, render_markdown_summary

log = logging.getLogger(__name__)


class LlmAssessment:
    """Reporting module entrypoint for post-analysis LLM assessment."""

    order = 999

    def __init__(self) -> None:
        self.options: Dict[str, Any] = {}
        self.reports_path = "reports"

    def _bool(self, key: str, default: bool) -> bool:
        value = self.options.get(key, default)
        return value if isinstance(value, bool) else str(value).strip().lower() in {"1", "yes", "true", "on"}

    def _int(self, key: str, default: int) -> int:
        try:
            return int(self.options.get(key, default))
        except (TypeError, ValueError):
            return default

    def _float(self, key: str, default: float) -> float:
        try:
            return float(self.options.get(key, default))
        except (TypeError, ValueError):
            return default

    def _metadata(self) -> Dict[str, str]:
        return {
            "provider": str(self.options.get("provider", "openai_compatible")),
            "model": str(self.options.get("model", "")),
            "prompt_version": str(self.options.get("system_prompt_version", "v1")),
        }

    def run(self, results: Dict[str, Any]) -> Dict[str, Any] | None:
        """Run module; never break main reporting pipeline on failure."""
        if not self._bool("enabled", False):
            return None

        metadata = self._metadata()
        assessment = None
        try:
            evidence = normalize_results(results, self.options)
            system_prompt, user_prompt = build_prompts(evidence, prompt_version=metadata["prompt_version"])
            client = LLMClient(
                provider=metadata["provider"],
                endpoint=str(self.options.get("endpoint", "http://127.0.0.1:8001/v1/chat/completions")),
                api_key=str(self.options.get("api_key", "")),
                model=metadata["model"] or "qwen2.5-72b-instruct",
                timeout=self._int("timeout", 120),
                verify_tls=self._bool("verify_tls", True),
            )
            response = client.chat_completion(system_prompt=system_prompt, user_prompt=user_prompt, temperature=self._float("temperature", 0.0), max_tokens=self._int("max_tokens", 2200))
            if not response.get("ok"):
                assessment = build_error_stub("llm_invocation_failed", "LLM invocation failed: %s" % response.get("error", "unknown"), metadata)
            else:
                assessment = parse_and_validate_llm_output(response.get("content", "{}"), metadata=metadata)
        except Exception as exc:
            log.warning("llm_assessment execution failed, fallback to error stub: %s", exc.__class__.__name__)
            assessment = build_error_stub("module_exception", "llm_assessment internal exception", metadata)

        self._write_outputs(assessment)
        if self._bool("attach_to_results", False):
            results["llm_assessment"] = assessment
        return assessment

    def _write_outputs(self, assessment: Dict[str, Any]) -> None:
        reports_dir = Path(self.reports_path)
        try:
            reports_dir.mkdir(parents=True, exist_ok=True)
            (reports_dir / "llm_summary.json").write_text(json.dumps(assessment, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as exc:
            log.warning("llm_assessment failed to write json output: %s", exc.__class__.__name__)

        if not self._bool("store_markdown", True):
            return
        try:
            markdown = render_markdown_summary(assessment)
            (reports_dir / "llm_summary.md").write_text(markdown, encoding="utf-8")
        except Exception as exc:
            log.warning("llm_assessment failed to write markdown output: %s", exc.__class__.__name__)
