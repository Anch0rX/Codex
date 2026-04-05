import json
from pathlib import Path
from urllib import error

from lib.cuckoo.common.llm.client import LLMClient
from lib.cuckoo.common.llm.normalizer import normalize_results
from lib.cuckoo.common.llm.postprocess import build_error_stub, parse_and_validate_llm_output, render_markdown_summary
from lib.cuckoo.common.llm.utils import clamp_confidence, sanitize_text
from modules.reporting.llm_assessment import LlmAssessment


def test_normalize_results_empty_and_missing_fields():
    data = normalize_results({}, {"max_input_events": 3})
    assert data["sample"]["task_id"] is None
    assert isinstance(data["behavior_summary"]["files"], list)
    assert data["signatures"] == []


def test_normalize_results_handles_unexpected_types_and_limits():
    results = {
        "behavior": {"summary": {"files": ["a", "a", "b", "c"], "keys": "bad"}, "processes": ["bad", {"process_name": "powershell.exe", "calls": [{"api": "CreateRemoteThread"}]}, {"process_name": "cmd.exe"}]},
        "network": {"domains": [{"domain": "A.COM"}, {"domain": "a.com"}]},
    }
    data = normalize_results(results, {"max_input_events": 2, "max_processes": 1})
    assert data["behavior_summary"]["files"] == ["a", "b"]
    assert len(data["process_highlights"]) == 1
    assert data["ioc_candidates"]["domains"] == ["a.com"]


def test_sanitizer_control_chars_and_fence_removal():
    text = "abc\x00\x01```json\n{\"a\":1}\n```def"
    out = sanitize_text(text, max_len=30)
    assert "[code_block_removed]" in out
    assert "\x00" not in out


def test_sanitizer_truncation():
    out = sanitize_text("x" * 500, max_len=40)
    assert len(out) == 40


def test_schema_parsing_fenced_and_mixed_text_and_defaults():
    raw = "analysis done\n```json\n{\"verdict\": {\"confidence\": 2, \"severity\": \"Severe\"}}\n```\nthanks"
    parsed = parse_and_validate_llm_output(raw, metadata={"provider": "p", "model": "m", "prompt_version": "v1"})
    assert parsed["verdict"]["confidence"] == 1.0
    assert parsed["verdict"]["severity"] == "high"
    assert parsed["model_metadata"]["provider"] == "p"


def test_schema_invalid_attack_id_and_evidence_types_fixed():
    payload = {
        "ttps": [{"id": "BAD", "name": "x"}, {"id": "T1055.012", "name": "ok", "evidence_ids": "bad"}],
        "observed_facts": [{"title": "x", "summary": "y", "evidence_ids": "oops"}],
        "iocs": {"domains": ["b.com", "a.com", "a.com", ""]},
    }
    parsed = parse_and_validate_llm_output(json.dumps(payload))
    assert len(parsed["ttps"]) == 1
    assert parsed["ttps"][0]["id"] == "T1055.012"
    assert parsed["observed_facts"][0]["evidence_ids"] == []
    assert parsed["iocs"]["domains"] == ["a.com", "b.com"]


def test_invalid_json_returns_error_stub():
    parsed = parse_and_validate_llm_output("not-json")
    assert parsed["status"] == "error"
    assert parsed["error_type"] == "invalid_json"


def test_client_timeout_http_nonjson_empty_content(monkeypatch):
    client = LLMClient("openai_compatible", "http://localhost:9", "", "test", timeout=1)

    monkeypatch.setattr(client, "_post_json", lambda payload: (_ for _ in ()).throw(TimeoutError()))
    assert client.chat_completion("s", "u")["error"] == "timeout"

    monkeypatch.setattr(client, "_post_json", lambda payload: (_ for _ in ()).throw(error.HTTPError("http://x", 500, "err", None, None)))
    assert client.chat_completion("s", "u")["error"] == "http_error"

    monkeypatch.setattr(client, "_post_json", lambda payload: (_ for _ in ()).throw(ValueError("bad json")))
    assert client.chat_completion("s", "u")["error"] == "invalid_response"

    monkeypatch.setattr(client, "_post_json", lambda payload: {"choices": []})
    assert client.chat_completion("s", "u")["error"] == "empty_response"

    monkeypatch.setattr(client, "_post_json", lambda payload: {"choices": [{"message": {"content": ""}}]})
    assert client.chat_completion("s", "u")["error"] == "empty_content"


def test_client_unsupported_provider():
    client = LLMClient("other", "http://x", "", "m")
    assert client.chat_completion("s", "u")["error"] == "unsupported_provider"


def test_reporting_enabled_false(monkeypatch, tmp_path: Path):
    module = LlmAssessment()
    module.reports_path = str(tmp_path)
    module.options = {"enabled": "no"}
    called = {"value": False}

    def fake(*args, **kwargs):
        called["value"] = True
        return {"ok": True, "content": "{}"}

    monkeypatch.setattr(LLMClient, "chat_completion", fake)
    assert module.run({}) is None
    assert called["value"] is False


def test_reporting_attach_toggle_and_nonfatal_client_failure(tmp_path: Path, monkeypatch):
    module = LlmAssessment()
    module.reports_path = str(tmp_path)
    module.options = {"enabled": "yes", "attach_to_results": "yes", "store_markdown": "yes"}
    monkeypatch.setattr(LLMClient, "chat_completion", lambda *a, **k: {"ok": False, "error": "timeout"})
    results = {}
    out = module.run(results)
    assert out["status"] == "error"
    assert "llm_assessment" in results
    assert (tmp_path / "llm_summary.json").exists()


def test_reporting_json_success_markdown_failure_is_nonfatal(tmp_path: Path, monkeypatch):
    module = LlmAssessment()
    module.reports_path = str(tmp_path)
    module.options = {"enabled": "yes", "store_markdown": "yes"}
    monkeypatch.setattr(LLMClient, "chat_completion", lambda *a, **k: {"ok": True, "content": "{}"})
    monkeypatch.setattr("modules.reporting.llm_assessment.render_markdown_summary", lambda assessment: (_ for _ in ()).throw(RuntimeError("md fail")))

    out = module.run({})
    assert out["status"] == "ok"
    assert (tmp_path / "llm_summary.json").exists()


def test_markdown_renderer_empty_and_long_fields():
    assessment = build_error_stub("x", "y", {"provider": "p", "model": "m", "prompt_version": "v1"})
    assessment["key_findings"] = [{"title": "T" * 300, "severity": "critical", "why_it_matters": "W" * 300, "evidence_ids": ["sig_1"]}]
    md = render_markdown_summary(assessment)
    assert "## Executive Verdict" in md
    assert "## Uncertainties" in md
    assert len(max(md.splitlines(), key=len)) < 400


def test_helper_clamp_confidence():
    assert clamp_confidence(9) == 1.0
    assert clamp_confidence(-1) == 0.0
