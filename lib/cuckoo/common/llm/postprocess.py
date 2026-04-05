"""Post processing for LLM response parsing, schema validation, and markdown rendering."""

from __future__ import annotations

import json
import re
from typing import Any, Dict

from .schema import apply_defaults
from .utils import clamp_confidence, sanitize_text

FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)
JSON_OBJ_RE = re.compile(r"\{.*\}", re.DOTALL)


def extract_json_blob(content: str) -> str:
    """Extract likely JSON object from fenced or mixed LLM output."""
    text = content.strip()
    fence_match = FENCE_RE.search(text)
    if fence_match:
        text = fence_match.group(1).strip()

    if text.startswith("{") and text.endswith("}"):
        return text

    obj_match = JSON_OBJ_RE.search(text)
    return obj_match.group(0).strip() if obj_match else text


def build_error_stub(error_type: str, message: str, metadata: Dict[str, str] | None = None) -> Dict[str, Any]:
    """Build minimal stable JSON on failures."""
    return apply_defaults(
        {
            "status": "error",
            "error_type": sanitize_text(error_type, max_len=48, redact_pii=False),
            "message": sanitize_text(message, max_len=180, redact_pii=False),
            "uncertainties": ["LLM assessment degraded due to upstream error."],
        },
        metadata=metadata,
    )


def parse_and_validate_llm_output(raw_content: str, metadata: Dict[str, str] | None = None) -> Dict[str, Any]:
    """Parse raw LLM output and return stable schema with defaults."""
    metadata = metadata or {}
    try:
        parsed = json.loads(extract_json_blob(raw_content))
    except Exception:
        return build_error_stub("invalid_json", "Model output could not be parsed as JSON.", metadata=metadata)

    result = apply_defaults(parsed, metadata=metadata)
    result["verdict"]["confidence"] = clamp_confidence(result["verdict"].get("confidence", 0.0))
    return result


def _truncate_for_md(value: Any, size: int = 180) -> str:
    text = sanitize_text(value, max_len=size, redact_pii=False)
    return text if len(text) <= size else text[:size] + "..."


def render_markdown_summary(assessment: Dict[str, Any]) -> str:
    """Render markdown report from validated assessment JSON."""
    verdict = assessment.get("verdict", {})
    lines = [
        "# LLM Assessment Summary",
        "",
        "## Executive Verdict",
        "- Status: `%s`" % assessment.get("status", "ok"),
        "- Malicious: `%s`" % verdict.get("is_malicious"),
        "- Confidence: `%.2f`" % clamp_confidence(verdict.get("confidence", 0.0)),
        "- Severity: `%s`" % verdict.get("severity", "unknown"),
    ]

    families = verdict.get("family_hypotheses", [])
    lines.extend(["", "### Family Hypotheses"])
    if families:
        for fam in families:
            lines.append("- **%s** (%.2f): %s | evidence: %s" % (_truncate_for_md(fam.get("name"), 80) or "N/A", clamp_confidence(fam.get("confidence", 0.0)), _truncate_for_md(fam.get("reason"), 140), ",".join(fam.get("evidence_ids", [])) or "n/a"))
    else:
        lines.append("- not observed")

    lines.extend(["", "## Key Findings"])
    findings = assessment.get("key_findings", [])
    if findings:
        for finding in findings:
            lines.append("- **%s** (%s): %s | evidence: %s" % (_truncate_for_md(finding.get("title"), 100), finding.get("severity", "unknown"), _truncate_for_md(finding.get("why_it_matters"), 150), ",".join(finding.get("evidence_ids", [])) or "n/a"))
    else:
        lines.append("- not observed")

    lines.extend(["", "## Attack Flow"])
    flow = assessment.get("attack_flow", [])
    if flow:
        for step in flow:
            lines.append("%s. **%s** - %s (evidence: %s)" % (step.get("step", "?"), _truncate_for_md(step.get("title"), 80), _truncate_for_md(step.get("details"), 140), ",".join(step.get("evidence_ids", [])) or "n/a"))
    else:
        lines.append("- insufficient evidence")

    lines.extend(["", "## ATT&CK / TTP Assessment"])
    ttps = assessment.get("ttps", [])
    if ttps:
        for ttp in ttps:
            lines.append("- `%s` %s (confidence %.2f) evidence: %s" % (ttp.get("id") or "N/A", _truncate_for_md(ttp.get("name"), 80), clamp_confidence(ttp.get("confidence", 0.0)), ",".join(ttp.get("evidence_ids", [])) or "n/a"))
    else:
        lines.append("- not observed")

    lines.extend(["", "## IOCs"])
    iocs = assessment.get("iocs", {})
    for key in ("hashes", "domains", "ips", "urls", "registry_keys", "file_paths", "mutexes"):
        values = iocs.get(key, [])
        lines.append("- %s: %s" % (key, ", ".join(_truncate_for_md(v, 90) for v in values[:10]) if values else "not observed"))

    lines.extend(["", "## Recommended Actions"])
    actions = assessment.get("analyst_actions", {})
    for bucket in ("soc", "ir", "reverse"):
        entries = actions.get(bucket, [])
        lines.append("- %s: %s" % (bucket.upper(), "; ".join(_truncate_for_md(e, 120) for e in entries) if entries else "not provided"))

    lines.extend(["", "## Uncertainties"])
    uncertainties = assessment.get("uncertainties", [])
    lines.extend(["- %s" % _truncate_for_md(u, 200) for u in uncertainties] if uncertainties else ["- none"])
    return "\n".join(lines) + "\n"
