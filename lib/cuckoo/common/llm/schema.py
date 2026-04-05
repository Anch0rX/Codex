"""Schema defaults and validation for llm_assessment output."""

from __future__ import annotations

import copy
import re
from typing import Any, Dict, List

from .utils import clamp_confidence, dedupe_preserve_order, normalize_severity, sanitize_text

ATTACK_ID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

DEFAULT_ASSESSMENT: Dict[str, Any] = {
    "status": "ok",
    "error_type": "",
    "message": "",
    "verdict": {"is_malicious": False, "confidence": 0.0, "severity": "unknown", "category": [], "family_hypotheses": []},
    "observed_facts": [],
    "attack_flow": [],
    "ttps": [],
    "iocs": {"hashes": [], "domains": [], "ips": [], "urls": [], "registry_keys": [], "file_paths": [], "mutexes": []},
    "key_findings": [],
    "analyst_actions": {"soc": [], "ir": [], "reverse": []},
    "uncertainties": [],
    "model_metadata": {"provider": "", "model": "", "prompt_version": ""},
}


def _to_list_str(values: Any, item_max: int = 180) -> List[str]:
    if not isinstance(values, list):
        return []
    return dedupe_preserve_order([sanitize_text(v, max_len=item_max, redact_pii=False) for v in values])


def apply_defaults(data: Dict[str, Any], metadata: Dict[str, str] | None = None) -> Dict[str, Any]:
    """Fill missing fields and coerce malformed model output into a stable schema."""
    metadata = metadata or {}
    result = copy.deepcopy(DEFAULT_ASSESSMENT)
    if not isinstance(data, dict):
        data = {}

    for key, value in data.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key].update(value)
        elif key in result:
            result[key] = value

    result["status"] = sanitize_text(result.get("status", "ok"), max_len=16, redact_pii=False) or "ok"
    result["error_type"] = sanitize_text(result.get("error_type", ""), max_len=48, redact_pii=False)
    result["message"] = sanitize_text(result.get("message", ""), max_len=200, redact_pii=False)

    verdict = result["verdict"] if isinstance(result.get("verdict"), dict) else {}
    result["verdict"] = {
        "is_malicious": bool(verdict.get("is_malicious", False)),
        "confidence": clamp_confidence(verdict.get("confidence", 0.0)),
        "severity": normalize_severity(verdict.get("severity"), allow_unknown=True),
        "category": _to_list_str(verdict.get("category"), 60),
        "family_hypotheses": [],
    }

    families = verdict.get("family_hypotheses", []) if isinstance(verdict.get("family_hypotheses"), list) else []
    for fam in families:
        if not isinstance(fam, dict):
            continue
        result["verdict"]["family_hypotheses"].append(
            {
                "name": sanitize_text(fam.get("name"), max_len=80, redact_pii=False),
                "confidence": clamp_confidence(fam.get("confidence", 0.0)),
                "reason": sanitize_text(fam.get("reason"), max_len=180, redact_pii=False),
                "evidence_ids": _to_list_str(fam.get("evidence_ids"), 60),
            }
        )

    for bucket in ("observed_facts", "attack_flow", "key_findings"):
        out = []
        values = result.get(bucket, []) if isinstance(result.get(bucket), list) else []
        for item in values:
            if not isinstance(item, dict):
                continue
            out.append(
                {
                    "title": sanitize_text(item.get("title"), max_len=120, redact_pii=False),
                    "summary" if bucket == "observed_facts" else ("details" if bucket == "attack_flow" else "why_it_matters"): sanitize_text(
                        item.get("summary") if bucket == "observed_facts" else item.get("details") if bucket == "attack_flow" else item.get("why_it_matters"),
                        max_len=220,
                        redact_pii=False,
                    ),
                    "step": item.get("step") if bucket == "attack_flow" and isinstance(item.get("step"), int) else None,
                    "severity": normalize_severity(item.get("severity"), allow_unknown=True) if bucket == "key_findings" else None,
                    "evidence_ids": _to_list_str(item.get("evidence_ids"), 60),
                }
            )
        cleaned = []
        for entry in out:
            if bucket == "observed_facts":
                cleaned.append({"title": entry["title"], "summary": entry["summary"], "evidence_ids": entry["evidence_ids"]})
            elif bucket == "attack_flow":
                cleaned.append({"step": entry["step"] or len(cleaned) + 1, "title": entry["title"], "details": entry["details"], "evidence_ids": entry["evidence_ids"]})
            else:
                cleaned.append({"title": entry["title"], "severity": entry["severity"], "why_it_matters": entry["why_it_matters"], "evidence_ids": entry["evidence_ids"]})
        result[bucket] = cleaned

    ttps_out = []
    for item in (result.get("ttps", []) if isinstance(result.get("ttps"), list) else []):
        if not isinstance(item, dict):
            continue
        attack_id = sanitize_text(item.get("id"), max_len=16, redact_pii=False).upper()
        if attack_id and not ATTACK_ID_RE.match(attack_id):
            continue
        ttps_out.append(
            {
                "id": attack_id,
                "name": sanitize_text(item.get("name"), max_len=80, redact_pii=False),
                "confidence": clamp_confidence(item.get("confidence", 0.0)),
                "reason": sanitize_text(item.get("reason"), max_len=180, redact_pii=False),
                "evidence_ids": _to_list_str(item.get("evidence_ids"), 60),
            }
        )
    result["ttps"] = ttps_out

    iocs = result.get("iocs", {}) if isinstance(result.get("iocs"), dict) else {}
    result["iocs"] = {k: sorted(_to_list_str(iocs.get(k), 280)) for k in ("hashes", "domains", "ips", "urls", "registry_keys", "file_paths", "mutexes")}

    actions = result.get("analyst_actions", {}) if isinstance(result.get("analyst_actions"), dict) else {}
    result["analyst_actions"] = {"soc": _to_list_str(actions.get("soc"), 200), "ir": _to_list_str(actions.get("ir"), 200), "reverse": _to_list_str(actions.get("reverse"), 200)}
    result["uncertainties"] = _to_list_str(result.get("uncertainties"), 220)

    model_meta = result.get("model_metadata", {}) if isinstance(result.get("model_metadata"), dict) else {}
    model_meta.update(metadata)
    result["model_metadata"] = {
        "provider": sanitize_text(model_meta.get("provider"), max_len=60, redact_pii=False),
        "model": sanitize_text(model_meta.get("model"), max_len=80, redact_pii=False),
        "prompt_version": sanitize_text(model_meta.get("prompt_version"), max_len=30, redact_pii=False),
    }

    return result
