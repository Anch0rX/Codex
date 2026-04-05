"""Normalize CAPE results into a compact evidence package for LLM analysis."""

from __future__ import annotations

from typing import Any, Dict, List

from .heuristics import (
    detect_credential_access,
    detect_defense_evasion,
    detect_discovery,
    detect_injection,
    detect_lolbins,
    detect_persistence,
    detect_ransomware_signals,
    extract_high_value_iocs,
)
from .utils import canonicalize_domain, canonicalize_ip, canonicalize_url, sanitize_list, sanitize_text, truncate_list


def _safe_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _safe_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def normalize_results(results: Dict[str, Any], options: Dict[str, Any] | None = None) -> Dict[str, Any]:
    """Build a compact evidence package from raw CAPE results."""
    results = _safe_dict(results)
    options = options or {}
    redact_pii = bool(options.get("redact_pii", True))
    max_events = int(options.get("max_input_events", 80))
    max_processes = int(options.get("max_processes", 20))
    max_signatures = int(options.get("max_signatures", 50))
    max_network = int(options.get("max_network_artifacts", 50))

    info = _safe_dict(results.get("info"))
    target = _safe_dict(results.get("target"))
    target_file = _safe_dict(target.get("file"))
    behavior = _safe_dict(results.get("behavior"))
    summary = _safe_dict(behavior.get("summary"))
    processes = _safe_list(behavior.get("processes"))
    signatures = _safe_list(results.get("signatures"))
    network = _safe_dict(results.get("network"))

    behavior_summary = {
        "files": sanitize_list(summary.get("files"), max_events, redact_pii=redact_pii),
        "keys": sanitize_list(summary.get("keys"), max_events, redact_pii=redact_pii),
        "mutexes": sanitize_list(summary.get("mutexes"), max_events, redact_pii=False),
        "executed_commands": sanitize_list(summary.get("executed_commands"), max_events, item_max_len=220, redact_pii=redact_pii),
        "services": sanitize_list(summary.get("services"), max_events, redact_pii=redact_pii),
        "scheduled_tasks": sanitize_list(summary.get("scheduled_tasks"), max_events, redact_pii=redact_pii),
        "injection_signals": sanitize_list(summary.get("injection_signals"), max_events, redact_pii=False),
    }

    process_highlights = []
    for idx, proc in enumerate(processes, start=1):
        if len(process_highlights) >= max_processes or not isinstance(proc, dict):
            continue
        calls = _safe_list(proc.get("calls"))
        api_names = [sanitize_text(c.get("api"), max_len=80, redact_pii=False) for c in calls if isinstance(c, dict) and c.get("api")]
        process_highlights.append(
            {
                "id": "proc_%d" % idx,
                "process_name": sanitize_text(proc.get("process_name"), max_len=120, redact_pii=False),
                "pid": proc.get("process_id") if isinstance(proc.get("process_id"), int) else None,
                "suspicious_api_calls": truncate_list(api_names, 12),
                "command_line": sanitize_text(proc.get("command_line"), max_len=220, redact_pii=redact_pii),
            }
        )

    normalized_signatures = []
    for idx, sig in enumerate(signatures, start=1):
        if len(normalized_signatures) >= max_signatures or not isinstance(sig, dict):
            continue
        normalized_signatures.append(
            {
                "id": "sig_%d" % idx,
                "name": sanitize_text(sig.get("name"), max_len=120, redact_pii=False),
                "severity": sig.get("severity", 1),
                "description": sanitize_text(sig.get("description"), max_len=320, redact_pii=redact_pii),
                "families": sanitize_list(sig.get("families"), 8, item_max_len=80, redact_pii=False),
                "ttp": sanitize_list(sig.get("ttp") or sig.get("mitre") or [], 8, item_max_len=30, redact_pii=False),
            }
        )

    domains = [canonicalize_domain(d.get("domain")) for d in _safe_list(network.get("domains")) if isinstance(d, dict) and d.get("domain")]
    ips = [canonicalize_ip(h.get("ip")) for h in _safe_list(network.get("hosts")) if isinstance(h, dict) and h.get("ip")]
    urls = [canonicalize_url(h.get("uri") or h.get("url")) for h in _safe_list(network.get("http")) if isinstance(h, dict)]

    ioc_candidates = {
        "hashes": sanitize_list([target_file.get("md5"), target_file.get("sha1"), target_file.get("sha256")], 10, redact_pii=False),
        "domains": truncate_list([d for d in domains if d], max_network),
        "ips": truncate_list([i for i in ips if i], max_network),
        "urls": truncate_list([u for u in urls if u], max_network),
        "registry_keys": behavior_summary["keys"],
        "file_paths": behavior_summary["files"],
        "mutexes": behavior_summary["mutexes"],
    }

    ioc_candidates = extract_high_value_iocs(ioc_candidates)

    risk_indicators = []
    for detector in (detect_persistence, detect_discovery, detect_credential_access, detect_ransomware_signals, detect_defense_evasion):
        risk_indicators.extend(detector(behavior_summary))
    risk_indicators.extend(detect_injection(process_highlights))
    risk_indicators.extend(detect_lolbins(process_highlights))
    for idx, risk in enumerate(risk_indicators, start=1):
        risk["id"] = "risk_%d" % idx

    network_highlights = []
    for idx, domain in enumerate(ioc_candidates["domains"][:10], start=1):
        network_highlights.append({"id": "net_%d" % idx, "type": "domain", "value": domain})

    return {
        "sample": {
            "task_id": info.get("id"),
            "category": info.get("category") or target.get("category"),
            "submitted_filename": sanitize_text(target_file.get("name"), max_len=120, redact_pii=False),
            "sha256": target_file.get("sha256"),
            "sha1": target_file.get("sha1"),
            "md5": target_file.get("md5"),
            "type": sanitize_text(target_file.get("type"), max_len=120, redact_pii=False),
        },
        "high_level_scores": {"malscore": results.get("malscore"), "signature_count": len(signatures), "process_count": len(processes)},
        "detections": _safe_dict(results.get("detections")),
        "behavior_summary": behavior_summary,
        "process_highlights": process_highlights,
        "network_summary": {
            "domains": ioc_candidates["domains"],
            "hosts": ioc_candidates["ips"],
            "http": sanitize_list(network.get("http"), max_network, item_max_len=180, redact_pii=redact_pii),
            "dns": sanitize_list(network.get("dns"), max_network, item_max_len=180, redact_pii=redact_pii),
            "tcp": sanitize_list(network.get("tcp"), max_network, item_max_len=160, redact_pii=False),
            "udp": sanitize_list(network.get("udp"), max_network, item_max_len=160, redact_pii=False),
        },
        "network_highlights": network_highlights,
        "signatures": normalized_signatures,
        "config_extraction": _safe_dict(results.get("CAPE")) or _safe_dict(results.get("cape")),
        "ioc_candidates": ioc_candidates,
        "risk_indicators": risk_indicators,
        "raw_evidence_refs": ["info", "target", "detections", "signatures", "behavior.summary", "behavior.processes", "network", "dropped", "procdump", "CAPE"],
    }
