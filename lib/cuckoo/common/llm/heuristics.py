"""Rule-based extraction helpers for high-value malware behavior."""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List

from .utils import dedupe_preserve_order, normalize_severity, sanitize_text

LOLBINS = {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "regsvr32.exe", "rundll32.exe", "wmic.exe", "certutil.exe", "bitsadmin.exe"}


def _contains_any(values: Iterable[str], needles: Iterable[str]) -> bool:
    joined = " ".join(v.lower() for v in values if isinstance(v, str))
    return any(n.lower() in joined for n in needles)


def _risk(title: str, severity: str, reason: str, evidence_ref: str) -> Dict[str, str]:
    return {
        "title": sanitize_text(title, max_len=80, redact_pii=False),
        "severity": normalize_severity(severity),
        "reason": sanitize_text(reason, max_len=180, redact_pii=False),
        "evidence_ref": sanitize_text(evidence_ref, max_len=60, redact_pii=False),
    }


def detect_persistence(summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    keys = summary.get("keys", [])
    commands = summary.get("executed_commands", [])
    if _contains_any(keys, ["run\\", "runonce", "startup"]) or _contains_any(commands, ["schtasks", "sc create"]):
        return [_risk("Persistence behavior observed", "high", "Autostart registry or task/service creation activity found", "behavior_summary")]
    return []


def detect_injection(processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    apis = ["writeprocessmemory", "createremotethread", "ntunmapviewofsection", "queueuserapc"]
    for proc in processes:
        calls = [str(x).lower() for x in proc.get("suspicious_api_calls", [])]
        if any(api in calls for api in apis):
            return [_risk("Process injection-like activity", "critical", "Injection-related APIs observed", proc.get("id", "process_highlights"))]
    return []


def detect_lolbins(processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for proc in processes:
        name = str(proc.get("process_name", "")).lower()
        if name in LOLBINS:
            out.append(_risk("LOLBins execution", "medium", "Potentially abused built-in binary executed", proc.get("id", "process_highlights")))
    return out


def detect_discovery(summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    if _contains_any(summary.get("executed_commands", []), ["whoami", "ipconfig", "net user", "systeminfo", "nltest"]):
        return [_risk("Discovery commands detected", "medium", "Reconnaissance-like commands observed", "behavior_summary.executed_commands")]
    return []


def detect_credential_access(summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    if _contains_any(summary.get("executed_commands", []), ["lsass", "sekurlsa", "sam", "security\\account"]):
        return [_risk("Credential access hints", "high", "Commands suggest credential dumping intent", "behavior_summary.executed_commands")]
    return []


def detect_ransomware_signals(summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    if _contains_any(summary.get("executed_commands", []), ["vssadmin delete shadows", "wbadmin delete catalog"]) or len(summary.get("files", [])) > 200:
        return [_risk("Ransomware-like activity", "critical", "Shadow copy deletion or unusual bulk file operations observed", "behavior_summary")]
    return []


def detect_defense_evasion(summary: Dict[str, Any]) -> List[Dict[str, Any]]:
    if _contains_any(summary.get("executed_commands", []), ["set-mppreference", "wevtutil cl", "bcdedit /set"]):
        return [_risk("Defense evasion behavior", "high", "Security disabling or log tampering commands found", "behavior_summary.executed_commands")]
    return []


def extract_high_value_iocs(ioc_candidates: Dict[str, List[str]]) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {k: [] for k in ("hashes", "domains", "ips", "urls", "registry_keys", "file_paths", "mutexes")}
    hash_re = re.compile(r"^[a-fA-F0-9]{32,64}$")
    for value in ioc_candidates.get("hashes", []):
        if isinstance(value, str) and hash_re.match(value):
            out["hashes"].append(value.lower())
    for key in ("domains", "ips", "urls", "registry_keys", "file_paths", "mutexes"):
        out[key].extend([sanitize_text(v, max_len=260, redact_pii=False) for v in ioc_candidates.get(key, []) if isinstance(v, str) and v.strip()])
    return {k: sorted(dedupe_preserve_order(v)) for k, v in out.items()}
