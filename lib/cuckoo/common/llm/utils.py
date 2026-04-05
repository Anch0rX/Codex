"""Shared helpers for robust LLM assessment preprocessing and normalization."""

from __future__ import annotations

import re
import string
from typing import Any, Iterable, List, Sequence
from urllib.parse import urlsplit, urlunsplit

CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
FENCE_RE = re.compile(r"```.*?```", re.DOTALL)
MULTI_SPACE_RE = re.compile(r"\s+")


def clamp_confidence(value: Any) -> float:
    """Clamp arbitrary confidence-like value into [0, 1]."""
    try:
        out = float(value)
    except (TypeError, ValueError):
        return 0.0
    if out < 0:
        return 0.0
    if out > 1:
        return 1.0
    return out


def normalize_severity(value: Any, allow_unknown: bool = True) -> str:
    """Normalize severity labels to low/medium/high/critical(/unknown)."""
    text = str(value or "").strip().lower()
    if text in {"low", "medium", "high", "critical"}:
        return text
    if text in {"1", "info", "informational"}:
        return "low"
    if text in {"2", "moderate"}:
        return "medium"
    if text in {"3", "severe"}:
        return "high"
    if text in {"4", "5"}:
        return "critical"
    return "unknown" if allow_unknown else "low"


def dedupe_preserve_order(values: Iterable[Any]) -> List[str]:
    """Dedupe values preserving order, keeping only non-empty strings."""
    out: List[str] = []
    seen = set()
    for value in values or []:
        if not isinstance(value, str):
            continue
        text = value.strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def truncate_list(values: Sequence[str], limit: int) -> List[str]:
    """Return at most `limit` items from a sequence."""
    return list(values[: max(0, int(limit))])


def sanitize_text(value: Any, max_len: int = 256, redact_pii: bool = True) -> str:
    """Sanitize untrusted sample-derived text for prompt safety and readability."""
    text = str(value or "")
    text = CONTROL_RE.sub("?", text)
    text = FENCE_RE.sub("[code_block_removed]", text)
    text = "".join(c if c in string.printable or c in "中文，。；：！？（）【】《》、“”‘’" else "?" for c in text)
    text = MULTI_SPACE_RE.sub(" ", text).strip()
    if redact_pii:
        text = re.sub(r"\\Users\\[^\\\s]+", r"\\Users\\<redacted>", text, flags=re.IGNORECASE)
        text = re.sub(r"/home/[^/\s]+", r"/home/<redacted>", text, flags=re.IGNORECASE)
    return text[:max_len]


def canonicalize_domain(value: Any) -> str:
    """Return canonical domain representation."""
    text = sanitize_text(value, max_len=255, redact_pii=False).lower().strip(".")
    return text


def canonicalize_ip(value: Any) -> str:
    """Return canonical IP representation."""
    return sanitize_text(value, max_len=64, redact_pii=False)


def canonicalize_url(value: Any, max_len: int = 300) -> str:
    """Canonicalize URL and truncate overly long query strings."""
    text = sanitize_text(value, max_len=max_len * 2, redact_pii=False)
    if not text:
        return ""
    try:
        parts = urlsplit(text)
        query = parts.query
        if len(query) > 80:
            query = query[:80] + "..."
        return urlunsplit((parts.scheme.lower(), parts.netloc.lower(), parts.path[:140], query, ""))[:max_len]
    except Exception:
        return text[:max_len]


def sanitize_list(values: Any, limit: int, item_max_len: int = 256, redact_pii: bool = True) -> List[str]:
    """Sanitize, dedupe and truncate list-like input."""
    if not isinstance(values, list):
        return []
    cleaned = [sanitize_text(v, max_len=item_max_len, redact_pii=redact_pii) for v in values]
    return truncate_list(dedupe_preserve_order(cleaned), limit)
