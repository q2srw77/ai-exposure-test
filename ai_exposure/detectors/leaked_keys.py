from __future__ import annotations

import re
from typing import ClassVar

from ..models import Evidence, Finding, ProbeResult, Severity
from .base import Detector

# Order matters: specific prefixes first. Each match claims its span, so a later,
# broader pattern (OpenAI ``sk-``) never re-reports the same token (e.g. sk-or-v1-, sk-ant-).
# Lengths are lenient lower bounds (heuristic); sources in DETECTOR_DEEPEN_1_3.md Plan 1.
_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("OpenRouter", re.compile(r"(?<![A-Za-z0-9])sk-or-v1-[A-Za-z0-9]{32,}")),
    ("Anthropic", re.compile(r"(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI", re.compile(r"(?<![A-Za-z0-9])sk-(?:proj-)?[A-Za-z0-9_\-]{20,}")),
    ("Groq", re.compile(r"\bgsk_[A-Za-z0-9]{40,}")),
    ("Replicate", re.compile(r"\br8_[A-Za-z0-9]{30,}")),
    ("Perplexity", re.compile(r"\bpplx-[A-Za-z0-9]{40,}")),
    ("xAI", re.compile(r"\bxai-[A-Za-z0-9]{60,}")),
    ("LangSmith", re.compile(r"\blsv2_(?:pt|sk)_[A-Za-z0-9]{32}_[A-Za-z0-9]{10}")),
    ("Pinecone", re.compile(r"\bpcsk_[A-Za-z0-9]{4,}_[A-Za-z0-9]{40,}")),
    ("Hugging Face", re.compile(r"hf_[A-Za-z0-9]{30,}")),
    ("Google API", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
]

# Gemini context: a Google ``AIza`` key is only critical when the Gemini API host is
# within this many chars (Maps/Firebase keys are often intentionally public -> medium).
_GEMINI_HOST = "generativelanguage.googleapis.com"
_GEMINI_WINDOW = 500


def redact_key(key: str) -> str:
    """Redact to first 6 … last 4. Never emit the full key."""
    if len(key) <= 10:
        return key[:2] + "…" + key[-2:]
    return f"{key[:6]}…{key[-4:]}"


class LeakedKeysDetector(Detector):
    name: ClassVar[str] = "leaked_keys"
    extra_paths: ClassVar[list[str]] = []

    def analyze(self, probe: ProbeResult) -> list[Finding]:
        # Skip error pages: Vercel/CDN 404 bodies embed request ids that match sk-*.
        if probe.status != 200 or not probe.body:
            return []
        # OpenAPI/Swagger specs embed example sk- tokens — not live leaks.
        if probe.path.endswith(("openapi.json", "swagger.json")):
            return []
        ctype = next((v for k, v in probe.headers.items() if k.lower() == "content-type"), "")
        if "json" in ctype.lower() and '"openapi"' in probe.body[:200].lower():
            return []
        findings: list[Finding] = []
        seen: set[str] = set()
        claimed: list[tuple[int, int]] = []
        body = probe.body
        for vendor, pattern in _PATTERNS:
            for match in pattern.finditer(body):
                start, end = match.span()
                if any(start < e and s < end for s, e in claimed):
                    continue
                claimed.append((start, end))
                raw = match.group(0)
                redacted = redact_key(raw)
                if redacted in seen:
                    continue
                seen.add(redacted)
                severity = Severity.critical
                detail = f"Pattern match for {vendor} API key (not vendor-validated)."
                if vendor == "Google API":
                    ctx = body[max(0, start - _GEMINI_WINDOW): end + _GEMINI_WINDOW]
                    if _GEMINI_HOST in ctx:
                        detail += f" {_GEMINI_HOST} nearby: likely Gemini key."
                    else:
                        severity = Severity.medium
                        detail += " No Gemini host nearby; may be a public Maps/Firebase key."
                findings.append(
                    Finding(
                        detector=self.name,
                        title=f"Possible leaked {vendor} API key",
                        host=probe.host,
                        url=probe.url,
                        severity=severity,
                        evidence=Evidence.heuristic,
                        owasp_llm="LLM02: Sensitive Information Disclosure",
                        detail=detail,
                        snippet=redacted,
                    )
                )
        return findings
