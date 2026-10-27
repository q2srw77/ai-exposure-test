from __future__ import annotations

import re
from typing import ClassVar

from ..models import Evidence, Finding, ProbeResult, Severity
from .base import Detector

_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("OpenAI", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}")),
    ("Anthropic", re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("Hugging Face", re.compile(r"hf_[A-Za-z0-9]{30,}")),
    ("Google API", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
]


def redact_key(key: str) -> str:
    """Redact to first 6 … last 4. Never emit the full key."""
    if len(key) <= 10:
        return key[:2] + "…" + key[-2:]
    return f"{key[:6]}…{key[-4:]}"


class LeakedKeysDetector(Detector):
    name: ClassVar[str] = "leaked_keys"
    extra_paths: ClassVar[list[str]] = []

    def analyze(self, probe: ProbeResult) -> list[Finding]:
        if not probe.body:
            return []
        findings: list[Finding] = []
        seen: set[str] = set()
        for vendor, pattern in _PATTERNS:
            for match in pattern.finditer(probe.body):
                raw = match.group(0)
                redacted = redact_key(raw)
                if redacted in seen:
                    continue
                seen.add(redacted)
                findings.append(
                    Finding(
                        detector=self.name,
                        title=f"Possible leaked {vendor} API key",
                        host=probe.host,
                        url=probe.url,
                        severity=Severity.critical,
                        evidence=Evidence.heuristic,
                        owasp_llm="LLM02: Sensitive Information Disclosure",
                        detail=f"Pattern match for {vendor} API key (not vendor-validated).",
                        snippet=redacted,
                    )
                )
        return findings
