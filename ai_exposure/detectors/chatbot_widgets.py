from __future__ import annotations

from typing import ClassVar

from ..models import Evidence, Finding, ProbeResult, Severity
from .base import Detector

# (label, needles, severity, owasp) — info widgets: no OWASP LLM mapping (inventory only)
_RULES: list[tuple[str, tuple[str, ...], Severity, str | None]] = [
    (
        "Intercom chat widget",
        ("widget.intercom.io", "intercomSettings"),
        Severity.info,
        None,
    ),
    (
        "Drift chatbot",
        ("js.driftt.com",),
        Severity.info,
        None,
    ),
    (
        "Zendesk AI / Web Widget",
        ("static.zdassets.com/ekr",),
        Severity.info,
        None,
    ),
    (
        "Ada chatbot",
        ("static.ada.support",),
        Severity.info,
        None,
    ),
    (
        "OpenAI API call in client JS",
        ("api.openai.com",),
        Severity.medium,
        "LLM07: System Prompt Leakage",
    ),
    (
        "Anthropic API call in client JS",
        ("api.anthropic.com",),
        Severity.medium,
        "LLM07: System Prompt Leakage",
    ),
    (
        "Hugging Face inference call",
        ("api-inference.huggingface.co",),
        Severity.medium,
        "LLM07: System Prompt Leakage",
    ),
]


class ChatbotWidgetsDetector(Detector):
    name: ClassVar[str] = "chatbot_widgets"
    extra_paths: ClassVar[list[str]] = []

    def analyze(self, probe: ProbeResult) -> list[Finding]:
        if probe.path != "/" or not probe.body:
            return []
        findings: list[Finding] = []
        body = probe.body
        for label, needles, severity, owasp in _RULES:
            hit = next((n for n in needles if n in body), None)
            if hit is None:
                continue
            idx = body.find(hit)
            start = max(0, idx - 40)
            end = min(len(body), idx + len(hit) + 40)
            findings.append(
                Finding(
                    detector=self.name,
                    title=label,
                    host=probe.host,
                    url=probe.url,
                    severity=severity,
                    evidence=Evidence.probable,
                    owasp_llm=owasp,
                    detail=f"Case-sensitive match for '{hit}' on root page.",
                    snippet=body[start:end],
                )
            )
        return findings
