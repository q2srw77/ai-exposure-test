from __future__ import annotations

import json
from typing import ClassVar

from ..models import Evidence, Finding, ProbeResult, Severity
from .base import Detector


def _json_body(body: str) -> dict | list | None:
    try:
        return json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return None


class ExposedEndpointsDetector(Detector):
    name: ClassVar[str] = "exposed_endpoints"
    extra_paths: ClassVar[list[str]] = [
        "/api/tags",
        "/api/v1/heartbeat",
        "/collections",
        "/v1/models",
        "/api/2.0/mlflow/experiments/search",
    ]

    def analyze(self, probe: ProbeResult) -> list[Finding]:
        if probe.status != 200 or not probe.body:
            return []
        findings: list[Finding] = []
        path = probe.path
        body = probe.body
        data = _json_body(body)

        def add(
            title: str,
            severity: Severity,
            evidence: Evidence,
            owasp: str,
            detail: str,
            snippet: str = "",
        ) -> None:
            findings.append(
                Finding(
                    detector=self.name,
                    title=title,
                    host=probe.host,
                    url=probe.url,
                    severity=severity,
                    evidence=evidence,
                    owasp_llm=owasp,
                    detail=detail,
                    snippet=snippet or body[:200],
                )
            )

        if path == "/api/tags" and isinstance(data, dict) and "models" in data:
            add(
                "Unauthenticated Ollama API",
                Severity.high,
                Evidence.confirmed,
                "LLM10: Unbounded Consumption",
                "Ollama /api/tags returned models without authentication.",
            )

        if (
            path == "/v1/models"
            and isinstance(data, dict)
            and "data" in data
            and '"object"' in body
        ):
            add(
                "Open OpenAI-compatible model endpoint",
                Severity.high,
                Evidence.probable,
                "LLM10: Unbounded Consumption",
                "OpenAI-compatible /v1/models responded with a data payload.",
            )

        if path == "/collections" and "collections" in body:
            add(
                "Possibly open vector database",
                Severity.medium,
                Evidence.probable,
                "LLM02: Sensitive Information Disclosure",
                "Path /collections returned a body mentioning collections.",
            )

        if "mlflow" in path and isinstance(data, dict) and "experiments" in data:
            add(
                "Unauthenticated MLflow tracking server",
                Severity.high,
                Evidence.confirmed,
                "LLM03: Supply Chain",
                "MLflow experiments search endpoint returned data without auth.",
            )

        if path == "/":
            if "gradio-app" in body or "window.gradio_config" in body:
                add(
                    "Public Gradio app",
                    Severity.medium,
                    Evidence.probable,
                    "LLM06: Excessive Agency",
                    "Root page contains Gradio signatures.",
                )
            if "streamlit" in body and "_stcore" in body:
                add(
                    "Public Streamlit app",
                    Severity.medium,
                    Evidence.probable,
                    "LLM06: Excessive Agency",
                    "Root page contains Streamlit signatures.",
                )
            if "jupyter" in body and "notebook" in body:
                add(
                    "Exposed Jupyter interface",
                    Severity.critical,
                    Evidence.probable,
                    "LLM06: Excessive Agency",
                    "Root page contains Jupyter notebook signatures.",
                )

        return findings
