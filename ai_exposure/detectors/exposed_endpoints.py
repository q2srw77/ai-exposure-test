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


# Plan 3 agent surfaces (GET-only).
_AGENT_CARD_PATHS = ("/.well-known/agent-card.json", "/.well-known/agent.json")
_AI_PLUGIN_PATH = "/.well-known/ai-plugin.json"
_LLMS_TXT_PATH = "/llms.txt"
_AGENT_SURFACE_PATHS = (*_AGENT_CARD_PATHS, _AI_PLUGIN_PATH, _LLMS_TXT_PATH)


def _json_dict(body: str) -> dict | None:
    data = _json_body(body)
    return data if isinstance(data, dict) else None


def _looks_like_llms_txt(body: str) -> bool:
    text = body.strip()
    if not text or text.lstrip().startswith(("<", "{", "[")):
        return False
    return text.startswith("#") or "llms" in text.lower() or "](" in text


class ExposedEndpointsDetector(Detector):
    name: ClassVar[str] = "exposed_endpoints"
    extra_paths: ClassVar[list[str]] = [
        "/api/tags",
        "/api/v1/heartbeat",
        "/collections",
        "/v1/models",
        "/api/2.0/mlflow/experiments/search",
        "/api/v1/version",
        "/api/version",
        "/api/config",
        *_AGENT_CARD_PATHS,
        _AI_PLUGIN_PATH,
        _LLMS_TXT_PATH,
    ]

    def _finding(self, probe: ProbeResult, title: str, severity: Severity, evidence: Evidence,
                 owasp: str | None, detail: str) -> Finding:
        return Finding(
            detector=self.name,
            title=title,
            host=probe.host,
            url=probe.url,
            severity=severity,
            evidence=evidence,
            owasp_llm=owasp,
            detail=detail,
            snippet=probe.body[:200],
        )

    def _analyze_agent_surface(self, probe: ProbeResult) -> list[Finding]:
        if probe.status != 200:
            return []
        if probe.path in _AGENT_CARD_PATHS:
            data = _json_dict(probe.body)
            if data is None or "skills" not in data or "url" not in data:
                return []
            name = data.get("name") or "unnamed"
            return [self._finding(
                probe, "Exposed A2A agent card", Severity.medium, Evidence.confirmed,
                "LLM06: Excessive Agency",
                f"A2A agent card '{name}' with {len(data.get('skills') or [])} skill(s) publicly readable.",
            )]
        if probe.path == _AI_PLUGIN_PATH:
            data = _json_dict(probe.body)
            if data is None:
                return []
            clear = "schema_version" in data and "api" in data
            if not (clear or "schema_version" in data or "api" in data
                    or ("name" in data and "description" in data)):
                return []
            return [self._finding(
                probe, "Exposed AI plugin manifest", Severity.medium,
                Evidence.confirmed if clear else Evidence.probable,
                "LLM06: Excessive Agency",
                "ai-plugin.json manifest " + ("(schema_version + api)." if clear else "(partial plugin shape)."),
            )]
        if probe.path == _LLMS_TXT_PATH:
            if not _looks_like_llms_txt(probe.body):
                return []
            return [self._finding(
                probe, "llms.txt published", Severity.info, Evidence.probable, None,
                "llms.txt present (LLM-facing site index; inventory only).",
            )]
        return []

    def analyze(self, probe: ProbeResult) -> list[Finding]:
        if probe.status != 200 or not probe.body:
            return []
        if probe.path in _AGENT_SURFACE_PATHS:
            return self._analyze_agent_surface(probe)
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

        if (
            path == "/api/v1/version"
            and isinstance(data, dict)
            and "version" in data
            and "langflow" in body.lower()
        ):
            add(
                "Exposed Langflow API",
                Severity.critical,
                Evidence.confirmed,
                "LLM06: Excessive Agency",
                "Langflow /api/v1/version answered without authentication "
                "(check CVE-2025-3248 unauth RCE, CISA KEV).",
            )

        if path == "/api/version" and isinstance(data, dict) and "ray_version" in data:
            add(
                "Exposed Ray dashboard",
                Severity.critical,
                Evidence.confirmed,
                "LLM06: Excessive Agency",
                f"Ray dashboard /api/version returned ray_version={data.get('ray_version')} "
                "without authentication (ShadowRay / CVE-2023-48022 job submission).",
            )

        if (
            path == "/api/config"
            and isinstance(data, dict)
            and "open webui" in str(data.get("name", "")).lower()
        ):
            detail = "Open WebUI /api/config is publicly reachable."
            feats = data.get("features") if isinstance(data.get("features"), dict) else {}
            signup = next(
                (d[k] for d in (data, feats) for k in ("enable_signup", "ENABLE_SIGNUP") if k in d),
                None,
            )
            if signup is True:
                detail += " Public signup is enabled (enable_signup=true)."
            add(
                "Exposed Open WebUI",
                Severity.high,
                Evidence.confirmed,
                "LLM06: Excessive Agency",
                detail,
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
