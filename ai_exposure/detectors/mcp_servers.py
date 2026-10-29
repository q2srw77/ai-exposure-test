"""Plan 5: strict MCP fingerprints (GET-only; never calls a tool).

Fires only on MCP-specific shapes, not generic event-stream noise:
- ``/sse`` with ``text/event-stream`` AND an MCP endpoint handshake in the first event
  (``event: endpoint`` or ``session_id``). Never POSTs to the advertised /messages URL.
- ``tools/list`` JSON (bare or JSON-RPC ``result.tools``) whose tools carry ``name``.
High-agency bump is name-only and in place: a tool name containing exec/shell/... -> critical.
"""
from __future__ import annotations

import json
import re
from typing import ClassVar

from ..models import Evidence, Finding, ProbeResult, Severity
from .base import Detector

_OWASP = "LLM06: Excessive Agency"
_HIGH_AGENCY_NEEDLES = (
    "read_file", "write_file", "delete_file", "execute", "exec", "shell", "run_command", "run_code",
    "query_sql", "execute_sql", "fetch_url", "http_request", "browser",
)

# Whole-token match: needle bounded by start/end or a non-alphanumeric (``_``, ``-``, ``.``, space).
_HIGH_AGENCY = re.compile(
    r"(?<![a-z0-9])(?:" + "|".join(sorted(map(re.escape, _HIGH_AGENCY_NEEDLES), key=len, reverse=True))
    + r")(?![a-z0-9])"
)


def is_high_agency(name: str) -> bool:
    return bool(_HIGH_AGENCY.search(name.lower()))


def _ctype(probe: ProbeResult) -> str:
    return next((v for k, v in probe.headers.items() if k.lower() == "content-type"), "").lower()


def _tool_names(data: object) -> list[str] | None:
    """Tool names from a tools/list payload; None when the shape is not a tool list."""
    if isinstance(data, dict):
        res = data.get("result")
        if data.get("jsonrpc") == "2.0" and isinstance(res, dict):
            tools = res.get("tools")
        else:
            tools = data.get("tools")
    else:
        return None
    if not isinstance(tools, list):
        return None
    if not tools or not all(isinstance(t, dict) and t.get("name") for t in tools):
        return None
    return [str(t["name"]) for t in tools]


class McpServersDetector(Detector):
    name: ClassVar[str] = "mcp_servers"
    extra_paths: ClassVar[list[str]] = ["/sse", "/tools/list"]

    def _finding(self, probe: ProbeResult, title: str, sev: Severity, detail: str, snippet: str) -> Finding:
        return Finding(detector=self.name, title=title, host=probe.host, url=probe.url, severity=sev,
                       evidence=Evidence.confirmed, owasp_llm=_OWASP, detail=detail, snippet=snippet[:200])

    def analyze(self, probe: ProbeResult) -> list[Finding]:
        if probe.status != 200 or not probe.body:
            return []
        path = probe.path.split("?", 1)[0].rstrip("/")
        if path.endswith("/sse"):
            if "text/event-stream" not in _ctype(probe):
                return []
            low = probe.body.lower()
            if "event: endpoint" not in low and "event:endpoint" not in low and "session_id" not in low:
                return []
            return [self._finding(probe, "Exposed MCP SSE endpoint", Severity.high,
                                  "MCP HTTP+SSE transport sent an endpoint handshake without authentication.",
                                  probe.body)]
        if path.endswith("/tools/list"):
            try:
                data = json.loads(probe.body)
            except (json.JSONDecodeError, TypeError):
                return []
            names = _tool_names(data)
            if names is None:
                return []
            risky = [n for n in names if is_high_agency(n)]
            sev = Severity.critical if risky else Severity.high
            detail = f"MCP tools/list publicly readable ({len(names)} tool(s))."
            if risky:
                detail += f" High-agency tool names (name-only match): {', '.join(risky[:8])}."
            snippet = ", ".join(risky[:12]) if risky else ", ".join(names[:12])
            return [self._finding(probe, "Unauthenticated MCP tools/list", sev, detail, snippet)]
        return []
