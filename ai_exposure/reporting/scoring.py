from __future__ import annotations

from urllib.parse import urlsplit

from ..models import Evidence, Finding, Severity

_SEVERITY_ORDER = {
    Severity.critical: 0,
    Severity.high: 1,
    Severity.medium: 2,
    Severity.low: 3,
    Severity.info: 4,
}

_EVIDENCE_ORDER = {
    Evidence.confirmed: 0,
    Evidence.probable: 1,
    Evidence.heuristic: 2,
}


_AGENT_CARD_ALIAS_PATH = "/.well-known/agent.json"
_AGENT_CARD_CANON_PATH = "/.well-known/agent-card.json"


def _canonicalize_path(path: str) -> str:
    """Map known alias paths onto a canonical form for dedupe keys."""
    if path == _AGENT_CARD_ALIAS_PATH:
        return _AGENT_CARD_CANON_PATH
    return path


def _scheme_free_url(url: str) -> str:
    """Strip http/https scheme and default ports so scheme twins share a key."""
    parts = urlsplit(url)
    if parts.scheme.lower() not in ("http", "https"):
        return url
    netloc = parts.netloc.lower()
    for port in (":80", ":443"):
        if netloc.endswith(port):
            netloc = netloc[: -len(port)]
    path = _canonicalize_path(parts.path or "/")
    return netloc + path + (("?" + parts.query) if parts.query else "")


def _prefer_over(existing: Finding, candidate: Finding) -> bool:
    """Prefer https over http; for A2A cards prefer agent-card.json over agent.json."""
    e, c = existing.url.lower(), candidate.url.lower()
    if c.startswith("https://") and not e.startswith("https://"):
        return True
    if _AGENT_CARD_CANON_PATH in c and _AGENT_CARD_ALIAS_PATH in e.split("?")[0]:
        # same scheme family: keep canonical card path
        if e.startswith("https://") == c.startswith("https://") or c.startswith("https://"):
            return True
    return False


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Dedupe by (detector, title, host, scheme-free url, snippet).

    Including the snippet keeps distinct leaked keys that share a title and URL.

    http:// and https:// twins collapse to one finding; https is preferred,
    otherwise the first occurrence is kept. A2A agent-card.json and agent.json
    aliases collapse to one finding per host (prefer agent-card.json).
    Order follows first occurrence.
    """
    index: dict[tuple[str, str, str, str, str], int] = {}
    out: list[Finding] = []
    for f in findings:
        key = (f.detector, f.title, f.host.lower(), _scheme_free_url(f.url), f.snippet or "")
        i = index.get(key)
        if i is None:
            index[key] = len(out)
            out.append(f)
        elif _prefer_over(out[i], f):
            out[i] = f
    return out


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Sort severity critical→info, then evidence confirmed→heuristic, then host."""
    return sorted(
        findings,
        key=lambda f: (
            _SEVERITY_ORDER.get(f.severity, 99),
            _EVIDENCE_ORDER.get(f.evidence, 99),
            f.host,
        ),
    )


def finalize(findings: list[Finding]) -> list[Finding]:
    return sort_findings(dedupe_findings(findings))
