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


def _scheme_free_url(url: str) -> str:
    """Strip http/https scheme and default ports so scheme twins share a key."""
    parts = urlsplit(url)
    if parts.scheme.lower() not in ("http", "https"):
        return url
    netloc = parts.netloc.lower()
    for port in (":80", ":443"):
        if netloc.endswith(port):
            netloc = netloc[: -len(port)]
    path = parts.path or "/"
    return netloc + path + (("?" + parts.query) if parts.query else "")


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Dedupe by (detector, title, host, scheme-free url, snippet).

    Including the snippet keeps distinct leaked keys that share a title and URL.

    http:// and https:// twins collapse to one finding; https is preferred,
    otherwise the first occurrence is kept. Order follows first occurrence.
    """
    index: dict[tuple[str, str, str, str, str], int] = {}
    out: list[Finding] = []
    for f in findings:
        key = (f.detector, f.title, f.host.lower(), _scheme_free_url(f.url), f.snippet or "")
        i = index.get(key)
        if i is None:
            index[key] = len(out)
            out.append(f)
        elif f.url.lower().startswith("https://") and not out[i].url.lower().startswith("https://"):
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
