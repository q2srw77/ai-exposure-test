from __future__ import annotations

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


def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """Dedupe by (detector, title, host, url); keep first occurrence."""
    seen: set[tuple[str, str, str, str]] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.detector, f.title, f.host, f.url)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
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
