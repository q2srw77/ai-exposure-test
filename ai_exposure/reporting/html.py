"""Self-contained HTML scan report (No / Few / Many states).

Layout follows wireframes/report-states.html. Inline CSS only, no external assets.
"""
from __future__ import annotations

from collections import Counter
from html import escape

from ..models import Finding, ScanResult, Severity
from .scoring import sort_findings

FEW_MIN = 1
MANY_MIN = 10

# (detector, label, coverage description, OWASP note)
COVERAGE_CLASSES: list[tuple[str, str, str, str]] = [
    ("leaked_keys", "Leaked keys",
     "vendor prefixes tested on HTML + linked .js (OpenAI, Anthropic, HF, Google, …).", "OWASP LLM02"),
    ("exposed_endpoints", "Exposed AI infra",
     "unauth paths probed (Ollama, Gradio, Streamlit, Jupyter, …) with body markers.", "LLM-mapped where applicable"),
    ("chatbot_widgets", "Chat widgets &amp; client LLM calls",
     "embed needles + same-origin script crawl for API hosts.", "inventory + LLM07"),
]

OWASP_CATEGORIES: list[tuple[str, str, bool]] = [
    ("LLM02", "Sensitive Information", False),
    ("LLM06", "Excessive Agency", True),
    ("LLM07", "System Prompt / client API", False),
    ("LLM08", "Vector / embedding", True),
]

LIMITS = [
    "Auth walls and non-public hosts were not in scope.",
    "CT / DNS discovery gaps — hosts we never saw stay unchecked.",
    "No live key validation; patterns are heuristic / confirmed by presence only.",
]

CSS = """
:root{--bg:#0f1419;--panel:#1a2332;--panel2:#243044;--border:#2e3d52;--text:#e8eef6;--muted:#8b9bb0;
--ok:#2e7d32;--ok-bg:#1b3a1f;--crit:#c62828;--high:#ef6c00;--med:#f9a825;--low:#1565c0;--info:#607d8b;--accent:#4fc3f7}
*{box-sizing:border-box}body{margin:0;padding:1.5rem;font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
background:var(--bg);color:var(--text);line-height:1.45}
.report{max-width:920px;margin:0 auto;background:var(--panel);border:1px solid var(--border);border-radius:12px;overflow:hidden}
.report-head{padding:1.1rem 1.25rem;border-bottom:1px solid var(--border);display:flex;flex-wrap:wrap;gap:1rem;justify-content:space-between}
.report-head h1{margin:0;font-size:1.05rem}.meta{color:var(--muted);font-size:.82rem;margin-top:.25rem}
.pill{display:inline-flex;padding:.35rem .75rem;border-radius:999px;font-size:.8rem;font-weight:600}
.pill.clean{background:var(--ok-bg);color:#81c784;border:1px solid var(--ok)}
.pill.warn{background:#3a2a12;color:#ffcc80;border:1px solid var(--high)}
.pill.alert{background:#3a1515;color:#ef9a9a;border:1px solid var(--crit)}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:.75rem;padding:1rem 1.25rem;border-bottom:1px solid var(--border)}
.metric{background:var(--panel2);border-radius:8px;padding:.75rem}
.metric .label{color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.04em}
.metric .value{font-size:1.35rem;font-weight:700;margin-top:.15rem}
.section{padding:1rem 1.25rem;border-bottom:1px solid var(--border)}.section:last-child{border-bottom:none}
.section h2,.section h3{margin:0 0 .65rem;font-size:.92rem}.lead{margin:0 0 .75rem;color:var(--muted);font-size:.88rem}
.checklist{list-style:none;margin:0;padding:0}.checklist li{display:flex;gap:.65rem;padding:.55rem 0;border-top:1px solid var(--border);font-size:.88rem}
.checklist li:first-child{border-top:none}
.check{flex:0 0 auto;width:1.25rem;height:1.25rem;border-radius:50%;background:var(--ok);color:#fff;font-size:.7rem;font-weight:700;display:grid;place-items:center}
.check.hit{background:var(--crit)}.check.few{background:var(--high)}.sub{color:var(--muted);font-size:.78rem}
.owasp{display:flex;flex-wrap:wrap;gap:.4rem}.tag{background:var(--panel2);border:1px solid var(--border);border-radius:6px;padding:.25rem .55rem;font-size:.78rem;color:var(--muted)}
.tag.clear{border-color:var(--ok);color:#81c784}.tag.hit{border-color:var(--crit);color:#ef9a9a}
.limits{background:#1a222c;border-radius:8px;padding:.75rem .9rem;font-size:.85rem;color:var(--muted)}.limits ul{margin:.4rem 0 0;padding-left:1.1rem}
table.findings{width:100%;border-collapse:collapse;font-size:.85rem}
table.findings th{text-align:left;color:var(--muted);font-weight:500;font-size:.75rem;text-transform:uppercase;padding:.4rem .5rem;border-bottom:1px solid var(--border)}
table.findings td{padding:.55rem .5rem;border-bottom:1px solid var(--border);vertical-align:top}
.sev{display:inline-block;padding:.15rem .45rem;border-radius:4px;color:#fff;font-size:.72rem;font-weight:600;text-transform:uppercase}
.sev.critical{background:var(--crit)}.sev.high{background:var(--high)}.sev.medium{background:var(--med);color:#222}.sev.low{background:var(--low)}.sev.info{background:var(--info)}
.url{color:var(--accent);font-family:ui-monospace,monospace;font-size:.78rem;word-break:break-all}
.snippet{color:var(--muted);font-family:ui-monospace,monospace;font-size:.75rem;word-break:break-all}
details summary{cursor:pointer;font-weight:600;font-size:.92rem}
"""


def report_state(result: ScanResult) -> str:
    n = len(result.findings)
    if n < FEW_MIN:
        return "no"
    if n < MANY_MIN:
        return "few"
    return "many"


def _e(v: object) -> str:
    return escape(str(v or ""), quote=True)


def _sev(f: Finding) -> str:
    return f.severity.value if isinstance(f.severity, Severity) else str(f.severity)


def _owasp_code(f: Finding) -> str | None:
    if not f.owasp_llm:
        return None
    return f.owasp_llm.split(":")[0].strip().upper() or None


def _fmt_dt(dt) -> str:
    return dt.strftime("%Y-%m-%d %H:%M %Z").strip() if dt else "—"


def _duration(result: ScanResult) -> str:
    if not result.finished_at:
        return "—"
    secs = int((result.finished_at - result.started_at).total_seconds())
    m, s = divmod(max(secs, 0), 60)
    return f"{m}m {s}s"


def _metric(label: str, value: object) -> str:
    return f'<div class="metric"><div class="label">{_e(label)}</div><div class="value">{_e(value)}</div></div>'


def _findings_table(findings: list[Finding]) -> str:
    rows = []
    for f in findings:
        snip = f'<div class="snippet">{_e(f.snippet)}</div>' if f.snippet else ""
        rows.append(
            f'<tr><td><span class="sev {_e(_sev(f))}">{_e(_sev(f))}</span></td>'
            f"<td>{_e(f.title)}{snip}</td>"
            f'<td><span class="url">{_e(f.url)}</span></td>'
            f"<td>{_e(_owasp_code(f) or '—')}</td></tr>"
        )
    return ('<table class="findings"><thead><tr><th>Sev</th><th>Title</th><th>Where</th><th>OWASP</th></tr></thead>'
            "<tbody>" + "".join(rows) + "</tbody></table>")


def _coverage(by_det: Counter, heading: str, lead: str) -> str:
    items = []
    for det, label, desc, owasp in COVERAGE_CLASSES:
        hits = by_det.get(det, 0)
        if hits:
            mark, cls, txt = "!", "check hit", f"{hits} hit{'s' if hits != 1 else ''}."
        else:
            mark, cls, txt = "✓", "check", desc
        items.append(
            f'<li data-class="{det}" data-hits="{hits}"><span class="{cls}">{mark}</span>'
            f"<div><strong>{label}</strong> — {txt}<div class=\"sub\">Detector: {det} · {owasp}</div></div></li>"
        )
    return (f'<div class="section" id="coverage"><h2>{heading}</h2><p class="lead">{lead}</p>'
            f'<ul class="checklist">{"".join(items)}</ul></div>')


def _owasp(findings: list[Finding]) -> str:
    counts = Counter(c for c in (_owasp_code(f) for f in findings) if c)
    tags = []
    known = {c for c, _, _ in OWASP_CATEGORIES}
    for code, name, partial in OWASP_CATEGORIES:
        n = counts.get(code, 0)
        if n:
            tags.append(f'<span class="tag hit">{code} {name} — {n} finding{"s" if n != 1 else ""}</span>')
        else:
            tags.append(f'<span class="tag clear">{code} {name} — clear{"*" if partial else ""}</span>')
    for code in sorted(set(counts) - known):
        tags.append(f'<span class="tag hit">{_e(code)} — {counts[code]} finding{"s" if counts[code] != 1 else ""}</span>')
    return ('<div class="section" id="owasp"><h3>OWASP LLM categories covered</h3>'
            f'<div class="owasp">{"".join(tags)}</div>'
            '<p class="sub">*Within current detector scope. Agent-card / MCP probes deepen later.</p></div>')


def _limits(result: ScanResult) -> str:
    extra = ""
    if result.errors:
        extra = f"<li>{len(result.errors)} probe/discovery error(s) during this scan — affected targets may be unchecked.</li>"
    lis = "".join(f"<li>{x}</li>" for x in LIMITS)
    return ('<div class="section" id="limits"><h3>Scan limits &amp; next steps</h3><div class="limits">'
            f"<strong>Why “clean” is not “done”:</strong><ul>{lis}{extra}</ul>"
            "<p>Suggested next: expand Extra hosts, re-run after deploy windows, add detectors as they ship.</p>"
            "</div></div>")


def render_html_report(result: ScanResult) -> str:
    state = report_state(result)
    findings = sort_findings(list(result.findings))
    n = len(findings)
    by_det = Counter(f.detector for f in findings)
    sev = Counter(_sev(f) for f in findings)
    total = len(COVERAGE_CLASSES)
    clear = sum(1 for d, *_ in COVERAGE_CLASSES if not by_det.get(d))

    if state == "no":
        pill = '<span class="pill clean">✓ Clean — 0 findings</span>'
        metrics = [_metric("Findings", 0), _metric("Hosts alive", len(result.hosts_alive)),
                   _metric("Hosts discovered", len(result.hosts_discovered)), _metric("Detectors run", total)]
    elif state == "few":
        pill = f'<span class="pill warn">{n} finding{"s" if n != 1 else ""} · {clear} classes clear</span>'
        metrics = [_metric("Findings", n), _metric("Critical / High", sev["critical"] + sev["high"]),
                   _metric("Hosts alive", len(result.hosts_alive)), _metric("Classes clear", f"{clear} / {total}")]
    else:
        pill = f'<span class="pill alert">{n} findings · severity-first</span>'
        metrics = [_metric("Findings", n), _metric("Critical", sev["critical"]),
                   _metric("High / Med", sev["high"] + sev["medium"]), _metric("Low / Info", sev["low"] + sev["info"])]

    head = (f'<div class="report-head"><div><h1>{_e(result.domain)} — AI Exposure Scan</h1>'
            f'<div class="meta">Started {_e(_fmt_dt(result.started_at))} · Finished {_e(_fmt_dt(result.finished_at))}'
            f" · Duration {_e(_duration(result))}</div></div>{pill}</div>")
    parts = [head, f'<div class="metrics">{"".join(metrics)}</div>']

    attest = (f"{clear} of {total} AI exposure classes clear on the hosts we reached. "
              "This is what we checked — not a guarantee of zero risk everywhere.")
    if state == "no":
        parts += [_coverage(by_det, "Coverage attestation", attest), _owasp(findings)]
    elif state == "few":
        parts.append(f'<div class="section" id="findings"><h2>Findings</h2>{_findings_table(findings)}</div>')
        parts += [_coverage(by_det, "Still clear", attest), _owasp(findings)]
    else:
        summary = " ".join(f'<span class="tag hit">{_e(d)} ×{c}</span>' for d, c in by_det.most_common())
        parts.append(f'<div class="section" id="summary"><h3>Summary by class</h3><div class="owasp">{summary}</div></div>')
        order = [d for d, *_ in COVERAGE_CLASSES] + sorted(set(by_det) - {d for d, *_ in COVERAGE_CLASSES})
        for det in order:
            group = [f for f in findings if f.detector == det]
            if group:
                parts.append(f'<div class="section findings-group" data-detector="{_e(det)}">'
                             f"<h3>{_e(det)} ({len(group)})</h3>{_findings_table(group)}</div>")
        parts.append('<div class="section"><details><summary>What we still cleared</summary>'
                     + _coverage(by_det, "Coverage attestation", attest) + _owasp(findings) + "</details></div>")
    parts.append(_limits(result))

    return ("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            f"<title>AI Exposure report — {_e(result.domain)}</title><style>{CSS}</style></head>"
            f'<body data-report-state="{state}"><main class="report">{"".join(parts)}</main></body></html>\n')
