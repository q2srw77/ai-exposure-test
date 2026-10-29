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
     "unauth paths probed (Ollama, Gradio, Streamlit, Jupyter, Langflow, Ray, Open WebUI, Chroma, Qdrant, Flowise, n8n, LiteLLM, agent-card, "
     "ai-plugin, llms.txt, …) with body markers.", "LLM-mapped where applicable"),
    ("chatbot_widgets", "Chat widgets &amp; client LLM calls",
     "embed needles + same-origin script crawl for API hosts.", "inventory + LLM07"),
]

# Few/Many ✓ rows: outcome copy (Researcher lock) — NOT the No-state probe inventory.
CLEAR_OUTCOME = {
    "leaked_keys": "no live-looking vendor API keys (OpenAI / Anthropic / HF / Google / …) in HTML or linked JS on reached hosts.",
    "exposed_endpoints": "no unauth Gradio / Ollama / Jupyter / Streamlit / Langflow / Ray / Open WebUI / Chroma / Qdrant / Flowise / n8n / LiteLLM / agent-card markers on probed paths.",
    "chatbot_widgets": "no third-party chat embeds or browser-side LLM API calls on reached hosts.",
}
WHY_IT_MATTERS = {
    "leaked_keys": "live-looking API keys on public HTML/JS let anyone spend quota, pull data, or impersonate your AI apps (OWASP LLM02).",
    "exposed_endpoints": "unauth Gradio/Ollama/Jupyter/Langflow/Ray/Open WebUI paths are remote-control and model-theft surface (LLM06/LLM10).",
    "chatbot_widgets": "third-party embeds and browser-side model calls expand vendor/PII exposure and prompt leakage paths (LLM07).",
}
LABEL_PLAIN = {"leaked_keys": "Leaked keys", "exposed_endpoints": "Exposed AI infra",
               "chatbot_widgets": "Chat widgets &amp; client LLM calls"}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]

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
NEXT_STEPS = "Suggested next: expand Extra hosts, re-run after deploy windows."

CSS = """
:root{--bg:#0f1419;--panel:#1a2332;--panel2:#243044;--border:#2e3d52;--text:#e8eef6;--muted:#b4c0cf;
--ok:#2e7d32;--ok-bg:#1b3a1f;--crit:#c62828;--high:#ef6c00;--med:#f9a825;--low:#1565c0;--info:#607d8b;--accent:#4fc3f7}
*{box-sizing:border-box}html,body{width:100%}body{margin:0;padding:clamp(.75rem,2.5vw,2rem);font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;
background:var(--bg);color:var(--text);line-height:1.5;font-size:clamp(.9rem,.85rem + .2vw,1rem)}
.report{width:100%;max-width:min(1100px,100%);margin:0 auto;display:flex;flex-direction:column;gap:1rem}
.band{background:var(--panel);border:1px solid var(--border);border-radius:12px;overflow:hidden}
.band-title{margin:0;padding:.85rem clamp(1rem,2vw,1.5rem);font-size:.8rem;text-transform:uppercase;letter-spacing:.06em;font-weight:700;border-bottom:1px solid var(--border);display:flex;flex-wrap:wrap;gap:.75rem;justify-content:space-between;align-items:center}
.report-head{padding:clamp(1rem,2vw,1.5rem);border-bottom:1px solid var(--border);display:flex;flex-wrap:wrap;gap:1rem;justify-content:space-between;align-items:flex-start}
.report-head h1{margin:0;font-size:clamp(1.15rem,1rem + .8vw,1.6rem)}.meta{color:var(--muted);font-size:.85rem;margin-top:.25rem}
.headline{padding:1rem clamp(1rem,2vw,1.5rem);font-size:1.05rem;font-weight:600;border-bottom:1px solid var(--border)}
.headline .why{display:block;font-weight:400;font-size:.92rem;color:var(--muted);margin-top:.25rem}
.pill{display:inline-flex;padding:.4rem .85rem;border-radius:999px;font-size:.85rem;font-weight:700;white-space:nowrap}
.pill.clean{background:var(--ok-bg);color:#a5d6a7;border:1px solid var(--ok)}
.pill.warn{background:#3a2a12;color:#ffcc80;border:1px solid var(--high)}
.pill.fail{background:#2a2f38;color:var(--text);border:1px solid var(--info)}
.pill.alert{background:#3a1515;color:#ef9a9a;border:1px solid var(--crit)}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.75rem;padding:1rem clamp(1rem,2vw,1.5rem);border-bottom:1px solid var(--border)}
.metric{background:var(--panel2);border-radius:8px;padding:.8rem 1rem}
.metric .label{color:var(--muted);font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;font-weight:600}
.metric .value{font-size:1.6rem;font-weight:800;margin-top:.15rem}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:.75rem;padding:1rem clamp(1rem,2vw,1.5rem)}
.card{background:var(--panel2);border:1px solid var(--border);border-left:4px solid var(--ok);border-radius:8px;padding:.9rem 1rem}
.card.hit{border-left-color:var(--crit)}.card.few{border-left-color:var(--high)}.card.failed{border-left-color:var(--info)}
.card h3{margin:0 0 .35rem;font-size:1rem}.card p{margin:.4rem 0 0;font-size:.88rem}
.chip{display:inline-block;padding:.15rem .55rem;border-radius:999px;font-size:.75rem;font-weight:700;border:1px solid var(--ok);color:#a5d6a7}
.chip.hit{border-color:var(--crit);color:#ef9a9a}.chip.failed{border-color:var(--info);color:var(--text)}
.section{padding:1rem clamp(1rem,2vw,1.5rem);border-bottom:1px solid var(--border)}.section:last-child{border-bottom:none}
.section h2,.section h3{margin:0 0 .65rem;font-size:.98rem}.lead{margin:0 0 .75rem;color:var(--muted);font-size:.9rem}
.checklist{list-style:none;margin:0;padding:0}.checklist li{display:flex;gap:.65rem;padding:.55rem 0;border-top:1px solid var(--border);font-size:.9rem}
.checklist li:first-child{border-top:none}
.check{flex:0 0 auto;width:1.3rem;height:1.3rem;border-radius:50%;background:var(--ok);color:#fff;font-size:.72rem;font-weight:700;display:grid;place-items:center}
.check.hit{background:var(--crit)}.check.few{background:var(--high)}.sub{color:var(--muted);font-size:.8rem}
.owasp{display:flex;flex-wrap:wrap;gap:.4rem}.tag{background:var(--panel2);border:1px solid var(--border);border-radius:6px;padding:.25rem .55rem;font-size:.8rem}
.tag.clear{border-color:var(--ok);color:#a5d6a7}.tag.hit{border-color:var(--crit);color:#ef9a9a}
.limits{background:#1a222c;border-radius:8px;padding:.75rem .9rem;font-size:.88rem}.limits ul{margin:.4rem 0 0;padding-left:1.1rem}
.table-wrap{overflow-x:auto}
table.findings{width:100%;border-collapse:collapse;font-size:.88rem;min-width:560px}
table.findings th{text-align:left;color:var(--muted);font-weight:700;font-size:.75rem;text-transform:uppercase;padding:.45rem .5rem;border-bottom:1px solid var(--border)}
table.findings td{padding:.55rem .5rem;border-bottom:1px solid var(--border);vertical-align:top}
.sev{display:inline-block;padding:.15rem .45rem;border-radius:4px;color:#fff;font-size:.72rem;font-weight:700;text-transform:uppercase}
.sev.critical{background:var(--crit)}.sev.high{background:var(--high)}.sev.medium{background:var(--med);color:#222}.sev.low{background:var(--low)}.sev.info{background:var(--info)}
.url{color:var(--accent);font-family:ui-monospace,monospace;font-size:.8rem;word-break:break-all}
.snippet{color:var(--muted);font-family:ui-monospace,monospace;font-size:.78rem;word-break:break-all}
details.det{border-bottom:1px solid var(--border)}details.det:last-of-type{border-bottom:none}
details.det>summary{cursor:pointer;list-style:none;padding:.9rem clamp(1rem,2vw,1.5rem);display:flex;flex-wrap:wrap;gap:.5rem 1rem;align-items:center;font-weight:700}
details.det>summary::-webkit-details-marker{display:none}
details.det>summary::before{content:"\\25B8";transition:transform .15s}details.det[open]>summary::before{transform:rotate(90deg)}
details.det>summary .sum{font-weight:500;color:var(--muted);font-size:.88rem}
details.det .body{padding:0 clamp(1rem,2vw,1.5rem) 1rem}
details.plain>summary{cursor:pointer;font-weight:700;padding:.9rem clamp(1rem,2vw,1.5rem)}
details.plain .section{border-bottom:none}
.toggles{display:flex;gap:.5rem}.toggles button{background:var(--panel2);color:var(--text);border:1px solid var(--border);border-radius:6px;padding:.3rem .7rem;font:inherit;font-size:.8rem;cursor:pointer;text-transform:none;letter-spacing:0}
.notice{background:#2a2f38;border-left:3px solid var(--info);border-radius:6px;padding:.65rem .8rem;font-size:.9rem}
@media (max-width:600px){.report-head{flex-direction:column}}
@media print{body{background:#fff;color:#000;padding:0}.band{border-color:#999;background:#fff}.toggles{display:none}
.metric,.card{background:#f4f4f4}details>summary::before{display:none}:root{--muted:#333;--text:#000}}
"""


def report_state(result: ScanResult) -> str:
    n = len(result.findings)
    if n == 0 and not result.hosts_alive:
        return "failed"  # scan failed / no hosts reached — never show Clean
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
    return ('<div class="table-wrap"><table class="findings"><thead><tr><th>Sev</th><th>Title</th><th>Where</th><th>OWASP</th></tr></thead>'
            "<tbody>" + "".join(rows) + "</tbody></table></div>")


def _coverage(by_det: Counter, heading: str, lead: str, severe: set[str] | None = None,
              only_clear: bool = False, inventory: bool = False) -> str:
    items = []
    for det, label, desc, owasp in COVERAGE_CLASSES:
        hits = by_det.get(det, 0)
        if hits and only_clear:
            continue
        if hits:
            cls = "check hit" if severe is None or det in severe else "check few"
            mark, txt = "!", f"{hits} hit{'s' if hits != 1 else ''} — see Findings."
        else:
            mark, cls = "✓", "check"
            txt = desc if inventory else CLEAR_OUTCOME.get(det, desc)
        items.append(
            f'<li data-class="{det}" data-hits="{hits}"><span class="{cls}">{mark}</span>'
            f"<div><strong>{label}</strong> — {txt}<div class=\"sub\">Detector: {det} · {owasp}</div></div></li>"
        )
    if not items:
        items.append('<li><span class="check hit">!</span><div>No classes fully clear in this scan.</div></li>')
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
            f"<p>{NEXT_STEPS}</p>"
            "</div></div>")


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def _worst(fs: list[Finding]) -> str:
    present = {_sev(f) for f in fs}
    return next((x for x in SEV_ORDER if x in present), "info")


def _class_cards(findings: list[Finding], state: str) -> str:
    cards = []
    for det, label, _desc, _ow in COVERAGE_CLASSES:
        group = [f for f in findings if f.detector == det]
        if state == "failed":
            cls, chip = "card failed", '<span class="chip failed">Not checked — 0 hosts reached</span>'
        elif group:
            w = _worst(group)
            cls = "card hit" if w in ("critical", "high") else "card few"
            chip = f'<span class="chip hit">{len(group)} · worst {w}</span>'
        else:
            cls, chip = "card", '<span class="chip">Clear on reached hosts</span>'
        cards.append(f'<div class="{cls}" data-card="{det}"><h3>{label}</h3>{chip}'
                     f'<p>{_e(WHY_IT_MATTERS[det])}</p></div>')
    return f'<div class="cards" id="classes">{"".join(cards)}</div>'


def _headline(state: str, n: int, sev: Counter, clear: int, total: int, result: ScanResult) -> str:
    alive = len(result.hosts_alive)
    if state == "failed":
        h = "Scan incomplete — no hosts responded, so nothing was verified."
        w = "Treat this as unknown risk, not clean. Check the domain / extra hosts and re-run."
    elif state == "no":
        h = f"No AI exposure found across {_plural(alive, 'reached host')} — all {total} classes clear."
        w = "Keys, exposed AI infrastructure and client-side LLM calls were all checked; see attestation below."
    else:
        ch = sev["critical"] + sev["high"]
        h = (f"{_plural(n, 'AI exposure finding')} across {_plural(alive, 'reached host')}"
             f"{f' — {ch} critical/high need action' if ch else ''}.")
        w = f"{_plural(clear, 'class', 'classes')} clear of {total}. Fix critical/high first; details are grouped by class below."
    return f'<div class="headline" id="headline">{_e(h)}<span class="why">{_e(w)}</span></div>'


def _detector_details(findings: list[Finding], by_det: Counter, state: str) -> str:
    order = [d for d, *_ in COVERAGE_CLASSES] + sorted(set(by_det) - {d for d, *_ in COVERAGE_CLASSES})
    out = []
    for det in order:
        group = [f for f in findings if f.detector == det]
        label = LABEL_PLAIN.get(det, _e(det))
        if group:
            summ = f"{_plural(len(group), 'finding')} · worst {_worst(group)}"
            body = _findings_table(group)
            st = "hits"
        elif state == "failed":
            summ, st = "Not checked — 0 hosts reached", "failed"
            body = '<div class="notice">No live content reached; this class is unverified.</div>'
        else:
            summ, st = "Clear on reached hosts", "clean"
            body = f'<p class="lead">✓ {CLEAR_OUTCOME.get(det, "")}</p>'
        # Lead contract: open if any Critical/High; Info-only stays collapsed.
        has_crit_high = any(_sev(f) in ("critical", "high") for f in group)
        op = " open" if group and has_crit_high else ""
        out.append(f'<details class="det" data-detector="{_e(det)}" data-state="{st}"{op}>'
                   f'<summary>{label} <span class="sum">— {_e(summ)}</span></summary>'
                   f'<div class="body">{body}</div></details>')
    return "".join(out)


TOGGLE_JS = ("<script>function aiexpToggle(o){document.querySelectorAll('details').forEach(function(d){d.open=o})}"
             "window.addEventListener('beforeprint',function(){aiexpToggle(true)});</script>")


def render_html_report(result: ScanResult, *, urls_probed: int | None = None,
                       preset: str | None = None) -> str:
    """Single render path for Streamlit on-screen + download.

    Layout: Executive band (headline, metric cards, class cards) then Details band
    (collapsible detector sections, coverage/OWASP, limits).
    ``urls_probed`` / ``preset`` are optional; unknown shows "—".
    """
    if urls_probed is None:
        urls_probed = getattr(result, "urls_probed", None)
    state = report_state(result)
    findings = sort_findings(list(result.findings))
    n = len(findings)
    by_det = Counter(f.detector for f in findings)
    sev = Counter(_sev(f) for f in findings)
    total = len(COVERAGE_CLASSES)
    clear = sum(1 for d, *_ in COVERAGE_CLASSES if not by_det.get(d))
    clear_txt = _plural(clear, "class", "classes") + " clear"

    base = [_metric("Findings", n), _metric("Hosts alive", len(result.hosts_alive)),
            _metric("URLs / JS probed", str(urls_probed) if urls_probed is not None else "—"),
            _metric("Detectors run", total)]
    severe = {f.detector for f in findings if _sev(f) in ("critical", "high")}
    if state == "failed":
        pill = '<span class="pill fail">Scan incomplete — 0 hosts alive</span>'
        metrics = base
    elif state == "no":
        pill = '<span class="pill clean">✓ Clean — 0 findings</span>'
        metrics = base
    elif state == "few":
        pill = f'<span class="pill warn">{_plural(n, "finding")} · {clear_txt}</span>'
        metrics = base + [_metric("Critical / High", sev["critical"] + sev["high"]),
                          _metric("Classes clear", f"{clear} / {total}")]
    else:
        pill = f'<span class="pill alert">{n} findings · severity-first</span>'
        metrics = base + [_metric("Critical", sev["critical"]),
                          _metric("High / Med", sev["high"] + sev["medium"]),
                          _metric("Info", sev["low"] + sev["info"])]

    head = (f'<div class="report-head"><div><h1>{_e(result.domain)} — AI Exposure Scan</h1>'
            f'<div class="meta">Started {_e(_fmt_dt(result.started_at))} · Finished {_e(_fmt_dt(result.finished_at))}'
            f" · Duration {_e(_duration(result))}{(' · Preset: ' + _e(preset)) if preset else ''}</div></div>{pill}</div>")
    exec_band = ('<section class="band" id="executive"><h2 class="band-title">Executive summary</h2>'
                 + head + _headline(state, n, sev, clear, total, result)
                 + f'<div class="metrics">{"".join(metrics)}</div>' + _class_cards(findings, state) + "</section>")

    attest = (f"{clear} of {total} AI exposure classes clear on the hosts we reached. "
              "This is what we checked — not a guarantee of zero risk everywhere.")
    d = ['<section class="band" id="details"><h2 class="band-title"><span>Details</span>'
         '<span class="toggles"><button type="button" onclick="aiexpToggle(true)">Expand all</button>'
         '<button type="button" onclick="aiexpToggle(false)">Collapse all</button></span></h2>']
    if state == "failed":
        errs = f" {len(result.errors)} discovery/probe error(s) recorded." if result.errors else ""
        d.append('<div class="section" id="failed"><h2>No hosts reached</h2><div class="notice">'
                 f"Discovery found {len(result.hosts_discovered)} host(s) but none responded, so no detector "
                 f"ran against live content. This is not a clean result.{_e(errs)}</div></div>")
    d.append(_detector_details(findings, by_det, state))
    if state == "no":
        d += [_coverage(by_det, "Coverage attestation", attest, inventory=True), _owasp(findings)]
    elif state == "few":
        d += [_coverage(by_det, "Still clear", attest, severe), _owasp(findings)]
    elif state == "many":
        d.append('<details class="plain"><summary>What we still cleared</summary>'
                 + _coverage(by_det, "Coverage attestation", attest, only_clear=True) + _owasp(findings) + "</details>")
    d.append(_limits(result))
    d.append("</section>")

    return ("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            f"<title>AI Exposure report — {_e(result.domain)}</title><style>{CSS}</style></head>"
            f'<body data-report-state="{state}"><main class="report">{exec_band}{"".join(d)}</main>'
            f"{TOGGLE_JS}</body></html>\n")
