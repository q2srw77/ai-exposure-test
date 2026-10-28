"""Thin Streamlit test harness for ai_exposure. No scanning logic — wraps scan_stream only."""
from __future__ import annotations

import asyncio
import csv
import io
import json
from pathlib import Path

import streamlit as st

from ai_exposure import ProgressEvent, ScanOptions, ScanResult, scan_stream
from ai_exposure.models import Evidence, Severity
from ai_exposure.reporting import render_html_report

REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_FIXTURES = str(REPO_ROOT / "tests" / "fixtures")

# Live Host fixtures under *.ai-test.cyphersecurity.us (matrix / vercel.json).
AI_TEST_PAGES_HOSTS = [
    "clean.ai-test.cyphersecurity.us",
    "widgets-intercom.ai-test.cyphersecurity.us",
    "widgets-drift.ai-test.cyphersecurity.us",
    "widgets-zendesk.ai-test.cyphersecurity.us",
    "widgets-ada.ai-test.cyphersecurity.us",
    "openai-js.ai-test.cyphersecurity.us",
    "anthropic-js.ai-test.cyphersecurity.us",
    "hf-js.ai-test.cyphersecurity.us",
    "keys.ai-test.cyphersecurity.us",
    "keys-js.ai-test.cyphersecurity.us",
    "keys2.ai-test.cyphersecurity.us",
    "infra2.ai-test.cyphersecurity.us",
    "agents.ai-test.cyphersecurity.us",
    "gradio.ai-test.cyphersecurity.us",
    "streamlit.ai-test.cyphersecurity.us",
    "jupyter.ai-test.cyphersecurity.us",
    "api.ai-test.cyphersecurity.us",
]

SEVERITY_COLORS = {
    "critical": "#c62828",
    "high": "#ef6c00",
    "medium": "#f9a825",
    "low": "#1565c0",
    "info": "#757575",
}


def _severity_badge(sev: str) -> str:
    color = SEVERITY_COLORS.get(sev, "#757575")
    return (
        f'<span style="background:{color};color:white;padding:2px 8px;'
        f'border-radius:4px;font-size:0.85em;">{sev}</span>'
    )


def _evidence_badge(ev: str) -> str:
    return (
        f'<span style="background:#eceff1;color:#37474f;padding:2px 8px;'
        f'border-radius:4px;font-size:0.85em;">{ev}</span>'
    )


async def _run_scan(opts: ScanOptions) -> tuple[list[dict], ScanResult | None]:
    events: list[dict] = []
    result: ScanResult | None = None
    async for item in scan_stream(opts):
        if isinstance(item, ProgressEvent):
            events.append(
                {
                    "stage": item.stage,
                    "message": item.message,
                    "done": item.done,
                    "total": item.total,
                }
            )
        elif isinstance(item, ScanResult):
            result = item
    return events, result


def _html_report_download(result: ScanResult) -> None:
    st.download_button(
        "Download HTML report",
        data=render_html_report(result),
        file_name=f"ai-exposure-{result.domain}-report.html",
        mime="text/html",
    )


def _findings_csv(result: ScanResult) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(
        ["severity", "evidence", "title", "host", "owasp_llm", "detail", "snippet", "url"]
    )
    for f in result.findings:
        writer.writerow(
            [
                f.severity.value,
                f.evidence.value,
                f.title,
                f.host,
                f.owasp_llm or "",
                f.detail,
                f.snippet,
                f.url,
            ]
        )
    return buf.getvalue()


st.set_page_config(page_title="AI Exposure Scanner", layout="wide")
st.title("AI Exposure Scanner")
st.caption("Test harness — wraps `scan_stream` only. Core stays UI-free.")

with st.sidebar:
    st.header("Scan controls")
    if "domain_input" not in st.session_state:
        st.session_state.domain_input = "example.com"
    domain = st.text_input("Domain", key="domain_input")
    mode = st.radio("Mode", ["Replay recorded responses", "Live scan"], index=0)
    is_live = mode == "Live scan"

    if is_live:
        authorized = st.checkbox("I am authorized to scan this domain")
        replay_dir = None
        if "use_crtsh_toggle" not in st.session_state:
            st.session_state.use_crtsh_toggle = True
        use_crtsh = st.toggle("Use crt.sh", key="use_crtsh_toggle")
        use_dns_wordlist = st.toggle(
            "DNS wordlist",
            value=False,
            help="Resolves ~40 common AI labels (ai, api, llm, gradio, ollama, …) as <label>.<Domain> via public DNS "
            "and adds hits. Single-label only — does NOT find nested hosts like *.ai-test.<Domain>; use Extra hosts.",
        )
    else:
        use_dns_wordlist = False
        authorized = True
        replay_dir = st.text_input("Replay directory", value=DEFAULT_FIXTURES)
        if "use_crtsh_toggle" not in st.session_state:
            st.session_state.use_crtsh_toggle = False
        use_crtsh = st.toggle("Use crt.sh", key="use_crtsh_toggle")

    if "extra_hosts_text" not in st.session_state:
        st.session_state.extra_hosts_text = ""

    def _load_ai_test_pages_preset() -> None:
        # Must run in on_click (before widgets instantiate) — mutating keyed widget state
        # after st.text_input/st.toggle raises StreamlitWidgetAlreadyInstantiatedError.
        st.session_state.extra_hosts_text = "\n".join(AI_TEST_PAGES_HOSTS)
        st.session_state.domain_input = "cyphersecurity.us"
        st.session_state.use_crtsh_toggle = False

    st.button(
        "Load AI Test Pages preset",
        help="Fills Extra hosts with the 17 *.ai-test.cyphersecurity.us fixture leaves "
        "(nested Hosts CT/wordlist miss). Sets Domain to cyphersecurity.us and turns crt.sh off.",
        on_click=_load_ai_test_pages_preset,
    )

    extra_hosts_text = st.text_area(
        "Extra hosts",
        placeholder="keys.ai-test.example.com\napi.example.com",
        help="One host per line (URLs ok; hostname is used). Merged with crt.sh results, "
        "root domain always kept. Use when Certificate Transparency lags behind live hosts.",
        key="extra_hosts_text",
    )
    extra_hosts = [ln.strip() for ln in extra_hosts_text.splitlines() if ln.strip()]

    max_hosts = st.slider("Max hosts", 1, 500, 200)
    concurrency = st.slider("Concurrency", 1, 100, 20)
    timeout_seconds = st.slider("Timeout (seconds)", 1, 30, 8)

    can_run = bool(domain.strip()) and (authorized if is_live else True)
    run = st.button("Run scan", type="primary", disabled=not can_run)
    if is_live and not authorized:
        st.caption("Check authorization to enable Run in live mode.")

    with st.expander("About / known limitations"):
        st.markdown(
            """
- HTTP(S) probing only. Non-HTTP AI services are not covered.
- Only the root page HTML is analyzed. Keys and SDK calls inside linked JavaScript files are not yet checked.
- Key detection is pattern-based and not validated against the vendor, so false positives are expected (heuristic grade).
- crt.sh can be slow or rate limited.
- Signatures are a starting set and vendor URLs change over time.
- The scanner does not verify domain ownership. The production platform must enforce scan authorization.
            """
        )

if "progress_events" not in st.session_state:
    st.session_state.progress_events = []
if "scan_result" not in st.session_state:
    st.session_state.scan_result = None
if "scan_error" not in st.session_state:
    st.session_state.scan_error = None

if run:
    opts = ScanOptions(
        domain=domain.strip(),
        use_crtsh=use_crtsh,
        max_hosts=max_hosts,
        extra_hosts=extra_hosts,
        use_dns_wordlist=use_dns_wordlist,
        concurrency=concurrency,
        timeout_seconds=float(timeout_seconds),
        replay_dir=replay_dir,
    )
    st.session_state.scan_error = None
    try:
        events, result = asyncio.run(_run_scan(opts))
        st.session_state.progress_events = events
        st.session_state.scan_result = result
    except Exception as e:
        st.session_state.scan_error = f"{type(e).__name__}: {e}"
        st.session_state.progress_events = []
        st.session_state.scan_result = None

if st.session_state.scan_error:
    st.error(st.session_state.scan_error)

events = st.session_state.progress_events
result: ScanResult | None = st.session_state.scan_result

st.subheader("Progress")
if events:
    last = events[-1]
    total = last.get("total") or 0
    done = last.get("done") or 0
    if total > 0:
        st.progress(min(done / total, 1.0), text=f"{last.get('stage')}: {last.get('message')}")
    else:
        st.info(last.get("message", ""))
    with st.expander("Last 15 progress events", expanded=True):
        for ev in events[-15:]:
            st.text(f"[{ev['stage']}] {ev['message']} ({ev['done']}/{ev['total']})")
else:
    st.caption("Run a scan to see progress.")

st.subheader("Summary")
if result:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Hosts discovered", len(result.hosts_discovered))
    c2.metric("Hosts alive", len(result.hosts_alive))
    c3.metric("Findings", len(result.findings))
    c4.metric("Errors", len(result.errors))
else:
    st.caption("No result yet.")

tab_findings, tab_json, tab_errors = st.tabs(["Findings", "Raw JSON", "Errors"])

with tab_findings:
    if not result:
        st.caption("No scan result yet.")
    elif not result.findings:
        st.info("No AI exposure findings — see the HTML report for coverage attestation and scan limits.")
        _html_report_download(result)
    else:
        sev_opts = [s.value for s in Severity]
        ev_opts = [e.value for e in Evidence]
        f_sev = st.multiselect("Severity", sev_opts, default=sev_opts)
        f_ev = st.multiselect("Evidence", ev_opts, default=ev_opts)
        rows = [
            f
            for f in result.findings
            if f.severity.value in f_sev and f.evidence.value in f_ev
        ]
        html_rows = []
        for f in rows:
            html_rows.append(
                "<tr>"
                f"<td>{_severity_badge(f.severity.value)}</td>"
                f"<td>{_evidence_badge(f.evidence.value)}</td>"
                f"<td>{f.title}</td>"
                f"<td>{f.host}</td>"
                f"<td>{f.owasp_llm or '—'}</td>"
                f"<td>{f.detail}</td>"
                f"<td><code>{f.snippet}</code></td>"
                f'<td><a href="{f.url}">{f.url}</a></td>'
                "</tr>"
            )
        st.markdown(
            "<table style='width:100%;font-size:0.9em'><thead><tr>"
            "<th>Severity</th><th>Evidence</th><th>Title</th><th>Host</th>"
            "<th>OWASP</th><th>Detail</th><th>Snippet</th><th>URL</th>"
            "</tr></thead><tbody>"
            + "".join(html_rows)
            + "</tbody></table>",
            unsafe_allow_html=True,
        )
        st.download_button(
            "Download findings CSV",
            data=_findings_csv(result),
            file_name=f"ai-exposure-{result.domain}-findings.csv",
            mime="text/csv",
        )
        _html_report_download(result)

with tab_json:
    if not result:
        st.caption("No scan result yet.")
    else:
        payload = result.model_dump(mode="json")
        with st.expander("Full ScanResult JSON", expanded=True):
            st.json(payload)
        st.download_button(
            "Download JSON",
            data=json.dumps(payload, indent=2),
            file_name=f"ai-exposure-{result.domain}.json",
            mime="application/json",
        )

with tab_errors:
    if not result:
        st.caption("No scan result yet.")
    elif not result.errors:
        st.info("No errors.")
    else:
        for err in result.errors:
            st.warning(err)
