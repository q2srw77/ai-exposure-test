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

REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_FIXTURES = str(REPO_ROOT / "tests" / "fixtures")

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
    domain = st.text_input("Domain", value="example.com")
    mode = st.radio("Mode", ["Replay recorded responses", "Live scan"], index=0)
    is_live = mode == "Live scan"

    if is_live:
        authorized = st.checkbox("I am authorized to scan this domain")
        replay_dir = None
        use_crtsh = st.toggle("Use crt.sh", value=True)
    else:
        authorized = True
        replay_dir = st.text_input("Replay directory", value=DEFAULT_FIXTURES)
        use_crtsh = st.toggle("Use crt.sh", value=False)

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
        st.info("No AI exposure findings.")
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
