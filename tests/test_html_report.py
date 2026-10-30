from datetime import datetime, timedelta

from ai_exposure.models import Evidence, Finding, ScanResult, Severity
from ai_exposure.reporting import render_html_report, report_state

T0 = datetime(2026, 10, 27, 14, 2)


def _f(i, det="leaked_keys", sev=Severity.critical, owasp="LLM02: Sensitive Information Disclosure"):
    return Finding(detector=det, title=f"Finding {i} <b>", host=f"h{i}.example.com",
                   url=f"https://h{i}.example.com/", severity=sev, evidence=Evidence.confirmed,
                   owasp_llm=owasp, snippet="sk-proj…REDACTED")


def _result(findings):
    return ScanResult(domain="example.com", hosts_discovered=["a", "b"], hosts_alive=["a"],
                      findings=findings, started_at=T0, finished_at=T0 + timedelta(seconds=131))


def test_thresholds():
    assert report_state(_result([])) == "no"
    assert report_state(_result([_f(i) for i in range(1)])) == "few"
    assert report_state(_result([_f(i) for i in range(9)])) == "few"
    assert report_state(_result([_f(i) for i in range(10)])) == "many"


def test_no_findings_leads_with_attestation():
    html = render_html_report(_result([]))
    assert html.startswith("<!DOCTYPE html>")
    assert 'data-report-state="no"' in html
    assert "Coverage attestation" in html and "3 of 3 AI exposure classes clear" in html
    for det in ("leaked_keys", "exposed_endpoints", "chatbot_widgets"):
        assert f'data-class="{det}" data-hits="0"' in html
    assert "LLM02 Sensitive Information — clear" in html
    assert "Scan limits" in html and "Duration 2m 11s" in html
    assert "<link" not in html and "<script src" not in html and "http" not in html.split("<body")[0]
    # No-state keeps the probe inventory under attestation
    assert "unauth paths probed" in html


def test_few_findings_table_and_checklist():
    fs = [_f(1), _f(2, "chatbot_widgets", Severity.medium, "LLM07"), _f(3, "chatbot_widgets", Severity.info, None)]
    html = render_html_report(_result(fs))
    assert 'data-report-state="few"' in html
    assert "Finding 1 &lt;b&gt;" in html and "<b>" not in html  # escaped
    assert "sk-proj…REDACTED" in html
    assert "Still clear" in html and "1 of 3 AI exposure classes clear" in html
    assert 'data-class="exposed_endpoints" data-hits="0"' in html
    assert "LLM02 Sensitive Information — 1 finding" in html
    assert "LLM07 System Prompt / client API — 1 finding" in html
    assert "LLM06 Excessive Agency — clear*" in html
    assert "Scan limits" in html


def test_many_findings_grouped_severity_first():
    fs = [_f(i, "chatbot_widgets", Severity.info, None) for i in range(6)]
    fs += [_f(10 + i, "exposed_endpoints", Severity.high, "LLM06") for i in range(3)]
    fs += [_f(20 + i) for i in range(2)]
    html = render_html_report(_result(fs))
    assert 'data-report-state="many"' in html
    assert "11 findings · severity-first" in html
    assert 'data-card="chatbot_widgets"' in html and "6 · worst info" in html
    # groups ordered by detector class, leaked_keys first
    assert html.index('data-detector="leaked_keys"') < html.index('data-detector="exposed_endpoints"') \
        < html.index('data-detector="chatbot_widgets"')
    assert "What we still cleared" in html and "Scan limits" in html
    assert "Finding 20 &lt;b&gt;" in html


def test_failed_scan_never_clean():
    r = ScanResult(domain="example.com", hosts_discovered=["a"], hosts_alive=[], findings=[],
                   started_at=T0, finished_at=T0 + timedelta(seconds=5))
    html = render_html_report(r)
    assert 'data-report-state="failed"' in html
    assert "Clean" not in html.split("<body")[1].split("Why")[0]
    assert "0 hosts alive" in html and "Scan limits" in html


def test_metrics_and_preset():
    html = render_html_report(_result([]), urls_probed=48, preset="AI Test Pages")
    assert "URLs / JS probed" in html and ">48<" in html and "· Preset: AI Test Pages" in html
    assert "URLs / JS probed</div><div class=\"value\">0<" in render_html_report(_result([]))  # falls back to result.urls_probed


def test_many_still_cleared_only_clear_rows():
    fs = [_f(i) for i in range(10)]
    html = render_html_report(_result(fs))
    cleared = html.split("What we still cleared")[1].split("</details>")[0]
    assert 'data-class="leaked_keys"' not in cleared
    assert 'data-class="exposed_endpoints" data-hits="0"' in cleared


def test_exec_first_then_collapsible_details():
    fs = [_f(1), _f(2, "chatbot_widgets", Severity.medium, "LLM07")]
    html = render_html_report(_result(fs))
    assert html.index('id="executive"') < html.index('id="details"')
    assert html.index('id="classes"') < html.index("<details")
    for det in ("leaked_keys", "exposed_endpoints", "chatbot_widgets"):
        assert f'<details class="det" data-detector="{det}"' in html
    assert "Leaked keys <span class=\"sum\">— 1 finding · worst critical" in html
    assert "Expand all" in html and "Collapse all" in html and "beforeprint" in html
    assert "max-width:920px" not in html and "max-width:min(1100px,100%)" in html
    assert "@media print" in html
    assert "Clear on reached hosts" in html and "1 · worst critical" in html
    assert "spend quota" in html  # why-it-matters lock


def test_few_clear_row_outcome_copy_and_grammar():
    html = render_html_report(_result([_f(1), _f(2, "chatbot_widgets")]))
    assert "2 findings · 1 class clear" in html
    still = html.split("Still clear")[1]
    assert "no unauth Gradio / Ollama / Jupyter / Streamlit / Langflow / Ray / Open WebUI / Chroma / Qdrant / Flowise / n8n / LiteLLM / agent-card markers on probed paths." in still
    assert "unauth paths probed" not in still
    assert "1 hit — see Findings." in still
    html2 = render_html_report(_result([_f(1)]))
    assert "1 finding · 2 classes clear" in html2


def test_failed_cards_not_clear():
    r = ScanResult(domain="example.com", hosts_discovered=["a"], hosts_alive=[], findings=[],
                   started_at=T0, finished_at=T0 + timedelta(seconds=5))
    html = render_html_report(r)
    assert "Clear on reached hosts" not in html and 'data-state="failed"' in html


def test_urls_probed_falls_back_to_result_field():
    from datetime import datetime, timezone
    from ai_exposure.models import ScanResult
    from ai_exposure.reporting import render_html_report
    r = ScanResult(domain="example.com", urls_probed=37, started_at=datetime.now(timezone.utc))
    assert "37" in render_html_report(r)


def test_plan6_top_hosts_strip():
    fs = [_f(1), _f(1, "chatbot_widgets", Severity.info, None), _f(1, "exposed_endpoints", Severity.high)]
    fs += [_f(i, "chatbot_widgets", Severity.info, None) for i in range(2, 9)]
    html = render_html_report(_result(fs))
    strip = html.split('id="top-hosts"')[1].split("</div>")[0]
    assert 'data-host="h1.example.com"' in strip and '<span class="n">3</span>' in strip
    assert strip.index("h1.example.com") < strip.index("h2.example.com")
    assert strip.count("data-host=") == 5 and "+3 more hosts" in strip
    assert 'id="top-hosts"' not in render_html_report(_result([]))
    assert html.index('id="classes"') < html.index('id="top-hosts"') < html.index('id="details"')


def test_plan6_attestation_strip_in_many_state():
    fs = [_f(i) for i in range(10)]
    html = render_html_report(_result(fs))
    assert 'data-report-state="many"' in html
    exec_band = html.split('id="details"')[0]
    assert 'id="attestation-strip"' in exec_band
    assert 'data-attest="leaked_keys">Leaked keys — 10 hits' in exec_band
    assert 'data-attest="exposed_endpoints">Exposed AI infra — ✓ clear' in exec_band
    assert "What we still cleared" in html  # details block kept


def test_plan6_crit_why_only_on_critical():
    crit = _f(1)
    crit.detail = "OpenAI key <script> in app.js"
    fs = [crit, _f(2, "exposed_endpoints", Severity.high, "LLM06"), _f(3, "chatbot_widgets", Severity.medium, "LLM07")]
    html = render_html_report(_result(fs))
    assert html.count('class="crit-why"') == 1
    assert "Why: OpenAI key &lt;script&gt; in app.js" in html and "<script> in" not in html
    # fallback when no detail
    html2 = render_html_report(_result([_f(5)]))
    assert html2.count('class="crit-why"') == 1 and "rotate now" in html2


# ---- Plan 7 ----
def _ep(title, url, sev=Severity.high):
    return Finding(detector="exposed_endpoints", title=title, host=urlparse_host(url), url=url,
                   severity=sev, evidence=Evidence.confirmed)


def urlparse_host(u):
    from urllib.parse import urlparse
    return urlparse(u).netloc


def test_plan7_single_page_family_strip():
    html = render_html_report(_result([]))
    for gone in ('role="tablist"', "view-surface", "view-findings", "Attack surface", "data-lane", "break-before", 'class="port"'):
        assert gone not in html
    for n in range(1, 8):
        assert f'data-family="{n}"' in html
    for n in (2, 7):
        assert f'data-family="{n}" data-family-state="out-of-scope"' in html
    assert html.count("Not in scope") >= 2
    assert 'data-family="3" data-family-state="clear"' in html
    assert "By design, not in scope" in html and "No CVE exploitation" in html and "No prompt abuse" in html
    # hard skips
    for bad in ("sk-1234", "CVE-", "Meridian"):
        assert bad not in html


def test_plan7_family_1_vs_4_split():
    fs = [_ep("Unauthenticated Ollama API", "https://llm.example.com:11434/api/tags", Severity.critical),
          _ep("Exposed Chroma vector database", "https://rag.example.com/api/v1/heartbeat", Severity.medium),
          _ep("Exposed Qdrant vector database", "https://rag.example.com/", Severity.medium),
          _f(1), _f(2, "chatbot_widgets", Severity.low, None)]
    html = render_html_report(_result(fs))
    assert 'data-family="1" data-family-state="hits" data-hits="1"' in html
    assert 'data-family="4" data-family-state="hits" data-hits="2"' in html
    assert 'data-family="6" data-family-state="hits" data-hits="1"' in html
    assert 'data-family="5" data-family-state="hits" data-hits="1"' in html
    assert "Attack surface" not in html and "data-lane" not in html
