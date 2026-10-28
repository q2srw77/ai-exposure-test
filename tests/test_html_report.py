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
    assert "<link" not in html and "<script" not in html and "http" not in html.split("<body")[0]


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
    assert "Summary by class" in html and "chatbot_widgets ×6" in html
    # groups ordered by detector class, leaked_keys first
    assert html.index('data-detector="leaked_keys"') < html.index('data-detector="exposed_endpoints"') \
        < html.index('data-detector="chatbot_widgets"')
    assert "What we still cleared" in html and "Scan limits" in html
    assert "Finding 20 &lt;b&gt;" in html
