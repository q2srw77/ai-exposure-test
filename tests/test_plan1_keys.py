"""Plan 1 deepen: new key vendors + extra client-JS API needles (fake keys only)."""
import pytest

from ai_exposure.detectors.chatbot_widgets import ChatbotWidgetsDetector
from ai_exposure.detectors.leaked_keys import LeakedKeysDetector
from ai_exposure.models import ProbeResult, Severity

A = "A1b2C3d4E5f6G7h8J9k0" * 5  # 100 alnum chars


def probe(body, path="/", ctype="text/html"):
    return ProbeResult.model_validate({
        "host": "keys2.example.com", "port": 443, "scheme": "https", "path": path,
        "status": 200, "headers": {"content-type": ctype}, "body": body,
    })


def keys(body):
    return LeakedKeysDetector().analyze(probe(body))


CASES = [
    ("Groq", "gsk_" + A[:52]),
    ("Replicate", "r8_" + A[:37]),
    ("Perplexity", "pplx-" + A[:48]),
    ("xAI", "xai-" + A[:80]),
    ("OpenRouter", "sk-or-v1-" + "0123456789abcdef" * 4),
    ("LangSmith", "lsv2_pt_" + "0123456789abcdef" * 2 + "_0123456789"),
    ("Pinecone", "pcsk_ab12_" + A[:50]),
]


@pytest.mark.parametrize("vendor,key", CASES)
def test_new_vendor_detected_and_redacted(vendor, key):
    out = keys(f'<script>const k="{key}";</script>')
    assert [f.title for f in out] == [f"Possible leaked {vendor} API key"]
    f = out[0]
    assert f.severity is Severity.critical
    assert f.owasp_llm.startswith("LLM02")
    assert f.snippet == f"{key[:6]}…{key[-4:]}" and key not in f.snippet


def test_openrouter_not_double_counted_as_openai():
    out = keys('k="sk-or-v1-' + "ab" * 32 + '"')
    assert [f.title for f in out] == ["Possible leaked OpenRouter API key"]


def test_anthropic_not_double_counted_as_openai():
    out = keys('k="sk-ant-api03-' + A[:40] + '"')
    assert [f.title for f in out] == ["Possible leaked Anthropic API key"]


def test_openai_still_detected():
    out = keys('k="sk-proj-' + A[:40] + '"')
    assert [f.title for f in out] == ["Possible leaked OpenAI API key"]


def test_google_key_severity_depends_on_gemini_host():
    key = "AIza" + A[:35]
    plain = keys(f'maps("{key}")')
    gem = keys(f'fetch("https://generativelanguage.googleapis.com/v1beta/models?key={key}")')
    assert plain[0].severity is Severity.medium
    assert gem[0].severity is Severity.critical


@pytest.mark.parametrize("host,label", [
    ("generativelanguage.googleapis.com", "Google Gemini"),
    ("api.groq.com", "Groq"),
    ("openrouter.ai/api", "OpenRouter"),
    ("api.x.ai", "xAI"),
    ("api.mistral.ai", "Mistral"),
    ("api.cohere.com", "Cohere"),
])
@pytest.mark.parametrize("path,ctype", [("/", "text/html"), ("/assets/app.js", "application/javascript")])
def test_new_js_needles(host, label, path, ctype):
    out = ChatbotWidgetsDetector().analyze(probe(f'fetch("https://{host}/v1/chat")', path, ctype))
    assert [f.title for f in out] == [f"{label} API call in client JS"]
    assert out[0].severity is Severity.medium and out[0].owasp_llm.startswith("LLM07")


def test_skip_non_200_vercel_not_found():
    """Vercel 404 request ids can look like sk-… — do not report them."""
    body = "The page could not be found\n\nNOT_FOUND\n\niad1::sk-1793140341511-393b37bc703a\n"
    p = ProbeResult.model_validate({
        "host": "gradio.example.com", "port": 443, "scheme": "https",
        "path": "/.well-known/ai-plugin.json", "status": 404,
        "headers": {"content-type": "text/plain"}, "body": body,
    })
    assert LeakedKeysDetector().analyze(p) == []


def test_200_still_reports_openai_key():
    body = 'const k = "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789";'
    p = ProbeResult.model_validate({
        "host": "keys.example.com", "port": 443, "scheme": "https", "path": "/",
        "status": 200, "headers": {"content-type": "text/html"}, "body": body,
    })
    fs = LeakedKeysDetector().analyze(p)
    assert len(fs) == 1 and "OpenAI" in fs[0].title
