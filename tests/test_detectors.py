import json
from pathlib import Path

from ai_exposure.detectors import get_registry
from ai_exposure.detectors.leaked_keys import redact_key
from ai_exposure.models import ProbeResult

FIX = Path(__file__).parent / "fixtures"
FAKE_KEY = "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCD"


def load(name):
    return ProbeResult.model_validate(json.loads((FIX / name).read_text()))


def run_all(probe):
    out = []
    for d in get_registry().values():
        out += d.analyze(probe)
    return out


def test_registry_has_builtin():
    assert {"exposed_endpoints", "leaked_keys", "chatbot_widgets"} <= set(get_registry())


def test_clean_page_zero():
    assert run_all(load("clean_marketing.json")) == []


def test_ollama():
    f = run_all(load("ollama_api_tags.json"))
    assert len(f) == 1
    assert (f[0].title, f[0].severity.value, f[0].evidence.value) == ("Unauthenticated Ollama API", "high", "confirmed")
    assert f[0].owasp_llm == "LLM10: Unbounded Consumption"


def test_fake_key_redacted():
    f = run_all(load("fake_openai_key.json"))
    assert len(f) == 1
    assert f[0].severity.value == "critical" and f[0].evidence.value == "heuristic"
    assert f[0].snippet == redact_key(FAKE_KEY) == "sk-abc…ABCD"
    assert FAKE_KEY not in f[0].model_dump_json()


def test_vector_gradio_intercom_openai_jupyter():
    assert [x.title for x in run_all(load("vector_collections.json"))] == ["Possibly open vector database"]
    assert [x.title for x in run_all(load("gradio_app.json"))] == ["Public Gradio app"]
    findings = run_all(load("intercom_widget.json"))
    assert [x.title for x in findings] == ["Intercom chat widget"]
    assert findings[0].owasp_llm is None
    o = run_all(load("openai_client_js.json"))
    assert [x.title for x in o] == ["OpenAI API call in client JS"] and o[0].severity.value == "medium"
    j = run_all(load("jupyter_login.json"))
    assert [x.title for x in j] == ["Exposed Jupyter interface"] and j[0].severity.value == "critical"
