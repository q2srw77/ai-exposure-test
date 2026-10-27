"""Plan 3: widget needles + agent surfaces (synthetic bodies)."""
import json

import pytest

from ai_exposure.detectors.chatbot_widgets import ChatbotWidgetsDetector
from ai_exposure.detectors.exposed_endpoints import ExposedEndpointsDetector
from ai_exposure.models import Evidence, ProbeResult, Severity


def run(path, body, status=200, ctype="text/html"):
    if not isinstance(body, str):
        body = json.dumps(body)
        ctype = "application/json"
    p = ProbeResult.model_validate({
        "host": "agents.example.com", "port": 443, "scheme": "https", "path": path,
        "status": status, "headers": {"content-type": ctype}, "body": body,
    })
    det = ChatbotWidgetsDetector() if path == "/" else ExposedEndpointsDetector()
    return det.analyze(p)


def titles(fs):
    return [f.title for f in fs]


@pytest.mark.parametrize("needle,title", [
    ('<script src="https://www.chatbase.co/embed.min.js"></script>', "Chatbase chatbot"),
    ('<iframe id="chatbot-iframe"></iframe>', "Chatbase chatbot"),
    ('<script src="https://cdn.voiceflow.com/widget/bundle.mjs"></script>', "Voiceflow chat widget"),
    ('<script src="https://cdn.botpress.cloud/webchat/v2/inject.js"></script>', "Botpress webchat"),
    ('<script src="//code.tidio.co/abc.js"></script>', "Tidio chat widget"),
    ('<script src="https://client.crisp.chat/l.js"></script>', "Crisp chat widget"),
])
def test_widget_needles(needle, title):
    fs = run("/", f"<html><body>{needle}</body></html>")
    assert titles(fs) == [title]
    assert fs[0].severity == Severity.info and fs[0].owasp_llm is None


def test_paths_registered():
    for p in ("/.well-known/agent-card.json", "/.well-known/agent.json",
              "/.well-known/ai-plugin.json", "/llms.txt"):
        assert p in ExposedEndpointsDetector.extra_paths
        assert p not in ChatbotWidgetsDetector.extra_paths


@pytest.mark.parametrize("path", ["/.well-known/agent-card.json", "/.well-known/agent.json"])
def test_agent_card_hit(path):
    fs = run(path, {"name": "Demo", "url": "https://agents.example.com/a2a", "skills": [{"id": "s"}]})
    assert titles(fs) == ["Exposed A2A agent card"]
    f = fs[0]
    assert f.severity == Severity.medium and f.evidence == Evidence.confirmed
    assert f.owasp_llm == "LLM06: Excessive Agency"


def test_agent_card_missing_skills():
    assert run("/.well-known/agent-card.json", {"name": "Demo", "url": "https://x"}) == []


def test_agent_card_non_200_or_html():
    card = {"url": "https://x", "skills": []}
    assert run("/.well-known/agent-card.json", card, status=404) == []
    assert run("/.well-known/agent-card.json", "<html>skills url</html>") == []


def test_ai_plugin_hit():
    fs = run("/.well-known/ai-plugin.json", {
        "schema_version": "v1", "name_for_model": "demo", "description_for_model": "d",
        "api": {"type": "openapi", "url": "https://x/openapi.yaml"},
    })
    assert titles(fs) == ["Exposed AI plugin manifest"]
    assert fs[0].severity == Severity.medium and fs[0].evidence == Evidence.confirmed


def test_ai_plugin_partial_and_miss():
    fs = run("/.well-known/ai-plugin.json", {"name": "demo", "description": "d"})
    assert fs[0].evidence == Evidence.probable
    assert run("/.well-known/ai-plugin.json", {"foo": 1}) == []


def test_llms_txt_hit():
    fs = run("/llms.txt", "# Demo\n\n> Site\n\n- [Docs](https://x/docs.md)\n", ctype="text/plain")
    assert titles(fs) == ["llms.txt published"]
    assert fs[0].severity == Severity.info and fs[0].owasp_llm is None


def test_llms_txt_empty_or_html():
    assert run("/llms.txt", "", ctype="text/plain") == []
    assert run("/llms.txt", "   \n", ctype="text/plain") == []
    assert run("/llms.txt", "<html>Not Found</html>") == []


def test_widgets_not_on_linked_js():
    p = ProbeResult.model_validate({
        "host": "a.example.com", "port": 443, "scheme": "https", "path": "/app.js",
        "status": 200, "headers": {"content-type": "application/javascript"},
        "body": 'load("https://client.crisp.chat/l.js")',
    })
    assert ChatbotWidgetsDetector().analyze(p) == []
