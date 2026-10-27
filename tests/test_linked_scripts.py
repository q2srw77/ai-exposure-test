"""Linked <script src> crawl: same-origin .js fetched as a second probe pass."""

from ai_exposure import ScanOptions, scan
from ai_exposure.models import ProbeResult
from ai_exposure.probe import http_probe
from ai_exposure.probe.scripts import extract_script_paths, is_javascript
from ai_exposure.scanner import linked_script_targets
from ai_exposure.detectors.chatbot_widgets import ChatbotWidgetsDetector

FAKE_KEY = "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCD"
HTML = """<!doctype html><html><head>
<script src="/assets/keys-app.js"></script>
<script src="assets/keys-app.js"></script>
<script src="https://cdn.example.net/vendor.js"></script>
<script src="data:text/javascript,alert(1)"></script>
<script src="javascript:void(0)"></script>
<script src=""></script>
<script>inline()</script>
</head><body>hi</body></html>"""
APP_JS = f'const k="{FAKE_KEY}";fetch("https://api.openai.com/v1/chat/completions");window.intercomSettings={{}};'


def _root(body: str = HTML, status: int = 200) -> ProbeResult:
    return ProbeResult(host="js.example.com", port=443, scheme="https", path="/", status=status,
                       headers={"content-type": "text/html"}, body=body)


def test_extract_same_origin_only_and_dedup():
    assert extract_script_paths(_root()) == ["/assets/keys-app.js"]


def test_extract_cap_and_relative():
    body = "".join(f'<script src="js/{i}.js?v=1"></script>' for i in range(25))
    paths = extract_script_paths(_root(body), cap=10)
    assert len(paths) == 10 and paths[0] == "/js/0.js?v=1"


def test_extract_skips_non_root_and_non_200_and_js():
    assert extract_script_paths(_root(status=404)) == []
    js = ProbeResult(host="js.example.com", port=443, scheme="https", path="/assets/keys-app.js", status=200,
                     headers={"content-type": "application/javascript"}, body='<script src="/x.js">')
    assert extract_script_paths(js) == []  # no recursion
    assert linked_script_targets([_root(), js]) == []  # already probed -> deduped


def test_chatbot_js_rules_only_on_js():
    js = ProbeResult(host="h", port=443, scheme="https", path="/a.js", status=200, body=APP_JS)
    assert is_javascript(js)
    titles = {f.title for f in ChatbotWidgetsDetector().analyze(js)}
    assert titles == {"OpenAI API call in client JS"}  # Intercom widget stays root-only
    other = js.model_copy(update={"path": "/api/data", "headers": {"content-type": "application/json"}})
    assert ChatbotWidgetsDetector().analyze(other) == []


async def test_scan_fetches_linked_js(monkeypatch):
    calls: list[str] = []

    async def fake_probe_one(client, sem, host, port, path):
        calls.append(path)
        base = ProbeResult(host=host, port=port, scheme="https", path=path)
        if path == "/":
            return base.model_copy(update={"status": 200, "headers": {"content-type": "text/html"}, "body": HTML})
        if path == "/assets/keys-app.js":
            return base.model_copy(update={"status": 200,
                                           "headers": {"content-type": "application/javascript"}, "body": APP_JS})
        return base.model_copy(update={"status": 404})

    monkeypatch.setattr(http_probe, "probe_one", fake_probe_one)
    r = await scan(ScanOptions(domain="js.example.com", use_crtsh=False, ports=[443]))
    assert calls.count("/assets/keys-app.js") == 1
    js_url = "https://js.example.com/assets/keys-app.js"
    by_det = {(f.detector, f.url) for f in r.findings}
    assert ("leaked_keys", js_url) in by_det
    assert ("chatbot_widgets", js_url) in by_det
    assert not any(f.detector == "exposed_endpoints" and f.url == js_url for f in r.findings)
    assert FAKE_KEY not in r.model_dump_json()
