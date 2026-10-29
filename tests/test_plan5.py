"""Plan 5 locks (PLAN5_FIXTURE.md §2): strict MCP + bounded SSE read + .js.map siblings + AI key prefixes."""
import asyncio
import json
from pathlib import Path

import httpx
import pytest

from ai_exposure.detectors.exposed_endpoints import ExposedEndpointsDetector
from ai_exposure.detectors.leaked_keys import LeakedKeysDetector
from ai_exposure.detectors.mcp_servers import McpServersDetector, is_high_agency
from ai_exposure.models import ProbeResult, Severity
from ai_exposure.probe import http_probe
from ai_exposure.probe.http_probe import MAP_BODY_CAP, SSE_BYTE_CAP, map_sibling_targets
from ai_exposure.scanner import linked_script_targets

FIX = Path(__file__).resolve().parent.parent / "fixtures" / "plan5"
SSE = {"content-type": "text/event-stream"}
HANDSHAKE = "event: endpoint\ndata: /messages?session_id=plan5-fixture\n\n"


def probe(path, body, headers=None, status=200, host="p5.example.com"):
    body = body if isinstance(body, str) else json.dumps(body)
    return ProbeResult(host=host, port=443, scheme="https", path=path, status=status,
                       headers=headers or {"content-type": "application/json"}, body=body)


def mcp(path, body, headers=None, status=200):
    return McpServersDetector().analyze(probe(path, body, headers, status))


def test_paths_only_sse_and_tools_list():
    assert McpServersDetector.extra_paths == ["/sse", "/tools/list"]


# --- SSE ---
def test_sse_positive():
    fs = mcp("/sse", HANDSHAKE, SSE)
    assert [(f.title, f.severity, f.owasp_llm) for f in fs] == [
        ("Exposed MCP SSE endpoint", Severity.high, "LLM06: Excessive Agency")]


def test_sse_session_id_alone_positive():
    assert mcp("/sse", "data: {\"session_id\": \"x\"}\n\n", SSE)


@pytest.mark.parametrize("body,headers", [
    (HANDSHAKE, {"content-type": "text/html"}),
    ('data: {"price": 1}\n\n', SSE),
    (": keepalive\n\n", SSE),
])
def test_sse_negatives(body, headers):
    assert mcp("/sse", body, headers) == []


def test_sse_needs_200_and_sse_path():
    assert mcp("/sse", HANDSHAKE, SSE, status=401) == []
    assert mcp("/events", HANDSHAKE, SSE) == []


def _run_sse(handler):
    seen = []

    def h(req):
        seen.append(req.method)
        return handler(req)

    async def go():
        async with httpx.AsyncClient(transport=httpx.MockTransport(h)) as c:
            return await http_probe.probe_one(c, asyncio.Semaphore(1), "h.test", 443, "/sse")
    r = asyncio.run(go())
    assert seen == ["GET"]  # never POSTs /messages
    return r


def test_sse_read_stops_at_first_event():
    async def stream():
        yield HANDSHAKE.encode()
        await asyncio.sleep(60)
        yield b"never"

    r = _run_sse(lambda req: httpx.Response(200, headers=SSE, content=stream()))
    assert r.body == HANDSHAKE
    assert McpServersDetector().analyze(r)[0].title == "Exposed MCP SSE endpoint"


def test_sse_byte_cap_8kb():
    r = _run_sse(lambda req: httpx.Response(200, headers=SSE, content=b"x" * (SSE_BYTE_CAP * 3)))
    assert len(r.body) == SSE_BYTE_CAP == 8192


def test_sse_time_cap(monkeypatch):
    assert http_probe.SSE_TIME_CAP == 3.0
    monkeypatch.setattr(http_probe, "SSE_TIME_CAP", 0.2)

    async def stream():
        yield b"data: partial"
        await asyncio.sleep(60)

    assert _run_sse(lambda req: httpx.Response(200, headers=SSE, content=stream())).body == "data: partial"


# --- tools/list ---
def test_tools_list_fixture_jsonrpc_bumped_in_place():
    fs = mcp("/tools/list", (FIX / "m" / "tools-list.json").read_text())
    assert len(fs) == 1  # bump is in place, no 2nd row
    f = fs[0]
    assert (f.title, f.severity, f.owasp_llm) == (
        "Unauthenticated MCP tools/list", Severity.critical, "LLM06: Excessive Agency")
    assert "read_file" in f.snippet and "run_command" in f.snippet


def test_tools_list_bare_shape():
    fs = mcp("/tools/list", {"tools": [{"name": "search_docs"}]})
    assert [(f.title, f.severity) for f in fs] == [("Unauthenticated MCP tools/list", Severity.high)]


@pytest.mark.parametrize("body,status", [
    ({"tools": "x"}, 200),
    ({"tools": ["hammer"]}, 200),
    ({"status": "ok"}, 200),
    ("<html>tools</html>", 200),
    ({"tools": [{"name": "read_file"}]}, 401),
])
def test_tools_list_negatives(body, status):
    assert mcp("/tools/list", body, status=status) == []


@pytest.mark.parametrize("name,hit", [
    ("read_file", True), ("run_command", True), ("exec_python", True), ("Shell", True),
    ("http_request", True), ("browser_open", True), ("tool.execute", True), ("search_docs", False),
    ("get_weather", False), ("executive_summary", False), ("seashell_facts", False), ("execsummary", False),
])
def test_bump_needles_name_only(name, hit):
    assert is_high_agency(name) is hit


def test_bump_ignores_descriptions():
    body = {"tools": [{"name": "search_docs", "description": "can exec shell read_file"}]}
    assert mcp("/tools/list", body)[0].severity is Severity.high


# --- .js.map siblings ---
def test_map_sibling_targets():
    t = [("h", 443, "/a.js"), ("h", 443, "/b.js?v=2"), ("h", 443, "/c.css"), ("h", 443, "/a.js")]
    assert map_sibling_targets(t) == [("h", 443, "/a.js.map"), ("h", 443, "/b.js.map")]


def test_map_sibling_skips_cross_origin_js():
    html = '<script src="https://cdn.other.com/x.js"></script><script src="/assets/plan5-app.js"></script>'
    root = probe("/", html, {"content-type": "text/html"})
    assert map_sibling_targets(linked_script_targets([root])) == [("p5.example.com", 443, "/assets/plan5-app.js.map")]


def test_map_body_cap_2mb():
    async def go():
        t = httpx.MockTransport(lambda r: httpx.Response(200, content=b"a" * (MAP_BODY_CAP + 10)))
        async with httpx.AsyncClient(transport=t) as c:
            return await http_probe.probe_one(c, asyncio.Semaphore(1), "h", 443, "/a.js.map")
    assert len(asyncio.run(go()).body) == MAP_BODY_CAP == 2_000_000


def test_map_fixture_yields_three_ai_keys_only_from_leaked_keys():
    p = probe("/assets/plan5-app.js.map", (FIX / "s" / "app.js.map").read_text())
    titles = sorted(f.title for f in LeakedKeysDetector().analyze(p))
    assert titles == ["Possible leaked Fireworks API key", "Possible leaked Tavily API key",
                      "Possible leaked Voyage AI API key"]


@pytest.mark.asyncio
async def test_scanner_runs_only_leaked_keys_on_map(monkeypatch):
    from ai_exposure import scanner
    from ai_exposure.models import ScanOptions

    html = '<script src="/assets/plan5-app.js"></script>'
    map_body = (FIX / "s" / "app.js.map").read_text() + ' "event: endpoint" pong'

    async def fake_all(hosts, ports, paths, *a, **k):
        return [probe("/", html, {"content-type": "text/html"}, host=hosts[0])]

    async def fake_targets(combos, *a, **k):
        return [probe(path, map_body if path.endswith(".map") else "x", {"content-type": "application/json"},
                      host=h) for h, _, path in combos]

    monkeypatch.setattr(scanner.http_probe, "probe_all", fake_all)
    monkeypatch.setattr(scanner.http_probe, "probe_targets", fake_targets)
    r = await scanner.scan(ScanOptions(domain="p5.example.com", use_crtsh=False, ports=[443]))
    map_rows = [f for f in r.findings if f.url.endswith(".js.map")]
    assert {f.detector for f in map_rows} == {"leaked_keys"} and len(map_rows) == 3


# --- AI prefixes ---
@pytest.mark.parametrize("vendor,key", [
    ("Fireworks", "fw_PLAN5FIXTUREx0000000000000000"),
    ("Voyage AI", "pa-PLAN5FIXTUREx00000000000000000000000000000000"),
    ("Tavily", "tvly-PLAN5FIXTUREx000000000000"),
])
def test_ai_prefix_fixture_strings(vendor, key):
    fs = LeakedKeysDetector().analyze(probe("/a.js", f'const k="{key}";', {"content-type": "text/javascript"}))
    assert [f.title for f in fs] == [f"Possible leaked {vendor} API key"]
    assert key not in fs[0].snippet


def test_voyage_after_hyphen_still_matches():  # Jason lookbehind kept verbatim
    assert LeakedKeysDetector().analyze(probe("/", "x-pa-" + "A1" * 22, {"content-type": "text/html"}))


@pytest.mark.parametrize("body", ["fw_abcdefghij", "xfw_" + "A1" * 15, "tvly-short"])
def test_ai_prefix_negatives(body):
    assert LeakedKeysDetector().analyze(probe("/", body, {"content-type": "text/html"})) == []


def test_non_ai_and_elevenlabs_out_of_scope():
    body = "ghp_" + "A" * 40 + " sk_live_" + "A" * 24 + " AKIA" + "A" * 16 + " sk_" + "a" * 44
    assert LeakedKeysDetector().analyze(probe("/", body, {"content-type": "text/html"})) == []


# --- regression: MCP doesn't fire on infra4 / existing paths ---
def test_mcp_quiet_on_infra4_bodies():
    for f in (Path(__file__).resolve().parent.parent / "fixtures" / "infra4").rglob("*"):
        if f.is_file():
            for path in ("/", "/openapi.json", "/api/v1/heartbeat"):
                assert mcp(path, f.read_text(errors="replace")) == []
    assert "/sse" not in ExposedEndpointsDetector.extra_paths
