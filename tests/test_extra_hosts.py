import pytest

from ai_exposure import ScanOptions, scan
from ai_exposure import scanner as sc
from ai_exposure.scanner import build_host_list, normalize_host


@pytest.fixture
def capture(monkeypatch):
    seen = {}

    async def fake_probe_all(hosts, ports, paths, conc, timeout, on_done=None):
        seen["hosts"] = list(hosts)
        return []

    monkeypatch.setattr(sc.http_probe, "probe_all", fake_probe_all)
    return seen


def _crt(monkeypatch, hosts=None, exc=None):
    async def fake(domain, max_hosts, timeout=None):
        if exc:
            raise exc
        return list(hosts)
    monkeypatch.setattr(sc.crtsh, "discover", fake)


@pytest.mark.parametrize("raw,want", [
    ("  Keys.AI-Test.Example.com ", "keys.ai-test.example.com"),
    ("https://api.example.com/api/tags?x=1", "api.example.com"),
    ("http://host.example.com:8080", "host.example.com"),
    ("chat.example.com.", "chat.example.com"),
    ("*.wild.example.com", "wild.example.com"),
    ("", None), ("   ", None), ("# comment", None),
])
def test_normalize_host(raw, want):
    assert normalize_host(raw) == want


def test_build_order_dedupe_and_cap():
    out = build_host_list("example.com", ["B.example.com", "https://b.example.com/", "", "c.example.com"],
                          ["example.com", "z.example.com", "c.example.com", "y.example.com"], 4)
    assert out == ["example.com", "b.example.com", "c.example.com", "z.example.com"]
    assert build_host_list("example.com", ["a.example.com"], ["z.example.com"], 1) == ["example.com"]


async def test_crtsh_on_merges_extras(monkeypatch, capture):
    _crt(monkeypatch, ["x.example.com", "keys.example.com"])
    r = await scan(ScanOptions(domain="example.com", extra_hosts=["KEYS.example.com", "gradio.example.com"]))
    assert capture["hosts"] == ["example.com", "keys.example.com", "gradio.example.com", "x.example.com"]
    assert r.hosts_discovered == capture["hosts"]


async def test_crtsh_off_uses_root_plus_extras(monkeypatch, capture):
    _crt(monkeypatch, exc=AssertionError("crt.sh must not be called"))
    await scan(ScanOptions(domain="example.com", use_crtsh=False, extra_hosts=["https://api.example.com/x"]))
    assert capture["hosts"] == ["example.com", "api.example.com"]


async def test_root_kept_when_crtsh_omits_it_or_fails(monkeypatch, capture):
    _crt(monkeypatch, ["other.example.com"])
    await scan(ScanOptions(domain="example.com"))
    assert capture["hosts"][0] == "example.com"
    _crt(monkeypatch, exc=RuntimeError("down"))
    r = await scan(ScanOptions(domain="example.com", extra_hosts=["a.example.com"]))
    assert capture["hosts"] == ["example.com", "a.example.com"]
    assert any("crt.sh" in e for e in r.errors)


async def test_max_hosts_prefers_root_then_extras(monkeypatch, capture):
    _crt(monkeypatch, [f"c{i}.example.com" for i in range(10)])
    await scan(ScanOptions(domain="example.com", max_hosts=3, extra_hosts=["e1.example.com", "e2.example.com"]))
    assert capture["hosts"] == ["example.com", "e1.example.com", "e2.example.com"]
