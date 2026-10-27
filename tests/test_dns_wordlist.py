import asyncio
import pytest
from ai_exposure.discovery import wordlist
from ai_exposure.models import ScanOptions
from ai_exposure.scanner import build_host_list
from ai_exposure import scanner


def fake(resolving):
    async def r(n):
        return n in resolving
    return r


def run(c):
    return asyncio.run(c)


def test_core_labels_shape():
    assert len(wordlist.CORE_LABELS) == 40
    assert not set(wordlist.LAB_LABELS) - {"gradio", "streamlit", "jupyter", "api"} & set(wordlist.CORE_LABELS)
    assert "keys" not in wordlist.CORE_LABELS and "ai-test" not in wordlist.CORE_LABELS


def test_subset_resolves_in_label_order():
    hits = run(wordlist.discover("Example.com.", resolver=fake({"gradio.example.com", "ai.example.com"})))
    assert hits == ["ai.example.com", "gradio.example.com"]


def test_no_resolve_empty():
    assert run(wordlist.discover("example.com", resolver=fake(set()))) == []


def test_resolver_exception_is_miss():
    async def boom(n):
        raise RuntimeError("x")
    assert run(wordlist.discover("example.com", ["ai"], resolver=boom)) == []


def test_custom_labels_and_ipv6_only_host():
    # resolver abstraction: AAAA-only host just returns True
    hits = run(wordlist.discover("ai-test.example.com", wordlist.LAB_LABELS, resolver=fake({"keys.ai-test.example.com"})))
    assert hits == ["keys.ai-test.example.com"]


def test_merge_order_and_dedupe():
    hosts = build_host_list("example.com", ["x.example.com", "ai.example.com"], ["crt.example.com", "ai.example.com"],
                            50, ["ai.example.com", "llm.example.com"])
    assert hosts == ["example.com", "x.example.com", "ai.example.com", "llm.example.com", "crt.example.com"]


def test_max_hosts_keeps_root_and_extras_first():
    hosts = build_host_list("example.com", ["x.example.com"], ["crt.example.com"], 3, ["ai.example.com", "llm.example.com"])
    assert hosts == ["example.com", "x.example.com", "ai.example.com"]


def test_backcompat_signature():
    assert build_host_list("example.com", [], ["a.example.com"], 10) == ["example.com", "a.example.com"]


def test_default_off():
    assert ScanOptions(domain="example.com").use_dns_wordlist is False


def test_scan_stream_crtsh_off_wordlist_on(monkeypatch):
    calls = {}

    async def fake_discover(root, labels=None, **kw):
        calls["labels"] = labels
        return ["ai.example.com"]

    async def fake_probe(hosts, *a, **kw):
        calls["hosts"] = list(hosts)
        return []

    monkeypatch.setattr(wordlist, "discover", fake_discover)
    monkeypatch.setattr(scanner.http_probe, "probe_all", fake_probe, raising=False)
    opts = ScanOptions(domain="example.com", use_crtsh=False, use_dns_wordlist=True, extra_hosts=["x.example.com"])

    async def go():
        last = None
        async for ev in scanner.scan_stream(opts):
            last = ev
        return last

    res = run(go())
    assert calls["labels"] is None
    assert calls["hosts"][:3] == ["example.com", "x.example.com", "ai.example.com"]
    assert res.hosts_discovered == ["example.com", "x.example.com", "ai.example.com"]


def test_sinkhole_ip_ignored():
    assert wordlist._is_sinkhole("198.18.0.1") and not wordlist._is_sinkhole("93.184.215.14")
