import socket
import textwrap
from pathlib import Path

import pytest

from ai_exposure import ScanOptions, scan, scan_stream
from ai_exposure.models import Evidence, Finding, ProgressEvent, ScanResult, Severity
from ai_exposure.reporting.scoring import finalize

FIX = str(Path(__file__).parent / "fixtures")
FAKE_KEY = "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCD"


@pytest.fixture
def no_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("network used")
    monkeypatch.setattr(socket.socket, "connect", boom)
    monkeypatch.setattr(socket, "create_connection", boom)


async def test_replay_offline(no_network):
    r = await scan(ScanOptions(domain="example.com", use_crtsh=False, replay_dir=FIX))
    assert isinstance(r, ScanResult)
    titles = [f.title for f in r.findings]
    assert titles.count("Unauthenticated Ollama API") == 1
    assert FAKE_KEY not in r.model_dump_json()
    assert any("dead.example.com" in e for e in r.errors)  # dead host recorded, scan completes
    assert "dead.example.com" not in r.hosts_alive
    assert r.findings[0].severity == Severity.critical


async def test_stream_events_then_result(no_network):
    items = [e async for e in scan_stream(ScanOptions(domain="example.com", replay_dir=FIX))]
    assert all(isinstance(e, ProgressEvent) for e in items[:-1])
    assert isinstance(items[-1], ScanResult)
    assert {e.stage for e in items[:-1]} == {"discovery", "probe", "detect", "report"}


async def test_live_probe_errors_dont_crash():
    # Unroutable reserved TLD host: errors recorded, scan completes.
    r = await scan(ScanOptions(domain="nonexistent.invalid", use_crtsh=False, ports=[80],
                               timeout_seconds=1, enabled_detectors=["chatbot_widgets"]))
    assert r.errors and r.findings == []


async def test_detector_exception_caught(no_network, monkeypatch):
    from ai_exposure.detectors import get_registry
    det = get_registry()["chatbot_widgets"]
    monkeypatch.setattr(det, "analyze", lambda p: 1 / 0)
    r = await scan(ScanOptions(domain="example.com", replay_dir=FIX))
    assert any("ZeroDivisionError" in e for e in r.errors)


def _f(sev, ev, host, title="t"):
    return Finding(detector="d", title=title, host=host, url=f"http://{host}/", severity=sev,
                   evidence=ev, owasp_llm="x")


def test_sort_and_dedupe():
    fs = [_f(Severity.info, Evidence.probable, "a"), _f(Severity.critical, Evidence.heuristic, "b"),
          _f(Severity.critical, Evidence.confirmed, "c"), _f(Severity.critical, Evidence.confirmed, "c")]
    out = finalize(fs)
    assert [(f.severity, f.evidence, f.host) for f in out] == [
        (Severity.critical, Evidence.confirmed, "c"), (Severity.critical, Evidence.heuristic, "b"),
        (Severity.info, Evidence.probable, "a")]


def test_new_detector_one_file(tmp_path):
    import importlib
    import ai_exposure.detectors as pkg
    p = Path(pkg.__path__[0]) / "zz_test_plugin.py"
    p.write_text(textwrap.dedent('''
        from .base import Detector
        class ZZ(Detector):
            name = "zz_test"
            def analyze(self, probe):
                return []
    '''))
    try:
        importlib.reload(pkg)
        assert "zz_test" in pkg.get_registry()
    finally:
        p.unlink()
        from ai_exposure.detectors import base
        base._REGISTRY.pop("zz_test", None)


@pytest.mark.asyncio
async def test_urls_probed_counts_replay_probes(no_network):
    from ai_exposure.probe.replay import load_replay
    r = await scan(ScanOptions(domain="example.com", use_crtsh=False, replay_dir=FIX))
    assert r.urls_probed > 0
    assert r.urls_probed >= len(load_replay(FIX))
