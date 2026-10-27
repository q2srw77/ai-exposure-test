"""Plan 2 first infra slice: Langflow / Ray / Open WebUI (synthetic bodies)."""
import json

import pytest

from ai_exposure.detectors.exposed_endpoints import ExposedEndpointsDetector
from ai_exposure.models import Evidence, ProbeResult, Severity


def run(path, payload):
    body = payload if isinstance(payload, str) else json.dumps(payload)
    p = ProbeResult.model_validate({
        "host": "infra2.example.com", "port": 443, "scheme": "https", "path": path,
        "status": 200, "headers": {"content-type": "application/json"}, "body": body,
    })
    return ExposedEndpointsDetector().analyze(p)


def titles(fs):
    return [f.title for f in fs]


def test_paths_registered():
    for p in ("/api/v1/version", "/api/version", "/api/config", "/api/tags"):
        assert p in ExposedEndpointsDetector.extra_paths


def test_langflow_hit():
    fs = run("/api/v1/version", {"version": "1.1.0", "package": "langflow", "main_version": "1.1.0"})
    assert titles(fs) == ["Exposed Langflow API"]
    assert fs[0].severity == Severity.critical and fs[0].evidence == Evidence.confirmed


def test_ray_hit():
    fs = run("/api/version", {"version": "4", "ray_version": "2.9.0", "ray_commit": "abc"})
    assert titles(fs) == ["Exposed Ray dashboard"]
    assert fs[0].severity == Severity.critical and "2.9.0" in fs[0].detail


@pytest.mark.parametrize("cfg,signup", [
    ({"name": "Open WebUI", "version": "0.5.0", "features": {"enable_signup": True}}, True),
    ({"name": "Open WebUI", "version": "0.5.0", "features": {"enable_signup": False}}, False),
])
def test_openwebui_hit(cfg, signup):
    fs = run("/api/config", cfg)
    assert titles(fs) == ["Exposed Open WebUI"]
    assert fs[0].severity == Severity.high
    assert ("signup" in fs[0].detail.lower()) is signup


@pytest.mark.parametrize("path,payload", [
    ("/api/version", {"version": "0.1.30"}),               # e.g. Ollama, no ray_version
    ("/api/v1/version", {"version": "1.0.0"}),             # no langflow marker
    ("/api/config", {"name": "Grafana", "version": "1"}),  # other product
    ("/api/config", "not json"),
])
def test_no_false_positive(path, payload):
    assert run(path, payload) == []
