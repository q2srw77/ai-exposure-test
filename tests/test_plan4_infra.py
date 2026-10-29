"""Plan 4: Chroma / Flowise / n8n / Qdrant / LiteLLM fingerprints + §6 sk- locks."""
import json

import pytest

from ai_exposure.detectors.exposed_endpoints import ExposedEndpointsDetector
from ai_exposure.detectors.leaked_keys import LeakedKeysDetector
from ai_exposure.models import ProbeResult

KEY = "sk-proj-" + "A1b2C3d4E5f6G7h8J9k0L1m2N3p4"


def probe(path, payload, headers=None, status=200):
    body = payload if isinstance(payload, str) else json.dumps(payload)
    return ProbeResult.model_validate({
        "host": "p4.example.com", "port": 443, "scheme": "https", "path": path, "status": status,
        "headers": headers or {"content-type": "application/json"}, "body": body,
    })


def titles(path, payload, headers=None):
    return [f.title for f in ExposedEndpointsDetector().analyze(probe(path, payload, headers))]


def test_paths_registered():
    for p in ("/api/v1/heartbeat", "/api/v2/heartbeat", "/api/v1/ping", "/rest/settings", "/openapi.json"):
        assert p in ExposedEndpointsDetector.extra_paths


@pytest.mark.parametrize("path", ["/api/v1/heartbeat", "/api/v2/heartbeat"])
def test_chroma_heartbeat(path):
    assert titles(path, {"nanosecond heartbeat": 1730000000000}) == ["Exposed Chroma vector database"]


def test_chroma_heartbeat_fp():
    assert titles("/api/v1/heartbeat", {"status": "ok"}) == []


def test_chroma_collections_header_gate():
    body = [{"id": "x", "name": "docs"}]
    assert "Open Chroma collections API" in titles("/api/v1/collections", body, {"chroma-trace-id": "t"})
    assert titles("/api/v1/collections", body) == []


def test_qdrant_root():
    assert titles("/", {"title": "qdrant - vector search engine", "version": "1.9.0"}) == [
        "Exposed Qdrant vector database"]
    assert titles("/", {"title": "my api"}) == []


def test_flowise_ping_and_root():
    assert titles("/api/v1/ping", "pong") == ["Exposed Flowise API"]
    assert titles("/api/v1/ping", "pong pong ok") == []
    assert titles("/", "<html><title>Flowise - Build AI Agents, Visually</title></html>") == ["Exposed Flowise UI"]


def test_flowise_bare_version_not_flagged():
    assert titles("/api/v1/version", {"version": "2.1.0"}) == []


def test_n8n_settings_and_root():
    fs = ExposedEndpointsDetector().analyze(probe("/rest/settings", {"data": {"versionCli": "1.64.0"}}))
    assert [f.title for f in fs] == ["Exposed n8n instance"]
    assert "1.64.0" in fs[0].detail and "cve" not in fs[0].detail.lower()
    assert titles("/rest/settings", {"data": {"theme": "dark"}}) == []
    assert titles("/", '<html><head><meta name="n8n:config:rest-endpoint" content="cmVzdA=="></head></html>') == [
        "Exposed n8n UI"]


def test_litellm_openapi_and_root():
    assert titles("/openapi.json", {"openapi": "3.1.0", "info": {"title": "LiteLLM API"}}) == ["Exposed LiteLLM proxy"]
    assert titles("/openapi.json", {"openapi": "3.1.0", "info": {"title": "Shop API"}}) == []
    assert titles("/", "<html><title>LiteLLM API - Swagger UI</title></html>") == ["Exposed LiteLLM proxy"]
    assert titles("/", "<html><title>Blog</title>we compared litellm vs others</html>") == []


def test_v1_models_401_stays_passive():
    p = probe("/v1/models", {"error": "auth"}, status=401)
    assert ExposedEndpointsDetector().analyze(p) == []


# §6 locks
def keys(path, body, headers=None):
    return LeakedKeysDetector().analyze(probe(path, body, headers or {"content-type": "text/html"}))


def test_sk_requires_nonalnum_boundary():
    assert keys("/", f'<button class="ask-assistant-button{KEY[2:]}">') == []
    assert keys("/", f"<div>task-{KEY[3:]}</div>") == []
    assert len(keys("/", f'const k="{KEY}";')) == 1


@pytest.mark.parametrize("path", ["/openapi.json", "/swagger.json", "/docs/openapi.json"])
def test_openapi_examples_skipped(path):
    assert keys(path, json.dumps({"openapi": "3.0", "example": KEY}), {"content-type": "application/json"}) == []


def test_openapi_shape_skipped_by_content():
    body = json.dumps({"openapi": "3.0.0", "x": KEY})
    assert keys("/api/spec", body, {"content-type": "application/json"}) == []
