from ai_exposure.models import Evidence, Finding, Severity
from ai_exposure.reporting.scoring import dedupe_findings


def _f(url, detector="jupyter", title="Exposed Jupyter", host="jupyter.example.com"):
    return Finding(detector=detector, title=title, host=host, url=url,
                   severity=Severity.critical, evidence=Evidence.confirmed)


def test_http_https_twins_collapse_prefer_https():
    out = dedupe_findings([_f("http://jupyter.example.com/api"), _f("https://jupyter.example.com/api")])
    assert len(out) == 1 and out[0].url.startswith("https://")


def test_https_first_kept():
    out = dedupe_findings([_f("https://jupyter.example.com/api"), _f("http://jupyter.example.com/api")])
    assert len(out) == 1 and out[0].url.startswith("https://")


def test_http_only_kept():
    out = dedupe_findings([_f("http://jupyter.example.com/api")])
    assert len(out) == 1 and out[0].url.startswith("http://")


def test_default_ports_collapse():
    out = dedupe_findings([_f("http://jupyter.example.com:80/api"), _f("https://jupyter.example.com:443/api")])
    assert len(out) == 1 and out[0].url.startswith("https://")


def test_different_detectors_same_host_stay_separate():
    out = dedupe_findings([
        _f("https://api.example.com/", detector="ollama", title="Ollama", host="api.example.com"),
        _f("https://api.example.com/", detector="mlflow", title="MLflow", host="api.example.com"),
    ])
    assert len(out) == 2


def test_different_titles_or_paths_stay_separate():
    out = dedupe_findings([
        _f("https://keys.example.com/", detector="leaked_keys", title="OpenAI key", host="keys.example.com"),
        _f("https://keys.example.com/", detector="leaked_keys", title="Anthropic key", host="keys.example.com"),
        _f("https://keys.example.com/a", detector="leaked_keys", title="OpenAI key", host="keys.example.com"),
    ])
    assert len(out) == 3


def test_non_default_ports_stay_separate():
    out = dedupe_findings([_f("http://jupyter.example.com:8888/api"), _f("https://jupyter.example.com/api")])
    assert len(out) == 2


def _k(url, snippet):
    return Finding(detector="leaked_keys", title="Possible leaked OpenAI API key", host="keys.example.com",
                   url=url, snippet=snippet, severity=Severity.high, evidence=Evidence.confirmed)


def test_same_title_url_different_snippets_stay_separate():
    out = dedupe_findings([_k("https://keys.example.com/", "sk-pro…0001"), _k("https://keys.example.com/", "sk-ant…0001")])
    assert len(out) == 2


def test_same_snippet_http_https_twins_collapse():
    out = dedupe_findings([_k("http://keys.example.com/", "sk-pro…0001"), _k("https://keys.example.com/", "sk-pro…0001")])
    assert len(out) == 1 and out[0].url.startswith("https://")
