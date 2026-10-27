# AI Exposure Scanner: Build Specification

> Paste this whole file into your AI app builder (Lovable, Grok, Bolt, etc.) as the project brief.
> Authorization note: this tool actively probes hosts. Only scan domains you own or have written permission to test.

## 1. Goal

Build a **domain-level AI exposure scanner**. Given a company domain, it discovers subdomains, probes them over HTTP(S), and detects AI-related exposure risks: exposed AI infrastructure, leaked AI API keys, and AI components embedded in public pages. Every finding carries a severity, an **evidence grade**, and an OWASP LLM Top 10 mapping.

The app has two parts:

1. **Scanner core**: a pure Python package with no UI code. This is what will later be executed by a separate production platform.
2. **Test harness UI**: a thin web front end used only to run the scanner, watch progress, and verify the output looks right before the core moves to production.

The scanner core must be fully usable without the UI. The UI is disposable.

## 2. Tech stack

- Python 3.11+
- `asyncio` for concurrency
- `httpx` (async client) for HTTP probing
- `dnspython` for DNS resolution
- `pydantic` v2 for typed models
- `pytest` + `pytest-asyncio` for tests
- Test harness: Streamlit (preferred) or a FastAPI backend with a simple React/HTML front end
- SQLite for optional scan history

## 3. Scanner core: package layout

```
ai_exposure/
  __init__.py            exports scan, scan_stream, ScanOptions
  models.py              all Pydantic models
  scanner.py             orchestrates the four stages
  discovery/
    crtsh.py             subdomains from certificate transparency (crt.sh)
  probe/
    http_probe.py        async probing with rate limit and timeouts
    replay.py            loads recorded responses for offline testing
  detectors/
    base.py              Detector interface + registry
    exposed_endpoints.py
    chatbot_widgets.py
    leaked_keys.py
  reporting/
    scoring.py           dedupe + sort
tests/
  fixtures/              recorded responses as JSON files
  test_detectors.py
  test_scanner.py
```

### Public API (this is the contract the production platform will call)

```python
async def scan(opts: ScanOptions) -> ScanResult
async def scan_stream(opts: ScanOptions) -> AsyncIterator[ProgressEvent | ScanResult]
```

`scan_stream` yields `ProgressEvent` objects as the scan runs and finishes with one `ScanResult`. `scan` simply consumes the stream and returns the final result.

## 4. Data models

**Evidence** (enum): `confirmed` (verified directly, e.g. an unauthenticated API actually responded), `probable` (strong signature match, not fully verified), `heuristic` (pattern match only, e.g. a regex hit).

**Severity** (enum): `info`, `low`, `medium`, `high`, `critical`.

**ScanOptions**
- `domain: str`
- `use_crtsh: bool = True`
- `max_hosts: int = 200`
- `concurrency: int = 20`
- `timeout_seconds: float = 8.0`
- `ports: list[int] = [80, 443, 8000, 8080, 8501, 7860, 11434]`
- `replay_dir: str | None` (if set, use recorded responses instead of live probing)
- `enabled_detectors: list[str] | None` (None means all)

**ProbeResult**: `host, port, scheme, path, status, headers, body, error`

**Finding**: `detector, title, host, url, severity, evidence, owasp_llm, detail, snippet`

**ScanResult**: `domain, hosts_discovered, hosts_alive, findings[], errors[], started_at, finished_at`

**ProgressEvent**: `stage` (discovery | probe | detect | report), `message`, `done`, `total`

## 5. Pipeline stages

1. **Discovery.** Start with the root domain. If `use_crtsh` is on, query `https://crt.sh/?q=%25.{domain}&output=json`, normalize names (lowercase, strip wildcards), keep only names ending in the target domain. Cap at `max_hosts`. If crt.sh fails, record an error and continue with the root domain only.
2. **Probing.** For every host, port, and path combination, make an async GET with a shared semaphore for concurrency, per-request timeout, redirects followed, TLS verification disabled (many exposed dev servers use self-signed certs), response body capped at 500,000 characters, and User-Agent `ai-exposure-scanner/0.1`. Paths probed are `/` plus every `extra_paths` declared by detectors. Network errors become a ProbeResult with `error` set; they never crash the scan.
3. **Detection.** Run every enabled detector against every probe that returned a status. A detector exception is caught and logged to `errors`; it never aborts the scan.
4. **Reporting.** Dedupe findings by `(detector, title, host, url)`. Sort by severity (critical first), then evidence grade (confirmed first), then host.

## 6. Detector plugin interface

Each detector is a class with a unique `name`, an optional list `extra_paths`, and one method `analyze(probe) -> list[Finding]`. Detectors register themselves in a registry, so adding a new detector means adding one file with no changes to the scanner. Detectors must be pure functions of the probe response (no network calls), which keeps them testable with recorded fixtures.

## 7. Detection rules

### 7.1 Exposed AI endpoints (`exposed_endpoints`)

Extra paths: `/api/tags`, `/api/v1/heartbeat`, `/collections`, `/v1/models`, `/api/2.0/mlflow/experiments/search`. Only evaluate responses with HTTP 200 and a non-empty body.

| Condition | Finding title | Severity | Evidence | OWASP LLM |
|---|---|---|---|---|
| Path `/api/tags` and JSON body has key `models` | Unauthenticated Ollama API | high | confirmed | LLM10: Unbounded Consumption |
| Path `/v1/models`, JSON has key `data`, body contains `"object"` | Open OpenAI-compatible model endpoint | high | probable | LLM10: Unbounded Consumption |
| Path `/collections` and body contains "collections" | Possibly open vector database | medium | probable | LLM02: Sensitive Information Disclosure |
| Path contains `mlflow` and JSON has key `experiments` | Unauthenticated MLflow tracking server | high | confirmed | LLM03: Supply Chain |
| Path `/` and body contains `gradio-app` or `window.gradio_config` | Public Gradio app | medium | probable | LLM06: Excessive Agency |
| Path `/` and body contains `streamlit` and `_stcore` | Public Streamlit app | medium | probable | LLM06: Excessive Agency |
| Path `/` and body contains `jupyter` and `notebook` | Exposed Jupyter interface | critical | probable | LLM06: Excessive Agency |

### 7.2 Leaked API keys (`leaked_keys`)

Run these regexes against every response body. All matches are **heuristic** evidence (pattern only, not validated with the vendor) and **critical** severity, mapped to LLM02: Sensitive Information Disclosure.

- OpenAI: `sk-(?:proj-)?[A-Za-z0-9_\-]{20,}`
- Anthropic: `sk-ant-[A-Za-z0-9_\-]{20,}`
- Hugging Face: `hf_[A-Za-z0-9]{30,}`
- Google API: `AIza[0-9A-Za-z_\-]{35}`

**Never store or display the full key.** Redact to first 6 characters, an ellipsis, and the last 4 characters.

### 7.3 Chatbot widgets and AI vendor calls (`chatbot_widgets`)

Only evaluate path `/`. Case-sensitive substring match against the body.

| Label | Needles | Severity |
|---|---|---|
| Intercom chat widget | `widget.intercom.io`, `intercomSettings` | info |
| Drift chatbot | `js.driftt.com` | info |
| Zendesk AI / Web Widget | `static.zdassets.com/ekr` | info |
| Ada chatbot | `static.ada.support` | info |
| OpenAI API call in client JS | `api.openai.com` | medium (LLM07: System Prompt Leakage) |
| Anthropic API call in client JS | `api.anthropic.com` | medium (LLM07: System Prompt Leakage) |
| Hugging Face inference call | `api-inference.huggingface.co` | medium (LLM07: System Prompt Leakage) |

All are **probable** evidence. Direct AI vendor calls from the browser are medium because they can expose keys and prompts; third-party widgets are informational.

## 8. Test harness UI requirements

A single-page app that wraps `scan_stream`. It must never contain scanning logic.

**Sidebar controls**
- Domain text input
- Checkbox: "I am authorized to scan this domain" (the Run button is disabled until checked in live mode)
- Mode switch: Live scan vs Replay recorded responses (replay shows a directory input, default `tests/fixtures`, and does not require the authorization checkbox)
- Toggle: use crt.sh
- Sliders: max hosts (1 to 500), concurrency (1 to 100), timeout seconds (1 to 30)
- Run scan button

**Main area**
- Live progress: a log of the last 15 progress events plus a progress bar
- Summary metrics: hosts discovered, hosts alive, findings count, errors count
- Three tabs:
  - **Findings**: filterable table with multiselect filters for severity and evidence grade. Columns: severity, evidence, title, host, OWASP mapping, detail, snippet, URL. CSV download button. Empty state: "No AI exposure findings."
  - **Raw JSON**: collapsible JSON of the full ScanResult, with a download button. This is the key view for confirming the output matches what production will receive.
  - **Errors**: list of recorded errors or "No errors."
- Color-code severity (critical red, high orange, medium yellow, low blue, info gray) and show evidence grade as a badge.

## 9. Acceptance criteria

1. The scanner core runs from a Python script with no UI installed: `asyncio.run(scan(ScanOptions(domain="example.com")))` returns a valid `ScanResult`.
2. Replay mode runs the whole pipeline with zero network access.
3. A clean marketing page produces zero findings.
4. A fixture simulating an open Ollama endpoint produces exactly one finding: "Unauthenticated Ollama API", high, confirmed.
5. A fixture containing a fake OpenAI-style key produces one critical, heuristic finding with a redacted snippet. The full key never appears anywhere in output.
6. A dead or slow host results in recorded errors, and the scan still completes.
7. Findings are sorted critical first, confirmed first, and duplicates are removed.
8. Adding a new detector requires adding one file and no edits to `scanner.py`.
9. The UI's Raw JSON tab output is identical to what `scan()` returns.

## 10. Test fixtures to create

Create these as JSON files in `tests/fixtures/`, each a serialized ProbeResult: clean marketing page, open Ollama `/api/tags` response, open vector database `/collections` response, Gradio app root page, page with Intercom widget, page with `api.openai.com` call in inline JS, page with a fake OpenAI-style key, and a Jupyter login page.

## 11. Known limitations (state these in the app's About section)

- HTTP(S) probing only. Non-HTTP AI services are not covered.
- Only the root page HTML is analyzed. Keys and SDK calls inside linked JavaScript files are not yet checked.
- Key detection is pattern-based and not validated against the vendor, so false positives are expected, which is why those findings are graded heuristic.
- crt.sh can be slow or rate limited.
- Signatures are a starting set and vendor URLs change over time.
- The scanner does not verify domain ownership. The production platform must enforce scan authorization.

## 12. Suggested next iterations

1. Crawl linked `.js` bundles and scan them for keys and vendor SDK calls.
2. Move detector signatures into YAML files so non-developers can contribute.
3. Add passive DNS sources and Shodan or Censys lookups.
4. Store scan history in SQLite and show a diff between runs.
5. Add an optional Nuclei integration for template-based checks.
