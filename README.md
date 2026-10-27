# AI Exposure Scanner (core)

> **Authorization:** this tool actively probes hosts. Only scan domains you own or have written permission to test.

Pure Python scanner core (no UI). See `SPEC.md`.

## Install
```bash
python3.11 -m venv .venv && .venv/bin/pip install -e '.[dev]'
```

## Run offline (replay fixtures, zero network)
```python
import asyncio
from ai_exposure import scan, scan_stream, ScanOptions

opts = ScanOptions(domain="example.com", use_crtsh=False, replay_dir="tests/fixtures")
# Seed hosts CT doesn't know yet (merged with crt.sh; order: root, extras, crt.sh; capped by max_hosts):
# ScanOptions(domain="example.com", extra_hosts=["api.example.com", "https://chat.example.com/x"])
print(asyncio.run(scan(opts)).model_dump_json(indent=2))

async def main():
    async for ev in scan_stream(opts):
        print(ev)
asyncio.run(main())
```

## Tests
```bash
.venv/bin/pytest -q
```

## Adding a detector
Drop one file in `ai_exposure/detectors/` with a `Detector` subclass that sets `name`; it auto-registers.

## Test harness (Streamlit)

Thin UI wrapper around `scan_stream` — no scanning logic in the front end.

```bash
.venv/bin/pip install -e '.[ui]'
.venv/bin/streamlit run app.py
```

Use **Replay recorded responses** (default) against `tests/fixtures` for offline checks. Live mode requires the authorization checkbox.

## Docker
```bash
docker compose up --build          # Streamlit harness → http://localhost:8501
docker compose run --rm test       # run pytest in the container
```
Replay mode works out of the box: fixtures are baked in at `/app/tests/fixtures`.
Live scans from the container need outbound network; only scan domains you're authorized to test.

**DNS wordlist** (`use_dns_wordlist=True` / Streamlit "DNS wordlist" toggle, live mode): resolves ~40 AI labels (`ai`, `api`, `llm`, `gradio`, `ollama`, …) as `<label>.<Domain>` via public DNS (1.1.1.1/8.8.8.8) and merges hits after Extra hosts, before crt.sh. Single-label only — nested hosts like `*.ai-test.<Domain>` still need Extra hosts. Lab labels live in `wordlist.LAB_LABELS` (opt-in via `wordlist_labels`).
