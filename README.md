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
