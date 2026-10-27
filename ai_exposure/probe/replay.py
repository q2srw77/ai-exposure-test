from __future__ import annotations

import json
from pathlib import Path

from ..models import ProbeResult


def load_replay(replay_dir: str) -> list[ProbeResult]:
    """Load recorded ProbeResults (one object or a list per *.json file). Zero network."""
    out: list[ProbeResult] = []
    root = Path(replay_dir)
    if not root.is_dir():
        return out
    for f in sorted(root.glob("*.json")):
        data = json.loads(f.read_text(encoding="utf-8"))
        if isinstance(data, list):
            for item in data:
                out.append(ProbeResult.model_validate(item))
        else:
            out.append(ProbeResult.model_validate(data))
    return out
