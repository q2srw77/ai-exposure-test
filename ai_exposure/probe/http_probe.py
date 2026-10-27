from __future__ import annotations
import asyncio
from collections.abc import Callable
import httpx
from ..models import ProbeResult

BODY_CAP = 500_000
USER_AGENT = "ai-exposure-scanner/0.1"


def scheme_for(port: int) -> str:
    return "https" if port in (443, 8443) else "http"


async def probe_one(client: httpx.AsyncClient, sem: asyncio.Semaphore, host: str, port: int, path: str) -> ProbeResult:
    scheme = scheme_for(port)
    base = ProbeResult(host=host, port=port, scheme=scheme, path=path)
    async with sem:
        try:
            r = await client.get(base.url)
            return base.model_copy(update={"status": r.status_code, "headers": dict(r.headers),
                                           "body": r.text[:BODY_CAP]})
        except Exception as e:  # network errors never crash the scan
            return base.model_copy(update={"error": f"{type(e).__name__}: {e}"})


async def probe_all(hosts: list[str], ports: list[int], paths: list[str], concurrency: int, timeout: float,
                    on_done: Callable[[int, int], None] | None = None) -> list[ProbeResult]:
    sem = asyncio.Semaphore(max(1, concurrency))
    combos = [(h, p, path) for h in hosts for p in ports for path in paths]
    results: list[ProbeResult] = []
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False,
                                 headers={"User-Agent": USER_AGENT}) as client:
        tasks = [asyncio.create_task(probe_one(client, sem, *c)) for c in combos]
        for fut in asyncio.as_completed(tasks):
            results.append(await fut)
            if on_done:
                on_done(len(results), len(combos))
    return results
