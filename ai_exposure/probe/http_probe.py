from __future__ import annotations
import asyncio
import time
from collections.abc import Callable
import httpx
from ..models import ProbeResult

BODY_CAP = 500_000
MAP_BODY_CAP = 2_000_000  # Plan 5: .js.map siblings (leaked_keys only)
USER_AGENT = "ai-exposure-scanner/0.1"

# Plan 5: SSE first-event read caps (MCP HTTP+SSE transport streams forever).
SSE_BYTE_CAP = 8 * 1024
SSE_TIME_CAP = 3.0


def is_sse_path(path: str) -> bool:
    return path.split("?", 1)[0].rstrip("/").endswith("/sse")


def is_map_path(path: str) -> bool:
    return path.split("?", 1)[0].lower().endswith(".js.map")


def map_sibling_targets(script_targets: list[tuple[str, int, str]]) -> list[tuple[str, int, str]]:
    """For each same-origin *.js target (from linked_script_targets), also probe *.js.map.

    Ported from third-party probe/active.py map_sibling_targets(); bodies feed leaked_keys only."""
    out: list[tuple[str, int, str]] = []
    seen: set[tuple[str, int, str]] = set()
    for host, port, path in script_targets:
        if not path.lower().split("?", 1)[0].endswith(".js"):
            continue
        t = (host, port, path.split("?", 1)[0] + ".map")
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


async def _read_sse_first_event(client: httpx.AsyncClient, url: str) -> tuple[int, dict[str, str], str]:
    """Stream GET; stop at first blank-line event boundary, SSE_BYTE_CAP bytes, or SSE_TIME_CAP seconds."""
    buf = bytearray()
    deadline = time.monotonic() + SSE_TIME_CAP
    async with client.stream("GET", url, headers={"Accept": "text/event-stream"}) as r:
        status, headers = r.status_code, dict(r.headers)
        it = r.aiter_bytes().__aiter__()
        while len(buf) < SSE_BYTE_CAP:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            try:
                chunk = await asyncio.wait_for(it.__anext__(), timeout=left)
            except (StopAsyncIteration, asyncio.TimeoutError):
                break
            buf.extend(chunk)
            if b"\n\n" in buf or b"\r\n\r\n" in buf:
                break
    return status, headers, bytes(buf[:SSE_BYTE_CAP]).decode("utf-8", "replace")


def scheme_for(port: int) -> str:
    return "https" if port in (443, 8443) else "http"


async def probe_one(client: httpx.AsyncClient, sem: asyncio.Semaphore, host: str, port: int, path: str) -> ProbeResult:
    scheme = scheme_for(port)
    base = ProbeResult(host=host, port=port, scheme=scheme, path=path)
    async with sem:
        try:
            if is_sse_path(path):
                status, headers, body = await _read_sse_first_event(client, base.url)
                return base.model_copy(update={"status": status, "headers": headers, "body": body})
            r = await client.get(base.url)
            return base.model_copy(update={"status": r.status_code, "headers": dict(r.headers),
                                           "body": r.text[:MAP_BODY_CAP if is_map_path(path) else BODY_CAP]})
        except Exception as e:  # network errors never crash the scan
            return base.model_copy(update={"error": f"{type(e).__name__}: {e}"})


async def probe_all(hosts: list[str], ports: list[int], paths: list[str], concurrency: int, timeout: float,
                    on_done: Callable[[int, int], None] | None = None) -> list[ProbeResult]:
    combos = [(h, p, path) for h in hosts for p in ports for path in paths]
    return await probe_targets(combos, concurrency, timeout, on_done=on_done)


async def probe_targets(combos: list[tuple[str, int, str]], concurrency: int, timeout: float,
                        on_done: Callable[[int, int], None] | None = None) -> list[ProbeResult]:
    """Probe explicit (host, port, path) targets with the shared client settings."""
    sem = asyncio.Semaphore(max(1, concurrency))
    results: list[ProbeResult] = []
    if not combos:
        return results
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False,
                                 headers={"User-Agent": USER_AGENT}) as client:
        tasks = [asyncio.create_task(probe_one(client, sem, *c)) for c in combos]
        for fut in asyncio.as_completed(tasks):
            results.append(await fut)
            if on_done:
                on_done(len(results), len(combos))
    return results
