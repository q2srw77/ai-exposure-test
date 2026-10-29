from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime, timezone

from . import detectors as _detectors  # noqa: F401  — trigger registry load
from .detectors.base import all_extra_paths, enabled_detectors
from .discovery import crtsh, wordlist
from .models import ProgressEvent, ProbeResult, ScanOptions, ScanResult
from .probe import http_probe
from .probe.replay import load_replay
from .probe.scripts import MAX_SCRIPTS_PER_ORIGIN, extract_script_paths
from .reporting.scoring import finalize


def normalize_host(raw: str) -> str | None:
    """Return a bare lowercase hostname from a host/URL string, or None."""
    s = (raw or "").strip().lower()
    if not s or s.startswith("#"):
        return None
    if "://" in s:
        s = s.split("://", 1)[1]
    s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    s = s.rsplit("@", 1)[-1]
    if s.startswith("["):
        return None  # IPv6 literals not supported as hosts here
    s = s.split(":", 1)[0].strip(".")
    if s.startswith("*."):
        s = s[2:]
    return s or None


def build_host_list(
    root: str,
    extra_hosts: list[str],
    crtsh_hosts: list[str],
    max_hosts: int,
    wordlist_hosts: list[str] | None = None,
) -> list[str]:
    """Root, extra_hosts, wordlist DNS hits, then crt.sh hosts; dedupe; cap at max_hosts."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in [root, *extra_hosts, *(wordlist_hosts or []), *crtsh_hosts]:
        h = normalize_host(raw)
        if h and h not in seen:
            seen.add(h)
            out.append(h)
    return out[: max(1, max_hosts)]


def linked_script_targets(
    probes: list[ProbeResult], cap_per_origin: int = MAX_SCRIPTS_PER_ORIGIN
) -> list[tuple[str, int, str]]:
    """(host, port, path) targets for same-origin scripts linked from `/` HTML; deduped."""
    already = {(p.host, p.port, p.path) for p in probes}
    out: list[tuple[str, int, str]] = []
    for p in probes:
        for path in extract_script_paths(p, cap_per_origin):
            t = (p.host, p.port, path)
            if t not in already:
                already.add(t)
                out.append(t)
    return out


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


async def scan_stream(opts: ScanOptions) -> AsyncIterator[ProgressEvent | ScanResult]:
    """Yield ProgressEvents then a final ScanResult."""
    started = _utcnow()
    errors: list[str] = []
    root = normalize_host(opts.domain) or opts.domain.lower().strip(".")
    hosts: list[str] = [root]
    crt_hosts: list[str] = []

    # --- discovery ---
    yield ProgressEvent(stage="discovery", message=f"Starting discovery for {opts.domain}", done=0, total=1)
    if opts.replay_dir:
        # Offline: hosts come from fixture probe hosts (still record root).
        yield ProgressEvent(
            stage="discovery",
            message="Replay mode — skipping live crt.sh discovery",
            done=1,
            total=1,
        )
    elif opts.use_crtsh:
        try:
            crt_hosts = await crtsh.discover(opts.domain, opts.max_hosts, timeout=opts.timeout_seconds)
            yield ProgressEvent(
                stage="discovery",
                message=f"crt.sh returned {len(crt_hosts)} host(s)",
                done=1,
                total=1,
            )
        except Exception as e:
            errors.append(f"crt.sh discovery failed: {type(e).__name__}: {e}")
            yield ProgressEvent(
                stage="discovery",
                message="crt.sh failed; continuing with root domain only",
                done=1,
                total=1,
            )
    else:
        yield ProgressEvent(
            stage="discovery",
            message="crt.sh disabled; using root domain only",
            done=1,
            total=1,
        )

    wl_hosts: list[str] = []
    if opts.use_dns_wordlist and not opts.replay_dir:
        try:
            wl_hosts = await wordlist.discover(
                root, opts.wordlist_labels, concurrency=opts.concurrency, timeout=min(opts.timeout_seconds, 5.0)
            )
            yield ProgressEvent(
                stage="discovery", message=f"DNS wordlist resolved {len(wl_hosts)} host(s)", done=1, total=1
            )
        except Exception as e:  # noqa: BLE001
            errors.append(f"DNS wordlist failed: {type(e).__name__}: {e}")

    hosts = build_host_list(root, opts.extra_hosts, crt_hosts, opts.max_hosts, wl_hosts)
    if opts.extra_hosts:
        yield ProgressEvent(
            stage="discovery",
            message=f"Merged extra hosts; {len(hosts)} host(s) to probe",
            done=1,
            total=1,
        )

    # --- probe ---
    dets = enabled_detectors(opts.enabled_detectors)
    paths = ["/"] + all_extra_paths(opts.enabled_detectors)
    # Ensure unique paths, / first
    seen_paths: set[str] = set()
    ordered_paths: list[str] = []
    for p in paths:
        if p not in seen_paths:
            seen_paths.add(p)
            ordered_paths.append(p)

    probes: list[ProbeResult]
    if opts.replay_dir:
        yield ProgressEvent(stage="probe", message=f"Loading replay from {opts.replay_dir}", done=0, total=1)
        probes = load_replay(opts.replay_dir)
        # Derive discovered hosts from fixtures when replaying.
        fixture_hosts = sorted({p.host for p in probes})
        if fixture_hosts:
            hosts = fixture_hosts
        for i, _ in enumerate(probes, start=1):
            if i == 1 or i == len(probes):
                yield ProgressEvent(
                    stage="probe",
                    message=f"Replay loaded {len(probes)} probe(s)",
                    done=i,
                    total=len(probes) or 1,
                )
        if not probes:
            yield ProgressEvent(stage="probe", message="No replay fixtures found", done=1, total=1)
    else:
        total = max(1, len(hosts) * len(opts.ports) * len(ordered_paths))
        yield ProgressEvent(stage="probe", message="Starting HTTP probe", done=0, total=total)
        progress = {"n": 0}

        def on_done(done: int, tot: int) -> None:
            progress["n"] = done

        probes = await http_probe.probe_all(
            hosts,
            opts.ports,
            ordered_paths,
            opts.concurrency,
            opts.timeout_seconds,
            on_done=on_done,
        )
        yield ProgressEvent(
            stage="probe",
            message=f"Probed {len(probes)} target(s)",
            done=len(probes),
            total=total,
        )

        # Second pass: same-origin <script src> from 200 HTML `/` pages. Scripts are
        # never re-parsed, so this is one level deep by construction.
        script_targets = linked_script_targets(probes)
        # Plan 5: also try <script>.js.map siblings (source-map disclosure -> leaked_keys).
        have = {(p.host, p.port, p.path) for p in probes} | set(script_targets)
        script_targets += [t for t in http_probe.map_sibling_targets(script_targets) if t not in have]
        if script_targets:
            yield ProgressEvent(
                stage="probe",
                message=f"Fetching {len(script_targets)} linked script(s)",
                done=0,
                total=len(script_targets),
            )
            js_probes = await http_probe.probe_targets(script_targets, opts.concurrency, opts.timeout_seconds)
            probes.extend(js_probes)
            yield ProgressEvent(
                stage="probe",
                message=f"Fetched {len(js_probes)} linked script(s)",
                done=len(js_probes),
                total=len(script_targets),
            )

    # Record probe-level errors
    for p in probes:
        if p.error:
            errors.append(f"probe {p.url}: {p.error}")

    hosts_alive = sorted({p.host for p in probes if p.status is not None and p.error is None})

    # --- detect ---
    yield ProgressEvent(
        stage="detect",
        message=f"Running {len(dets)} detector(s)",
        done=0,
        total=max(1, len(dets)),
    )
    findings_raw = []
    for i, det in enumerate(dets, start=1):
        for probe in probes:
            if probe.status is None:
                continue
            # Plan 5: .js.map siblings feed leaked_keys only (no "source map exposed" row).
            if det.name != "leaked_keys" and http_probe.is_map_path(probe.path):
                continue
            try:
                findings_raw.extend(det.analyze(probe))
            except Exception as e:
                errors.append(f"detector {det.name} on {probe.url}: {type(e).__name__}: {e}")
        yield ProgressEvent(
            stage="detect",
            message=f"Finished detector {det.name}",
            done=i,
            total=len(dets) or 1,
        )

    # --- report ---
    yield ProgressEvent(stage="report", message="Deduping and sorting findings", done=0, total=1)
    findings = finalize(findings_raw)
    finished = _utcnow()
    result = ScanResult(
        domain=opts.domain,
        hosts_discovered=hosts,
        hosts_alive=hosts_alive,
        urls_probed=len(probes),
        findings=findings,
        errors=errors,
        started_at=started,
        finished_at=finished,
    )
    yield ProgressEvent(
        stage="report",
        message=f"Done: {len(findings)} finding(s), {len(errors)} error(s)",
        done=1,
        total=1,
    )
    yield result


async def scan(opts: ScanOptions) -> ScanResult:
    """Consume scan_stream and return the final ScanResult."""
    final: ScanResult | None = None
    async for event in scan_stream(opts):
        if isinstance(event, ScanResult):
            final = event
    if final is None:
        raise RuntimeError("scan_stream did not yield a ScanResult")
    return final
