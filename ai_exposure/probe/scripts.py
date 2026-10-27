"""Linked-script discovery: find same-origin <script src> URLs in a root HTML probe.

Only `/` HTML responses are parsed; JS responses are never re-parsed (no recursion).
Cross-origin scripts (CDNs, third-party widgets) are skipped in this cut — they are
mostly vendor libraries and fetching them widens scan scope beyond the target host.
"""

from __future__ import annotations

from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from ..models import ProbeResult

MAX_SCRIPTS_PER_ORIGIN = 10
_SKIP_SCHEMES = ("data:", "javascript:", "blob:", "about:")


class _ScriptSrcParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.srcs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "script":
            return
        for k, v in attrs:
            if k.lower() == "src" and v:
                self.srcs.append(v.strip())


def is_html(probe: ProbeResult) -> bool:
    ctype = next((v for k, v in probe.headers.items() if k.lower() == "content-type"), "")
    if ctype:
        return "html" in ctype.lower()
    head = probe.body.lstrip()[:200].lower()
    return head.startswith("<!doctype html") or "<html" in head or "<script" in probe.body.lower()


def is_javascript(probe: ProbeResult) -> bool:
    ctype = next((v for k, v in probe.headers.items() if k.lower() == "content-type"), "").lower()
    if "javascript" in ctype or "ecmascript" in ctype:
        return True
    return urlsplit(probe.path).path.lower().endswith((".js", ".mjs"))


def extract_script_paths(probe: ProbeResult, cap: int = MAX_SCRIPTS_PER_ORIGIN) -> list[str]:
    """Return deduped same-origin script paths (path+query) from a 200 HTML `/` probe."""
    if probe.path != "/" or probe.status != 200 or not probe.body or not is_html(probe):
        return []
    parser = _ScriptSrcParser()
    try:
        parser.feed(probe.body)
    except Exception:  # noqa: BLE001 — malformed HTML never crashes the scan
        pass
    page = urlsplit(probe.url)
    out: list[str] = []
    seen: set[str] = set()
    for src in parser.srcs:
        if not src or src.lower().startswith(_SKIP_SCHEMES):
            continue
        u = urlsplit(urljoin(probe.url, src))
        if u.scheme not in ("http", "https"):
            continue
        # Same-origin only (scheme + host + port).
        if (u.scheme, u.hostname, u.port or (443 if u.scheme == "https" else 80)) != (
            page.scheme,
            page.hostname,
            page.port or (443 if page.scheme == "https" else 80),
        ):
            continue
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        if path == "/" or path in seen:
            continue
        seen.add(path)
        out.append(path)
        if len(out) >= cap:
            break
    return out
