from __future__ import annotations
import httpx

CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"


def normalize(names: list[str], domain: str, max_hosts: int) -> list[str]:
    domain = domain.lower().strip(".")
    out: list[str] = [domain]
    seen = {domain}
    for raw in names:
        for name in str(raw).splitlines():
            n = name.strip().lower().lstrip("*.").strip(".")
            if n and (n == domain or n.endswith("." + domain)) and n not in seen:
                seen.add(n)
                out.append(n)
    return out[:max_hosts]


async def discover(domain: str, max_hosts: int, timeout: float = 30.0) -> list[str]:
    """Return subdomains from crt.sh (root first). Raises on failure; caller records the error."""
    async with httpx.AsyncClient(timeout=timeout, headers={"User-Agent": "ai-exposure-scanner/0.1"}) as c:
        r = await c.get(CRTSH_URL.format(domain=domain))
        r.raise_for_status()
        data = r.json()
    return normalize([row.get("name_value", "") for row in data], domain, max_hosts)
