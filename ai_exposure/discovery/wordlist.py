"""AI DNS wordlist discovery: resolve L.{root} (A/AAAA) for AI-ish labels; keep only hits.

Single-label only — does NOT find nested hosts like keys.ai-test.example.com (use extra_hosts).
"""
from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterable

CORE_LABELS: tuple[str, ...] = (
    "ai", "api", "llm", "gpt", "chat", "chatbot", "assistant", "bot", "genai", "ml", "nlp",
    "openai", "anthropic", "claude", "huggingface", "hf", "ollama", "gradio", "streamlit",
    "jupyter", "notebook", "mlflow", "langflow", "flowise", "langchain", "vector", "embeddings",
    "rag", "inference", "llm-api", "ai-api", "gpt-api", "openai-api", "chat-api", "staging-ai",
    "dev-ai", "test-ai", "internal-ai", "labs", "sandbox",
)

EXPAND_LABELS: tuple[str, ...] = (
    "bedrock", "vertex", "azure-openai", "copilot", "perplexity", "cohere", "replicate", "together",
    "fireworks", "vllm", "textgen", "webui", "open-webui", "anythingllm", "privategpt", "localai",
    "litellm", "phoenix", "wandb", "labelstudio", "airflow", "kubeflow", "seldon", "triton", "torchserve",
)

# Lab-only (Domain = ai-test.<root>). Never used by default; opt in via ScanOptions.wordlist_labels.
LAB_LABELS: tuple[str, ...] = (
    "clean", "keys", "gradio", "streamlit", "jupyter", "api", "openai-js", "anthropic-js", "hf-js",
    "widgets-intercom", "widgets-drift", "widgets-zendesk", "widgets-ada",
)

PUBLIC_NAMESERVERS: list[str] = ["1.1.1.1", "8.8.8.8"]

# Resolver: async fn(fqdn) -> bool (resolves to A or AAAA).
Resolver = Callable[[str], Awaitable[bool]]


def _is_sinkhole(ip: str) -> bool:
    """198.18.0.0/15 is benchmark space; some sandboxes fake-resolve everything there."""
    import ipaddress
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network("198.18.0.0/15")
    except ValueError:
        return False


def make_dns_resolver(nameservers: list[str] | None = None, timeout: float = 3.0) -> Resolver:
    import dns.asyncresolver
    import dns.exception
    import dns.resolver

    r = dns.asyncresolver.Resolver(configure=False)
    r.nameservers = list(nameservers or PUBLIC_NAMESERVERS)  # avoid box/sinkhole DNS (198.18.0.1)
    r.lifetime = timeout

    async def resolve(fqdn: str) -> bool:
        for rtype in ("A", "AAAA"):
            try:
                ans = await r.resolve(fqdn, rtype)
                if any(not _is_sinkhole(a.to_text()) for a in ans):
                    return True
            except dns.resolver.NXDOMAIN:
                return False
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
                continue
        return False

    return resolve


def candidates(root: str, labels: Iterable[str]) -> list[str]:
    root = root.lower().strip(".")
    out, seen = [], set()
    for lab in labels:
        lab = str(lab).strip().lower().strip(".")
        if lab and lab not in seen:
            seen.add(lab)
            out.append(f"{lab}.{root}")
    return out


async def discover(
    root: str,
    labels: Iterable[str] | None = None,
    resolver: Resolver | None = None,
    concurrency: int = 20,
    timeout: float = 3.0,
) -> list[str]:
    """Return FQDNs (in label order) that resolve to A/AAAA."""
    names = candidates(root, CORE_LABELS if labels is None else labels)
    resolve = resolver or make_dns_resolver(timeout=timeout)
    sem = asyncio.Semaphore(max(1, concurrency))

    async def one(n: str) -> bool:
        async with sem:
            try:
                return await resolve(n)
            except Exception:
                return False

    hits = await asyncio.gather(*(one(n) for n in names))
    return [n for n, ok in zip(names, hits) if ok]
