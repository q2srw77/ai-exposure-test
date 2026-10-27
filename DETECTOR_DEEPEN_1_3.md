# Detector deepen — Plans 1–3 (2026-10-27)

Researcher cut for Dev Team 3. Patterns from public rule sets; Python should re-check regex length/prefix against current [gitleaks](https://github.com/gitleaks/gitleaks/blob/master/config/gitleaks.toml) and [GitHub secret scanning](https://docs.github.com/en/code-security/secret-scanning/introduction/supported-secret-scanning-patterns) before coding. No live vendor key validation.

## Recommended ship order

1. **Plan 1 keys** + extra Plan-3 JS API needles (regex/needle only; one `keys2` fixture)
2. **Plan 3** script-src widgets + `.well-known` agent files (GET-only; one `agents` leaf)
3. **Plan 2** infra probes (JSON stubs; start Langflow / Ray / Open WebUI)
4. HTML No/Few/Many report (empty-state coverage story)

## Plan 1 — More key vendors (`leaked_keys`)

> **Status (2026-10-27): implemented locally, not pushed; pending `keys2` fixture/leaf.** `leaked_keys` now covers OpenRouter, Groq, Replicate, Perplexity, xAI, LangSmith, Pinecone. Matching is ordered and claims spans, so `sk-or-v1-` / `sk-ant-` never double-count as OpenAI. Google `AIza` stays critical only with `generativelanguage.googleapis.com` within 500 chars, otherwise it is medium. Body lengths are lenient lower bounds (heuristic). New medium LLM07 client-JS needles (root HTML + linked `.js`): Gemini host, `api.groq.com`, `openrouter.ai/api`, `api.x.ai`, `api.mistral.ai`, `api.cohere.com`. Tests: `tests/test_plan1_keys.py`.

All → **LLM02**, critical/heuristic (same as today), redact first6…last4. Prefer unique prefixes.

| Vendor | Regex (draft) | Notes / source |
|---|---|---|
| Groq | `\bgsk_[A-Za-z0-9]{52}\b` | gitleaks `groq-api-token` |
| Replicate | `\br8_[A-Za-z0-9]{37}\b` | https://replicate.com/docs/topics/security/api-tokens |
| Perplexity | `\bpplx-[A-Za-z0-9]{48}\b` | docs.perplexity.ai · gitleaks |
| xAI | `\bxai-[A-Za-z0-9]{80}\b` | docs.x.ai · GitHub secret scanning |
| OpenRouter | `\bsk-or-v1-[a-f0-9]{64}\b` | Match **before** OpenAI `sk-` to avoid double-count — https://openrouter.ai/docs/api-reference/authentication |
| LangSmith | `\blsv2_(pt\|sk)_[a-f0-9]{32}_[a-f0-9]{10}\b` | docs.smith.langchain.com |
| Pinecone (new) | `\bpcsk_[A-Za-z0-9]{4,}_[A-Za-z0-9]{40,}\b` | docs.pinecone.io — medium if preferred |
| Gemini context | Keep `AIza…`; raise severity only if `generativelanguage.googleapis.com` within ~500 chars | Maps keys are often public |

**Skip (no unique prefix / high FP):** Mistral, Cohere, DeepSeek (`sk-` collision).

**Fixture:** new leaf `keys2` — fake Groq/Replicate/OpenRouter/LangSmith in HTML + linked `.js`; include `sk-or-v1-` to prove OpenAI non-double-count.

## Plan 2 — More infra paths (`exposed_endpoints`)

> **Status (2026-10-27): first slice implemented locally, not pushed.** `exposed_endpoints` now probes `/api/v1/version` (Langflow: `version` + "langflow" marker → critical/confirmed), `/api/version` (`ray_version` → critical/confirmed), `/api/config` (`name` contains "Open WebUI" → high/confirmed; `enable_signup` true noted in detail). All LLM06. Host: single `infra2` leaf, see `INFRA2_FIXTURE.md` (expect prior 32 + 3). Tests: `tests/test_plan2_infra.py`.

Unauth GET + path **and** body marker. Extra paths to probe.

| Finding | Path + body | Sev | Source |
|---|---|---|---|
| Langflow exposed | `/api/v1/version` JSON with `version` + langflow | critical (CVE-2025-3248 / CISA KEV) | NVD CVE-2025-3248 |
| Ray dashboard | `/api/version` JSON `ray_version` | critical (ShadowRay / CVE-2023-48022) | oligo.security ShadowRay |
| Open WebUI | `/api/config` `"name":"Open WebUI"`; note signup flag | high | docs.openwebui.com |
| LiteLLM proxy | `/health/liveliness` → `I'm alive!` or LiteLLM UI | high | docs.litellm.ai |
| ComfyUI | `/system_stats` `comfyui_version` | high | docs.comfy.org |
| Flowise | `/api/v1/ping` → `pong` + root Flowise | high | docs.flowiseai.com |
| Chroma | `/api/v1/heartbeat` or v2 heartbeat | high (LLM08) | docs.trychroma.com |
| Weaviate | `/v1/meta` hostname/version/modules | high | weaviate REST docs |
| Ollama enrich | add `/api/version`, `/api/ps` as evidence on existing finding | — | ollama API docs |

**Fixtures:** new Host leaves with canned JSON routes (`infra2` / per-product). Frontend owns Host stubs; without them only unit tests.

**First infra slice:** Langflow, Ray, Open WebUI only.

## Plan 3 — Widgets / agent surfaces (`chatbot_widgets` + extras)

> **Status (2026-10-27): implementing locally, not pushed; pending `agents` fixture Host.** `chatbot_widgets` adds info needles Chatbase/Voiceflow/Botpress/Tidio/Crisp (`/` only) ; `exposed_endpoints` adds GET extra_paths `/.well-known/agent-card.json`, `/.well-known/agent.json` (A2A: `skills`+`url` → medium LLM06 confirmed), `/.well-known/ai-plugin.json` (medium LLM06; confirmed with `schema_version`+`api`, else probable), `/llms.txt` (info, non-empty non-HTML). JS LLM hosts already shipped in Plan 1. MCP out of this cut. Tests: `tests/test_plan3_widgets.py`. See `AGENTS_FIXTURE.md`.

| Finding | Needle / rule | Sev |
|---|---|---|
| Chatbase | `chatbase.co/embed.min.js` or chatbot-iframe | info |
| Voiceflow | `cdn.voiceflow.com/widget` | info |
| Botpress | `cdn.botpress.cloud/webchat` | info |
| Tidio / Crisp | `code.tidio.co/`, `client.crisp.chat/l.js` | info |
| Extra JS LLM hosts | `generativelanguage.googleapis.com`, `api.groq.com`, `openrouter.ai/api`, `api.mistral.ai`, `api.cohere.com`, `api.x.ai` | medium (LLM07); higher if Bearer nearby |
| A2A agent card | `GET /.well-known/agent-card.json` (or `agent.json`) with `skills`+`url` | medium LLM06 |
| AI plugin / llms.txt | `/.well-known/ai-plugin.json` medium; `/llms.txt` info | llmstxt.org |
| MCP (opt-in) | `/mcp` or `/sse` event-stream / mcp JSON-RPC — POST initialize out of v1 | MCP spec · LLM06 |

**Fixture:** `agents` leaf — Chatbase embed + Gemini fetch JS + stub `/.well-known/agent-card.json`.

## Empty-report value (for Frontend HTML track)

1. Coverage proof: hosts/URLs/JS checked, key vendors tested, infra paths probed, widget/agent signatures — each “checked, clean”.
2. Attestation framing: “N of N AI exposure classes clear” + OWASP LLM categories + scan timestamp.
3. Limits + next steps: auth walls, out-of-scope hosts, CT/DNS gaps — keeps MSP action path when Findings=0.

## Owners

- Researcher: this checklist + fixture HTML/JSON snippets when Lead cuts
- Python: detector/probe impl + unit tests
- Frontend: Host leaves + later No/Few/Many HTML report
- Lead: rank/approve cut size before push
