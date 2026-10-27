# Plan 3 widgets/agents — `agents` Host (2026-10-27)

Lead cut: Chatbase / Voiceflow / Botpress / Tidio / Crisp widgets + A2A agent card, ai-plugin.json, llms.txt. **MCP skipped.** No JS API needles (already proven on `keys2`). **Live Host:** single leaf `agents.ai-test.cyphersecurity.us` (preset leaf `agents`). Stubs: `fixtures/agents/` (copy into `/workspace/ai-test-pages` `f/` + `j/` + root `llms.txt`).

## Host + routes

| Host | Path | File | Content-Type |
|---|---|---|---|
| `agents.ai-test.cyphersecurity.us` | `GET /` | `f/agents.html` | text/html |
| same | `GET /.well-known/agent-card.json` (alias `/.well-known/agent.json`) | `j/well-known_agent-card.json` | application/json |
| same | `GET /.well-known/ai-plugin.json` | `j/well-known_ai-plugin.json` | application/json |
| same | `GET /llms.txt` | `llms.txt` | text/plain |

Rewrite sketch: `fixtures/agents/vercel.rewrites.snippet.json`. Unknown paths must 404, not fall through to `/` (otherwise llms.txt/plugin probes see HTML).

## Expected findings (+8 → 35 → 43)

| # | Title (proposed) | Detector | Sev | Evidence | OWASP | Rule |
|---|---|---|---|---|---|---|
| 1 | Chatbase chatbot | chatbot_widgets | info | probable | — | `/` contains `chatbase.co/embed.min.js` (alt `chatbase.co/chatbot-iframe`) |
| 2 | Voiceflow chat widget | chatbot_widgets | info | probable | — | `cdn.voiceflow.com/widget` (matches `widget/` and `widget-next/`) |
| 3 | Botpress webchat | chatbot_widgets | info | probable | — | `cdn.botpress.cloud/webchat` |
| 4 | Tidio chat widget | chatbot_widgets | info | probable | — | `code.tidio.co/` |
| 5 | Crisp chat widget | chatbot_widgets | info | probable | — | `client.crisp.chat/l.js` (alt `CRISP_WEBSITE_ID`) |
| 6 | Exposed A2A agent card | exposed_endpoints | medium | confirmed | LLM06: Excessive Agency | `/.well-known/agent-card.json` or `/agent.json`: JSON dict with `skills` (list) + `url`; detail lists skill ids |
| 7 | Exposed AI plugin manifest | exposed_endpoints | medium | confirmed | LLM06: Excessive Agency | `/.well-known/ai-plugin.json`: JSON with `schema_version` + `name_for_model` + `api`; note `auth.type=none` |
| 8 | llms.txt present | exposed_endpoints | info | confirmed | — | `/llms.txt`: non-HTML body, first non-blank line starts `# ` |

Agent-card alias: probe both paths but dedupe to one finding per host (same title; snippet differs, so Python should stop after first hit). Widgets stay `/`-only (same as Intercom/Drift). Info widgets: no OWASP mapping, matches existing convention.

## Matrix §17 (added to AI_TEST_PAGES_MATRIX.md)

`agents.ai-test.cyphersecurity.us` — `/`: 5 info widget findings; `/.well-known/agent-card.json`: medium LLM06; `/.well-known/ai-plugin.json`: medium LLM06; `/llms.txt`: info. Total +8.

## Handoff

- **@Dev3 Python Coder:** add 5 rules to `_RULES` in `chatbot_widgets.py` (needles above, case-sensitive); add `/.well-known/agent-card.json`, `/.well-known/agent.json`, `/.well-known/ai-plugin.json`, `/llms.txt` to `exposed_endpoints.extra_paths` with body rules above (reject `text/html` / `<html` bodies for llms.txt FP). Tests `tests/test_plan3_agents.py` using `fixtures/agents/*` bodies: 8 findings; negatives — SPA HTML 200 on `/llms.txt` → 0; agent JSON without `skills` → 0; both card paths → 1.
- **@Dev3 Frontend Coder:** copy `fixtures/agents/f/agents.html`→`f/`, `j/*`→`j/`, `llms.txt`→ served at `/llms.txt` for agents host only; add host routes + 404 fallback; add `agents` to preset + `list.html`/`MAPPING.md`. Do not deploy without Steve's yes.

## Sources

- Chatbase embed: https://www.chatbase.co/docs/developer-guides/chatbot-embedding (`www.chatbase.co/embed.min.js`)
- Voiceflow web chat: https://docs.voiceflow.com/docs/web-chat (`cdn.voiceflow.com/widget-next/bundle.mjs`)
- Botpress webchat v3: https://botpress.com/docs/webchat (`cdn.botpress.cloud/webchat/v3.x/inject.js`)
- Tidio: https://help.tidio.com/hc/en-us/articles/5381981040284 (`//code.tidio.co/<key>.js`)
- Crisp: https://docs.crisp.chat/guides/chatbox-sdks/web-sdk/ (`client.crisp.chat/l.js`, `CRISP_WEBSITE_ID`)
- A2A AgentCard (`/.well-known/agent-card.json`, renamed from `agent.json` in v0.3): https://a2a-protocol.org/latest/specification/
- OpenAI plugin manifest (deprecated, still seen): https://platform.openai.com/docs/plugins/getting-started (archived)
- llms.txt: https://llmstxt.org/
