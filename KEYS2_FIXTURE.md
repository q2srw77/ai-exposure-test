# keys2 fixture — Plan 1 cut (2026-10-27)

Host: `keys2.ai-test.cyphersecurity.us`
Asset path (locked style): **`/assets/keys2-app.js`**

## Files
- `f/keys2.html` → `/` (HTML keys + script src only)
- `assets/keys2-app.js` → linked crawl body

## Expect (after Plan 1 detector land)

### On `https://keys2…/`
- leaked_keys: Groq, Replicate, Perplexity, OpenRouter (title **OpenRouter**, not OpenAI)
- No OpenAI finding from `sk-or-v1-…` (order: OpenRouter before OpenAI `sk-`)

### On `https://keys2…/assets/keys2-app.js` (linked crawl)
- leaked_keys: xAI, LangSmith, Pinecone, OpenRouter (dedupe by redaction if same OR key already seen)
- chatbot_widgets / JS needles: Groq API, OpenRouter API, xAI API, Gemini (`generativelanguage.googleapis.com`) — medium LLM07

## Snippets for Frontend Host

**`/` HTML** — see `f/keys2.html`  
**`/assets/keys2-app.js`** — see `assets/keys2-app.js`

## Preset
Add `keys2.ai-test.cyphersecurity.us` as 15th leaf (Python/Frontend after Lead).
