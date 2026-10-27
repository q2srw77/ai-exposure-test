# AI Test Pages fixture matrix (for Lovable on cyphersecurity.us)

Source: `ai_exposure/detectors/*` + `tests/fixtures/*` in q2srw77/ai-exposure-test (SPEC §7).
Constraint: `chatbot_widgets` and Gradio/Streamlit/Jupyter only evaluate **path `/`**. Use one subdomain per HTML fixture (or one host with only that content on `/`). API stubs can share one host.
Fake data only — never real vendor keys.

Recommended base: `*.ai-test.cyphersecurity.us` (Steve DNS) → Lovable custom domain / multi-route.

## HTML fixtures (each host, path `/`, Content-Type text/html, 200)

### 1. clean.ai-test.cyphersecurity.us/
Expect: 0 findings
```html
<!DOCTYPE html><html><head><title>Example Corp</title></head><body><h1>Welcome to Example</h1><p>We build great products.</p></body></html>
```

### 2. widgets-intercom.ai-test.cyphersecurity.us/
Expect: Intercom chat widget · info · no OWASP
```html
<html><body><script src="https://widget.intercom.io/widget/abc"></script><script>window.intercomSettings={app_id:'abc'};</script></body></html>
```

### 3. widgets-drift.ai-test.cyphersecurity.us/
Expect: Drift chatbot · info · no OWASP
```html
<html><body><script src="https://js.driftt.com/include/123.js"></script></body></html>
```

### 4. widgets-zendesk.ai-test.cyphersecurity.us/
Expect: Zendesk AI / Web Widget · info · no OWASP
```html
<html><body><script src="https://static.zdassets.com/ekr/snippet.js"></script></body></html>
```

### 5. widgets-ada.ai-test.cyphersecurity.us/
Expect: Ada chatbot · info · no OWASP
```html
<html><body><script src="https://static.ada.support/embed.js"></script></body></html>
```

### 6. openai-js.ai-test.cyphersecurity.us/
Expect: OpenAI API call in client JS · medium · LLM07
```html
<html><body><script>fetch('https://api.openai.com/v1/chat/completions',{method:'POST'})</script></body></html>
```

### 7. anthropic-js.ai-test.cyphersecurity.us/
Expect: Anthropic API call in client JS · medium · LLM07
```html
<html><body><script>fetch('https://api.anthropic.com/v1/messages',{method:'POST'})</script></body></html>
```

### 8. hf-js.ai-test.cyphersecurity.us/
Expect: Hugging Face inference call · medium · LLM07
```html
<html><body><script>fetch('https://api-inference.huggingface.co/models/gpt2',{method:'POST'})</script></body></html>
```

### 9. keys.ai-test.cyphersecurity.us/
Expect: 4× leaked_keys · critical · heuristic · LLM02 — OpenAI matches sk-ant first; Anthropic dropped by redaction dedupe (OpenAI×2 + HF + Google)
```html
<html><body><script>
const OPENAI='sk-proj-TESTFAKEOPENAIKEY0001';
const ANTHROPIC='sk-ant-TESTFAKEANTHROPICKEY0001';
const HF='hf_TESTFAKEHUGGINGFACETOKEN000001';
const GOOGLE='AIzaSyTESTFAKEGOOGLEAPIKEY00000000001234';
</script></body></html>
```

### 10. gradio.ai-test.cyphersecurity.us/
Expect: Public Gradio app · medium · probable · LLM06
```html
<!DOCTYPE html><html><body><gradio-app></gradio-app><script>window.gradio_config = {}</script></body></html>
```

### 11. streamlit.ai-test.cyphersecurity.us/
Expect: Public Streamlit app · medium · probable · LLM06 (needs BOTH needles)
```html
<html><body><div id="root">streamlit app</div><script>window._stcore = {};</script></body></html>
```

### 12. jupyter.ai-test.cyphersecurity.us/
Expect: Exposed Jupyter interface · critical · probable · LLM06
```html
<html><body><h1>jupyter notebook</h1><p>Login to continue</p></body></html>
```

## JSON API stubs (one host e.g. api.ai-test.cyphersecurity.us, path as listed, application/json, 200)

### 13. GET /api/tags
Expect: Unauthenticated Ollama API · high · confirmed · LLM10
```json
{"models": [{"name": "llama3:latest", "modified_at": "2024-01-01T00:00:00Z", "size": 123}]}
```

### 14. GET /v1/models
Expect: Open OpenAI-compatible model endpoint · high · probable · LLM10
```json
{"object": "list", "data": [{"id": "gpt-test", "object": "model"}]}
```

### 15. GET /collections
Expect: Possibly open vector database · medium · probable · LLM02
```json
{"collections": [{"name": "docs"}, {"name": "embeddings"}]}
```

### 16. GET /api/2.0/mlflow/experiments/search
Expect: Unauthenticated MLflow tracking server · high · confirmed · LLM03
```json
{"experiments": [{"experiment_id": "0", "name": "Default"}]}
```

## Live scan check
Point scanner at `ai-test.cyphersecurity.us` (crt.sh must see the subdomains, or scan each host with discovery off / max hosts covering them). Auth checkbox on. Clean host = 0 findings; others match table above.

## Linked JS crawl fixture (next cut)

### 14. keys-js.ai-test.cyphersecurity.us/
`/` HTML only references `/assets/keys-app.js` — **no inline secrets**.
Expect **with** script crawl: 1× leaked_keys (OpenAI from `sk-proj-TESTFAKEOPENAIKEYFROMJS00001`) + 1× OpenAI API call in client JS; finding URL = script. Expect **without** crawl: 0 findings.
See `JS_CRAWL_CUT.md` + `/workspace/ai-test-pages/f/keys-js.html` + `assets/keys-app.js`.

## Linked .js crawl (scanner behavior)

Scanner fetches up to 10 **same-origin** `<script src>` URLs from a 200 HTML `/` (one level; scripts are not re-parsed; cross-origin/CDN skipped). On those bodies it runs `leaked_keys` + the medium client-JS API rules (api.openai.com / api.anthropic.com / api-inference.huggingface.co). Widget (Intercom/Drift/Zendesk/Ada) and Gradio/Streamlit/Jupyter stay `/`-only. Fixture leaf: §14 `keys-js` above.

### 15. keys2.ai-test.cyphersecurity.us/
Expect: Plan 1 deepen — Groq/Replicate/Perplexity/OpenRouter on `/`; xAI/LangSmith/Pinecone + Groq/OpenRouter/xAI/Gemini JS needles on `/assets/keys2-app.js`. OpenRouter must **not** double-count as OpenAI.
See `KEYS2_FIXTURE.md` + `/workspace/ai-test-pages/f/keys2.html` + `assets/keys2-app.js`.

### 16. infra2.ai-test.cyphersecurity.us/
Plan 2 first infra slice — three paths on one Host:
- `/api/v1/version` → Langflow JSON · critical
- `/api/version` → Ray JSON (`ray_version`) · critical
- `/api/config` → Open WebUI JSON · high
See `INFRA2_FIXTURE.md`. Expect prior Plan 1 matrix **+3**.
