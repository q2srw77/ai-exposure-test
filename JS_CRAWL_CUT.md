# Linked `.js` crawl cut — intel + fixture (2026-10-27)

Steve approved. Python owns probe+detect; Frontend owns AI Test Pages host + rewrite; Researcher owns rules/fixture below.

## Behavior

1. After each **200 HTML** probe on path `/` (status 200, `Content-Type` contains `html` or body looks like HTML), extract script URLs.
2. Parse `src` from `<script … src="…">` (regex or HTML parser). Ignore inline scripts (no `src`).
3. Resolve relative URLs against the page URL. **v1 scope: same-origin only** (scheme+host match the page). Skip `integrity=` optional later.
4. Keep candidates that look like JS: path ends with `.js` / `.mjs`, or `type` is module/javascript. Cap **10** scripts per host (document order). Soft skip names matching `/jquery|react(-dom)?|vue|angular|bootstrap|gtag|analytics|chunk-vendors/i` if still over budget — prefer first-party paths (`/assets/`, `/static/`, `/js/`, `/dist/`).
5. GET each as a normal probe (same concurrency/timeout/body cap). Path on ProbeResult = URL path (e.g. `/assets/keys-app.js`).
6. Detectors on JS bodies:
   - **`leaked_keys`**: already path-agnostic — run as-is.
   - **JS embed needles** (OpenAI/Anthropic/HF API URLs in client JS): run on `.js` bodies too (relax `path == "/"` for those rules only).
   - **Chat widgets / Gradio / Streamlit / Jupyter**: stay **`/` only**.
7. Finding `url` = the script URL (or page URL with detail noting script). Prefer script URL so evidence points at the leak.
8. Progress: emit probe events for script fetches. Errors on script GET go to `errors`, don’t abort.
9. Off by default? **On by default for live scans** once shipped (or `ScanOptions.follow_script_src: bool = True`). Document in About: capped same-origin `.js` follow.

## Fixture (AI Test Pages)

| Host | `/` | Linked asset | Expect (after crawl) |
|---|---|---|---|
| `keys-js.ai-test.cyphersecurity.us` | HTML with `<script src="/assets/keys-app.js">` only — **no** inline keys | `/assets/keys-app.js` contains `sk-proj-TESTFAKEOPENAIKEYFROMJS00001` + `api.openai.com` fetch | **1** leaked_keys (OpenAI) + **1** OpenAI API call in client JS; finding URLs under `/assets/keys-app.js` |
| Same host **without** crawl (regression) | | | **0** findings (proves the cut matters) |

Files on box:
- `/workspace/ai-test-pages/f/keys-js.html`
- `/workspace/ai-test-pages/assets/keys-app.js`

Frontend: add Host `keys-js.ai-test.cyphersecurity.us` → `/f/keys-js.html`; ensure `/assets/keys-app.js` is publicly served; DNS CNAME; append host to `AI_TEST_PAGES_HOSTS` preset (14th leaf).

## Offline tests

Recorded fixtures: HTML `/` referencing `/assets/keys-app.js`, plus JS body probe — assert both findings; assert without JS probe → 0.

## Non-goals (this cut)

- Cross-origin CDN scripts (later allowlist)
- `sourceMappingURL` follow
- Full browser JS execution
- CSS/`link`/`import` chains beyond script src
