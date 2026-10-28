# Reporting — No / Few / Many HTML states (2026-10-27)

Steve cut Reporting. Source wireframe: `wireframes/report-states.html`. Lead lock: **@Dev3 Python Coder** owns HTML render + Streamlit download first; **@Dev3 Frontend Coder** polishes after; Researcher owns this copy/attestation.

Thresholds (finding count after scan):
| State | Findings | Test Pages example | Pill |
|---|---|---|---|
| **No** | 0 | `clean.ai-test.cyphersecurity.us` alone (or domain with zero matches) | `✓ Clean — 0 findings` |
| **Few** | 1–9 | single widget host or keys-only leaf | `{N} findings · {C} classes clear` |
| **Many** | ≥10 | full AI Test Pages preset (~43 after Plan 3) | `{N} findings · severity-first` |

Classes = 3 detectors: `leaked_keys` · `exposed_endpoints` · `chatbot_widgets`.

---

## Shared shell (every report)

**Head**
- Title: `{domain} — AI Exposure Scan`
- Meta: `Started {ts} · Finished {ts} · Duration {dur}` (+ `· Preset: AI Test Pages` when preset used)
- Pill: per state table above

**Metrics row (always)**
- Findings · Hosts alive · URLs / JS probed · Detectors run  
  Few also shows: Critical/High · Classes clear `{cleared}/3`  
  Many also shows: Critical · High/Med · Info

**Scan limits (always — never omit)**
> **Why “clean” is not “done”:** / **Scan limits**
> - Auth walls and non-public hosts were not in scope.
> - CT / DNS discovery gaps — hosts we never saw stay unchecked.
> - No live key validation; patterns are heuristic / confirmed by presence only.
> - Suggested next: expand Extra hosts, re-run after deploy windows.

---

## No (Findings = 0) — lead with attestation

**Pill:** `✓ Clean — 0 findings`

**Section: Coverage attestation**
- Lead: `{N} of {N} AI exposure classes clear on the hosts we reached. This is what we checked — not a guarantee of zero risk everywhere.`
- Checklist (all ✓):
  1. **Leaked keys** — vendor prefixes tested on HTML + linked `.js` (OpenAI, Anthropic, HF, Google, …).  
     Sub: `Detector: leaked_keys · OWASP LLM02`
  2. **Exposed AI infra** — unauth paths probed (Ollama, Gradio, Streamlit, Jupyter, Langflow, Ray, Open WebUI, agent-card, ai-plugin, llms.txt, …) with body markers.  
     Sub: `Detector: exposed_endpoints · LLM-mapped where applicable`
  3. **Chat widgets & client LLM calls** — embed needles + same-origin script crawl for API hosts.  
     Sub: `Detector: chatbot_widgets · inventory + LLM07`

**Section: OWASP LLM categories covered**
- Tags (all clear*): `LLM02 Sensitive Information — clear` · `LLM06 Excessive Agency — clear*` · `LLM07 System Prompt / client API — clear` · `LLM08 Vector / embedding — clear*`
- Foot: `*Within current detector scope.`

**Rule:** empty state never ends on “No AI exposure findings.” Coverage → OWASP → Limits.

---

## Few (1–9 findings)

**Pill:** `{N} findings · {C} classes clear`

**Section: Findings** — table columns: Sev · Title (+ snippet) · Where (URL) · OWASP

**Section: Still clear** — same 3-class checklist; ✓ for clear classes; `!` (hit) for classes with findings, with count + short note.

**Section: OWASP LLM categories** — hit tags with counts; clear* for untouched.

**Section: Scan limits** — same block as No (keep coverage story for MSP).

---

## Many (≥10 findings)

**Pill:** `{N} findings · severity-first`

**Section: Summary by class** — tags e.g. `leaked_keys ×N` · `exposed_endpoints ×N` · `chatbot_widgets ×N`

**Findings:** group by detector, then severity-first tables (Sev · Title · Where). Coverage checklist collapses under disclosure **“What we still cleared”** (same 3-class strings as No, only clear rows).

**Section: Scan limits** — same always-on block.

---

## Attestation checklist (PASS criteria for HTML export)

Must appear on every downloadable report:
- [ ] Domain + start/finish timestamps + duration
- [ ] Findings count matches CSV row count for that scan
- [ ] Hosts alive + URLs/JS probed + detectors run (non-zero when scan succeeded)
- [ ] No-state: all 3 class ✓ lines + OWASP clear tags + limits
- [ ] Few/Many: findings table populated; limits still present
- [ ] Distinguish **scan succeeded, 0 matches** from **scan failed / no hosts** (latter: do not show Clean pill; show error / “0 hosts alive”)

Fixture demos: wireframe tabs already encode No / Few / Many. Product: Streamlit **Download HTML report** using these strings.

---

## Handoff

- **@Dev3 Python Coder:** implement HTML export + Streamlit download from this copy + `wireframes/report-states.html` layout. Map ScanResult → No/Few/Many via thresholds above. Hold push for Lead ready-check.
- **@Dev3 Frontend Coder:** polish visual to wireframe after Python lands; no parallel export.
- **Researcher:** re-score Plan 3 CSV for clean **43** after `088616f` rebuild; score report states when HTML preview exists.

