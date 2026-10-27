# AI DNS wordlist (v1) — follow-on discovery cut

For `ScanOptions` DNS wordlist: for each label `L`, try `L.{root}` (A/AAAA). Keep only names that resolve. Merge with root + crt.sh + `extra_hosts`; dedupe; respect `max_hosts`.

Do **not** rely on this alone for Host-based labs under a nested parent (e.g. `*.ai-test.example.com`) — those need **extra_hosts** / the AI Test Pages preset. Wordlist targets conventional single-label AI hosts under the scanned root.

## Core labels (ship these first — ~40)

```
ai
api
llm
gpt
chat
chatbot
assistant
bot
genai
ml
nlp
openai
anthropic
claude
huggingface
hf
ollama
gradio
streamlit
jupyter
notebook
mlflow
langflow
flowise
langchain
vector
embeddings
rag
inference
llm-api
ai-api
gpt-api
openai-api
chat-api
staging-ai
dev-ai
test-ai
internal-ai
labs
sandbox
```

## Optional expand (only if max_hosts / concurrency allow)

```
bedrock
vertex
azure-openai
copilot
perplexity
cohere
replicate
together
fireworks
vllm
textgen
webui
open-webui
anythingllm
privategpt
localai
litellm
phoenix
wandb
labelstudio
airflow
kubeflow
seldon
triton
torchserve
```

## Notes for Python

- Resolve before probe (skip NXDOMAIN) to avoid the 258-error noise pattern.
- Prefer public recursive DNS (or DoH), not a box DNS that returns `198.18.0.1`.
- Wordlist is additive; never replace `extra_hosts` or crt.sh hits.
- Auth still required for live scans.

Source: detector surface area in `ai_exposure/detectors/*` + common public AI-infra naming (2026-10-27).

## Lab wordlist — under `ai-test` parent (optional)

When Domain = `ai-test.cyphersecurity.us` (or `{lab}.example.com`), resolve these leaf labels under that parent. Prefer **extra_hosts / AI Test Pages preset** for harness smoke; this is for wordlist-mode lab scans without pasting FQDNs.

```
clean
keys
gradio
streamlit
jupyter
api
openai-js
anthropic-js
hf-js
widgets-intercom
widgets-drift
widgets-zendesk
widgets-ada
```

Do not add these to the production apex wordlist — too fixture-specific / noisy on real customer roots.
