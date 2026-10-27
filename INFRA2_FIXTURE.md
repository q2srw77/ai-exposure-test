# Plan 2 infra first slice — `infra2` Host (2026-10-27)

Steve/Lead cut: Langflow / Ray / Open WebUI only. **Live Host:** single leaf `infra2.ai-test.cyphersecurity.us` (three paths). Path+body rules in `exposed_endpoints` — Host shape does not change detector code.

## Host + routes

| Host | Probe path | Expect |
|---|---|---|
| `infra2.ai-test.cyphersecurity.us` | `GET /api/v1/version` | Exposed Langflow API · critical |
| same | `GET /api/version` | Exposed Ray dashboard · critical |
| same | `GET /api/config` | Exposed Open WebUI · high (signup note if enabled) |

JSON bodies (Frontend `j/`):

**Langflow** — `/api/v1/version`:
```json
{"version":"1.1.0","package":"langflow","main_version":"1.1.0"}
```

**Ray** — `/api/version`:
```json
{"ray_version":"2.9.0","ray_commit":"fake000fixture","python_version":"3.11.0"}
```

**Open WebUI** — `/api/config`:
```json
{"status":true,"name":"Open WebUI","version":"0.3.0","features":{"enable_signup":true,"enable_login_form":true}}
```

Expect vs prior Plan 1 matrix: **+3** findings (32 → 35) when `infra2` is in the preset.
