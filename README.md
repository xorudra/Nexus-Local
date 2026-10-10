# Nexus-Local

Your personal AI dashboard — 19 providers, one login. Runs locally, or as a hosted instance for you and your friends.

**Live demo:** https://nexus-local.onrender.com

Want to try it without installing? Open the link above. For the full local version with your own keys, follow the setup below.

## Setup

**Prerequisite:** Install Node.js (includes npm).

On Windows, open PowerShell or CMD and run:
```bash
winget install OpenJS.NodeJS
```
Or download from [nodejs.org](https://nodejs.org/).

Then:
```bash
npm install -g github:xorudra/Nexus-Local
```

Then type **`nexuslocal`** from any directory. That's it.

Auto-installs dependencies and launches everything. No admin rights needed.

## First Run

Type `nexuslocal`. It starts the engine + dashboard and opens **http://127.0.0.1:8080** in your browser.

The install ships with an encrypted key vault — log in with the master password and the providers are ready. That vault's only protection is the password itself; read the Security section below before reusing this setup.

To use your own keys instead, delete `keys.enc` from the install folder and use the **Quick Import** box on the setup page: paste all keys at once as `name: key` (one per line), click Fill Fields Below, set your password, done.

## Pages

- **Dashboard** (`/`) — task composer with provider/model picker, image attachments, usage overview
- **Connections** (`/connections`) — all providers grouped in expanders (Direct, Relay, FreeLLMAPI) with key status and usage
- **Update Keys** (`/settings`) — update API keys after login (shows last 4 chars, blank = keep current)
- **API Access** (`/api-access`, admin only) — status of the external `/v1` API: endpoint, service-key hint, supply-lane readiness, live self-test

Use the ☰ menu (top-left) to navigate between pages.

## Features

- **Task Composer** — pick a provider (shown as "Relay: Groq" or "FreeLLMAPI: Groq"), get model autocomplete, attach images (JPG/PNG/WebP up to 8MB), send
- **Provider Groups** — 14 direct providers, 5 relay providers, unified gateway — all with live key status
- **Image Attachments** — vision-capable providers accept images alongside text
- **Encrypted Storage** — all keys AES-256-GCM encrypted, PBKDF2 600k iterations, never stored as plaintext

## External API (`/v1`)

Nexus can supply other projects (e.g. DSRclone's AI service) through an
OpenAI-compatible endpoint:

- `GET /v1/models` — `nexus-auto`, per-lane `lane/model` ids, and live lane catalogs
- `POST /v1/chat/completions` — standard OpenAI request/response shape

**Off by default.** Set the `NEXUS_V1_API_KEY` environment variable to enable
it; clients send it as `Authorization: Bearer <key>`. Without the variable the
routes answer 404. The key is a service credential — it can also be generated
from the admin console (stored encrypted and mirrored like the other console
secrets; the env var stays as fallback). The API Access page shows the admin
the full key; everyone else only ever sees its last 4 characters.

Ask for model `nexus-auto` and Nexus tries its relay lanes in order
(Gemini → OpenRouter → Groq → NVIDIA → Pollinations) until one answers,
honouring the same circuit breaker as dashboard chat; usage is logged as
`v1:<lane>`. While the provider vault is locked (no admin login since the
last restart) only keyless lanes answer — the same rule dashboard chat
follows before unlock.

## Uninstall

```bash
npm uninstall -g nexuslocal
```

## Structure

```
├── README.md
├── package.json  ← `npm install -g` entry (bin: nexuslocal)
├── bin/          ← nexuslocal CLI launcher
├── app/          ← dashboard + engine code
└── deploy/       ← Render deployment config
```

## Providers (19)

**14 Direct** (HuggingFace, SiliconFlow, Zhipu, Cohere, Mistral, Cloudflare, Google, OpenRouter, Groq, NVIDIA, Pollinations, Kilo, OVH, AI Horde) + **5 Relay** (OpenRouter, Gemini, Groq, NVIDIA, Pollinations keyless).

FreeLLMAPI is the built-in engine (127.0.0.1:3001) that powers the 14 direct providers — it's the infrastructure, not a provider itself.

Keyless providers (Pollinations, AI Horde, Kilo, OVH) work with no setup.

## Security

Nexus runs in two shapes, and this section describes both honestly: locally
via the CLI above (bound to your machine), and as a hosted instance — the
live demo linked at the top is a real multi-user deployment on Render,
reached over HTTPS, where the owner and invited friends sign in. The hosted
instance is not localhost-only, and AI requests always leave the server for
the provider you picked.

- Provider keys are stored AES-256-GCM encrypted (PBKDF2 600,000
  iterations) and decrypted only in memory after an admin login. After a
  restart the vault stays locked — keyless providers only — until then.
- An encrypted keys file ships in this repository. Encryption is the only
  barrier on that file: anyone can download it and attack it offline,
  where no lockout applies, so the master password's strength is what
  protects it. Pick a long one.
- The admin can enable TOTP two-factor sign-in. Friend accounts use
  PBKDF2-HMAC-SHA256 password hashes, and friends' personal key vaults
  are encrypted under their own passwords — the admin cannot read them.
- Friend data, console settings, and usage/audit history are mirrored
  back to GitHub as encrypted files so they survive the host's
  ephemeral disk. The mirrors are ciphertext only.
