# Nexus

Your personal AI dashboard — 19 providers, all on your machine.

## Setup

1. Install **Node.js 18+** from https://nodejs.org/
2. Install **Python 3.10+** from https://www.python.org/downloads/ (tick *Add to PATH*)
3. Download `NexusLocal.zip` from the [releases page](https://github.com/xorudra/Nexus-Local/releases)
4. Unzip anywhere
5. Double-click **`start.bat`**

That's it. Everything configures automatically on first run. Two windows open (engine + dashboard) — keep both open.

## First Run

1. Open http://127.0.0.1:8080 in your browser
2. Set your password
3. Enter your **Nexus API key** (shown in the Engine window on first run)
4. Done — one key for everything

## Providers (19)

- **14 via built-in engine:** HuggingFace, SiliconFlow, Zhipu, Cohere, Mistral, Cloudflare, Google, OpenRouter, Groq, NVIDIA, Pollinations, Kilo, OVH, AI Horde
- **5 via built-in relay** (auto-starts): OpenRouter, Gemini, Groq, NVIDIA, Pollinations (keyless)

## What's Inside

```
Nexus/
├── start.bat       ← double-click to launch everything
├── server.py       ← dashboard
├── dashboard.html
├── engine/         ← AI engine (internal)
├── engine-data/    ← engine database
└── README.md
```

## Security

- Everything runs on localhost only
- Keys encrypted with AES-256
- No data leaves your machine except API calls you make
