# Nexus

Your personal AI dashboard — 19 providers, all on your machine.

## Setup

1. Install **Node.js 18+** from https://nodejs.org/
2. Install **Python 3.10+** from https://www.python.org/downloads/ (tick *Add to PATH*)
3. Download `NexusLocal.zip` from https://github.com/xorudra/Nexus-Local/blob/main/NexusLocal.zip
4. Unzip — you'll get a `Nexus` folder
5. Open it, double-click **`start.bat`**

That's it. Everything sets up automatically on first run.

## First Run

1. Two windows open (engine + dashboard) — keep both open
2. Open http://127.0.0.1:8080
3. Set your password, enter your Nexus API key (shown in the Engine window)
4. Done

## Providers (19)

- **14 via built-in engine:** HuggingFace, SiliconFlow, Zhipu, Cohere, Mistral, Cloudflare, Google, OpenRouter, Groq, NVIDIA, Pollinations, Kilo, OVH, AI Horde
- **5 via built-in relay:** OpenRouter, Gemini, Groq, NVIDIA, Pollinations (keyless)

## Security

- Everything runs on localhost only
- Keys encrypted with AES-256
- No data leaves your machine except API calls you make
