# Nexus Local Dashboard

Your personal AI dashboard — all providers on your machine, zero cloud dependency.

## Quick Setup (Recommended: FreeLLMAPI)

The simplest way — one key for everything:

1. Install **Node.js 18+** from https://nodejs.org/ (LTS version)
2. Install **Python 3.10+** from https://www.python.org/downloads/ (tick *Add to PATH*)
3. Download **both** from the [releases page](https://github.com/xorudra/Nexus-Local/releases):
   - `FreeLLMAPI-Windows.zip` — the gateway
   - `NexusLocal.zip` — the dashboard
4. Unzip `FreeLLMAPI-Windows.zip`:
   - Copy `.env.example` to `.env`
   - Generate an encryption key: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
   - Put it in `.env` as `ENCRYPTION_KEY`
   - Double-click `start.bat` (first run installs dependencies)
   - Gateway runs on http://127.0.0.1:3001 — keep this window open
5. Unzip `NexusLocal.zip`:
   - Double-click `start.bat`
   - When asked for provider keys, choose **FreeLLMAPI** only:
     - Gateway URL: `http://127.0.0.1:3001`
     - API Key: your gateway's unified key (shown in the gateway console on first run)
   - Skip the individual provider keys
6. Open http://127.0.0.1:8080 → log in with your encryption password

That's it. All requests go through the gateway with one key.

## Manual Setup (19 Individual Keys)

If you prefer not to run the gateway, you can enter each provider's API key directly:

**14 providers:** HuggingFace, SiliconFlow, Zhipu, Cohere, Mistral, Cloudflare, Google, OpenRouter, Groq, NVIDIA, Pollinations, Kilo, OVH, AI Horde

**5 relay providers** (built-in, auto-starts on 127.0.0.1:8099):
- OpenRouter, Gemini (Google), Groq, NVIDIA, Pollinations (keyless)

On first run, enter each key when prompted. They're stored AES-256 encrypted.

## Task Composer

The dashboard includes a *Task composer* at the bottom of the page. It contains a provider dropdown (showing only providers with configured keys), a model name input, a message text box, and a **Send** button. Replies appear below the button; errors are shown in red.

## Usage Tracking

All local usage is logged to `usage.jsonl` and displayed on the quota cards.

## Security Notes

- Everything runs on localhost — no data leaves your machine except the API calls you make
- Keys are AES-256 encrypted, password required on each launch
- Sessions expire after 30 minutes idle
- Never saves passwords or keys unencrypted on disk
