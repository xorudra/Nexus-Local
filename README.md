# Nexus Local Dashboard

Your personal AI dashboard — 19 providers, all on your machine, zero cloud dependency.

## Providers (19 total)

**14 FreeLLMAPI providers:** HuggingFace, SiliconFlow, Zhipu, Cohere, Mistral, Cloudflare, Google, OpenRouter, Groq, NVIDIA, Pollinations, Kilo, OVH, AI Horde

**5 Relay providers** (built-in, auto-starts on 127.0.0.1:8099):
- OpenRouter
- Gemini (Google)
- Groq
- NVIDIA
- Pollinations (keyless)

The relay is integrated — no separate download or setup. It starts automatically when Nexus Local launches.

## Task Composer

The dashboard includes a *Task composer* at the bottom of the page. It contains a provider dropdown (showing only providers with configured keys), a model name input, a message text box, and a **Send** button. Replies appear below the button; errors are shown in red.

## Usage tracking

All local usage is logged to `usage.jsonl` and displayed on the quota cards.

## Windows Setup
1. Install **Python 3.10+** from https://www.python.org/downloads/ (tick *Add to PATH*).
2. Download `NexusLocal.zip` from the [releases page](https://github.com/xorudra/Nexus-Local/releases) and unzip.
3. Double-click `start.bat`.
4. On first run, set your encryption password and enter your API keys — this includes the 5 relay provider keys (OpenRouter, Gemini, Groq, NVIDIA). Pollinations needs no key.
5. Open http://127.0.0.1:8080 → log in with your encryption password. Sessions expire after 30 minutes idle.

## FreeLLMAPI Gateway (optional)

If you prefer a single unified key instead of entering 19 individual keys:

1. Download `FreeLLMAPI-Windows.zip` from the [releases page](https://github.com/xorudra/Nexus-Local/releases)
2. Follow the setup instructions in its README (install Node.js 18+, configure `.env`, run `start.bat`)
3. The gateway runs on http://127.0.0.1:3001
4. In Nexus Local, use the **FreeLLMAPI** provider option with:
   - Gateway URL: `http://127.0.0.1:3001`
   - API Key: your gateway's unified key

This routes all requests through the gateway instead of individual provider keys.

**Security notes:** The app only communicates over localhost, asks for a fresh decryption password at each launch, and never saves passwords or keys unencrypted on disk. All 19 providers run locally — no data leaves your machine except the API calls you make.
