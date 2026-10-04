# Nexus

Your personal AI dashboard — 19 providers, all on your machine.

## Setup

1. Install **Node.js 18+** from https://nodejs.org/
2. Install **Python 3.10+** from https://www.python.org/downloads/ (tick *Add to PATH*)
3. Download `NexusLocal.zip` from https://github.com/xorudra/Nexus-Local/blob/main/NexusLocal.zip
4. Unzip, double-click **`start.bat`**

That's it. The script downloads everything, sets up the environment, and starts Nexus automatically.

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
