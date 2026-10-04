# Nexus-Local

Your personal AI dashboard — 19 providers, all on your machine.

## Setup

1. Download this repo (Code → Download ZIP) and unzip
2. **Move the folder out of OneDrive** — e.g. to `C:\Nexus-Local`
   (OneDrive corrupts the engine's `node_modules` during install)
3. Double-click **`start.bat`**

That's it. The script automatically downloads portable Python + Node.js if missing, sets up everything, and launches.

No manual installs. No admin rights needed.

## First Run

Two windows open (engine + dashboard). Then open **http://127.0.0.1:8080** in your browser.

Set your password, enter the API key shown in the Engine window. Done.

## Structure

```
├── start.bat   ← double-click to launch (handles all setup)
├── README.md
├── app/        ← dashboard + engine code
├── tools/      ← auto-downloaded portable Python + Node.js (created on first run)
└── deploy/     ← Render deployment config
```

## Providers

- **Relay** (5): OpenRouter, Gemini, Groq, NVIDIA, Pollinations keyless — built-in, no setup
- **FreeLLMAPI Gateway** (14): HuggingFace, SiliconFlow, Zhipu, Cohere, Mistral, Cloudflare, Google, OpenRouter, Groq, NVIDIA, Pollinations, Kilo, OVH, AI Horde — via local engine
- **OmniRoute Gateway** (358): Auto-installed via start.bat, configure at http://127.0.0.1:20128

## Security

Runs on localhost only. API keys encrypted with AES-256. Nothing leaves your machine except the AI requests you make.
