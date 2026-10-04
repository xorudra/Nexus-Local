# Nexus-Local

Your personal AI dashboard — 19 providers, all on your machine.

## Setup

### Option A: npm (coming soon)

The `nexuslocal` npm package is ready (`package.json` + `bin/` launcher).
To enable `npm install -g nexuslocal` from anywhere, the repo needs to be
public or published to npmjs.com.

### Option B: Manual

1. Download this repo (Code → Download ZIP) and unzip
2. **Move the folder out of OneDrive** — e.g. to `C:\Nexus-Local`
   (OneDrive corrupts the engine's `node_modules` during install)
3. Double-click **`start.bat`**

Both methods auto-install dependencies and launch everything.
No admin rights needed.

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

## Providers (19)

14 via built-in engine (HuggingFace, SiliconFlow, Zhipu, Cohere, Mistral, Cloudflare, Google, OpenRouter, Groq, NVIDIA, Pollinations, Kilo, OVH, AI Horde) + 5 via built-in relay (OpenRouter, Gemini, Groq, NVIDIA, Pollinations keyless).

## Security

Runs on localhost only. API keys encrypted with AES-256. Nothing leaves your machine except the AI requests you make.
