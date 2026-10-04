# Nexus-Local

Your personal AI dashboard — 19 providers, all on your machine.

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

Two windows open (engine + dashboard). Then open **http://127.0.0.1:8080** in your browser.

Set your password, enter the API key shown in the Engine window. Done.

## Structure

```
├── README.md
├── package.json  ← `npm install -g` entry (bin: nexuslocal)
├── bin/          ← nexuslocal CLI launcher
├── app/          ← dashboard + engine code
└── deploy/       ← Render deployment config
```

## Providers (19)

14 via built-in engine (HuggingFace, SiliconFlow, Zhipu, Cohere, Mistral, Cloudflare, Google, OpenRouter, Groq, NVIDIA, Pollinations, Kilo, OVH, AI Horde) + 5 via built-in relay (OpenRouter, Gemini, Groq, NVIDIA, Pollinations keyless).

## Security

Runs on localhost only. API keys encrypted with AES-256. Nothing leaves your machine except the AI requests you make.
