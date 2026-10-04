# Nexus

Your personal AI dashboard — 19 providers, all on your machine.

## Setup

1. Install **Node.js 18+** from https://nodejs.org/
2. Install **Python 3.10+** from https://www.python.org/downloads/ (tick *Add to PATH*)
3. Download this repo (Code → Download ZIP) and unzip
4. Double-click **`start.bat`**

That's it. Everything sets up automatically.

## Structure

```
├── start.bat   ← double-click to launch
├── README.md
├── app/        ← dashboard + engine (you don't need to touch this)
└── deploy/     ← Render deployment config
```

## First Run

Two windows open (engine + dashboard). Open **http://127.0.0.1:8080**, set your password, enter your API key shown in the Engine window. Done.

## Providers (19)

14 via built-in engine + 5 via built-in relay (OpenRouter, Gemini, Groq, NVIDIA, Pollinations keyless).

## Security

Localhost only. AES-256 encrypted. Nothing leaves your machine except your AI requests.
