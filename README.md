# Nexus Local Dashboard

Your personal AI dashboard — all providers on your machine, zero cloud dependency.

## One-Command Setup (Easiest)

1. Download `setup.bat` from the [releases page](https://github.com/xorudra/Nexus-Local/releases)
2. Double-click it

That's it. It checks for Python and Node.js, downloads everything, configures the gateway, and starts both services. You'll only need to enter your FreeLLMAPI key in Nexus Local setup.

## Manual Setup

If you prefer to set up each piece yourself:

### FreeLLMAPI Gateway
1. Install **Node.js 18+** from https://nodejs.org/ (LTS version)
2. Download `FreeLLMAPI-Windows.zip` from the [releases page](https://github.com/xorudra/Nexus-Local/releases)
3. Unzip, copy `.env.example` to `.env`
4. Generate an encryption key: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
5. Put it in `.env` as `ENCRYPTION_KEY`
6. Double-click `start.bat` — gateway runs on http://127.0.0.1:3001

### Nexus Local Dashboard
1. Install **Python 3.10+** from https://www.python.org/downloads/ (tick *Add to PATH*)
2. Download `NexusLocal.zip` from the [releases page](https://github.com/xorudra/Nexus-Local/releases)
3. Unzip, double-click `start.bat`
4. When asked for provider keys, choose **FreeLLMAPI**:
   - Gateway URL: `http://127.0.0.1:3001`
   - API Key: your gateway's unified key (shown in gateway console on first run)
   - Or enter 19 individual provider keys if you prefer (14 + 5 relay, all built-in)
5. Open http://127.0.0.1:8080 → log in with your encryption password

## Task Composer

The dashboard includes a *Task composer* at the bottom of the page. It contains a provider dropdown (showing only providers with configured keys), a model name input, a message text box, and a **Send** button. Replies appear below the button; errors are shown in red.

## Usage Tracking

All local usage is logged to `usage.jsonl` and displayed on the quota cards.

## Security Notes

- Everything runs on localhost — no data leaves your machine except the API calls you make
- Keys are AES-256 encrypted, password required on each launch
- Sessions expire after 30 minutes idle
- Never saves passwords or keys unencrypted on disk
