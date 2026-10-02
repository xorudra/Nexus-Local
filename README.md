# Nexus Local Dashboard

## Task Composer

The dashboard includes a *Task composer* at the bottom of the page. It contains a provider dropdown (showing only providers with configured keys), a model name input, a message text box, and a **Send** button. Replies appear below the button; errors are shown in red.

## Usage tracking

All local usage is logged to `usage.jsonl` and displayed on the quota cards.

## Windows Setup
1. Install **Python 3.10+** from https://www.python.org/downloads/ (tick *Add to PATH*).
2. Unzip the repository folder.
3. Double‑click `start.bat` (or run it from a command prompt).
   15|open http://127.0.0.1:8080 → log in on the login page with your encryption password. Sessions expire after 30 minutes idle; logging out clears the session.

**Security notes**: The app only communicates over localhost, asks for a fresh decryption password at each launch, and never saves passwords or keys unencrypted on disk.

