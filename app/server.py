#!/usr/bin/env python3
"""Simple Nexus local Windows dashboard server.

Features
~~~~~~~~~
* Requires :mod:`cryptography` (already listed in requirements.txt)
* Prompts for the keys password on startup.  If ``keys.enc`` is missing,
  a wizard collects keys for 14 providers and stores them encrypted.
* Keeps decrypted keys **only** in memory; never writes them to disk.
* Serves:
  * GET  /api/status   -> 200 with JSON {"ok": true}
  * GET  /api/quotas   -> provider list with placeholder quota structures
  * GET  /api/usage    -> aggregate usage stats
  * POST /api/chat     -> chat via provider APIs
  * GET  /            -> dashboard.html (requires login)
  * GET  /login        -> login.html
  * POST /api/login    -> password auth, creates session
  * POST /api/logout   -> end session

* Listens on 127.0.0.1:8080 exclusively.
"""

from __future__ import annotations

import os
import json
import datetime
import base64
import hashlib
import secrets
import time
from pathlib import Path

QUOTAS_PATH = Path(__file__).parent / "quotas.json"
from http.cookies import SimpleCookie
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

from getpass import getpass
from key_security import encrypt_keys, decrypt_keys

USAGE_PATH = Path(__file__).parent / "usage.jsonl"
SESSIONS = {}
_login_attempts = {}

SESSION_EXPIRY = 1800

def get_usage_history():
    """Last 7 days of per-provider usage from usage.jsonl.

    Returns {provider: {"requests": [d6..d0], "tokens": [d6..d0]}} where
    d0 (index 6) is today. Zero-filled; never errors on missing/empty file.
    """
    days = [(datetime.date.today() - datetime.timedelta(days=i)).isoformat()
            for i in range(7)]  # index 0 = today
    hist = {name: {"requests": [0] * 7, "tokens": [0] * 7}
            for name in PROVIDER_NAMES}
    if not os.path.exists(USAGE_PATH):
        return hist
    try:
        with open(USAGE_PATH) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                day = str(entry.get("ts", ""))[:10]
                if day not in days:
                    continue
                prov = entry.get("provider")
                if prov not in hist:
                    continue
                pos = 6 - days.index(day)  # index 6 = today
                hist[prov]["requests"][pos] += 1
                hist[prov]["tokens"][pos] += (entry.get("prompt_tokens", 0)
                                             + entry.get("completion_tokens", 0))
    except OSError:
        pass
    return hist

PROVIDER_NAMES = [
    "aihorde",
    "cloudflare",
    "cohere",
    "google",
    "groq",
    "huggingface",
    "kilo",
    "mistral",
    "nvidia",
    "openrouter",
    "ovh",
    "pollinations",
    "siliconflow",
    "zhipu",
    # Relay providers (Rudra's other-Gmail keys, served via integrated relay on 127.0.0.1:8099)
    "relay_openrouter",
    "relay_gemini",
    "relay_groq",
    "relay_nvidia",
    "relay_pollinations",
]
# Load quotas.json at startup (script-relative so it works from any cwd)
with open(Path(__file__).parent / "quotas.json", "r") as f:
    QUOTAS_DATA = json.load(f)


# ---------------------------------------------------------------------------
# Integrated relay for the 5 outside providers.
# Serves relay_openrouter, relay_gemini, relay_groq, relay_nvidia,
# relay_pollinations (keyless) on 127.0.0.1:8099 in a daemon thread.
# Keys come from Handler.keys (decrypted in-memory, never on disk).
# ---------------------------------------------------------------------------
RELAY_PORT = 8099
RELAY_UPSTREAMS = {
    "relay_openrouter": "https://openrouter.ai/api/v1",
    "relay_gemini": "https://generativelanguage.googleapis.com/v1beta/openai",
    "relay_groq": "https://api.groq.com/openai/v1",
    "relay_nvidia": "https://integrate.api.nvidia.com/v1",
    "relay_pollinations": "https://text.pollinations.ai/openai",
}
# relay_pollinations needs no key
RELAY_KEYLESS = {"relay_pollinations"}


class RelayHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        return

    def do_GET(self):
        self._proxy()

    def do_POST(self):
        self._proxy()

    def _send_json(self, obj, code=200):
        data = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _proxy(self):
        path = self.path
        if path == "/health":
            self._send_json({"ok": True, "providers": list(RELAY_UPSTREAMS.keys())})
            return
        # Expect /<name>/v1/...
        parts = path.lstrip("/").split("/", 1)
        if len(parts) < 2 or parts[0] not in RELAY_UPSTREAMS:
            self._send_json({"error": "unknown relay provider"}, 404)
            return
        name, rest = parts[0], "/" + parts[1]
        upstream = RELAY_UPSTREAMS[name] + rest
        if "?" in path:
            upstream += "?" + path.split("?", 1)[1]

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else None

        req = Request(upstream, data=body, method=self.command)
        for k, v in self.headers.items():
            if k.lower() not in ("host", "content-length", "authorization"):
                req.add_header(k, v)
        if name not in RELAY_KEYLESS:
            key = (Handler.keys or {}).get(name)
            if not key:
                self._send_json({"error": f"no key configured for {name}"}, 502)
                return
            req.add_header("Authorization", f"Bearer {key}")

        try:
            with urlopen(req, timeout=60) as resp:
                data = resp.read()
                self.send_response(resp.status)
                self.send_header("Content-Type", resp.headers.get("Content-Type", "application/json"))
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        except HTTPError as e:
            data = e.read()
            self.send_response(e.code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            self._send_json({"error": str(e)[:200]}, 502)


def start_relay():
    """Start the integrated relay in a daemon thread."""
    import threading
    server = ThreadingHTTPServer(("127.0.0.1", RELAY_PORT), RelayHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    print(f"Integrated relay on 127.0.0.1:{RELAY_PORT} (5 providers)")
    return server


def wizard_collect_keys() -> dict:
    print("--- First run wizard ---")
    print()
    print("RECOMMENDED: Use FreeLLMAPI gateway (one key for all providers).")
    print("Download FreeLLMAPI-Windows.zip from the releases page and start it first.")
    print()
    keys: dict = {}
    fkey = getpass("FreeLLMAPI unified API key (leave blank to enter individual keys instead): ")
    if fkey:
        keys["freellmapi"] = fkey
        gw_url = input("FreeLLMAPI gateway URL [http://127.0.0.1:3001]: ").strip()
        keys["freellmapi_url"] = gw_url or "http://127.0.0.1:3001"
        print("FreeLLMAPI configured. Skipping individual provider keys.")
        return keys
    print()
    print("Enter individual provider API keys (leave blank to skip any):")
    for name in PROVIDER_NAMES:
        if name == "freellmapi":
            continue
        val = getpass(f"  {name} API key: ")
        if val:
            keys[name] = val
    return keys


class Handler(BaseHTTPRequestHandler):
    server_version = "LocalDashboard/0.1"
    keys: dict | None = None
    _head_only = False  # set True during do_HEAD so bodies are suppressed

    # Session helpers
    def _get_session(self):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        token = cookie.get("session")
        if token:
            token = token.value
            if token in SESSIONS:
                ts = SESSIONS[token]
                now = time.time()
                if now - ts < SESSION_EXPIRY:
                    SESSIONS[token] = now
                    return token
                else:
                    del SESSIONS[token]
        return None

    def _require_session(self):
        if not self._get_session():
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self._send_body(json.dumps({"error": "not logged in"}).encode())
            return False
        return True

    def _set_json_headers(self, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

    def do_GET(self):
        self._head_only = False
        self._do_get_head()

    def do_HEAD(self):
        # HEAD mirrors GET routing/status codes but sends no body
        # (uptime monitors use HEAD; without this BaseHTTPRequestHandler
        # answers 501 Not Implemented).
        self._head_only = True
        try:
            self._do_get_head()
        finally:
            self._head_only = False

    def _send_body(self, data: bytes):
        if not self._head_only:
            self.wfile.write(data)

    def send_error(self, code, message=None, explain=None):
        # Suppress the HTML error page body on HEAD responses.
        if self._head_only:
            self.send_response(code, message)
            self.send_header("Connection", "close")
            self.end_headers()
            return
        super().send_error(code, message, explain)

    def _do_get_head(self):
        parsed = urlparse(self.path)
        if parsed.path == "/setup":
            key_path = Path(__file__).parent / "keys.enc"
            if key_path.exists():
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
                return
            relay_names = [n for n in PROVIDER_NAMES if n.startswith("relay_")]
            other_names = [n for n in PROVIDER_NAMES if n != "freellmapi" and not n.startswith("relay_")]
            relay_fields = "".join(
                '<label>' + n.replace("relay_", "Relay: ") + '<input type="password" name="k_' + n + '" autocomplete="off"></label>'
                for n in relay_names
            )
            relay_section = (
                "<div style='background:#0f1622;border:1px solid #22c55e;border-radius:12px;padding:16px;margin-bottom:16px'>"
                "<h3 style='margin:0 0 8px;color:#22c55e'>Relay Providers</h3>"
                "<p style='color:#9aa3b2;font-size:14px;margin:0 0 12px'>Your outside keys via the built-in relay. Pollinations needs no key.</p>"
                + relay_fields +
                "</div>"
            )
            fields = "".join(
                '<label>' + n + '<input type="password" name="k_' + n + '" autocomplete="off"></label>'
                for n in other_names
            )
            freellmapi_section = (
                "<div style='background:#0f1622;border:1px solid #3b82f6;border-radius:12px;padding:16px;margin-bottom:16px'>"
                "<h3 style='margin:0 0 8px;color:#3b82f6'>FreeLLMAPI Gateway</h3>"
                "<p style='color:#9aa3b2;font-size:14px;margin:0 0 12px'>One key for all providers. "
                "The gateway starts automatically with Nexus-Local on 127.0.0.1:3001.</p>"
                "<label>FreeLLMAPI unified API key"
                "<input type=\"password\" name=\"k_freellmapi\" autocomplete=\"off\"></label>"
                "<label>Gateway URL"
                "<input type=\"text\" name=\"url_freellmapi\" placeholder=\"http://127.0.0.1:3001\" autocomplete=\"off\"></label>"
                "<details style='margin-top:16px'>"
                "<summary style='color:#9aa3b2;cursor:pointer'>Or enter individual provider keys</summary>"
                "<div style='margin-top:12px'>"
                + fields +
                "</div></details>"
                "</div>"
            )
            page = ("<!DOCTYPE html><html><head><meta charset='utf-8'>"
                    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                    "<title>Nexus Local - Setup</title><style>"
                    "body{background:#0a0c11;color:#e6e9f0;font-family:system-ui,sans-serif;margin:0;padding:24px}"
                    "h1{font-size:2rem;font-weight:800}h1 span{color:#3b82f6}"
                    ".card{max-width:560px;margin:0 auto;background:#11141b;border:1px solid #1e2430;border-radius:20px;padding:32px}"
                    "label{display:block;margin:12px 0 4px;color:#9aa3b2;font-size:14px}"
                    "input{width:100%;box-sizing:border-box;background:#0a0c11;border:1px solid #1e2430;border-radius:12px;color:#e6e9f0;padding:14px;font-size:16px}"
                    "button{background:#3b82f6;color:#fff;border:0;border-radius:12px;padding:16px 32px;font-size:16px;font-weight:600;width:100%;margin-top:20px;cursor:pointer}"
                    ".eyebrow{font-family:monospace;letter-spacing:.35em;font-size:12px;color:#3b82f6}"
                    "</style></head><body><div class='card'><div class='eyebrow'>NEXUS LOCAL</div>"
                    "<h1>Set up <span>your</span> keys</h1>"
                    "<p style='color:#9aa3b2'>Enter your FreeLLMAPI key, relay keys, or expand below for individual keys. Choose a strong password.</p>"
                    "<div style='background:#0f1622;border:1px solid #f59e0b;border-radius:12px;padding:16px;margin-bottom:16px'>"
                    "<h3 style='margin:0 0 8px;color:#f59e0b'>Quick Import</h3>"
                    "<p style='color:#9aa3b2;font-size:14px;margin:0 0 12px'>Paste all keys at once, one per line as <code>name: key</code>. Names: "
                    "relay_openrouter, relay_gemini, relay_groq, relay_nvidia, groq, google, openrouter, nvidia, freellmapi</p>"
                    "<textarea id='bulk' rows='6' style='width:100%;box-sizing:border-box;background:#0a0c11;border:1px solid #1e2430;border-radius:12px;color:#e6e9f0;padding:14px;font-size:14px;font-family:monospace' placeholder='relay_groq: gsk_...&#10;groq: gsk_...&#10;openrouter: sk-or-v1-...'></textarea>"
                    "<button type='button' onclick='fillKeys()' style='background:#f59e0b;margin-top:12px'>Fill Fields Below</button>"
                    "</div>"
                    "<script>"
                    "function fillKeys(){"
                    "var t=document.getElementById('bulk').value.split('\\n');"
                    "var n=0;"
                    "t.forEach(function(l){"
                    "var i=l.indexOf(':');if(i<0)return;"
                    "var k=l.slice(0,i).trim();var v=l.slice(i+1).trim();"
                    "if(!k||!v)return;"
                    "var el=document.querySelector('input[name=\"k_'+k+'\"]');"
                    "if(el){el.value=v;n++;}"
                    "});"
                    "alert(n+' keys filled');"
                    "}"
                    "</script>"
                    "<form method='POST' action='/setup'>" + relay_section + freellmapi_section +
                    "<label>Password (min 8 chars)<input type='password' name='password' required minlength='8'></label>"
                    "<label>Confirm password<input type='password' name='confirm' required></label>"
                    "<button type='submit'>Encrypt and Finish Setup</button>"
                    "</form></div></body></html>")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self._send_body(page.encode())
            return
        # Public login page
        if parsed.path == "/login":
            key_path = Path(__file__).parent / "keys.enc"
            if not key_path.exists():
                self.send_response(302)
                self.send_header("Location", "/setup")
                self.end_headers()
                return
            try:
                content = (Path(__file__).parent / "login.html").read_text(encoding="utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self._send_body(content.encode())
            except Exception as e:
                self.send_error(500, str(e))
            return
        # Settings page - update keys after login
        if parsed.path == "/settings":
            if not self._get_session():
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
                return
            # Show current keys (masked) with fields to update
            current = getattr(Handler, 'keys', {})
            sidebar = (Path(__file__).parent / "sidebar.html").read_text(encoding="utf-8")
            def masked(k):
                v = current.get(k, "")
                return f"***{v[-4:]}" if v and len(v) > 4 else ("set" if v else "not set")
            rows = ""
            for n in PROVIDER_NAMES:
                rows += f"<label>{n} <span style='color:#22c55e;font-size:12px'>({masked(n)})</span><input type='password' name='k_{n}' autocomplete='off' placeholder='Leave blank to keep current'></label>"
            page = ("<!DOCTYPE html><html><head><meta charset='utf-8'>"
                    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                    "<title>Nexus Local - Settings</title><style>"
                    "body{background:#0a0c11;color:#e6e9f0;font-family:system-ui,sans-serif;margin:0;padding:24px}"
                    ".card{max-width:560px;margin:0 auto;background:#11141b;border:1px solid #1e2430;border-radius:20px;padding:32px}"
                    "label{display:block;margin:12px 0 4px;color:#9aa3b2;font-size:14px}"
                    "input{width:100%;box-sizing:border-box;background:#0a0c11;border:1px solid #1e2430;border-radius:12px;color:#e6e9f0;padding:14px;font-size:16px}"
                    "button{background:#3b82f6;color:#fff;border:0;border-radius:12px;padding:16px 32px;font-size:16px;font-weight:600;width:100%;margin-top:20px;cursor:pointer}"
                    "</style></head><body>" + sidebar + "<div class='card' style='margin:40px auto'"
                    "<h1>Update Keys</h1>"
                    "<p style='color:#9aa3b2'>Only fill in the keys you want to change. Enter your password to save.</p>"
                    "<form method='POST' action='/settings'>" + rows +
                    "<label>Confirm Password<input type='password' name='password' required></label>"
                    "<button type='submit'>Save Keys</button>"
                    "</form><p><a href='/' style='color:#3b82f6'>Back to Dashboard</a></p>"
                    "</div></body></html>")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self._send_body(page.encode())
            return
        # Connections page - flow chart
        if parsed.path == "/connections":
            if not self._get_session():
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
                return
            try:
                content = (Path(__file__).parent / "connections.html").read_text(encoding="utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self._send_body(content.encode())
            except Exception as e:
                self.send_error(500, str(e))
            return
        # Root redirects based on session
        if parsed.path == "/":
            key_path = Path(__file__).parent / "keys.enc"
            if not key_path.exists():
                self.send_response(302)
                self.send_header("Location", "/setup")
                self.end_headers()
                return
            if self._get_session():
                try:
                    content = (Path(__file__).parent / "dashboard.html").read_text(encoding="utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.end_headers()
                    self._send_body(content.encode())
                except Exception as e:
                    self.send_error(500, str(e))
            else:
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
            return
        # API endpoints
        if parsed.path == "/api/status":
            if not self._require_session():
                return
            self._set_json_headers(200)
            self._send_body(json.dumps({"ok": True}).encode())
            return
        if parsed.path == "/api/quotas":
            if not self._require_session():
                return
            self._set_json_headers()
            history = get_usage_history()
            combined_history = {
                "requests": [0] * 7,
                "tokens": [0] * 7,
            }
            for prov_hist in history.values():
                for i in range(7):
                    combined_history["requests"][i] += prov_hist["requests"][i]
                    combined_history["tokens"][i] += prov_hist["tokens"][i]
            quotas = {
                "daily_usage": {"requests": 0, "tokens": 0},
                "monthly_usage": {"requests": 0, "tokens": 0},
                "history": combined_history,
                "providers": [],
            }
            if QUOTAS_PATH.exists():
                with open(QUOTAS_PATH) as f:
                    base = json.load(f)
                for name in PROVIDER_NAMES:
                    provider_data = base.get(name, {})
                    quotas["providers"].append({
                        "provider": name,
                        "display_name": provider_data.get("display_name", name.title()),
                        "reset": provider_data.get("reset", ""),
                        "history": history.get(name, {"requests": [0] * 7, "tokens": [0] * 7}),
                        "limits": {
                            "daily_requests": provider_data.get("daily_requests", {"limit": None, "notes": "", "source": ""}),
                            "monthly_requests": provider_data.get("monthly_requests", {"limit": None, "notes": "", "source": ""}),
                            "daily_tokens": provider_data.get("daily_tokens", {"limit": None, "notes": "", "source": ""}),
                            "monthly_tokens": provider_data.get("monthly_tokens", {"limit": None, "notes": "", "source": ""}),
                        },
                        "key_configured": bool((Handler.keys or {}).get(name)) or name in ("aihorde", "kilo", "ovh", "pollinations", "relay_pollinations"),
                        "daily_usage": {"requests": 0, "tokens": 0},
                        "monthly_usage": {"requests": 0, "tokens": 0},
                    })
            if os.path.exists(USAGE_PATH):
                with open(USAGE_PATH) as f:
                    for line in f:
                        entry = json.loads(line)
                        pt = entry.get("prompt_tokens", 0)
                        ct = entry.get("completion_tokens", 0)
                        quotas["daily_usage"]["requests"] += 1
                        quotas["daily_usage"]["tokens"] += pt + ct
                        quotas["monthly_usage"]["requests"] += 1
                        quotas["monthly_usage"]["tokens"] += pt + ct
            self._send_body(json.dumps(quotas).encode())
            return
        if parsed.path == "/api/usage":
            if not self._require_session():
                return
            usage_data = {
                "per_provider": {},
                "totals": {"requests": 0, "tokens": 0},
            }
            if os.path.exists(USAGE_PATH):
                with open(USAGE_PATH) as f:
                    for line in f:
                        entry = json.loads(line)
                        provider = entry["provider"]
                        pt = entry.get("prompt_tokens", 0)
                        ct = entry.get("completion_tokens", 0)
                        if provider not in usage_data["per_provider"]:
                            usage_data["per_provider"][provider] = {"requests": 0, "tokens": 0}
                        usage_data["per_provider"][provider]["requests"] += 1
                        usage_data["per_provider"][provider]["tokens"] += pt + ct
                        usage_data["totals"]["requests"] += 1
                        usage_data["totals"]["tokens"] += pt + ct
            self._send_body(json.dumps(usage_data).encode())
            return
        self.send_error(404, "Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/setup":
            key_path = Path(__file__).parent / "keys.enc"
            if key_path.exists():
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length", 0))
            form = parse_qs(self.rfile.read(length).decode())
            pw = form.get("password", [""])[0]
            if not pw or pw != form.get("confirm", [""])[0] or len(pw) < 8:
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": "passwords must match and be 8+ chars"}).encode())
                return
            keys = {}
            for n in PROVIDER_NAMES:
                v = form.get("k_" + n, [""])[0].strip()
                if v:
                    keys[n] = v
            gw_url = form.get("url_freellmapi", [""])[0].strip()
            if gw_url:
                if not (gw_url.startswith("http://") or gw_url.startswith("https://")):
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "gateway URL must start with http:// or https://"}).encode())
                    return
                keys["freellmapi_url"] = gw_url
            encrypt_keys(keys, pw, key_path)
            os.chmod(key_path, 0o600)
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
            return
        if parsed.path == "/settings":
            if not self._get_session():
                self._set_json_headers(401)
                self.wfile.write(json.dumps({"error": "not logged in"}).encode())
                return
            length = int(self.headers.get("Content-Length", 0))
            form = parse_qs(self.rfile.read(length).decode())
            pw = form.get("password", [""])[0]
            if not pw:
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": "password required"}).encode())
                return
            key_path = Path(__file__).parent / "keys.enc"
            try:
                keys = decrypt_keys(key_path, pw)
            except Exception:
                self._set_json_headers(401)
                self.wfile.write(json.dumps({"error": "wrong password"}).encode())
                return
            # Update with new values (blank = keep current)
            updated = 0
            for n in PROVIDER_NAMES:
                v = form.get("k_" + n, [""])[0].strip()
                if v:
                    keys[n] = v
                    updated += 1
            gw_url = form.get("url_freellmapi", [""])[0].strip()
            if gw_url:
                keys["freellmapi_url"] = gw_url
                updated += 1
            encrypt_keys(keys, pw, key_path)
            os.chmod(key_path, 0o600)
            Handler.keys = keys  # refresh in-memory
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return
        if parsed.path == "/api/models":
            if not self._get_session():
                self.send_response(401)
                self.end_headers()
                return
            provider = parse_qs(parsed.query).get("provider", [""])[0]
            models = []
            try:
                import urllib.request, json as js
                # Try relay for relay_* providers, engine for others
                if provider.startswith("relay_"):
                    base = provider.replace("relay_", "")
                    url = f"http://127.0.0.1:8099/{base}/v1/models"
                elif provider == "freellmapi":
                    url = "http://127.0.0.1:3001/v1/models"
                else:
                    # Direct providers - try engine
                    url = "http://127.0.0.1:3001/v1/models"
                req = urllib.request.Request(url, headers={"Authorization": "Bearer dummy"})
                # For relay, we need to go through the dashboard's key
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = js.loads(resp.read())
                    models = [m.get("id", "") for m in data.get("data", []) if m.get("id")]
                    # Filter by provider if needed
                    if not provider.startswith("relay_") and provider != "freellmapi":
                        models = [m for m in models if m.startswith(provider + "/") or "/" not in m]
            except Exception as e:
                pass
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self._send_body(js.dumps({"models": models}).encode())
            return
        if parsed.path == "/api/chat":
            content_length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(content_length)
            try:
                data = json.loads(raw)
            except Exception:
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": "invalid JSON"}).encode())
                return
            provider = data.get("provider")
            model = data.get("model")
            message = data.get("message")
            image = data.get("image")  # base64 data URI, optional
            file_data = data.get("file")  # {name, text/data, type}, optional
            link = data.get("link")  # URL string, optional
            # Prepend file text content to message
            if file_data and file_data.get("text"):
                message = f"[Attached file: {file_data.get('name', 'file')}]\n{file_data['text'][:8000]}\n\n{message}"
            if link:
                message = f"[Attached link: {link}]\n{message}"
            if not provider or not model or not message:
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": "provider, model, message required"}).encode())
                return
            key = Handler.keys.get(provider) if Handler.keys else None
            if not key:
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": f"no key configured for {provider}"}).encode())
                return
            provider_endpoints = {
                "groq": "https://api.groq.com/openai/v1",
                "openrouter": "https://openrouter.ai/api/v1",
                "siliconflow": "https://api.siliconflow.cn/v1",
                "nvidia": "https://integrate.api.nvidia.com/v1",
                "mistral": "https://api.mistral.ai/v1",
                "zhipu": "https://open.bigmodel.cn/api/paas/v4",
                "kilo": "https://api.kilo.ai/v1",
                "ovh": "https://oai.endpoints.kepler.ai.cloud.ovh.net/v1",
            }
            if provider.startswith("relay_"):
                # Integrated relay providers - route through localhost:8099
                # The relay attaches the key from Handler.keys
                base = f"http://127.0.0.1:{RELAY_PORT}/{provider}/v1"
                # For relay, we still check that a key is configured (except keyless)
                if provider not in RELAY_KEYLESS and not key:
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": f"no key configured for {provider}"}).encode())
                    return
            elif provider == "freellmapi":
                # Unified gateway key; base URL comes from setup (not a fixed endpoint)
                gw_url = ((Handler.keys or {}).get("freellmapi_url") or "").strip()
                if not gw_url:
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "Set your gateway URL in setup"}).encode())
                    return
                base = gw_url.rstrip("/")
            elif provider not in provider_endpoints:
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": f"chat not supported for {provider} in local version"}).encode())
                return
            else:
                base = provider_endpoints[provider]
            headers = {
                "Content-Type": "application/json",
            }
            # For relay providers, the integrated relay attaches the key
            # For direct providers, attach the key here
            if not provider.startswith("relay_"):
                headers["Authorization"] = f"Bearer {key}"
            if provider == "openrouter" or provider == "relay_openrouter":
                headers["X-Title"] = "NexusLocal"
            body = {
                "model": model,
                "messages": [{"role": "user", "content": ([{"type": "text", "text": message}] + ([{"type": "image_url", "image_url": {"url": image}}] if image else [])) if image else message}],
                "max_tokens": 1024,
            }
            try:
                req = Request(f"{base}/chat/completions", data=json.dumps(body).encode(), headers=headers, method="POST")
                with urlopen(req, timeout=60) as resp:
                    resp_data = json.loads(resp.read().decode())
                    reply = resp_data["choices"][0]["message"]["content"]
                    usage = resp_data.get("usage", {})
                    usage_line = {
                        "ts": datetime.datetime.now().isoformat(),
                        "provider": provider,
                        "model": model,
                        "prompt_tokens": usage.get("prompt_tokens", 0),
                        "completion_tokens": usage.get("completion_tokens", 0),
                    }
                    with open(USAGE_PATH, "a") as f2:
                        f2.write(json.dumps(usage_line) + "\n")
                    self._set_json_headers(200)
                    self.wfile.write(json.dumps({"reply": reply}).encode())
            except HTTPError as e:
                body_err = e.read().decode()[:200]
                self._set_json_headers(e.code)
                self.wfile.write(json.dumps({"error": f"provider {e.code}: {body_err}"}).encode())
            except URLError as e:
                self._set_json_headers(500)
                self.wfile.write(json.dumps({"error": f"provider error: {e.reason}"}).encode())
            except Exception as e:
                self._set_json_headers(500)
                self.wfile.write(json.dumps({"error": f"server error: {e}"}).encode())
            return
        if parsed.path == "/api/refresh":
            if not self._require_session():
                return
            self._set_json_headers()
            self.wfile.write(json.dumps({"ok": True, "refreshed_at": datetime.datetime.now().isoformat()}).encode())
            return
        if parsed.path == "/api/login":
            ip = self.client_address[0]
            now = time.time()
            recent = [t for t in _login_attempts.get(ip, []) if now - t < 900]
            if len(recent) >= 10:
                self._set_json_headers(429)
                self.wfile.write(json.dumps({"error": "too many attempts, try again later"}).encode())
                return

            content_length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(content_length)
            try:
                data = json.loads(raw)
            except Exception:
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": "invalid JSON"}).encode())
                return
            password = data.get("password")
            if not password:
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": "password required"}).encode())
                return
            key_path = Path(__file__).parent / "keys.enc"
            try:
                dec_keys = decrypt_keys(key_path, password)
            except Exception:
                recent.append(now)
                _login_attempts[ip] = recent
                time.sleep(1)
                self._set_json_headers(401)
                self.wfile.write(json.dumps({"error": "wrong password"}).encode())
                return
            # Successful
            _login_attempts.pop(ip, None)
            token = secrets.token_hex(32)
            SESSIONS[token] = time.time()
            Handler.keys = dec_keys
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            cookie = f"session={token}; HttpOnly; SameSite=Lax; Path=/"
            self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True}).encode())
            return
        if parsed.path == "/api/logout":
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            token = cookie.get("session").value if cookie.get("session") else None
            if token and token in SESSIONS:
                del SESSIONS[token]
            # Expire cookie
            self.send_response(200)
            self.send_header("Set-Cookie", "session=; Max-Age=0; Path=/")
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True}).encode())
            return
        self.send_error(404, "Not Found")

    def log_message(self, format, *args):
        return


def main():
    key_path = Path(__file__).parent / "keys.enc"
    if not key_path.exists():
        print("keys.enc not found – open http://127.0.0.1:8080/setup in your browser to configure keys.")
    # Don't decrypt keys at startup – login handled via API
    Handler.keys = None
    # Start the integrated relay for the 5 outside providers
    start_relay()
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8080"))
    addr = (host, port)
    httpd = ThreadingHTTPServer(addr, Handler)
    print(f"Serving on {addr[0]}:{addr[1]} – press Ctrl-C to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutdown requested")


if __name__ == "__main__":
    main()
