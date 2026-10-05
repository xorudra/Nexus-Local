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
from urllib.parse import urlparse, parse_qs, quote as _urlquote
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
    # siliconflow REMOVED 2026-10-05 per Rudra: one-time $1 credit exhausted, never resets, 402 on all models
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
# Also serves individual provider keys (groq, openrouter, etc.) through
# the same relay - user provides their own keys via setup.
# Keys come from Handler.keys (decrypted in-memory, never on disk).
# ---------------------------------------------------------------------------
RELAY_PORT = 8099
RELAY_UPSTREAMS = {
    "relay_openrouter": "https://openrouter.ai/api/v1",
    "relay_gemini": "https://generativelanguage.googleapis.com/v1beta/openai",
    "relay_groq": "https://api.groq.com/openai/v1",
    "relay_nvidia": "https://integrate.api.nvidia.com/v1",
    "relay_pollinations": "https://text.pollinations.ai/openai",
    # Individual providers via relay (user's own keys)
    "groq": "https://api.groq.com/openai/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "siliconflow": "https://api.siliconflow.com/v1",
    "nvidia": "https://integrate.api.nvidia.com/v1",
    "mistral": "https://api.mistral.ai/v1",
    "zhipu": "https://open.bigmodel.cn/api/paas/v4",
    "kilo": "https://api.kilo.ai/v1",
    "ovh": "https://oai.endpoints.kepler.ai.cloud.ovh.net/v1",
    "google": "https://generativelanguage.googleapis.com/v1beta/openai",
    "cloudflare": "https://api.cloudflare.com/client/v4/accounts",
    "cohere": "https://api.cohere.com/v1",
    "huggingface": "https://api-inference.huggingface.co/v1",
    "aihorde": "https://stablehorde.net/api/v2",
    "pollinations": "https://text.pollinations.ai/openai",
}
# relay_pollinations needs no key
RELAY_KEYLESS = {"relay_pollinations", "aihorde", "pollinations", "kilo", "ovh"}

def register_custom_providers(keys):
    """Register custom relay providers from keys dict into RELAY_UPSTREAMS."""
    if not keys:
        return
    for k, v in keys.items():
        if k.startswith("custom_relay_") and not k.endswith("_url"):
            name = k[len("custom_relay_"):]
            url = keys.get(k + "_url", "").strip()
            if url and name not in RELAY_UPSTREAMS:
                RELAY_UPSTREAMS[name] = url.rstrip("/")


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
        # Provider-specific path quirks for model listing
        if name == "aihorde" and rest == "/v1/models":
            rest = "/status/models"
        # RELAY_UPSTREAMS bases already include the API version prefix
        # (e.g. /v1, /api/v1, /v1beta/openai), so strip a leading /v1 from
        # the relay path to avoid doubling it (/v1/v1/models -> /v1/models).
        elif rest.startswith("/v1/"):
            rest = rest[3:]
        elif rest == "/v1":
            rest = ""
        upstream = RELAY_UPSTREAMS[name] + rest
        if "?" in path:
            upstream += "?" + path.split("?", 1)[1]

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else None

        req = Request(upstream, data=body, method=self.command)
        # Use a browser-like User-Agent; some upstreams (Groq via Cloudflare)
        # block Python-urllib's default signature with 403 error 1010.
        req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36")
        for k, v in self.headers.items():
            if k.lower() not in ("host", "content-length", "authorization", "user-agent"):
                req.add_header(k, v)
        if name not in RELAY_KEYLESS:
            # Check for custom relay key first, then standard key
            key = (Handler.keys or {}).get(f"custom_relay_{name}")
            if not key:
                key = (Handler.keys or {}).get(name)
            if not key:
                self._send_json({"error": f"no key configured for {name}"}, 502)
                return
            # Google's OpenAI-compatible endpoint (/v1beta/openai) requires the
            # key as Authorization: Bearer (verified: ?key= and x-goog-api-key
            # are ignored there; only the native API takes ?key=).
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
            keys_exist = key_path.exists()
            relay_names = [n for n in PROVIDER_NAMES if n.startswith("relay_")]
            other_names = [n for n in PROVIDER_NAMES if n != "freellmapi" and not n.startswith("relay_")]
            relay_fields = "".join(
                '<label>' + n.replace("relay_", "Relay: ") + '<input type="password" name="k_' + n + '" autocomplete="off"></label>'
                for n in relay_names
            )
            relay_section = (
                "<details style='background:#0c0c0f;border:1px solid rgba(255,213,0,.25);border-radius:10px;padding:16px;margin-bottom:16px'>"
                "<summary style='color:#FFD500;cursor:pointer;font-size:16px;font-weight:600;font-family:Oswald,sans-serif;letter-spacing:.06em'>Relay Providers</summary>"
                "<p style='color:#9aa3b2;font-size:14px;margin:12px 0'>Your outside keys via the built-in relay. Pollinations needs no key.</p>"
                + relay_fields +
                "</details>"
            )
            fields = "".join(
                '<label>' + n + '<input type="password" name="k_' + n + '" autocomplete="off"></label>'
                for n in other_names
            )
            freellmapi_section = (
                "<details style='background:#0c0c0f;border:1px solid rgba(255,213,0,.25);border-radius:10px;padding:16px;margin-bottom:16px'>"
                "<summary style='color:#FFD500;cursor:pointer;font-size:16px;font-weight:600;font-family:Oswald,sans-serif;letter-spacing:.06em'>FreeLLMAPI Gateway</summary>"
                "<p style='color:#9aa3b2;font-size:14px;margin:12px 0'>One key for all providers. "
                "The gateway starts automatically with Nexus-Local on 127.0.0.1:3001.</p>"
                "<label>FreeLLMAPI unified API key"
                "<input type=\"password\" name=\"k_freellmapi\" autocomplete=\"off\"></label>"
                "<label>Gateway URL"
                "<input type=\"text\" name=\"url_freellmapi\" placeholder=\"http://127.0.0.1:3001\" autocomplete=\"off\"></label>"
                "<details style='margin-top:16px'>"
                "<summary style='color:#9aa3b2;cursor:pointer'>Or enter FreeLLMAPI providers keys manually</summary>"
                "<div style='margin-top:12px'>"
                + fields +
                "</div></details>"
                "</details>"
            )
            page = ("<!DOCTYPE html><html><head><meta charset='utf-8'>"
                    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                    "<title>Nexus Local - Setup</title><style>@import url('https://fonts.googleapis.com/css2?family=Bebas+Neue&family=Oswald:wght@400;500;600&display=swap');"
                    "*{box-sizing:border-box}"
                    "body{background-color:#050507;background-image:radial-gradient(ellipse 90% 45% at 50% -5%, rgba(255,213,0,.07), transparent 70%);color:#e6e9f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;margin:0;padding:0}"
                    ".wrap{max-width:600px;margin:0 auto;padding:20px 16px 40px}"
                    ".hero{text-align:center;padding:24px 0 16px}"
                    ".eyebrow{font-family:'Bebas Neue',sans-serif;letter-spacing:.32em;font-size:15px;color:#FFD500;margin-bottom:10px}"
                    "h1{font-family:'Bebas Neue',sans-serif;font-size:34px;margin:0 0 8px;color:#fff;letter-spacing:.08em;line-height:1.2}h1 span{color:#FFD500}"
                    ".sub{color:#9aa3b2;font-size:14px;margin:0}"
                    ".steps{display:flex;justify-content:center;align-items:center;gap:6px;margin:18px 0}"
                    ".st{display:flex;align-items:center;gap:6px;font-size:12px;color:#6b7280}"
                    ".sn{width:24px;height:24px;border-radius:50%;background:#0a0a0d;border:1px solid #3a3a42;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:600}"
                    ".st.on{color:#fff}.st.on .sn{background:#FFD500;border-color:#000;color:#fff}"
                    ".st.done .sn{background:#F5B800;border-color:#F5B800;color:#0a0a0a}"
                    ".ln{width:24px;height:1px;background:#2a3142}"
                    ".tabs{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:16px}"
                    ".tab{background:#101014;border:1px solid #26262c;border-radius:10px;padding:14px 8px;text-align:center;cursor:pointer;transition:all .18s;color:#e8e8ea}"
                    ".tab:hover{border-color:rgba(255,213,0,.4)}"
                    ".tab.sel{border-color:#FFD500;background:rgba(255,213,0,.07);box-shadow:0 0 20px rgba(255,213,0,.12)}"
                    ".tab b{display:block;font-size:13px;margin-bottom:2px;font-family:Oswald,sans-serif;letter-spacing:.08em;text-transform:uppercase}"
                    ".tab span{font-size:11px;color:#8a8a92}"
                    ".card{background:#101014;border:1px solid rgba(255,213,0,.14);border-radius:12px;padding:20px;margin-bottom:14px;box-shadow:0 12px 32px rgba(0,0,0,.5),inset 0 1px 0 rgba(255,255,255,.05)}"
                    ".card h3{margin:0 0 6px;font-size:20px;font-family:'Bebas Neue',sans-serif;letter-spacing:.08em}"
                    ".hint{color:#9aa3b2;font-size:13px;margin:0 0 12px;line-height:1.45}"
                    "label{display:block;margin:10px 0 4px;color:#9aa3b2;font-size:13px}"
                    "input,textarea{width:100%;background:#0a0a0d;border:1px solid #26262c;border-radius:8px;color:#e8e8ea;padding:11px 13px;font-size:14px}"
                    "input:focus,textarea:focus{outline:none;border-color:#FFD500;box-shadow:0 0 0 3px rgba(255,213,0,.15)}"
                    "textarea{font-family:ui-monospace,monospace}"
                    "button[type='submit']{font-family:Oswald,sans-serif;font-weight:600;font-size:14px;letter-spacing:.22em;text-transform:uppercase;background:linear-gradient(#FFE45C,#F5B800);color:#0a0a0a;border:1px solid #0a0a0a;border-radius:8px;box-shadow:0 0 28px rgba(255,213,0,.28),inset 0 1px 0 rgba(255,255,255,.5);padding:16px;width:100%;margin-top:14px;cursor:pointer}"
                    "button[type='submit']:hover{filter:brightness(1.12)}"
                    "details{background:#0c0c0f;border:1px solid #26262c;border-radius:10px;margin-bottom:8px}"
                    "details summary{padding:12px 14px;cursor:pointer;font-weight:600;font-size:13px;list-style:none}"
                    "details summary::-webkit-details-marker{display:none}"
                    ".dbody{padding:0 14px 14px}"
                    ".warn{background:rgba(245,158,11,.08);border:1px solid #f59e0b;border-radius:12px;padding:13px 15px;margin-bottom:16px}"
                    ".warn p{margin:0;color:#fbbf24;font-size:13px}"
                    ".sec{display:none}.sec.on{display:block;animation:fi .25s}"
                    "@keyframes fi{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}"
                    "@media(max-width:480px){.tabs{grid-template-columns:1fr}}"
                    ".gold-div{height:2px;background:linear-gradient(90deg,transparent,rgba(255,213,0,.7),transparent);margin:0 -16px 16px}"
                    "@keyframes fadeUp{from{opacity:0;transform:translateY(18px)}to{opacity:1;transform:none}}""@keyframes grainShift{0%,100%{transform:translate(0,0)}12%{transform:translate(-3%,-5%)}25%{transform:translate(-8%,3%)}37%{transform:translate(4%,-8%)}50%{transform:translate(-3%,8%)}62%{transform:translate(-8%,3%)}75%{transform:translate(6%,0)}87%{transform:translate(0,6%)}}""@keyframes batDrift{0%,100%{transform:translateY(-50%) translateX(0)}50%{transform:translateY(-60%) translateX(-26px)}}""@keyframes tabGlow{0%,100%{box-shadow:0 0 14px rgba(255,213,0,.10)}50%{box-shadow:0 0 26px rgba(255,213,0,.28)}}""body::before{content:\"\";position:fixed;inset:0;z-index:2000;pointer-events:none;background:radial-gradient(ellipse at center,transparent 52%,rgba(0,0,0,.62) 100%)}""body::after{content:\"\";position:fixed;inset:-120px;z-index:2001;pointer-events:none;opacity:.05;background-image:url(\"data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A//www.w3.org/2000/svg%27%20width%3D%27140%27%20height%3D%27140%27%3E%3Cfilter%20id%3D%27n%27%3E%3CfeTurbulence%20type%3D%27fractalNoise%27%20baseFrequency%3D%270.85%27%20numOctaves%3D%272%27/%3E%3C/filter%3E%3Crect%20width%3D%27140%27%20height%3D%27140%27%20filter%3D%27url%28%23n%29%27%20opacity%3D%270.55%27/%3E%3C/svg%3E\");animation:grainShift 7s steps(8) infinite}"".hero{position:relative;overflow:hidden;animation:fadeUp .7s cubic-bezier(.2,.7,.3,1) both}"".hero::after{content:\"\";position:absolute;right:-34px;top:50%;width:280px;height:101px;background:url(\"data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A//www.w3.org/2000/svg%27%20viewBox%3D%270%200%20100%2036%27%3E%3Cpath%20d%3D%27M0%2C14%20L24%2C3%20L39%2C9%20L44%2C1%20L46.5%2C7%20L50%2C5%20L53.5%2C7%20L56%2C1%20L61%2C9%20L76%2C3%20L100%2C14%20L90%2C20%20L83%2C16%20L75%2C24%20L67%2C18%20L59%2C28%20L54%2C22%20L50%2C30%20L46%2C22%20L41%2C28%20L33%2C18%20L25%2C24%20L17%2C16%20L10%2C20%20Z%27%20fill%3D%27%23FFD500%27/%3E%3C/svg%3E\") no-repeat center/contain;opacity:.07;pointer-events:none;animation:batDrift 11s ease-in-out infinite}"".steps{animation:fadeUp .7s .08s cubic-bezier(.2,.7,.3,1) both}"".tabs{animation:fadeUp .7s .14s cubic-bezier(.2,.7,.3,1) both}"".tab.sel{animation:tabGlow 2.6s ease-in-out infinite}"".sec.on .card{animation:fadeUp .5s cubic-bezier(.2,.7,.3,1) both}"
                    "</style></head><body><div class='wrap'>"
                    "<div class='hero'><div class='eyebrow'>NEXUS LOCAL</div>" +
                    ("<div class='warn'><p><b>Keys already set up.</b> Submitting will <b>overwrite</b> existing keys.</p></div>" if keys_exist else "") +
                    "<h1>Set up <span>your</span> keys</h1>"
                    "<p class='sub'>Connect your AI providers in under a minute</p></div><div class='gold-div'></div>"
                    "<div class='steps'>"
                    "<div class='st on' id='st1'><div class='sn'>1</div>Method</div><div class='ln'></div>"
                    "<div class='st' id='st2'><div class='sn'>2</div>Keys</div><div class='ln'></div>"
                    "<div class='st' id='st3'><div class='sn'>3</div>Secure</div></div>"
                    "<div class='tabs'>"
                    "<div class='tab sel' onclick='swTab(\"q\",this)'><b>Quick Import</b><span>Paste all at once</span></div>"
                    "<div class='tab' onclick='swTab(\"m\",this)'><b>Manual</b><span>Fill each field</span></div>"
                    "<div class='tab' onclick='swTab(\"c\",this)'><b>Custom</b><span>Your providers</span></div>"
                    "</div>"
                    "<script>"
                    "function swTab(t,el){"
                    "document.querySelectorAll('.tab').forEach(x=>x.classList.remove('sel'));"
                    "el.classList.add('sel');"
                    "document.querySelectorAll('.sec').forEach(x=>x.classList.remove('on'));"
                    "document.getElementById('sec-'+t).classList.add('on');"
                    "document.getElementById('st1').className='st done';"
                    "document.getElementById('st2').className='st on';}"
                    "</script>"
                    "<div class='sec on' id='sec-q'><div class='card'>"
                    "<h3 style='color:#f59e0b'>Quick Import</h3>"
                    "<p style='color:#9aa3b2;font-size:14px;margin:0 0 12px'>Paste all keys at once, one per line as <code style=\"background:#1a1f2a;padding:2px 6px;border-radius:4px\">name: key</code>. Expand below to see valid names:</p>"
                    "<details style='margin-bottom:8px;background:#0c0c0f;border:1px solid #26262c;border-radius:8px;padding:10px 14px'>"
                    "<summary style='color:#FFD500;cursor:pointer;font-size:14px;font-weight:600'>Relay Providers (5)</summary>"
                    "<div style='display:flex;flex-wrap:wrap;gap:6px;margin-top:10px'>"
                    "<span style='background:#0a0a0d;color:#FFE45C;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid rgba(255,213,0,.25);font-family:monospace'>relay_groq</span>"
                    "<span style='background:#0a0a0d;color:#FFE45C;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid rgba(255,213,0,.25);font-family:monospace'>relay_gemini</span>"
                    "<span style='background:#0a0a0d;color:#FFE45C;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid rgba(255,213,0,.25);font-family:monospace'>relay_openrouter</span>"
                    "<span style='background:#0a0a0d;color:#FFE45C;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid rgba(255,213,0,.25);font-family:monospace'>relay_nvidia</span>"
                    "<span style='background:#0a0a0d;color:#FFE45C;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid rgba(255,213,0,.25);font-family:monospace'>relay_pollinations</span>"
                    "</div></details>"
                    "<details style='margin-bottom:12px;background:#0c0c0f;border:1px solid #26262c;border-radius:8px;padding:10px 14px'>"
                    "<summary style='color:#FFD500;cursor:pointer;font-size:14px;font-weight:600'>FreeLLMAPI Providers (14)</summary>"
                    "<div style='display:flex;flex-wrap:wrap;gap:6px;margin-top:10px'>"
                    "<span style='background:#0a0a0d;color:#e8e8ea;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid #2a2a32;font-family:monospace'>freellmapi</span>"
                    "<span style='background:#0a0a0d;color:#e8e8ea;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid #2a2a32;font-family:monospace'>groq</span>"
                    "<span style='background:#0a0a0d;color:#e8e8ea;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid #2a2a32;font-family:monospace'>google</span>"
                    "<span style='background:#0a0a0d;color:#e8e8ea;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid #2a2a32;font-family:monospace'>openrouter</span>"
                    "<span style='background:#0a0a0d;color:#e8e8ea;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid #2a2a32;font-family:monospace'>nvidia</span>"
                    "<span style='background:#0a0a0d;color:#e8e8ea;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid #2a2a32;font-family:monospace'>cloudflare</span>"
                    "<span style='background:#0a0a0d;color:#e8e8ea;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid #2a2a32;font-family:monospace'>cohere</span>"
                    "<span style='background:#0a0a0d;color:#e8e8ea;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid #2a2a32;font-family:monospace'>huggingface</span>"
                    "<span style='background:#0a0a0d;color:#e8e8ea;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid #2a2a32;font-family:monospace'>mistral</span>"
                    "<span style='background:#0a0a0d;color:#e8e8ea;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid #2a2a32;font-family:monospace'>siliconflow</span>"
                    "<span style='background:#0a0a0d;color:#e8e8ea;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid #2a2a32;font-family:monospace'>zhipu</span>"
                    "<span style='background:#0a0a0d;color:#e8e8ea;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid #2a2a32;font-family:monospace'>aihorde</span>"
                    "<span style='background:#0a0a0d;color:#e8e8ea;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid #2a2a32;font-family:monospace'>kilo</span>"
                    "<span style='background:#0a0a0d;color:#e8e8ea;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid #2a2a32;font-family:monospace'>ovh</span>"
                    "</div></details>"
                    "<textarea id='bulk' rows='6' oninput='previewKeys()' style='width:100%;box-sizing:border-box;background:#0a0a0d;border:1px solid #26262c;border-radius:8px;color:#e8e8ea;padding:14px;font-size:14px;font-family:monospace' placeholder='freellmapi: sk-...&#10;relay_groq: gsk_...&#10;groq: gsk_...&#10;openrouter: sk-or-v1-...'></textarea>"
                    "<div id='bulk-preview' style='margin:12px 0;font-size:13px'></div>"
                    "<div style='display:flex;gap:10px'>"
                    "<button type='button' onclick='fillKeys()' style='background:linear-gradient(#FFE45C,#F5B800);color:#0a0a0a;border:1px solid #0a0a0a;border-radius:8px;box-shadow:0 0 20px rgba(255,213,0,.25);padding:14px 24px;font-size:13px;font-family:Oswald,sans-serif;font-weight:600;letter-spacing:.14em;text-transform:uppercase;flex:1;cursor:pointer' onmousedown=\"this.style.transform='scale(.97)'\" onmouseup=\"this.style.transform='scale(1)'\">Fill Fields Below</button>"
                    "<button type='button' onclick=\"document.getElementById('bulk').value='';previewKeys()\" style='background:#141418;color:#8a8a92;border:1px solid #2a2a32;border-radius:8px;padding:14px 20px;font-size:13px;font-family:Oswald,sans-serif;letter-spacing:.1em;cursor:pointer'>Clear</button>"
                    "</div>"
                    "</div>"
                    "<script>"
                    "var VALID_KEYS=['freellmapi','relay_groq','relay_gemini','relay_openrouter','relay_nvidia','groq','google','openrouter','nvidia','cloudflare','cohere','huggingface','mistral','siliconflow','zhipu','aihorde','kilo','ovh','pollinations'];"
                    "function parseBulk(){"
                    "var lines=document.getElementById('bulk').value.split('\\n');"
                    "var found=[],unknown=[];"
                    "lines.forEach(function(l){"
                    "var i=l.indexOf(':');if(i<0)return;"
                    "var k=l.slice(0,i).trim().toLowerCase();var v=l.slice(i+1).trim();"
                    "if(!k||!v)return;"
                    "if(VALID_KEYS.indexOf(k)>=0){found.push(k);}else{unknown.push(k);}"
                    "});"
                    "return{found:found,unknown:unknown};"
                    "}"
                    "function previewKeys(){"
                    "var p=parseBulk();var el=document.getElementById('bulk-preview');"
                    "var h='';"
                    "if(p.found.length>0){h+='<div style=\"color:#FFD500;margin-bottom:6px\">Will fill: <b>'+p.found.join(', ')+'</b> ('+p.found.length+')</div>';}"
                    "if(p.unknown.length>0){h+='<div style=\"color:#ef4444\">Unknown names (skipped): <b>'+p.unknown.join(', ')+'</b></div>';}"
                    "if(p.found.length==0&&p.unknown.length==0&&document.getElementById('bulk').value.trim()){h='<div style=\"color:#9aa3b2\">Type lines as <code>name: key</code>...</div>';}"
                    "el.innerHTML=h;"
                    "}"
                    "function fillKeys(){"
                    "var lines=document.getElementById('bulk').value.split('\\n');"
                    "var n=0;var skipped=[];"
                    "lines.forEach(function(l){"
                    "var i=l.indexOf(':');if(i<0)return;"
                    "var k=l.slice(0,i).trim().toLowerCase();var v=l.slice(i+1).trim();"
                    "if(!k||!v)return;"
                    "var el=document.querySelector('input[name=\"k_'+k+'\"]');"
                    "if(el){el.value=v;el.style.border='2px solid #FFD500';el.style.background='#0f1f0f';n++;setTimeout(function(){el.style.border='';el.style.background='';},3000);}"
                    "else{skipped.push(k);}"
                    "});"
                    "var msg=document.getElementById('bulk-preview');"
                    "if(n>0){msg.innerHTML='<div style=\"background:#0f2f0f;border:1px solid #FFD500;border-radius:8px;padding:12px;color:#FFD500\"><b>'+n+' keys filled!</b> Fields are highlighted in green below. Scroll down to review.</div>';}"
                    "else{msg.innerHTML='<div style=\"background:#2f0f0f;border:1px solid #ef4444;border-radius:8px;padding:12px;color:#ef4444\">No valid keys found. Check the format: <code>name: key</code></div>';}"
                    "if(skipped.length>0){msg.innerHTML+='<div style=\"color:#f59e0b;margin-top:8px;font-size:13px\">Skipped unknown: '+skipped.join(', ')+'</div>';}"
                    "}"
                    "</script></div></div>"
                    "<form method='POST' action='/setup'>"
                    "<div class='sec' id='sec-m'><div class='card'>"
                    "<h3>Manual entry</h3><p class='hint'>Expand a section and fill in what you have</p>" +
                    relay_section + freellmapi_section +
                    "</div></div>"
                    "<div class='sec' id='sec-c'><div class='card'>"
                    "<h3>Custom providers</h3><p class='hint'>Add providers not in the list</p>"
                    "<details>"
                    "<summary style='color:#FFD500'>Via Relay</summary><div class='dbody'>"
                    "<p class='hint'>Your own endpoint + key, routed through the built-in relay</p>"
                    "<div id='custom-relay-list'></div>"
                    "<button type='button' onclick='addCustomRelay()' style='background:#141418;color:#FFD500;border:1px solid rgba(255,213,0,.35);border-radius:8px;padding:10px 20px;font-size:13px;font-family:Oswald,sans-serif;letter-spacing:.1em;cursor:pointer;margin-top:8px'>+ Add Provider</button>"
                    "</div></details>"
                    "<details>"
                    "<summary style='color:#FFD500'>Via FreeLLMAPI</summary><div class='dbody'>"
                    "<p class='hint'>Routed through your FreeLLMAPI gateway</p>"
                    "<div id='custom-fl-list'></div>"
                    "<button type='button' onclick='addCustomFL()' style='background:#141418;color:#FFD500;border:1px solid rgba(255,213,0,.35);border-radius:8px;padding:10px 20px;font-size:13px;font-family:Oswald,sans-serif;letter-spacing:.1em;cursor:pointer;margin-top:8px'>+ Add Provider</button>"
                    "</div></details>"
                    "<script>"
                    "var crCount=0;var cfCount=0;"
                    "function addCustomRelay(){"
                    "crCount++;"
                    "var d=document.createElement('div');"
                    "d.style.cssText='background:#0a0c11;border:1px solid #1e2430;border-radius:8px;padding:12px;margin-bottom:10px';"
                    "d.innerHTML='<label>Provider name (lowercase, no spaces)<input type=\"text\" name=\"cr_name_'+crCount+'\" placeholder=\"myprovider\" pattern=\"[a-z0-9_]+\"></label>'"
                    "+'<label>API endpoint (base URL)<input type=\"text\" name=\"cr_url_'+crCount+'\" placeholder=\"https://api.example.com/v1\"></label>'"
                    "+'<label>API key<input type=\"password\" name=\"cr_key_'+crCount+'\" autocomplete=\"off\"></label>'"
                    "+'<button type=\"button\" onclick=\"this.parentElement.remove()\" style=\"background:none;color:#ef4444;border:0;cursor:pointer;font-size:13px;padding:4px\">Remove</button>';"
                    "document.getElementById('custom-relay-list').appendChild(d);"
                    "}"
                    "function addCustomFL(){"
                    "cfCount++;"
                    "var d=document.createElement('div');"
                    "d.style.cssText='background:#0a0c11;border:1px solid #1e2430;border-radius:8px;padding:12px;margin-bottom:10px';"
                    "d.innerHTML='<label>Provider name (lowercase, no spaces)<input type=\"text\" name=\"cf_name_'+cfCount+'\" placeholder=\"myprovider\" pattern=\"[a-z0-9_]+\"></label>'"
                    "+'<label>API key<input type=\"password\" name=\"cf_key_'+cfCount+'\" autocomplete=\"off\"></label>'"
                    "+'<button type=\"button\" onclick=\"this.parentElement.remove()\" style=\"background:none;color:#ef4444;border:0;cursor:pointer;font-size:13px;padding:4px\">Remove</button>';"
                    "document.getElementById('custom-fl-list').appendChild(d);"
                    "}"
                    "</script></div></div>"
                    "<div class='card'><h3>Secure your keys</h3>"
                    "<p class='hint'>This password encrypts everything and unlocks your dashboard</p>"
                    "<label>Password (min 8 chars)<input type='password' name='password' required minlength='8' id='pw1'></label>"
                    "<label>Confirm password<input type='password' name='confirm' required id='pw2'></label>"
                    "<div id='pwm' style='font-size:13px;margin-top:6px'></div>"
                    "<script>"
                    "document.getElementById('pw2').addEventListener('input',function(){"
                    "var a=document.getElementById('pw1').value,b=this.value;"
                    "document.getElementById('pwm').innerHTML=a===b&&a.length>=8?'<span style=\"color:#FFD500\">✓ Match</span>':'<span style=\"color:#ef4444\">Must match (8+ chars)</span>';"
                    "if(a===b&&a.length>=8)document.getElementById('st3').className='st on';});"
                    "</script>"
                    "<button type='submit'>Encrypt and Finish Setup</button>"
                    "</form>"
                    "<p style='text-align:center;margin-top:20px;color:#9aa3b2'>Already have keys set up? <a href='/login' style='color:#FFD500'>Log in →</a></p>"
                    "</div></body></html>")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
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
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
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
                rows += f"<label>{n} <span style='color:#FFD500;font-size:12px'>({masked(n)})</span><input type='password' name='k_{n}' autocomplete='off' placeholder='Leave blank to keep current'></label>"
            page = ("<!DOCTYPE html><html><head><meta charset='utf-8'>"
                    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                    "<title>Nexus Local - Update Keys</title><style>@import url('https://fonts.googleapis.com/css2?family=Bebas+Neue&family=Oswald:wght@400;500;600&display=swap');"
                    "*{box-sizing:border-box}"
                    "body{background-color:#050507;background-image:radial-gradient(ellipse 90% 45% at 50% -5%, rgba(255,213,0,.07), transparent 70%);color:#e6e9f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;margin:0;padding:0}"
                    ".wrap{max-width:600px;margin:0 auto;padding:20px 16px 40px}"
                    ".hero{text-align:center;padding:24px 0 16px}"
                    ".eyebrow{font-family:'Bebas Neue',sans-serif;letter-spacing:.32em;font-size:15px;color:#FFD500;margin-bottom:10px}"
                    "h1{font-family:'Bebas Neue',sans-serif;font-size:32px;margin:0 0 8px;color:#fff;letter-spacing:.08em}"
                    ".sub{color:#9aa3b2;font-size:14px;margin:0}"
                    ".card{background:#101014;border:1px solid rgba(255,213,0,.14);border-radius:12px;padding:20px;margin-bottom:14px;margin-top:20px;box-shadow:0 12px 32px rgba(0,0,0,.5),inset 0 1px 0 rgba(255,255,255,.05)}"
                    "label{display:block;margin:10px 0 4px;color:#9aa3b2;font-size:13px}"
                    "input{width:100%;background:#0a0a0d;border:1px solid #26262c;border-radius:8px;color:#e8e8ea;padding:11px 13px;font-size:14px}"
                    "input:focus{outline:none;border-color:#FFD500;box-shadow:0 0 0 3px rgba(255,213,0,.15)}"
                    "button[type='submit']{font-family:Oswald,sans-serif;font-weight:600;font-size:14px;letter-spacing:.22em;text-transform:uppercase;background:linear-gradient(#FFE45C,#F5B800);color:#0a0a0a;border:1px solid #0a0a0a;border-radius:8px;box-shadow:0 0 28px rgba(255,213,0,.28),inset 0 1px 0 rgba(255,255,255,.5);padding:16px;width:100%;margin-top:16px;cursor:pointer}"
                    "button[type='submit']:hover{filter:brightness(1.12)}"
                    ".key-hint{color:#FFD500;font-size:11px;font-weight:600}"
                    ".back{text-align:center;margin-top:16px}"
                    ".back a{color:#FFD500;text-decoration:none;font-size:14px}"
                    "@keyframes fadeUp{from{opacity:0;transform:translateY(18px)}to{opacity:1;transform:none}}""@keyframes grainShift{0%,100%{transform:translate(0,0)}12%{transform:translate(-3%,-5%)}25%{transform:translate(-8%,3%)}37%{transform:translate(4%,-8%)}50%{transform:translate(-3%,8%)}62%{transform:translate(-8%,3%)}75%{transform:translate(6%,0)}87%{transform:translate(0,6%)}}""@keyframes batDrift{0%,100%{transform:translateY(-50%) translateX(0)}50%{transform:translateY(-60%) translateX(-26px)}}""@keyframes tabGlow{0%,100%{box-shadow:0 0 14px rgba(255,213,0,.10)}50%{box-shadow:0 0 26px rgba(255,213,0,.28)}}""body::before{content:\"\";position:fixed;inset:0;z-index:2000;pointer-events:none;background:radial-gradient(ellipse at center,transparent 52%,rgba(0,0,0,.62) 100%)}""body::after{content:\"\";position:fixed;inset:-120px;z-index:2001;pointer-events:none;opacity:.05;background-image:url(\"data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A//www.w3.org/2000/svg%27%20width%3D%27140%27%20height%3D%27140%27%3E%3Cfilter%20id%3D%27n%27%3E%3CfeTurbulence%20type%3D%27fractalNoise%27%20baseFrequency%3D%270.85%27%20numOctaves%3D%272%27/%3E%3C/filter%3E%3Crect%20width%3D%27140%27%20height%3D%27140%27%20filter%3D%27url%28%23n%29%27%20opacity%3D%270.55%27/%3E%3C/svg%3E\");animation:grainShift 7s steps(8) infinite}"".hero{position:relative;overflow:hidden;animation:fadeUp .7s cubic-bezier(.2,.7,.3,1) both}"".hero::after{content:\"\";position:absolute;right:-34px;top:50%;width:280px;height:101px;background:url(\"data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A//www.w3.org/2000/svg%27%20viewBox%3D%270%200%20100%2036%27%3E%3Cpath%20d%3D%27M0%2C14%20L24%2C3%20L39%2C9%20L44%2C1%20L46.5%2C7%20L50%2C5%20L53.5%2C7%20L56%2C1%20L61%2C9%20L76%2C3%20L100%2C14%20L90%2C20%20L83%2C16%20L75%2C24%20L67%2C18%20L59%2C28%20L54%2C22%20L50%2C30%20L46%2C22%20L41%2C28%20L33%2C18%20L25%2C24%20L17%2C16%20L10%2C20%20Z%27%20fill%3D%27%23FFD500%27/%3E%3C/svg%3E\") no-repeat center/contain;opacity:.07;pointer-events:none;animation:batDrift 11s ease-in-out infinite}"".steps{animation:fadeUp .7s .08s cubic-bezier(.2,.7,.3,1) both}"".tabs{animation:fadeUp .7s .14s cubic-bezier(.2,.7,.3,1) both}"".tab.sel{animation:tabGlow 2.6s ease-in-out infinite}"".sec.on .card{animation:fadeUp .5s cubic-bezier(.2,.7,.3,1) both}"
                    "</style></head><body>" + sidebar + "<div class='wrap'>"
                    "<div class='hero'><div class='eyebrow'>NEXUS LOCAL</div>"
                    "<h1>Update Keys</h1>"
                    "<p class='sub'>Only fill in the keys you want to change</p></div>"
                    "<div class='card'>"
                    "<form method='POST' action='/settings'>" + rows +
                    "<label>Confirm Password<input type='password' name='password' required></label>"
                    "<button type='submit'>Save Changes</button>"
                    "</form></div>"
                    "<p class='back'><a href='/'>← Back to Dashboard</a></p>"
                    "</div></body></html>")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
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
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
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
                    self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
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
                # Add custom providers
                for k in (Handler.keys or {}).keys():
                    if k.startswith("custom_relay_") and not k.endswith("_url"):
                        cname = k[len("custom_relay_"):]
                        quotas["providers"].append({
                            "provider": k,
                            "display_name": f"Relay: {cname.title()} (Custom)",
                            "reset": "",
                            "history": {"requests": [0] * 7, "tokens": [0] * 7},
                            "limits": {},
                            "key_configured": True,
                            "daily_usage": {"requests": 0, "tokens": 0},
                            "monthly_usage": {"requests": 0, "tokens": 0},
                        })
                    elif k.startswith("custom_fl_"):
                        cname = k[len("custom_fl_"):]
                        quotas["providers"].append({
                            "provider": k,
                            "display_name": f"FreeLLMAPI: {cname.title()} (Custom)",
                            "reset": "",
                            "history": {"requests": [0] * 7, "tokens": [0] * 7},
                            "limits": {},
                            "key_configured": True,
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
        if parsed.path == "/api/routing":
            if not self._get_session():
                self.send_response(401)
                self.end_headers()
                return
            qs = parse_qs(parsed.query)
            if qs.get("set", [""])[0] in ("quality", "save", "auto"):
                # Persist routing mode in keys.enc
                try:
                    keys = dict(Handler.keys or {})
                    keys["_routing_mode"] = qs["set"][0]
                    from pathlib import Path as _P
                    enc_path = _P(__file__).parent / "keys.enc"
                    # Need password - get from session or use stored
                    # For now, store in memory only (persist on next /update-keys)
                    Handler.keys = keys
                except Exception:
                    pass
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self._send_body(json.dumps({
                "routing": (Handler.keys or {}).get("_routing_mode", "quality")
            }).encode())
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
                keys = Handler.keys or {}
                if provider in ("google", "relay_gemini"):
                    # Google's OpenAI-compat endpoint has no /models; use the
                    # native API with ?key= instead.
                    gkey = keys.get("google") or keys.get("relay_gemini") or ""
                    url = ("https://generativelanguage.googleapis.com/v1beta/models?key="
                           + _urlquote(gkey, safe="")) if gkey else ""
                elif provider in RELAY_UPSTREAMS:
                    # Route through the integrated relay; it attaches the
                    # user's key and proxies to the upstream.
                    url = f"http://127.0.0.1:8099/{provider}/v1/models"
                elif provider == "freellmapi":
                    gw_url = (keys.get("freellmapi_url") or "").strip()
                    url = (gw_url.rstrip("/") if gw_url else "http://127.0.0.1:3001") + "/v1/models"
                else:
                    # Direct providers - try engine
                    url = "http://127.0.0.1:3001/v1/models"
                if not url:
                    raise ValueError("no key configured")
                # No auth header needed: the relay strips it and attaches the
                # real key; native endpoints use ?key= above.
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = js.loads(resp.read())
                    if isinstance(data, list):
                        # e.g. AI Horde: [{"name": "...", ...}]
                        models = [m.get("name", "") for m in data if isinstance(m, dict) and m.get("name")]
                    elif "models" in data and isinstance(data["models"], list):
                        # e.g. Google native: {"models": [{"name": "models/xxx"}]}
                        models = [str(m.get("name", "")).replace("models/", "")
                                  for m in data["models"] if isinstance(m, dict) and m.get("name")]
                    else:
                        # OpenAI format: {"data": [{"id": "..."}]}
                        models = [m.get("id", "") for m in data.get("data", []) if isinstance(m, dict) and m.get("id")]
                    # SiliconFlow: free credits exhausted (one-time $1, no reset).
                    # Hide models until credits are added.
                    if provider == "siliconflow":
                        models = []
                    # Rudra's rule: only free/freemium models. Only OpenRouter has
                    # paid models — its free lane is the :free suffix. Every
                    # other provider's key is already a free/freemium tier,
                    # so their full rosters stay.
                    elif provider in ("openrouter", "relay_openrouter"):
                        models = [m for m in models if m.endswith(":free")]
                    # Exclude non-chat models (embedding, TTS, image gen,
                    # transcription) — they fail on /chat/completions.
                    _NON_CHAT = ("embed", "tts", "transcribe", "-image", "_image",
                                 "text-to-image", "image-gen", "speech", "voxtral")
                    models = [m for m in models
                              if not any(k in m.lower() for k in _NON_CHAT)]
            except Exception as e:
                pass
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self._send_body(js.dumps({"models": models}).encode())
            return
        self.send_error(404, "Not Found")

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/setup":
            key_path = Path(__file__).parent / "keys.enc"
            keys_exist = key_path.exists()
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
            # Custom relay providers: cr_name_N, cr_url_N, cr_key_N
            import re
            for fk in list(form.keys()):
                m = re.match(r"^cr_name_(\d+)$", fk)
                if m:
                    idx = m.group(1)
                    name = form.get(fk, [""])[0].strip().lower()
                    url = form.get(f"cr_url_{idx}", [""])[0].strip()
                    key = form.get(f"cr_key_{idx}", [""])[0].strip()
                    if name and url and key and re.match(r"^[a-z0-9_]+$", name):
                        if not (url.startswith("http://") or url.startswith("https://")):
                            continue
                        keys[f"custom_relay_{name}"] = key
                        keys[f"custom_relay_{name}_url"] = url
            # Custom FreeLLMAPI providers: cf_name_N, cf_key_N
            for fk in list(form.keys()):
                m = re.match(r"^cf_name_(\d+)$", fk)
                if m:
                    idx = m.group(1)
                    name = form.get(fk, [""])[0].strip().lower()
                    key = form.get(f"cf_key_{idx}", [""])[0].strip()
                    if name and key and re.match(r"^[a-z0-9_]+$", name):
                        keys[f"custom_fl_{name}"] = key
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
            register_custom_providers(keys)
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
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
            mode = data.get("mode", "text")  # text, code, search, auto
            image = data.get("image")  # base64 data URI, optional
            file_data = data.get("file")  # {name, text/data, type}, optional
            link = data.get("link")  # URL string, optional
            # Mode-specific message preprocessing
            if mode == "auto":
                # Auto-detect: code keywords -> code mode, question words -> search, else text
                ml = (message or "").lower()
                code_kw = ["code", "function", "class", "def ", "import ", "debug", "python",
                           "javascript", "java ", " bug", "error", "script", "algorithm"]
                search_kw = ["who is", "what is", "when did", "where is", "latest", "current",
                             "news", "today", "2024", "2025", "2026", "price of", "who won"]
                if any(k in ml for k in code_kw):
                    mode = "code"
                elif any(k in ml for k in search_kw):
                    mode = "search"
                else:
                    mode = "text"
            if mode == "code":
                message = ("You are an expert coding assistant. Provide clean, working code with brief explanations. "
                          "Use markdown code blocks with language tags.\n\n" + (message or ""))
            elif mode == "image":
                # Image generation via Pollinations (free, no key)
                # Return the image URL directly - frontend will display it
                try:
                    import urllib.parse as _up2
                    prompt = _up2.quote_plus((message or "")[:500])
                    img_url = f"https://image.pollinations.ai/prompt/{prompt}?width=1024&height=1024&nologo=true"
                    self._set_json_headers(200)
                    self.wfile.write(json.dumps({
                        "reply": f"![Generated image]({img_url})",
                        "image_url": img_url
                    }).encode())
                except Exception as e:
                    self._set_json_headers(500)
                    self.wfile.write(json.dumps({"error": f"image gen failed: {str(e)[:100]}"}).encode())
                return
            elif mode == "search":
                # Web search mode: use Wikipedia API (reliable, free, no key)
                # plus DuckDuckGo as fallback
                try:
                    import urllib.parse as _up
                    # Try Wikipedia first for factual queries
                    # Extract likely topic (first few words)
                    topic = (message or "").strip().split("?")[0][:50]
                    # Remove question words
                    for qw in ["what is", "what are", "who is", "who was", "where is", "when did", "how does"]:
                        if topic.lower().startswith(qw):
                            topic = topic[len(qw):].strip()
                            break
                    if topic:
                        wq = _up.quote_plus(topic)
                        wreq = urllib.request.Request(
                            f"https://en.wikipedia.org/api/rest_v1/page/summary/{wq}",
                            headers={"User-Agent": "NexusLocal/1.0"})
                        with urllib.request.urlopen(wreq, timeout=10) as wresp:
                            wdata = json.loads(wresp.read().decode())
                            extract = wdata.get("extract", "")
                            if extract:
                                message = (f"Reference information:\n{extract[:800]}\n\n"
                                         f"Question: {message}\nAnswer using the reference above.")
                except Exception:
                    pass  # search failed, continue with plain message
            # Prepend file text content to message
            if file_data and file_data.get("text"):
                message = f"[Attached file: {file_data.get('name', 'file')}]\n{file_data['text'][:8000]}\n\n{message}"
            if link:
                message = f"[Attached link: {link}]\n{message}"
            # Routing mode: quality | save | auto (stored in keys dict)
            routing = (Handler.keys or {}).get("_routing_mode", "quality")
            # Default models for auto-selection (known working)
            _DEFAULT_MODELS = {
                "groq": "openai/gpt-oss-20b",
                "relay_groq": "openai/gpt-oss-20b",
                "google": "gemini-3.8-flash",
                "relay_gemini": "gemini-3.8-flash",
                "openrouter": "apodex/apodex-1.1-mini:free",
                "relay_openrouter": "apodex/apodex-1.1-mini:free",
                "nvidia": "google/gemma-3-12b-it",
                "relay_nvidia": "google/gemma-3-12b-it",
                "mistral": "mistral-small-latest",
                "cohere": "command-a-03-2025",
                "zhipu": "glm-4.5",
                "ovh": "Meta-Llama-3.3-70B-Instruct",
                "pollinations": "openai",
                "relay_pollinations": "openai",
            }
            # Auto provider selection when provider is "auto"
            # Returns a LIST of (provider, model) to try in order (fallback)
            _auto_candidates = []
            if provider == "auto":
                if routing == "save":
                    pref_list = ["groq", "relay_groq", "pollinations", "relay_pollinations",
                                 "openrouter", "relay_openrouter"]
                elif routing == "auto":
                    ml = (message or "").lower()
                    if mode == "code" or any(k in ml for k in
                            ["code", "function", "class", "debug", "python", "javascript", "bug"]):
                        routing_eff = "quality"
                    else:
                        routing_eff = "save"
                    routing = routing_eff
                    pref_list = (["relay_gemini", "google", "relay_openrouter", "openrouter",
                                  "relay_nvidia", "nvidia", "mistral", "cohere"]
                                 if routing_eff == "quality" else
                                 ["groq", "relay_groq", "pollinations", "relay_pollinations"])
                else:  # quality
                    # Prefer reliable providers first (Google often 503s, nvidia 403s on all chat)
                    pref_list = ["relay_openrouter", "openrouter",
                                 "mistral",
                                 "relay_gemini", "google", "cohere"]
                for cand in pref_list:
                    if (Handler.keys or {}).get(cand) or cand in RELAY_KEYLESS:
                        cand_model = model or _DEFAULT_MODELS.get(cand, "")
                        if cand_model:
                            _auto_candidates.append((cand, cand_model))
                if _auto_candidates:
                    provider, model = _auto_candidates[0]
                # Store remaining for fallback
                _fallback_candidates = _auto_candidates[1:]
            if not provider or not model or not message:
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": "provider, model, message required"}).encode())
                return
            key = Handler.keys.get(provider) if Handler.keys else None
            if not key and provider not in RELAY_KEYLESS:
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": f"no key configured for {provider}"}).encode())
                return
            # Cohere uses its native API (not OpenAI-compatible) — call directly
            if provider == "cohere":
                try:
                    cohere_body = {"model": model, "message": message}
                    if image:
                        # Cohere chat doesn't support images in this simple path
                        pass
                    req = Request("https://api.cohere.com/v1/chat",
                                  data=json.dumps(cohere_body).encode(),
                                  headers={"Content-Type": "application/json",
                                           "Authorization": f"Bearer {key}"},
                                  method="POST")
                    with urlopen(req, timeout=60) as resp:
                        resp_data = json.loads(resp.read().decode())
                        reply = resp_data.get("text", "")
                        self._set_json_headers(200)
                        self.wfile.write(json.dumps({"reply": reply}).encode())
                except HTTPError as e:
                    body_err = e.read().decode()[:200]
                    self._set_json_headers(e.code)
                    self.wfile.write(json.dumps({"error": f"provider {e.code}: {body_err}"}).encode())
                except URLError as e:
                    self._set_json_headers(500)
                    self.wfile.write(json.dumps({"error": f"network error: {str(e)[:100]}"}).encode())
                return
            # All providers route through the relay (RELAY_UPSTREAMS) or freellmapi gateway
            if provider.startswith("relay_") or provider in RELAY_UPSTREAMS:
                # Relay providers (including individual keys) - route through localhost:8099
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
            elif provider.startswith("custom_fl_"):
                # Custom FreeLLMAPI provider - routes through the FreeLLMAPI gateway
                gw_url = ((Handler.keys or {}).get("freellmapi_url") or "").strip()
                if not gw_url:
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "Set your gateway URL in setup"}).encode())
                    return
                base = gw_url.rstrip("/")
                if not key:
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": f"no key configured for {provider}"}).encode())
                    return
            elif provider.startswith("custom_relay_"):
                # Custom relay provider - routes through the relay
                cname = provider[len("custom_relay_"):]
                base = f"http://127.0.0.1:{RELAY_PORT}/{cname}/v1"
                if not key:
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": f"no key configured for {provider}"}).encode())
                    return
            else:
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": f"chat not supported for {provider} in local version"}).encode())
                return
            headers = {
                "Content-Type": "application/json",
            }
            # For relay providers, the integrated relay attaches the key
            # For freellmapi and custom_fl, attach the key here
            if provider == "freellmapi" or provider.startswith("custom_fl_"):
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
                    self.wfile.write(json.dumps({"reply": reply, "used_provider": provider, "used_model": model}).encode())
            except HTTPError as e:
                body_err = e.read().decode()[:200]
                # User-friendly messages for common errors
                if e.code == 503:
                    msg = "Provider is temporarily overloaded. Try again in a moment."
                elif e.code == 429:
                    msg = "Rate limit hit. Try again in a moment."
                elif e.code == 402:
                    msg = "This model requires payment. Try a different model."
                else:
                    # Try to extract clean message from JSON
                    try:
                        ej = json.loads(body_err)
                        msg = ej.get("error", {}).get("message", body_err[:100]) if isinstance(ej.get("error"), dict) else str(ej.get("error", body_err[:100]))
                    except:
                        msg = body_err[:100]
                self._set_json_headers(e.code)
                self.wfile.write(json.dumps({"error": msg}).encode())
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
            # Live connectivity check: quick models ping for each configured provider
            import concurrent.futures
            def _ping(name):
                try:
                    if name.startswith("relay_"):
                        base = f"http://127.0.0.1:{RELAY_PORT}/{name}/v1"
                    elif name in ("pollinations", "aihorde", "kilo", "ovh"):
                        return (name, True)  # keyless, assume up
                    else:
                        return (name, bool((Handler.keys or {}).get(name)))
                    req = Request(base + "/models", headers={"User-Agent": "Mozilla/5.0"})
                    with urlopen(req, timeout=8) as r:
                        return (name, r.status == 200)
                except Exception:
                    return (name, False)
            names = [n for n in PROVIDER_NAMES if (Handler.keys or {}).get(n) or n in RELAY_KEYLESS or n.startswith("relay_")]
            status = {}
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
                for name, ok in ex.map(_ping, names):
                    status[name] = ok
            # Persist to a status file the quotas endpoint can read
            try:
                with open(Path(__file__).parent / "provider_status.json", "w") as f:
                    json.dump({"checked_at": datetime.datetime.now().isoformat(), "status": status}, f)
            except Exception:
                pass
            self._set_json_headers()
            self.wfile.write(json.dumps({"ok": True, "status": status,
                "refreshed_at": datetime.datetime.now().isoformat()}).encode())
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
            register_custom_providers(dec_keys)
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
