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
import sys
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
from key_security import encrypt_keys, decrypt_keys, encrypt_raw, decrypt_raw

USAGE_PATH = Path(__file__).parent / "usage.jsonl"
SESSIONS = {}
_login_attempts = {}
# Per-session API rate limits: (bucket, session token) -> [timestamps].
# Stops a single session (friend or hijacked) from burning provider quota.
_RL = {}

def _rl_ok(bucket, token, limit, window=60):
    now = time.time()
    key = (bucket, token or "?")
    hits = [t for t in _RL.get(key, []) if now - t < window]
    if len(hits) >= limit:
        _RL[key] = hits
        return False
    hits.append(now)
    _RL[key] = hits
    if len(_RL) > 5000:
        _RL.clear()
    return True

# Provider health (circuit breaker): provider -> {"fails": int, "down_until": float}
_PROVIDER_HEALTH = {}

def _provider_down(p):
    h = _PROVIDER_HEALTH.get(p)
    return bool(h) and h.get("down_until", 0) > time.time()

def _note_failure(p):
    h = _PROVIDER_HEALTH.setdefault(p, {"fails": 0, "down_until": 0.0})
    h["fails"] = h.get("fails", 0) + 1
    if h["fails"] >= 2:
        h["down_until"] = time.time() + 180  # skip for 3 min after 2 straight failures

def _note_success(p):
    _PROVIDER_HEALTH.pop(p, None)

SESSION_EXPIRY = int(os.environ.get("NEXUS_SESSION_EXPIRY", "1800"))
def _model_caps(provider, model):
    """Capability tags for a model: chat, image, tts, stt, video, embedding, utility.
    Every model is used for what it's good at — the UI filters per mode."""
    m = (model or "").lower()
    if provider == "aihorde":
        return ["image"]  # AI Horde serves image models
    if "whisper" in m:
        return ["stt"]
    if any(k in m for k in ("orpheus", "text-to-speech", "/tts", "-tts")):
        return ["tts"]
    if any(k in m for k in ("stable-diffusion", "sdxl", "flux", "dall-e", "imagen",
                            "text-to-image", "image-gen", "dreamshaper", "juggernaut")) \
            or "-image" in m or "_image" in m:
        return ["image"]
    if any(k in m for k in ("ltx", "cogvideo", "animatediff", "stable-video", "text-to-video")):
        return ["video"]
    if any(k in m for k in ("embed", "bge-", "bge_", "/e5-", "gte-")):
        return ["embedding"]
    if any(k in m for k in ("ocr", "moderation", "prompt-guard", "llama-guard",
                            "transcribe", "distilbert", "smart-turn")):
        return ["utility"]
    return ["chat"]
ACCESS_PATH = Path(__file__).parent / "access.json"
USERS_PATH = Path(__file__).parent / "users.enc"
ACCESS_ENC_PATH = Path(__file__).parent / "access.enc"
# Server-held restore key (env var on the host, NEVER in the repo). It can
# decrypt ONLY the friend access list (password hashes) so the list — and
# friend logins — survive restarts without waiting for an admin login.
# Provider keys still require the master password; this key unlocks nothing
# else on its own.
RESTORE_KEY = os.environ.get("NEXUS_RESTORE_KEY", "")
# The one locked-state message: returned ONLY for operations that genuinely
# need the owner's decrypted provider keys while no admin has logged in yet
# since the last restart. Authentication, sessions, saved chats, personal
# key vaults, keyless providers and a friend's own (BYOK) keys must NEVER
# produce this — they do not depend on the owner's key.
LOCKED_ERROR = "server is locked — the admin needs to log in once after a restart"
# Per-user key vaults: app/userkeys/<label>.enc, encrypted with the user's own password
USERKEYS_DIR = Path(__file__).parent / "userkeys"
USERKEYS_DIR.mkdir(exist_ok=True)

import re as _re
_LABEL_RE = _re.compile(r"^[a-zA-Z0-9_]{1,30}$")

def _userkey_path(label):
    # Vault filename is the lowercased label with anything unsafe stripped,
    # so a label can never traverse out of USERKEYS_DIR.
    safe = _re.sub(r"[^a-z0-9_]", "", (label or "").lower())[:30]
    return USERKEYS_DIR / f"{safe}.enc"

def _load_userkeys(label, password):
    """Decrypt a friend's personal key vault. Returns dict or None."""
    try:
        p = _userkey_path(label)
        if not p.exists():
            return None
        d = decrypt_keys(p, password)
        return d if isinstance(d, dict) else None
    except Exception:
        return None

def _save_userkeys(label, keys_dict, password):
    p = _userkey_path(label)
    encrypt_keys(keys_dict, password, p)
    os.chmod(p, 0o600)

# Per-user saved chats: app/chats/<label>.enc, encrypted with the user's own
# login password (master password for the admin). Synced to GitHub through
# /api/friend_blob like users.enc and the key vaults, so chats survive
# redeploys. Format: {"chats": [{id, title, ts, updated, messages:[{r,t,m?}]}]}
CHATS_DIR = Path(__file__).parent / "chats"
CHATS_DIR.mkdir(exist_ok=True)

def _chat_path(label):
    safe = _re.sub(r"[^a-z0-9_]", "", (label or "").lower())[:30]
    return CHATS_DIR / f"{safe}.enc"

def _load_chats(label, password):
    try:
        p = _chat_path(label)
        if not p.exists():
            return {"chats": []}
        d = decrypt_keys(p, password)
        if isinstance(d, dict) and isinstance(d.get("chats"), list):
            return d
    except Exception:
        pass
    return {"chats": []}

def _save_chats(label, data, password):
    p = _chat_path(label)
    encrypt_keys(data, password, p)
    os.chmod(p, 0o600)

# ---- Admin saved chats: wrapped-DEK envelope (v2) ----
# The admin's chats are NOT encrypted directly with the master password.
# A random 256-bit data-encryption key (DEK) encrypts the chat data
# (AES-256-GCM, fresh nonce per save); the DEK is stored in the file only
# wrapped under a key-encryption key (KEK) derived from the master password
# (PBKDF2-HMAC-SHA256, 600k, dedicated salt + domain separation). At the
# login password step — the only moment the password exists server-side —
# the DEK is unwrapped into _CHAT_UNLOCKS (memory only). Sessions hold
# only an opaque unlock handle bound to their token; the master password,
# KEK and DEK are never stored in a session, transmitted, or logged.
_CHAT_V2_AAD_WRAP = b"nexus-admin-chats-v2:wrap"
_CHAT_V2_AAD_DATA = b"nexus-admin-chats-v2:data"
_CHAT_KEK_CONTEXT = "NexusLocal-admin-chats-v2\x00"
_CHAT_UNLOCKS = {}  # unlock_id -> {dek, wrap_*, label, admin, expires, bound_token}

# --- Temporary view passes (owner-approved 2026-10-09) ----------------------
# The admin can mint a short-lived, READ-ONLY link (/view/<token>) so
# someone can look at the pages without an account. Only the SHA-256 of
# the token is kept, grants live in memory only (a restart kills every
# pass), and viewer sessions are fenced to read-only calls in the
# handlers below. The token itself is shown once, at creation.
_VIEW_GRANTS = {}  # sha256(token) hex -> {"name", "created", "expires"}
_VIEWPASS_HOURS = (1, 6, 24)
_VIEWPASS_MAX = 5
_VIEWPASS_NAME_RE = _re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _\-]{0,23}$")


def _view_grant_for(token):
    """The live grant for a raw view token, or None. Expired grants are
    dropped on sight."""
    if not token:
        return None
    h = hashlib.sha256(token.encode()).hexdigest()
    g = _VIEW_GRANTS.get(h)
    if not g:
        return None
    if time.time() > g["expires"]:
        del _VIEW_GRANTS[h]
        return None
    return g


def _sweep_view_grants():
    now = time.time()
    for h in [h for h, g in _VIEW_GRANTS.items() if now > g["expires"]]:
        del _VIEW_GRANTS[h]

def _chat_kek(password, wrap_salt):
    return hashlib.pbkdf2_hmac("sha256", (_CHAT_KEK_CONTEXT + password).encode(),
                               wrap_salt, 600_000, dklen=32)

def _b64e(raw):
    return base64.b64encode(raw).decode()

def _b64d(text):
    return base64.b64decode(text)

def _write_chat_file_atomic(path, envelope):
    tmp = path.parent / (path.name + ".tmp")
    tmp.write_text(json.dumps(envelope), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)

def _new_chat_unlock(dek, wrap_fields, ttl=300):
    unlock_id = secrets.token_hex(32)
    _CHAT_UNLOCKS[unlock_id] = {
        "dek": dek,
        "wrap_salt": wrap_fields["wrap_salt"],
        "wrap_nonce": wrap_fields["wrap_nonce"],
        "wrapped_dek": wrap_fields["wrapped_dek"],
        "label": "Rudra", "admin": True,
        "expires": time.time() + ttl, "bound_token": None,
    }
    return unlock_id

def _drop_chat_unlock(unlock_id):
    if unlock_id:
        _CHAT_UNLOCKS.pop(unlock_id, None)

def _bind_chat_unlock(unlock_id, token):
    rec = _CHAT_UNLOCKS.get(unlock_id) if unlock_id else None
    if rec:
        rec["bound_token"] = token
        rec["expires"] = time.time() + SESSION_EXPIRY

def _save_admin_chats(rec, data):
    nonce, ct = encrypt_raw(rec["dek"], json.dumps(data).encode(), _CHAT_V2_AAD_DATA)
    _write_chat_file_atomic(_chat_path("Rudra"), {
        "v": 2,
        "wrap_salt": rec["wrap_salt"], "wrap_nonce": rec["wrap_nonce"],
        "wrapped_dek": rec["wrapped_dek"],
        "nonce": _b64e(nonce), "ciphertext": _b64e(ct),
    })

def _load_admin_chats_strict(dek):
    """Decrypt the v2 admin chat store. RAISES on any problem — an
    undecryptable store must never be mistaken for an empty one, or a
    later save would silently destroy the history."""
    p = _chat_path("Rudra")
    if not p.exists():
        return {"chats": []}
    env = json.loads(p.read_text(encoding="utf-8"))
    if not isinstance(env, dict) or env.get("v") != 2:
        raise ValueError("admin chat store is not v2")
    raw = decrypt_raw(dek, _b64d(env["nonce"]), _b64d(env["ciphertext"]),
                      _CHAT_V2_AAD_DATA)
    d = json.loads(raw)
    if not isinstance(d, dict) or not isinstance(d.get("chats"), list):
        raise ValueError("admin chat store has unexpected shape")
    return d

def _wrap_new_dek(password):
    """Generate a DEK and its wrap fields under a KEK from `password`."""
    dek = secrets.token_bytes(32)
    wrap_salt = os.urandom(16)
    wnonce, wct = encrypt_raw(_chat_kek(password, wrap_salt), dek, _CHAT_V2_AAD_WRAP)
    return dek, {"wrap_salt": _b64e(wrap_salt), "wrap_nonce": _b64e(wnonce),
                 "wrapped_dek": _b64e(wct)}

def _create_admin_chat_unlock(password):
    """Mint an in-memory chat unlock at the login password step, after the
    caller has PROVEN the master password (keys.enc decrypted). Returns an
    unlock_id, or None when the chat store cannot be opened with this
    password (corrupt or legacy dead-password store) — fail closed, the
    file is left byte-identical. Migrates legacy password-direct stores
    and first-run stores to the v2 wrapped-DEK format."""
    p = _chat_path("Rudra")
    try:
        if p.exists():
            env = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(env, dict) and env.get("v") == 2:
                dek = decrypt_raw(_chat_kek(password, _b64d(env["wrap_salt"])),
                                  _b64d(env["wrap_nonce"]), _b64d(env["wrapped_dek"]),
                                  _CHAT_V2_AAD_WRAP)
                if len(dek) != 32:
                    return None
                _load_admin_chats_strict(dek)  # sanity: data must open too
                return _new_chat_unlock(dek, env)
            # Legacy v1: chats encrypted directly with the master password.
            data = decrypt_keys(p, password)
            if not isinstance(data, dict) or not isinstance(data.get("chats"), list):
                return None
            dek, fields = _wrap_new_dek(password)
            unlock_id = _new_chat_unlock(dek, fields)
            _save_admin_chats(_CHAT_UNLOCKS[unlock_id], data)
            return unlock_id
        dek, fields = _wrap_new_dek(password)
        unlock_id = _new_chat_unlock(dek, fields)
        _save_admin_chats(_CHAT_UNLOCKS[unlock_id], {"chats": []})
        return unlock_id
    except Exception:
        return None

def _load_access():
    try:
        if ACCESS_PATH.exists():
            return json.loads(ACCESS_PATH.read_text())
    except Exception:
        pass
    return {}

def _save_access(d, master_pw=None):
    ACCESS_PATH.write_text(json.dumps(d, indent=2))
    _write_access_enc(d)
    # Persist encrypted backup so it survives redeploys (users.enc is tracked in git)
    if master_pw:
        try:
            encrypt_keys(d, master_pw, USERS_PATH)
            os.chmod(USERS_PATH, 0o600)
        except Exception:
            pass

def _restore_access(master_pw):
    """Restore access.json from encrypted users.enc after a redeploy wiped the disk."""
    try:
        needs = True
        if ACCESS_PATH.exists():
            try:
                existing = json.loads(ACCESS_PATH.read_text())
                needs = not isinstance(existing, dict) or not existing
            except Exception:
                needs = True
        if needs and USERS_PATH.exists():
            d = decrypt_keys(USERS_PATH, master_pw)
            if isinstance(d, dict):
                ACCESS_PATH.write_text(json.dumps(d, indent=2))
                _write_access_enc(d)
    except Exception:
        pass


def _write_access_enc(d):
    """Mirror the access list into access.enc under the server restore key,
    so a fresh instance can rebuild access.json at boot (no admin login
    needed). No-op when the host has no restore key configured."""
    if not RESTORE_KEY or not isinstance(d, dict):
        return
    try:
        encrypt_keys(d, RESTORE_KEY, ACCESS_ENC_PATH)
        os.chmod(ACCESS_ENC_PATH, 0o600)
    except Exception:
        pass


def _boot_restore_access():
    """At startup: rebuild access.json from access.enc (restore key). The
    mirror is the source of truth at boot: access.json is a runtime working
    file, and a stale copy baked into a deploy once shadowed the mirror and
    hid the real friend list behind a leftover test entry (2026-10-09).
    Falls back silently to whatever access.json holds (then the classic
    restore-at-admin-login) when no restore key/file exists."""
    try:
        if RESTORE_KEY and ACCESS_ENC_PATH.exists():
            d = decrypt_keys(ACCESS_ENC_PATH, RESTORE_KEY)
            if isinstance(d, dict) and d:
                ACCESS_PATH.write_text(json.dumps(d, indent=2))
                return
        # No usable mirror: keep an existing valid access.json as-is.
    except Exception:
        pass

# ---- TOTP 2FA (admin only) ----
import hmac as _hmac, struct as _struct, base64 as _base64

_PENDING_2FA = {}  # tmp_token -> {ts, keys}
_2FA_ATTEMPTS = {}  # tmp_token -> [timestamps] (rate limit code guesses)

def _totp_verify(secret_b32, code, window=1):
    try:
        secret = _base64.b32decode(secret_b32.upper())
        code = str(code).strip()
        t = int(time.time()) // 30
        for offset in range(-window, window + 1):
            msg = _struct.pack(">Q", t + offset)
            h = _hmac.new(secret, msg, hashlib.sha1).digest()
            o = h[-1] & 0x0F
            c = _struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF
            if _hmac.compare_digest(str(c % 1000000).zfill(6), code):
                return True
    except Exception:
        pass
    return False

_TOTP_LAST_STEP = {"v": -1}  # highest TOTP step accepted at login (replay guard)

def _totp_match_step(secret_b32, code, window=1):
    """Return the timestep a code matches, or None. Lets the login flow
    reject a code that was already used (replay within its validity window)."""
    try:
        secret = _base64.b32decode(secret_b32.upper())
        code = str(code).strip()
        t = int(time.time()) // 30
        for offset in range(-window, window + 1):
            msg = _struct.pack(">Q", t + offset)
            h = _hmac.new(secret, msg, hashlib.sha1).digest()
            o = h[-1] & 0x0F
            c = _struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF
            if _hmac.compare_digest(str(c % 1000000).zfill(6), code):
                return t + offset
    except Exception:
        pass
    return None

def _totp_secret():
    return _base64.b32encode(secrets.token_bytes(20)).decode()

# ---- Friend password hashing (PBKDF2, salted) ----
_PBKDF2_ITERS = 210000

def _hash_password(password):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _PBKDF2_ITERS)
    return f"pbkdf2${_PBKDF2_ITERS}${salt.hex()}${dk.hex()}"

def _verify_password(password, stored):
    """Returns (ok, needs_upgrade). Upgrades legacy unsalted SHA-256 hashes."""
    try:
        if stored.startswith("pbkdf2$"):
            _, iters, salt_hex, hash_hex = stored.split("$")
            dk = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                     bytes.fromhex(salt_hex), int(iters))
            ok = _hmac.compare_digest(dk.hex(), hash_hex)
            return ok, False
        # Legacy unsalted SHA-256 — verify, then upgrade
        ok = _hmac.compare_digest(hashlib.sha256(password.encode()).hexdigest(), stored)
        return ok, True
    except Exception:
        return False, False

# ---------------------------------------------------------------------------
# Structured server-side logging with secret redaction + usage-log rotation.
# Log lines go to stderr (Render captures them). Request bodies, passwords,
# API keys, session tokens and 2FA codes are NEVER logged: events carry only
# whitelisted metadata, and every value passes through _redact first.

_SECRET_FIELD_RE = _re.compile(
    r"(password|passwd|_pw|pw_|secret|token|api[_-]?key|cookie|authorization|otp|code)",
    _re.IGNORECASE)
_SECRET_VALUE_RE = _re.compile(
    r"(Bearer\s+)[A-Za-z0-9._\-+/=]+|"
    r"\b(?:sk|gsk|ghp|hf|xai)-[A-Za-z0-9_\-]{8,}\b|"
    r"\b[A-Fa-f0-9]{64}\b")


def _redact(value, field=""):
    """Return a log-safe copy of `value`: fields whose name suggests a
    secret are replaced wholesale; secret-shaped substrings inside other
    strings are masked."""
    if _SECRET_FIELD_RE.search(field or ""):
        return "[redacted]"
    if isinstance(value, str):
        return _SECRET_VALUE_RE.sub(
            lambda m: (m.group(1) + "[redacted]") if m.group(1) else "[redacted]",
            value)[:300]
    if isinstance(value, dict):
        return {k: _redact(v, k) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact(v) for v in value[:20]]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return str(type(value).__name__)


def _log_event(level, event, **fields):
    try:
        record = {"ts": time.time(), "level": level, "event": event}
        for k, v in fields.items():
            record[k] = _redact(v, k)
        print(json.dumps(record), file=sys.stderr, flush=True)
    except Exception:
        pass  # logging must never break a request


_USAGE_MAX_BYTES = 2_000_000   # rotate the usage log past ~2 MB
_USAGE_KEEP_LINES = 20_000     # ...keeping the newest 20k entries


def _append_usage(entry):
    """Append one usage record, trimming the log when it grows past the
    cap so it stays bounded forever (usage stats read the newest data;
    the trim keeps far more than the 7-day history window). Never raises:
    a logging failure must not fail the chat that produced the record."""
    try:
        with open(USAGE_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
        if os.path.getsize(USAGE_PATH) > _USAGE_MAX_BYTES:
            with open(USAGE_PATH) as f:
                lines = f.readlines()
            tmp = str(USAGE_PATH) + ".tmp"
            with open(tmp, "w") as f:
                f.writelines(lines[-_USAGE_KEEP_LINES:])
            os.replace(tmp, USAGE_PATH)
    except Exception:
        pass


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
# Load quotas.json at startup (script-relative so it works from any cwd).
# A corrupt quotas file must never stop the server from booting — the
# /api/quotas handler re-reads the file per request and reports a clean
# JSON 500 while it is broken; display data is not worth an outage.
try:
    with open(Path(__file__).parent / "quotas.json", "r") as f:
        QUOTAS_DATA = json.load(f)
except Exception:
    QUOTAS_DATA = {}


# ---------------------------------------------------------------------------
# Integrated relay for the 5 outside providers.
# Serves relay_openrouter, relay_gemini, relay_groq, relay_nvidia,
# relay_pollinations (keyless) on 127.0.0.1:8099 in a daemon thread.
# Also serves individual provider keys (groq, openrouter, etc.) through
# the same relay - user provides their own keys via setup.
# Keys come from Handler.keys (decrypted in-memory, never on disk).
# ---------------------------------------------------------------------------
RELAY_PORT = int(os.environ.get("NEXUS_RELAY_PORT", "8099"))
# Random per-process token: only the main server may call the relay.
# Prevents any other local process from using the decrypted keys via the relay.
RELAY_TOKEN = secrets.token_hex(32)
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
    "kilo": "https://api.kilo.ai/api/gateway",
    "ovh": "https://oai.endpoints.kepler.ai.cloud.ovh.net/v1",
    "google": "https://generativelanguage.googleapis.com/v1beta/openai",
    "cloudflare": "https://api.cloudflare.com/client/v4/accounts",
    "cohere": "https://api.cohere.com/v1",
    "huggingface": "https://router.huggingface.co/v1",
    "aihorde": "https://stablehorde.net/api/v2",
    "pollinations": "https://text.pollinations.ai/openai",
}
# relay_pollinations needs no key
RELAY_KEYLESS = {"relay_pollinations", "aihorde", "pollinations", "kilo", "ovh"}

# ---------------------------------------------------------------------------
# External API (owner order 2026-10-09): an OpenAI-compatible surface so
# Rudra's other project (DSRclone's AI service) can be supplied by Nexus.
# Disabled unless NEXUS_V1_API_KEY is set in the environment. The key is a
# service credential: never stored in the repo and never shown in the UI
# (the admin API page displays status + last 4 only). Requests ride the
# integrated relay lanes with failover; when the shared vault is locked,
# keyed lanes cannot run yet — exactly like the dashboard's own pre-unlock
# behaviour — while keyless lanes keep working.
# ---------------------------------------------------------------------------
_V1_LANES = [
    ("relay_gemini", "gemini-3.5-flash-lite"),
    ("relay_openrouter", "apodex/apodex-1.1-mini:free"),
    ("relay_groq", "openai/gpt-oss-20b"),
    ("relay_nvidia", "google/gemma-3-12b-it"),
    ("relay_pollinations", "openai"),
]
_V1_MODELS_CACHE = {"at": 0.0, "ids": []}


def _v1_api_key():
    return os.environ.get("NEXUS_V1_API_KEY", "")


def _v1_lane_key(lane):
    keys = getattr(Handler, "keys", None)
    if isinstance(keys, dict):
        return keys.get(lane) or ""
    return ""


def _v1_relay_call(lane, path, payload=None, timeout=90):
    """One integrated-relay call; returns parsed JSON, raises on failure.
    The relay itself reads the shared keys from Handler.keys in-process;
    X-Vault-Key is passed when a per-lane key is present, mirroring
    /api/chat's own relay dispatch."""
    headers = {"Content-Type": "application/json", "X-Relay-Token": RELAY_TOKEN}
    vault_key = _v1_lane_key(lane)
    if vault_key:
        headers["X-Vault-Key"] = vault_key
    data = json.dumps(payload).encode() if payload is not None else None
    req = Request(f"http://127.0.0.1:{RELAY_PORT}/{lane}/v1{path}",
                  data=data, headers=headers,
                  method="POST" if payload is not None else "GET")
    with urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def _v1_route(model):
    """Resolve a requested model to an ordered (lane, upstream model) list."""
    model = (model or "").strip()
    if model and model != "nexus-auto":
        if "/" in model:
            lane, rest = model.split("/", 1)
            if lane in RELAY_UPSTREAMS and rest:
                return [(lane, rest)]
        for lane, default in _V1_LANES:
            if model == default:
                return [(lane, model)]
        return [(lane, model) for lane, _d in _V1_LANES[:3]]
    return list(_V1_LANES)


def _v1_chat(messages, model, temperature=None):
    """Run a chat completion across the relay lanes until one answers.
    Returns (status_code, openai_shaped_dict, lane_used)."""
    last_error = "no lane available"
    for lane, mdl in _v1_route(model):
        if _provider_down(lane):
            continue
        if lane not in RELAY_KEYLESS and getattr(Handler, "keys", None) is None:
            last_error = "vault locked"
            continue
        payload = {"model": mdl, "messages": messages, "max_tokens": 4096}
        if temperature is not None:
            payload["temperature"] = temperature
        try:
            data = _v1_relay_call(lane, "/chat/completions", payload)
            reply = data["choices"][0]["message"]["content"]
            if not isinstance(reply, str):
                raise ValueError("unexpected upstream shape")
            _note_success(lane)
            usage = data.get("usage") or {}
            _append_usage({"ts": datetime.datetime.now().isoformat(),
                           "provider": f"v1:{lane}", "model": mdl,
                           "prompt_tokens": usage.get("prompt_tokens", 0),
                           "completion_tokens": usage.get("completion_tokens", 0)})
            data.setdefault("model", mdl)
            return 200, data, lane
        except HTTPError as e:
            _note_failure(lane)
            last_error = f"{lane} returned {e.code}"
            continue
        except Exception:
            _note_failure(lane)
            last_error = f"{lane} unreachable"
            continue
    return 502, {"error": {"message": f"all Nexus lanes failed ({last_error})",
                           "type": "upstream_error"}}, ""


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
        self._proxy_safe()


    def do_POST(self):
        self._proxy_safe()

    def _proxy_safe(self):
        # An unexpected relay error must answer JSON 500, never drop the
        # connection, and must be logged (redacted) server-side.
        self._resp_started = False
        try:
            self._proxy()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:
            _log_event("error", "relay_unhandled_exception",
                       path=self.path, error=f"{type(exc).__name__}: {exc}")
            if not self._resp_started:
                try:
                    self._send_json(500, {"error": "relay error"})
                except Exception:
                    pass

    def send_response(self, code, message=None):
        self._resp_started = True
        return super().send_response(code, message)

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
        # Only the main server (holding RELAY_TOKEN) may use the relay.
        if not _hmac.compare_digest(self.headers.get("X-Relay-Token", ""), RELAY_TOKEN):
            self._send_json({"error": "forbidden"}, 403)
            return
        # Expect /<name>/v1/...
        parts = path.lstrip("/").split("/", 1)
        if len(parts) < 2 or parts[0] not in RELAY_UPSTREAMS:
            self._send_json({"error": "unknown relay provider"}, 404)
            return
        name, rest = parts[0], "/" + parts[1]
        _cf_models = False
        _cf_token = ""
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
        if name == "cloudflare":
            # Stored key format is "account_id:api_token". Chat goes to the
            # account-scoped OpenAI-compat base; the model list lives on the
            # catalog search endpoint with a different response shape.
            _raw = self.headers.get("X-Vault-Key") or (Handler.keys or {}).get("cloudflare") or ""
            _acct, _, _tok = _raw.partition(":")
            _cf_token = _tok or _raw
            if rest == "/models":
                upstream = f"https://api.cloudflare.com/client/v4/accounts/{_acct}/ai/models/search?per_page=100"
                _cf_models = True
            else:
                upstream = f"https://api.cloudflare.com/client/v4/accounts/{_acct}/ai/v1" + rest

        length = int(self.headers.get("Content-Length", 0))
        if length > 12 * 1024 * 1024:
            self._send_json({"error": "body too large"}, 413)
            return
        body = self.rfile.read(length) if length else None

        req = Request(upstream, data=body, method=self.command)
        # Use a browser-like User-Agent; some upstreams (Groq via Cloudflare)
        # block Python-urllib's default signature with 403 error 1010.
        req.add_header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36")
        for k, v in self.headers.items():
            if k.lower() not in ("host", "content-length", "authorization", "user-agent", "x-vault-key", "x-relay-token"):
                req.add_header(k, v)
        if name == "cloudflare":
            # Only the token part goes upstream (account id is in the URL).
            if _cf_token:
                req.add_header("Authorization", f"Bearer {_cf_token}")
        elif name not in RELAY_KEYLESS:
            # Prefer a per-request vault key (friend's own key) over shared keys.
            # X-Vault-Key is only accepted on localhost and never forwarded upstream.
            key = self.headers.get("X-Vault-Key")
            if not key:
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
                if _cf_models:
                    # Translate Cloudflare's catalog shape to OpenAI's.
                    try:
                        _res = json.loads(data).get("result", [])
                        data = json.dumps({"data": [{"id": m.get("name", "")} for m in _res if isinstance(m, dict) and m.get("name")]}).encode()
                    except Exception:
                        pass
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
            self._send_json({"error": "upstream error"}, 502)


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
    server_version = "NexusLocal"
    sys_version = ""
    keys: dict | None = None
    _head_only = False  # set True during do_HEAD so bodies are suppressed

    def end_headers(self):
        # Security headers on every response
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        # CSP: allow self + Google Fonts (used by pages); no inline scripts from other origins
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                         "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
                         "font-src https://fonts.gstatic.com; img-src 'self' data:; "
                         "connect-src 'self'; frame-ancestors 'none'")
        super().end_headers()

    # Session helpers
    def _get_session(self):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        token = cookie.get("session")
        if token:
            token = token.value
            if token in SESSIONS:
                sess = SESSIONS[token]
                if not isinstance(sess, dict):
                    del SESSIONS[token]
                    return None
                now = time.time()
                if sess.get("hard_expires") and now > sess["hard_expires"]:
                    # Hard cap (e.g. a view pass end) beats the sliding window.
                    _drop_chat_unlock(sess.get("chat_unlock"))
                    del SESSIONS[token]
                    return None
                if now - sess["ts"] < SESSION_EXPIRY:
                    sess["ts"] = now  # sliding window
                    _rec = _CHAT_UNLOCKS.get(sess.get("chat_unlock") or "")
                    if _rec and _rec.get("bound_token") == token:
                        _rec["expires"] = now + SESSION_EXPIRY
                    return token
                else:
                    _drop_chat_unlock(sess.get("chat_unlock"))
                    del SESSIONS[token]
        return None

    def _session_info(self):
        token = self._get_session()
        if not token:
            return None
        sess = SESSIONS.get(token)
        if isinstance(sess, dict):
            return sess
        return None

    def _check_origin(self):
        """CSRF defense-in-depth: verify Origin/Referer matches Host for POSTs.
        SameSite=Lax already blocks cross-site POST cookies; this is backup."""
        origin = self.headers.get("Origin") or self.headers.get("Referer") or ""
        if not origin:
            return True  # Same-origin form posts may omit Origin; SameSite still protects
        host = self.headers.get("Host", "")
        # Extract host from origin
        try:
            from urllib.parse import urlparse
            ohost = urlparse(origin).netloc
        except Exception:
            return False
        return ohost == host

    def _effective_keys(self):
        """Keys for this request: shared keys with friend's own vault overlaid.
        A friend's key for a provider wins; other providers fall back to shared."""
        base = dict(Handler.keys or {})
        info = self._session_info() or {}
        uk = info.get("userkeys")
        if isinstance(uk, dict) and uk:
            base.update(uk)
        return base

    def _require_admin(self):
        info = self._session_info()
        if not info or not info.get("admin"):
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self._send_body(json.dumps({"error": "admin only"}).encode())
            return False
        return True

    def _require_session(self):
        if not self._get_session():
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self._send_body(json.dumps({"error": "not logged in"}).encode())
            return False
        return True

    def _send_locked(self):
        """503 for an operation that genuinely needs the owner's decrypted
        provider keys while the server is still locked (no admin login yet
        since the last restart). Never use this for auth/session failures."""
        self._set_json_headers(503)
        self.wfile.write(json.dumps({"error": LOCKED_ERROR}).encode())

    # -- External /v1 API (see the module-level note above _V1_LANES) --

    def _v1_authorized(self):
        key = _v1_api_key()
        if not key:
            return False
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        return _hmac.compare_digest(auth[len("Bearer "):].strip(), key)

    def _v1_gate(self):
        """Shared gate for /v1 routes. Returns True when the request may
        proceed; otherwise the error response has already been written.
        A disabled endpoint (no key configured) answers 404 so the
        surface stays invisible."""
        if not _v1_api_key():
            self._set_json_headers(404)
            self._send_body(json.dumps({"error": {"message": "not found", "type": "not_found"}}).encode())
            return False
        if not self._v1_authorized():
            self._set_json_headers(401)
            self._send_body(json.dumps({"error": {"message": "invalid api key", "type": "authentication_error"}}).encode())
            return False
        return True

    def _v1_models(self):
        if not self._v1_gate():
            return
        ids = ["nexus-auto"] + [f"{lane}/{mdl}" for lane, mdl in _V1_LANES]
        now = time.time()
        if now - _V1_MODELS_CACHE["at"] > 300:
            live = []
            for lane, _d in _V1_LANES:
                try:
                    data = _v1_relay_call(lane, "/models", timeout=5)
                    for m in data.get("data", []):
                        if isinstance(m, dict) and m.get("id"):
                            live.append(f"{lane}/{m['id']}")
                except Exception:
                    continue
            _V1_MODELS_CACHE.update(at=now, ids=live)
        for extra in _V1_MODELS_CACHE["ids"]:
            if extra not in ids:
                ids.append(extra)
        body = {"object": "list",
                "data": [{"id": i, "object": "model", "owned_by": "nexus-local"} for i in ids]}
        self._set_json_headers()
        self._send_body(json.dumps(body).encode())

    def _v1_chat_completions(self):
        if not self._v1_gate():
            return
        if not _rl_ok("v1", (self.headers.get("Authorization", "") or "")[-8:], 60, 60):
            self._set_json_headers(429)
            self.wfile.write(json.dumps({"error": {"message": "rate limit", "type": "rate_limit_error"}}).encode())
            return
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
            data = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            self._set_json_headers(400)
            self.wfile.write(json.dumps({"error": {"message": "invalid JSON", "type": "invalid_request_error"}}).encode())
            return
        messages = data.get("messages")
        if not isinstance(messages, list) or not messages:
            self._set_json_headers(400)
            self.wfile.write(json.dumps({"error": {"message": "messages must be a non-empty list", "type": "invalid_request_error"}}).encode())
            return
        code, out, _lane = _v1_chat(messages, data.get("model") or "nexus-auto",
                                    data.get("temperature"))
        self._set_json_headers(code)
        self.wfile.write(json.dumps(out).encode())

    def _v1_access_info(self):
        """Admin-only status for the API Access page. Never returns the
        key itself — status, last 4 and lane readiness only."""
        info = self._session_info()
        if not info or not info.get("admin"):
            self._set_json_headers(403)
            self._send_body(json.dumps({"error": "admin only"}).encode())
            return
        key = _v1_api_key()
        proto = self.headers.get("X-Forwarded-Proto", "http")
        host = self.headers.get("Host", "nexus-local.onrender.com")
        unlocked = getattr(Handler, "keys", None) is not None
        lanes = [{"lane": lane, "model": mdl,
                  "ready": (lane in RELAY_KEYLESS) or unlocked}
                 for lane, mdl in _V1_LANES]
        body = {"enabled": bool(key),
                "key_last4": key[-4:] if key else "",
                "base_url": f"{proto}://{host}/v1",
                "consumer": "DSRclone AI service",
                "vault_unlocked": unlocked,
                "lanes": lanes}
        self._set_json_headers()
        self._send_body(json.dumps(body).encode())

    def _v1_access_test(self):
        """Admin-only live self-test: one tiny nexus-auto completion
        through the same path external clients use."""
        info = self._session_info()
        if not info or not info.get("admin"):
            self._set_json_headers(403)
            self.wfile.write(json.dumps({"error": "admin only"}).encode())
            return
        if not _v1_api_key():
            self._set_json_headers(200)
            self.wfile.write(json.dumps({"ok": False, "error": "endpoint not enabled (NEXUS_V1_API_KEY is not set)"}).encode())
            return
        started = time.time()
        code, out, lane = _v1_chat([{"role": "user", "content": "Reply with exactly: NEXUS API OK"}],
                                   "nexus-auto")
        latency = int((time.time() - started) * 1000)
        if code == 200:
            try:
                reply = out["choices"][0]["message"]["content"]
            except Exception:
                reply = ""
            self._set_json_headers(200)
            self.wfile.write(json.dumps({"ok": True, "lane": lane,
                                         "model": out.get("model", ""),
                                         "reply": str(reply)[:160],
                                         "latency_ms": latency}).encode())
        else:
            self._set_json_headers(200)
            self.wfile.write(json.dumps({"ok": False, "lane": lane,
                                         "error": (out.get("error") or {}).get("message", "failed"),
                                         "latency_ms": latency}).encode())

    def _set_json_headers(self, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

    def send_response(self, code, message=None):
        self._resp_started = True
        return super().send_response(code, message)

    def _handle_uncaught(self, exc):
        """Last-resort handler wrapper: log (redacted) and, when nothing
        has been sent yet, answer a clean JSON 500 instead of dropping
        the connection. If a response already started, the stream cannot
        be repaired — the log line is the record."""
        _log_event("error", "unhandled_exception", path=self.path,
                   method=self.command,
                   error=f"{type(exc).__name__}: {exc}")
        if not getattr(self, "_resp_started", False):
            try:
                self._set_json_headers(500)
                self.wfile.write(json.dumps({"error": "internal error"}).encode())
            except Exception:
                pass

    def do_GET(self):
        self._head_only = False
        self._resp_started = False
        try:
            self._do_get_head()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:
            self._handle_uncaught(exc)

    def do_HEAD(self):
        # HEAD mirrors GET routing/status codes but sends no body
        # (uptime monitors use HEAD; without this BaseHTTPRequestHandler
        # answers 501 Not Implemented).
        self._head_only = True
        self._resp_started = False
        try:
            self._do_get_head()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:
            self._handle_uncaught(exc)
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
        if parsed.path == "/health":
            # Public readiness probe (Render health check / monitors).
            # Deliberately minimal: proves the process serves, leaks nothing.
            self._set_json_headers()
            self._send_body(json.dumps({"ok": True}).encode())
            return
        if parsed.path == "/v1/models":
            # External API (service-key auth, no session): see _V1_LANES.
            self._v1_models()
            return
        if parsed.path == "/api/v1-access":
            self._v1_access_info()
            return
        if parsed.path.startswith("/view/"):
            # Temporary view pass door: a valid, unexpired token mints a
            # read-only viewer session and lands on the dashboard.
            raw_token = parsed.path[len("/view/"):].strip()
            grant = _view_grant_for(raw_token)
            if not grant:
                self.send_response(404)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self._send_body(b"<h1>This view link is invalid or has expired.</h1>")
                return
            stok = secrets.token_hex(32)
            SESSIONS[stok] = {
                "label": f"viewer:{grant['name']}", "admin": False,
                "viewer": True,
                "grant": hashlib.sha256(raw_token.encode()).hexdigest(),
                "ts": time.time(), "hard_expires": grant["expires"],
            }
            self.send_response(302)
            self.send_header("Location", "/")
            self.send_header("Set-Cookie",
                             f"session={stok}; HttpOnly; Secure; SameSite=Lax; Path=/")
            self.end_headers()
            return
        if parsed.path == "/setup":
            key_path = Path(__file__).parent / "keys.enc"
            keys_exist = key_path.exists()
            # Once keys are set up, the page needs a session: admins get the
            # full (shared) setup; signed-in users get the same page in
            # personal mode, saving to their OWN vault (owner order
            # 2026-10-09: "Enable Setup Your Key page for User too").
            # First-time setup (no keys yet) stays public. Read-only view
            # passes never get the form.
            info = self._session_info()
            # Signed-out visitors get the page in personal (guest) mode too
            # (owner order 2026-10-09: "allow normal user in set up your
            # key page") — their account password authenticates the save.
            # Read-only view passes still bounce to /login.
            user_mode = bool(keys_exist and not (info or {}).get("admin")
                             and not (info or {}).get("viewer"))
            if keys_exist and info and info.get("viewer"):
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
                "<details style='background:#0c0c0f;border:1px solid rgba(168,85,247,.25);border-radius:10px;padding:16px;margin-bottom:16px'>"
                "<summary style='color:#A855F7;cursor:pointer;font-size:16px;font-weight:600;font-family:Oswald,sans-serif;letter-spacing:.06em'>Relay Providers</summary>"
                "<p style='color:#9aa3b2;font-size:14px;margin:12px 0'>Your outside keys via the built-in relay. Pollinations needs no key.</p>"
                + relay_fields +
                "</details>"
            )
            fields = "".join(
                '<label>' + n + '<input type="password" name="k_' + n + '" autocomplete="off"></label>'
                for n in other_names
            )
            freellmapi_section = (
                "<details style='background:#0c0c0f;border:1px solid rgba(168,85,247,.25);border-radius:10px;padding:16px;margin-bottom:16px'>"
                "<summary style='color:#A855F7;cursor:pointer;font-size:16px;font-weight:600;font-family:Oswald,sans-serif;letter-spacing:.06em'>FreeLLMAPI Gateway</summary>"
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
            secure_card = (
                "<div class='card'><h3>Confirm it\u2019s you</h3>"
                "<p class='hint'>Your account password encrypts your personal key vault. Keys are stored only for your account and are never shared.</p>"
                "<label>Your account password<input type='password' name='password' required id='pw1'></label>"
            ) if user_mode else (
                "<div class='card'><h3>Secure your keys</h3>"
                    "<p class='hint'>This password encrypts everything and unlocks your dashboard</p>"
                    "<label>Password (min 8 chars)<input type='password' name='password' required minlength='8' id='pw1'></label>"
                    "<label>Confirm password<input type='password' name='confirm' required id='pw2'></label>"
                    "<div id='pwm' style='font-size:13px;margin-top:6px'></div>"
                    "<script>"
                    "document.getElementById('pw2').addEventListener('input',function(){"
                    "var a=document.getElementById('pw1').value,b=this.value;"
                    "document.getElementById('pwm').innerHTML=a===b&&a.length>=8?'<span style=\"color:#A855F7\">✓ Match</span>':'<span style=\"color:#ef4444\">Must match (8+ chars)</span>';"
                    "if(a===b&&a.length>=8)document.getElementById('st3').className='st on';});"
                    "</script>"
            )
            page = ("<!DOCTYPE html><html><head><meta charset='utf-8'>"
                    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                    "<title>Nexus Local - Setup</title><style>@import url('https://fonts.googleapis.com/css2?family=Bebas+Neue&family=Oswald:wght@400;500;600&family=Press+Start+2P&display=swap');"
                    "*{box-sizing:border-box}"
                    "body{background-color:#050507;background-image:radial-gradient(ellipse 90% 45% at 50% -5%, rgba(168,85,247,.07), transparent 70%);color:#e6e9f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;margin:0;padding:0}"
                    ".wrap{max-width:600px;margin:0 auto;padding:20px 16px 40px}"
                    ".hero{text-align:center;padding:24px 0 16px}"
                    ".eyebrow{font-family:'Bebas Neue',sans-serif;letter-spacing:.32em;font-size:15px;color:#A855F7;margin-bottom:10px}"
                    "h1{font-family:'Bebas Neue',sans-serif;font-size:34px;margin:0 0 8px;color:#fff;letter-spacing:.08em;line-height:1.2}h1 span{color:#A855F7}"
                    ".sub{color:#9aa3b2;font-size:14px;margin:0}"
                    ".steps{display:flex;justify-content:center;align-items:center;gap:6px;margin:18px 0}"
                    ".st{display:flex;align-items:center;gap:6px;font-size:12px;color:#6b7280}"
                    ".sn{width:24px;height:24px;border-radius:50%;background:#0a0a0d;border:1px solid #3a3a42;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:600}"
                    ".st.on{color:#fff}.st.on .sn{background:#A855F7;border-color:#000;color:#fff}"
                    ".st.done .sn{background:#7C3AED;border-color:#7C3AED;color:#0a0a0a}"
                    ".ln{width:24px;height:1px;background:#2a3142}"
                    ".tabs{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:16px}"
                    ".tab{background:#101014;border:1px solid #26262c;border-radius:10px;padding:14px 8px;text-align:center;cursor:pointer;transition:all .18s;color:#e8e8ea}"
                    ".tab:hover{border-color:rgba(168,85,247,.4)}"
                    ".tab.sel{border-color:#A855F7;background:rgba(168,85,247,.07);box-shadow:0 0 20px rgba(168,85,247,.12)}"
                    ".tab b{display:block;font-size:13px;margin-bottom:2px;font-family:Oswald,sans-serif;letter-spacing:.08em;text-transform:uppercase}"
                    ".tab span{font-size:11px;color:#8a8a92}"
                    ".card{background:#101014;border:1px solid rgba(168,85,247,.14);border-radius:12px;padding:20px;margin-bottom:14px;box-shadow:0 12px 32px rgba(0,0,0,.5),inset 0 1px 0 rgba(255,255,255,.05)}"
                    ".card h3{margin:0 0 6px;font-size:20px;font-family:'Bebas Neue',sans-serif;letter-spacing:.08em}"
                    ".hint{color:#9aa3b2;font-size:13px;margin:0 0 12px;line-height:1.45}"
                    "label{display:block;margin:10px 0 4px;color:#9aa3b2;font-size:13px}"
                    "input,textarea{width:100%;background:#0a0a0d;border:1px solid #26262c;border-radius:8px;color:#e8e8ea;padding:11px 13px;font-size:14px}"
                    "input:focus,textarea:focus{outline:none;border-color:#A855F7;box-shadow:0 0 0 3px rgba(168,85,247,.15)}"
                    "textarea{font-family:ui-monospace,monospace}"
                    "button[type='submit']{font-family:Oswald,sans-serif;font-weight:600;font-size:14px;letter-spacing:.22em;text-transform:uppercase;background:linear-gradient(#C084FC,#7C3AED);color:#0a0a0a;border:1px solid #0a0a0a;border-radius:8px;box-shadow:0 0 28px rgba(168,85,247,.28),inset 0 1px 0 rgba(255,255,255,.5);padding:16px;width:100%;margin-top:14px;cursor:pointer}"
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
                    ".gold-div{height:2px;background:linear-gradient(90deg,transparent,rgba(168,85,247,.7),transparent);margin:0 -16px 16px}"
                    "@keyframes fadeUp{from{opacity:0;transform:translateY(18px)}to{opacity:1;transform:none}}""@keyframes grainShift{0%,100%{transform:translate(0,0)}12%{transform:translate(-3%,-5%)}25%{transform:translate(-8%,3%)}37%{transform:translate(4%,-8%)}50%{transform:translate(-3%,8%)}62%{transform:translate(-8%,3%)}75%{transform:translate(6%,0)}87%{transform:translate(0,6%)}}""@keyframes batDrift{0%,100%{transform:translateY(-50%) translateX(0)}50%{transform:translateY(-60%) translateX(-26px)}}""@keyframes tabGlow{0%,100%{box-shadow:0 0 14px rgba(168,85,247,.10)}50%{box-shadow:0 0 26px rgba(168,85,247,.28)}}""body::before{content:\"\";position:fixed;inset:0;z-index:2000;pointer-events:none;background:radial-gradient(ellipse at center,transparent 52%,rgba(0,0,0,.62) 100%)}""body::after{content:\"\";position:fixed;inset:-120px;z-index:2001;pointer-events:none;opacity:.05;background-image:url(\"data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A//www.w3.org/2000/svg%27%20width%3D%27140%27%20height%3D%27140%27%3E%3Cfilter%20id%3D%27n%27%3E%3CfeTurbulence%20type%3D%27fractalNoise%27%20baseFrequency%3D%270.85%27%20numOctaves%3D%272%27/%3E%3C/filter%3E%3Crect%20width%3D%27140%27%20height%3D%27140%27%20filter%3D%27url%28%23n%29%27%20opacity%3D%270.55%27/%3E%3C/svg%3E\");animation:grainShift 7s steps(8) infinite}"".hero{position:relative;overflow:hidden;animation:fadeUp .7s cubic-bezier(.2,.7,.3,1) both}"".hero::after{content:\"\";position:absolute;right:-34px;top:50%;width:280px;height:101px;background:url(\"data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A//www.w3.org/2000/svg%27%20viewBox%3D%270%200%20100%2036%27%3E%3Cpath%20d%3D%27M0%2C14%20L24%2C3%20L39%2C9%20L44%2C1%20L46.5%2C7%20L50%2C5%20L53.5%2C7%20L56%2C1%20L61%2C9%20L76%2C3%20L100%2C14%20L90%2C20%20L83%2C16%20L75%2C24%20L67%2C18%20L59%2C28%20L54%2C22%20L50%2C30%20L46%2C22%20L41%2C28%20L33%2C18%20L25%2C24%20L17%2C16%20L10%2C20%20Z%27%20fill%3D%27%23A855F7%27/%3E%3C/svg%3E\") no-repeat center/contain;opacity:.07;pointer-events:none;animation:batDrift 11s ease-in-out infinite}"".steps{animation:fadeUp .7s .08s cubic-bezier(.2,.7,.3,1) both}"".tabs{animation:fadeUp .7s .14s cubic-bezier(.2,.7,.3,1) both}"".tab.sel{animation:tabGlow 2.6s ease-in-out infinite}"".sec.on .card{animation:fadeUp .5s cubic-bezier(.2,.7,.3,1) both}"
                    "</style></head><body><div class='wrap'>"
                    "<div class='hero'><div class='eyebrow'>NEXUS LOCAL</div>" +
                    ("<div class='warn'><p><b>Your keys, your vault.</b> Everything you save here goes only into <b>your personal vault</b>, encrypted with your account password \u2014 the shared setup is never touched.</p></div>" if user_mode else "<div class='warn'><p><b>Keys already set up.</b> Submitting will <b>overwrite</b> existing keys.</p></div>" if keys_exist else "") +
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
                    "<summary style='color:#A855F7;cursor:pointer;font-size:14px;font-weight:600'>Relay Providers (5)</summary>"
                    "<div style='display:flex;flex-wrap:wrap;gap:6px;margin-top:10px'>"
                    "<span style='background:#0a0a0d;color:#C084FC;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid rgba(168,85,247,.25);font-family:monospace'>relay_groq</span>"
                    "<span style='background:#0a0a0d;color:#C084FC;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid rgba(168,85,247,.25);font-family:monospace'>relay_gemini</span>"
                    "<span style='background:#0a0a0d;color:#C084FC;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid rgba(168,85,247,.25);font-family:monospace'>relay_openrouter</span>"
                    "<span style='background:#0a0a0d;color:#C084FC;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid rgba(168,85,247,.25);font-family:monospace'>relay_nvidia</span>"
                    "<span style='background:#0a0a0d;color:#C084FC;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid rgba(168,85,247,.25);font-family:monospace'>relay_pollinations</span>"
                    "</div></details>"
                    "<details style='margin-bottom:12px;background:#0c0c0f;border:1px solid #26262c;border-radius:8px;padding:10px 14px'>"
                    "<summary style='color:#A855F7;cursor:pointer;font-size:14px;font-weight:600'>FreeLLMAPI Providers (14)</summary>"
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
                    "<span style='background:#0a0a0d;color:#e8e8ea;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid #2a2a32;font-family:monospace'>zhipu</span>"
                    "<span style='background:#0a0a0d;color:#e8e8ea;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid #2a2a32;font-family:monospace'>aihorde</span>"
                    "<span style='background:#0a0a0d;color:#e8e8ea;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid #2a2a32;font-family:monospace'>kilo</span>"
                    "<span style='background:#0a0a0d;color:#e8e8ea;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid #2a2a32;font-family:monospace'>ovh</span>"
                    "</div></details>"
                    "<textarea id='bulk' rows='6' oninput='previewKeys()' style='width:100%;box-sizing:border-box;background:#0a0a0d;border:1px solid #26262c;border-radius:8px;color:#e8e8ea;padding:14px;font-size:14px;font-family:monospace' placeholder='freellmapi: sk-...&#10;relay_groq: gsk_...&#10;groq: gsk_...&#10;openrouter: sk-or-v1-...'></textarea>"
                    "<div id='bulk-preview' style='margin:12px 0;font-size:13px'></div>"
                    "<div style='display:flex;gap:10px'>"
                    "<button type='button' onclick='fillKeys()' style='background:linear-gradient(#C084FC,#7C3AED);color:#0a0a0a;border:1px solid #0a0a0a;border-radius:8px;box-shadow:0 0 20px rgba(168,85,247,.25);padding:14px 24px;font-size:13px;font-family:Oswald,sans-serif;font-weight:600;letter-spacing:.14em;text-transform:uppercase;flex:1;cursor:pointer' onmousedown=\"this.style.transform='scale(.97)'\" onmouseup=\"this.style.transform='scale(1)'\">Fill Fields Below</button>"
                    "<button type='button' onclick=\"document.getElementById('bulk').value='';previewKeys()\" style='background:#141418;color:#8a8a92;border:1px solid #2a2a32;border-radius:8px;padding:14px 20px;font-size:13px;font-family:Oswald,sans-serif;letter-spacing:.1em;cursor:pointer'>Clear</button>"
                    "</div>"
                    "</div>"
                    "<script>"
                    "var VALID_KEYS=['freellmapi','relay_groq','relay_gemini','relay_openrouter','relay_nvidia','groq','google','openrouter','nvidia','cloudflare','cohere','huggingface','mistral','zhipu','aihorde','kilo','ovh','pollinations'];"
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
                    "if(p.found.length>0){h+='<div style=\"color:#A855F7;margin-bottom:6px\">Will fill: <b>'+p.found.join(', ')+'</b> ('+p.found.length+')</div>';}"
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
                    "if(el){el.value=v;el.style.border='2px solid #A855F7';el.style.background='#0f1f0f';n++;setTimeout(function(){el.style.border='';el.style.background='';},3000);}"
                    "else{skipped.push(k);}"
                    "});"
                    "var msg=document.getElementById('bulk-preview');"
                    "if(n>0){msg.innerHTML='<div style=\"background:#0f2f0f;border:1px solid #A855F7;border-radius:8px;padding:12px;color:#A855F7\"><b>'+n+' keys filled!</b> Fields are highlighted in green below. Scroll down to review.</div>';}"
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
                    "<summary style='color:#A855F7'>Via Relay</summary><div class='dbody'>"
                    "<p class='hint'>Your own endpoint + key, routed through the built-in relay</p>"
                    "<div id='custom-relay-list'></div>"
                    "<button type='button' onclick='addCustomRelay()' style='background:#141418;color:#A855F7;border:1px solid rgba(168,85,247,.35);border-radius:8px;padding:10px 20px;font-size:13px;font-family:Oswald,sans-serif;letter-spacing:.1em;cursor:pointer;margin-top:8px'>+ Add Provider</button>"
                    "</div></details>"
                    "<details>"
                    "<summary style='color:#A855F7'>Via FreeLLMAPI</summary><div class='dbody'>"
                    "<p class='hint'>Routed through your FreeLLMAPI gateway</p>"
                    "<div id='custom-fl-list'></div>"
                    "<button type='button' onclick='addCustomFL()' style='background:#141418;color:#A855F7;border:1px solid rgba(168,85,247,.35);border-radius:8px;padding:10px 20px;font-size:13px;font-family:Oswald,sans-serif;letter-spacing:.1em;cursor:pointer;margin-top:8px'>+ Add Provider</button>"
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
                    + secure_card
                    + ("<button type='submit'>Save My Keys</button>" if user_mode else "<button type='submit'>Encrypt and Finish Setup</button>")
                    + "</form>"
                    + ("<p style='text-align:center;margin-top:20px;color:#9aa3b2'>Your saved keys live under <a href='/mykeys' style='color:#A855F7'>My Keys</a> \u00b7 <a href='/' style='color:#A855F7'>Back to dashboard \u2192</a></p>" if user_mode else "<p style='text-align:center;margin-top:20px;color:#9aa3b2'>Already have keys set up? <a href='/login' style='color:#A855F7'>Log in →</a></p>")
                    + "</div></body></html>")
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
                self.send_error(500, "internal error")
            return
        # Settings page - update keys after login
        if parsed.path == "/settings":
            info = self._session_info()
            if not info:
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
                return
            if not (info.get("admin") or info.get("viewer")):
                self.send_response(403)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self._send_body(b"<h1>Admin only</h1>")
                return
            # Show current keys (masked) with fields to update. Viewers may
            # look (owner's choice) but every POST stays refused for them.
            current = getattr(Handler, 'keys', {})
            sidebar = (Path(__file__).parent / "sidebar.html").read_text(encoding="utf-8")
            def masked(k):
                v = current.get(k, "")
                return f"***{v[-4:]}" if v and len(v) > 4 else ("set" if v else "not set")
            def disp_name(n):
                if n.startswith("relay_"):
                    return "Relay: " + n[6:].replace("_", " ").title()
                return "FreeLLMAPI: " + n.replace("_", " ").title()
            def key_row(n):
                return (f"<label>{disp_name(n)} <span style='color:#A855F7;font-size:12px'>({masked(n)})</span>"
                        f"<input type='password' name='k_{n}' autocomplete='off' placeholder='Leave blank to keep current'></label>")
            relay_rows = "".join(key_row(n) for n in PROVIDER_NAMES if n.startswith("relay_"))
            fl_rows = "".join(key_row(n) for n in PROVIDER_NAMES if not n.startswith("relay_"))
            det_style = ("background:#0c0c0f;border:1px solid rgba(168,85,247,.25);border-radius:10px;"
                         "padding:16px;margin-bottom:14px")
            sum_style = ("color:#A855F7;cursor:pointer;font-size:15px;font-weight:600;"
                         "font-family:Oswald,sans-serif;letter-spacing:.06em")
            rows = (
                f"<details style='{det_style}'><summary style='{sum_style}'>FreeLLMAPI Providers</summary>"
                f"<div style='margin-top:12px'>{fl_rows}</div></details>"
                f"<details style='{det_style}'><summary style='{sum_style}'>Relay Providers</summary>"
                f"<div style='margin-top:12px'>{relay_rows}</div></details>"
            )
            page = ("<!DOCTYPE html><html><head><meta charset='utf-8'>"
                    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                    "<title>Nexus Local - Update Keys</title><style>@import url('https://fonts.googleapis.com/css2?family=Bebas+Neue&family=Oswald:wght@400;500;600&family=Press+Start+2P&display=swap');"
                    "*{box-sizing:border-box}"
                    "body{background-color:#050507;background-image:radial-gradient(ellipse 90% 45% at 50% -5%, rgba(168,85,247,.07), transparent 70%);color:#e6e9f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;margin:0;padding:0}"
                    ".wrap{max-width:600px;margin:0 auto;padding:20px 16px 40px}"
                    ".hero{text-align:center;padding:24px 0 16px}"
                    ".eyebrow{font-family:'Bebas Neue',sans-serif;letter-spacing:.32em;font-size:15px;color:#A855F7;margin-bottom:10px}"
                    "h1{font-family:'Bebas Neue',sans-serif;font-size:32px;margin:0 0 8px;color:#fff;letter-spacing:.08em}"
                    ".sub{color:#9aa3b2;font-size:14px;margin:0}"
                    ".card{background:#101014;border:1px solid rgba(168,85,247,.14);border-radius:12px;padding:20px;margin-bottom:14px;margin-top:20px;box-shadow:0 12px 32px rgba(0,0,0,.5),inset 0 1px 0 rgba(255,255,255,.05)}"
                    "label{display:block;margin:10px 0 4px;color:#9aa3b2;font-size:13px}"
                    "input{width:100%;background:#0a0a0d;border:1px solid #26262c;border-radius:8px;color:#e8e8ea;padding:11px 13px;font-size:14px}"
                    "input:focus{outline:none;border-color:#A855F7;box-shadow:0 0 0 3px rgba(168,85,247,.15)}"
                    "button[type='submit']{font-family:Oswald,sans-serif;font-weight:600;font-size:14px;letter-spacing:.22em;text-transform:uppercase;background:linear-gradient(#C084FC,#7C3AED);color:#0a0a0a;border:1px solid #0a0a0a;border-radius:8px;box-shadow:0 0 28px rgba(168,85,247,.28),inset 0 1px 0 rgba(255,255,255,.5);padding:16px;width:100%;margin-top:16px;cursor:pointer}"
                    "button[type='submit']:hover{filter:brightness(1.12)}"
                    ".key-hint{color:#A855F7;font-size:11px;font-weight:600}"
                    ".back{text-align:center;margin-top:16px}"
                    ".back a{color:#A855F7;text-decoration:none;font-size:14px}"
                    "@keyframes fadeUp{from{opacity:0;transform:translateY(18px)}to{opacity:1;transform:none}}""@keyframes grainShift{0%,100%{transform:translate(0,0)}12%{transform:translate(-3%,-5%)}25%{transform:translate(-8%,3%)}37%{transform:translate(4%,-8%)}50%{transform:translate(-3%,8%)}62%{transform:translate(-8%,3%)}75%{transform:translate(6%,0)}87%{transform:translate(0,6%)}}""@keyframes batDrift{0%,100%{transform:translateY(-50%) translateX(0)}50%{transform:translateY(-60%) translateX(-26px)}}""@keyframes tabGlow{0%,100%{box-shadow:0 0 14px rgba(168,85,247,.10)}50%{box-shadow:0 0 26px rgba(168,85,247,.28)}}""body::before{content:\"\";position:fixed;inset:0;z-index:2000;pointer-events:none;background:radial-gradient(ellipse at center,transparent 52%,rgba(0,0,0,.62) 100%)}""body::after{content:\"\";position:fixed;inset:-120px;z-index:2001;pointer-events:none;opacity:.05;background-image:url(\"data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A//www.w3.org/2000/svg%27%20width%3D%27140%27%20height%3D%27140%27%3E%3Cfilter%20id%3D%27n%27%3E%3CfeTurbulence%20type%3D%27fractalNoise%27%20baseFrequency%3D%270.85%27%20numOctaves%3D%272%27/%3E%3C/filter%3E%3Crect%20width%3D%27140%27%20height%3D%27140%27%20filter%3D%27url%28%23n%29%27%20opacity%3D%270.55%27/%3E%3C/svg%3E\");animation:grainShift 7s steps(8) infinite}"".hero{position:relative;overflow:hidden;animation:fadeUp .7s cubic-bezier(.2,.7,.3,1) both}"".hero::after{content:\"\";position:absolute;right:-34px;top:50%;width:280px;height:101px;background:url(\"data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A//www.w3.org/2000/svg%27%20viewBox%3D%270%200%20100%2036%27%3E%3Cpath%20d%3D%27M0%2C14%20L24%2C3%20L39%2C9%20L44%2C1%20L46.5%2C7%20L50%2C5%20L53.5%2C7%20L56%2C1%20L61%2C9%20L76%2C3%20L100%2C14%20L90%2C20%20L83%2C16%20L75%2C24%20L67%2C18%20L59%2C28%20L54%2C22%20L50%2C30%20L46%2C22%20L41%2C28%20L33%2C18%20L25%2C24%20L17%2C16%20L10%2C20%20Z%27%20fill%3D%27%23A855F7%27/%3E%3C/svg%3E\") no-repeat center/contain;opacity:.07;pointer-events:none;animation:batDrift 11s ease-in-out infinite}"".steps{animation:fadeUp .7s .08s cubic-bezier(.2,.7,.3,1) both}"".tabs{animation:fadeUp .7s .14s cubic-bezier(.2,.7,.3,1) both}"".tab.sel{animation:tabGlow 2.6s ease-in-out infinite}"".sec.on .card{animation:fadeUp .5s cubic-bezier(.2,.7,.3,1) both}"
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
        # Connections page - provider status for every signed-in user.
        # Friends get the same page read-only plus a bring-your-own-key
        # section (rendered client-side for non-admins, backed by
        # /api/mykeys); admins keep full management via Update Keys/Admin.
        if parsed.path == "/connections":
            info = self._session_info()
            if not info:
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
                self.send_error(500, "internal error")
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
                    self.send_error(500, "internal error")
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
        if parsed.path == "/api/friend_blob":
            # Returns the encrypted friend blob (same bytes as users.enc)
            # plus all personal key vaults. The sync job uses this to persist
            # friend changes to GitHub. Data is AES-256-GCM encrypted; safe to
            # expose like the public repo copy.
            try:
                import base64 as _b64
                blob = _b64.b64encode(USERS_PATH.read_bytes()).decode() if USERS_PATH.exists() else None
                vaults = {}
                if USERKEYS_DIR.exists():
                    for f in sorted(USERKEYS_DIR.glob("*.enc")):
                        try:
                            vaults[f.stem] = _b64.b64encode(f.read_bytes()).decode()
                        except Exception:
                            pass
                chats = {}
                if CHATS_DIR.exists():
                    for f in sorted(CHATS_DIR.glob("*.enc")):
                        try:
                            chats[f.stem] = _b64.b64encode(f.read_bytes()).decode()
                        except Exception:
                            pass
                # keys.enc too: it holds provider keys AND the 2FA secret.
                # Without syncing it, every redeploy reset live key/2FA
                # changes back to the repo copy (2FA kept "disabling itself").
                keys_b64 = None
                _kp = Path(__file__).parent / "keys.enc"
                if _kp.exists():
                    keys_b64 = _b64.b64encode(_kp.read_bytes()).decode()
                access_b64 = None
                if ACCESS_ENC_PATH.exists():
                    access_b64 = _b64.b64encode(ACCESS_ENC_PATH.read_bytes()).decode()
            except Exception:
                blob, vaults, chats, keys_b64, access_b64 = None, {}, {}, None, None
            self._set_json_headers(200)
            self._send_body(json.dumps({"blob": blob, "vaults": vaults, "chats": chats, "keys": keys_b64, "access": access_b64}).encode())
            return
        if parsed.path == "/api/2fa_qr":
            # QR code for the TOTP secret (admin only) — scan with authenticator app
            if not self._require_admin():
                return
            try:
                secret = (Handler.keys or {}).get("_totp_pending") or (Handler.keys or {}).get("_totp_secret", "")
            except Exception:
                secret = ""
            if not secret:
                self._set_json_headers(404)
                self._send_body(json.dumps({"error": "2FA not enabled"}).encode())
                return
            try:
                import qrcode, io
                otpauth = (f"otpauth://totp/NexusLocal:admin?secret={secret}"
                           f"&issuer=NexusLocal")
                qr = qrcode.QRCode(box_size=6, border=2)
                qr.add_data(otpauth)
                qr.make(fit=True)
                img = qr.make_image(fill_color="black", back_color="white")
                buf = io.BytesIO()
                img.save(buf, format="PNG")
                png = buf.getvalue()
            except Exception:
                self._set_json_headers(500)
                self._send_body(json.dumps({"error": "QR generation failed"}).encode())
                return
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(png)))
            self.end_headers()
            self._send_body(png)
            return
        if parsed.path == "/api/quotas":
            if not self._require_session():
                return
            # Key status is per-caller: shared keys (once unlocked) plus the
            # caller's own vault keys. A friend's BYOK keys must show as
            # configured even before — and without — the owner's unlock.
            _ekeys_q = self._effective_keys()
            # Build the whole payload BEFORE sending headers: if anything
            # below fails (e.g. a corrupt quotas.json), the request wrapper
            # can still answer a clean JSON 500 instead of a truncated 200.
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
                        "key_configured": bool(_ekeys_q.get(name)) or name in ("aihorde", "kilo", "ovh", "pollinations", "relay_pollinations"),
                        "down": _provider_down(name),
                        "daily_usage": {"requests": 0, "tokens": 0},
                        "monthly_usage": {"requests": 0, "tokens": 0},
                    })
                # Add custom providers
                for k in _ekeys_q.keys():
                    if k.startswith("custom_relay_") and not k.endswith("_url"):
                        cname = k[len("custom_relay_"):]
                        quotas["providers"].append({
                            "provider": k,
                            "display_name": f"Relay: {cname.title()} (Custom)",
                            "reset": "",
                            "history": {"requests": [0] * 7, "tokens": [0] * 7},
                            "limits": {},
                            "key_configured": True,
                            "down": _provider_down(k),
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
                            "down": _provider_down(k),
                            "daily_usage": {"requests": 0, "tokens": 0},
                            "monthly_usage": {"requests": 0, "tokens": 0},
                        })
            if os.path.exists(USAGE_PATH):
                with open(USAGE_PATH) as f:
                    for line in f:
                        try:
                            entry = json.loads(line)
                        except Exception:
                            continue  # one corrupt line must not kill the endpoint
                        if not isinstance(entry, dict):
                            continue
                        pt = entry.get("prompt_tokens", 0)
                        ct = entry.get("completion_tokens", 0)
                        quotas["daily_usage"]["requests"] += 1
                        quotas["daily_usage"]["tokens"] += pt + ct
                        quotas["monthly_usage"]["requests"] += 1
                        quotas["monthly_usage"]["tokens"] += pt + ct
            self._set_json_headers()
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
                        try:
                            entry = json.loads(line)
                        except Exception:
                            continue  # one corrupt line must not kill the endpoint
                        if not isinstance(entry, dict):
                            continue
                        provider = entry.get("provider")
                        if not isinstance(provider, str) or not provider:
                            continue
                        pt = entry.get("prompt_tokens", 0)
                        ct = entry.get("completion_tokens", 0)
                        if provider not in usage_data["per_provider"]:
                            usage_data["per_provider"][provider] = {"requests": 0, "tokens": 0}
                        usage_data["per_provider"][provider]["requests"] += 1
                        usage_data["per_provider"][provider]["tokens"] += pt + ct
                        usage_data["totals"]["requests"] += 1
                        usage_data["totals"]["tokens"] += pt + ct
            self._set_json_headers()
            self._send_body(json.dumps(usage_data).encode())
            return
        if parsed.path == "/api/routing":
            # GET = read only. State changes go through POST /api/routing.
            if not self._require_session():
                return
            self._set_json_headers()
            sess = SESSIONS.get(self._get_session() or "", {})
            routing_val = sess.get("routing", "quality") if isinstance(sess, dict) else "quality"
            self._send_body(json.dumps({"routing": routing_val}).encode())
            return
        if parsed.path == "/api/models":
            if not self._get_session():
                self._set_json_headers(401)
                self.wfile.write(json.dumps({"error": "not logged in"}).encode())
                return
            provider = parse_qs(parsed.query).get("provider", [""])[0]
            models = []
            try:
                import urllib.request, json as js
                keys = self._effective_keys()
                vault_key = keys.get(provider, "") if isinstance(keys, dict) else ""
                if provider in ("google", "relay_gemini"):
                    # Google's OpenAI-compat endpoint has no /models; use the
                    # native API with ?key= instead.
                    gkey = keys.get("google") or keys.get("relay_gemini") or ""
                    url = ("https://generativelanguage.googleapis.com/v1beta/models?key="
                           + _urlquote(gkey, safe="")) if gkey else ""
                elif provider in RELAY_UPSTREAMS:
                    # Route through the integrated relay; it attaches the
                    # user's key and proxies to the upstream.
                    url = f"http://127.0.0.1:{RELAY_PORT}/{provider}/v1/models"
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
                # Pass the effective (per-user) key so the relay uses the
                # friend's own key for model discovery when present.
                if provider in RELAY_UPSTREAMS:
                    req.add_header("X-Relay-Token", RELAY_TOKEN)
                    if vault_key:
                        req.add_header("X-Vault-Key", vault_key)
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
                    elif provider == "kilo":
                        # Kilo's catalog is mostly paid (401 keyless); only its
                        # free lane works without an account.
                        models = [m for m in models if m.endswith(":free") or m == "kilo-auto/free"]
                    # Capability filter: ?cap=chat (default) shows only chat models;
                    # cap=image/tts/stt/video shows models for that mode instead.
                    cap = parse_qs(parsed.query).get("cap", ["chat"])[0]
                    if cap not in ("chat", "image", "tts", "stt", "video", "all"):
                        cap = "chat"
                    if cap == "all":
                        pass
                    elif cap == "chat":
                        models = [m for m in models if "chat" in _model_caps(provider, m)]
                    else:
                        models = [m for m in models if cap in _model_caps(provider, m)]
                    # Pollinations' catalog only lists text models, but its image
                    # service (image.pollinations.ai) serves flux/turbo — inject them.
                    if provider in ("pollinations", "relay_pollinations"):
                        if cap == "image":
                            models = ["flux", "turbo"]
                        elif cap == "all":
                            models = models + [m for m in ("flux", "turbo") if m not in models]
                    # HF's inference API dropped free video models; text-to-video
                    # runs on the official LTX-Video Space (ZeroGPU) — inject it.
                    if provider == "huggingface":
                        if cap == "video":
                            models = ["Lightricks/LTX-Video"]
                        elif cap == "all":
                            models = models + [m for m in ("Lightricks/LTX-Video",) if m not in models]
            except Exception as e:
                pass
            # Injections must also apply when the upstream listing itself failed
            _cap2 = parse_qs(parsed.query).get("cap", ["chat"])[0]
            if provider in ("pollinations", "relay_pollinations") and _cap2 == "image" and not models:
                models = ["flux", "turbo"]
            if provider == "huggingface" and _cap2 == "video" and not models:
                models = ["Lightricks/LTX-Video"]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self._send_body(js.dumps({"models": models}).encode())
            return
        if parsed.path == "/admin":
            _ainfo = self._session_info()
            if not _ainfo or not (_ainfo.get("admin") or _ainfo.get("viewer")):
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
                return
            try:
                content = (Path(__file__).parent / "admin.html").read_text(encoding="utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.end_headers()
                self._send_body(content.encode())
            except Exception as e:
                self.send_error(500, "internal error")
            return
        if parsed.path == "/api-access":
            # Admin-only: the external /v1 API's status page. The service
            # key itself is never rendered — status + last 4 only.
            info = self._session_info()
            if not info:
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
                return
            if not info.get("admin"):
                self.send_response(403)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self._send_body(b"<h1>Admin only</h1>")
                return
            try:
                content = (Path(__file__).parent / "api.html").read_text(encoding="utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.end_headers()
                self._send_body(content.encode())
            except Exception as e:
                self.send_error(500, "internal error")
            return
        if parsed.path == "/mykeys":
            # Friend's personal key vault page (friends only; admins use Update Keys)
            info = self._session_info()
            if not info:
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
                return
            if info.get("admin"):
                self.send_response(302)
                self.send_header("Location", "/settings")
                self.end_headers()
                return
            if info.get("viewer"):
                # View passes never reach personal key vaults.
                self.send_response(403)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self._send_body(b"<h1>Not available with read-only access</h1>")
                return
            try:
                content = (Path(__file__).parent / "mykeys.html").read_text(encoding="utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.end_headers()
                self._send_body(content.encode())
            except Exception as e:
                self.send_error(500, "internal error")
            return
        self.send_error(404, "Not Found")

    def _setup_save_user_keys(self, info, form=None, fresh_token=None):
        """POST /setup for a signed-in non-admin user: the setup form saves
        into the user's OWN per-user vault (same store and rules as
        /api/mykeys) — never the shared keys.enc, never the master password.
        The account password both authenticates the save and encrypts the
        vault, exactly like the My Keys save."""
        label = info.get("label", "")
        if not _LABEL_RE.match(label):
            self._set_json_headers(400)
            self.wfile.write(json.dumps({"error": "invalid label"}).encode())
            return
        if form is None:
            length = int(self.headers.get("Content-Length", 0))
            form = parse_qs(self.rfile.read(length).decode())
        password = form.get("password", [""])[0]
        if not password:
            self._set_json_headers(400)
            self.wfile.write(json.dumps({"error": "password required to encrypt your vault"}).encode())
            return
        access = _load_access()
        stored = access.get(label, "")
        ok, needs_up = _verify_password(password, stored)
        if ok and needs_up and label in access:
            access[label] = _hash_password(password)
            _save_access(access)
        if not ok:
            self._set_json_headers(401)
            self.wfile.write(json.dumps({"error": "wrong password"}).encode())
            return
        keys = {}
        for n in PROVIDER_NAMES:
            v = form.get("k_" + n, [""])[0].strip()
            if v:
                keys[n] = v
        import re
        for fk in list(form.keys()):
            m = re.match(r"^cr_name_(\d+)$", fk)
            if m:
                idx = m.group(1)
                name = form.get(fk, [""])[0].strip().lower()
                url = form.get(f"cr_url_{idx}", [""])[0].strip()
                key = form.get(f"cr_key_{idx}", [""])[0].strip()
                if name and url and key and re.match(r"^[a-z0-9_]+$", name):
                    if url.startswith("http://") or url.startswith("https://"):
                        keys[f"custom_relay_{name}"] = key
                        keys[f"custom_relay_{name}_url"] = url
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
        vault = _load_userkeys(label, password) or {}
        vault.update(keys)
        _save_userkeys(label, vault, password)
        for tok, sess in SESSIONS.items():
            if isinstance(sess, dict) and sess.get("label") == label and not sess.get("admin"):
                sess["userkeys"] = dict(vault)
        self.send_response(302)
        self.send_header("Location", "/mykeys")
        if fresh_token:
            # Guest save: the visitor arrived signed out; hand them the
            # session minted by the router so they land signed in.
            self.send_header("Set-Cookie", f"session={fresh_token}; HttpOnly; Secure; SameSite=Lax; Path=/")
        self.end_headers()
        return

    def do_POST(self):
        self._resp_started = False
        try:
            self._do_post()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:
            self._handle_uncaught(exc)

    def _do_post(self):
        # DoS protection: reject bodies over 12 MB (covers image/file uploads)
        try:
            if int(self.headers.get("Content-Length", 0) or 0) > 12 * 1024 * 1024:
                self.send_response(413)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "body too large"}).encode())
                return
        except (ValueError, TypeError):
            pass
        parsed = urlparse(self.path)
        # CSRF defense-in-depth on state-changing POSTs (login excluded: no session yet)
        if parsed.path != "/api/login" and not self._check_origin():
            self._set_json_headers(403)
            self.wfile.write(json.dumps({"error": "origin mismatch"}).encode())
            return
        # Temporary view passes are READ-ONLY: only the whitelisted POST
        # routes may proceed, and the access handler narrows further
        # (viewers may call just list / 2fa_state there). Routing changes
        # are writes, so they are refused here like everything else.
        _pinfo = self._session_info()
        if (_pinfo and _pinfo.get("viewer")
                and parsed.path not in ("/api/access", "/api/logout")):
            self._set_json_headers(403)
            self.wfile.write(json.dumps({"error": "read-only access"}).encode())
            return
        if parsed.path == "/v1/chat/completions":
            # External API (service-key auth, no session): see _V1_LANES.
            self._v1_chat_completions()
            return
        if parsed.path == "/api/v1-access/test":
            self._v1_access_test()
            return
        if parsed.path == "/setup":
            key_path = Path(__file__).parent / "keys.enc"
            keys_exist = key_path.exists()
            # Signed-in users save to their own vault (see GET). Admin and
            # first-time setup keep the original shared-setup path below.
            _su = self._session_info()
            if keys_exist and _su and not _su.get("admin") and not _su.get("viewer"):
                self._setup_save_user_keys(_su)
                return
            # Signed-out normal users (owner order 2026-10-09): the account
            # password in the form identifies the friend — the same
            # password-only rule and the same rate-limit ledger as /api/login
            # — and the save lands in that user's OWN vault; a session is
            # minted so they arrive signed in. The master password never
            # matches here: admin setup stays behind a real admin session.
            if keys_exist and not _su:
                ip = self.client_address[0]
                now = time.time()
                recent = [t for t in _login_attempts.get(ip, []) if now - t < 900]
                if len(recent) >= 10:
                    self._set_json_headers(429)
                    self.wfile.write(json.dumps({"error": "too many attempts, try again later"}).encode())
                    return
                length = int(self.headers.get("Content-Length", 0))
                form = parse_qs(self.rfile.read(length).decode())
                password = form.get("password", [""])[0]
                label = None
                if password:
                    for cand, stored in _load_access().items():
                        ok, _nu = _verify_password(password, stored)
                        if ok:
                            label = cand
                            break
                if not label:
                    recent.append(now)
                    _login_attempts[ip] = recent
                    time.sleep(1)
                    self._set_json_headers(401)
                    self.wfile.write(json.dumps({"error": "wrong password"}).encode())
                    return
                _login_attempts.pop(ip, None)
                token = secrets.token_hex(32)
                SESSIONS[token] = {"ts": time.time(), "label": label, "admin": False}
                self._setup_save_user_keys({"label": label, "admin": False},
                                           form=form, fresh_token=token)
                return
            # If keys already set up, require admin for POST. First-time setup is public.
            if keys_exist and not (self._session_info() or {}).get("admin"):
                self._set_json_headers(403)
                self.wfile.write(json.dumps({"error": "admin only"}).encode())
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
            info = self._session_info()
            if not info:
                self._set_json_headers(401)
                self.wfile.write(json.dumps({"error": "not logged in"}).encode())
                return
            if not info.get("admin"):
                self._set_json_headers(403)
                self.wfile.write(json.dumps({"error": "admin only"}).encode())
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
        if parsed.path == "/api/transcribe":
            # Speech-to-text for the composer mic button (Groq Whisper).
            if not self._require_session():
                return
            _ekeys_t = self._effective_keys()
            if Handler.keys is None and not (_ekeys_t or {}).get("groq"):
                # Transcription needs a Groq key — the owner's (still locked)
                # or the caller's own vault key. With neither available this
                # operation genuinely requires the owner's unlock.
                self._send_locked()
                return
            if not _rl_ok("transcribe", self._get_session(), 12, 60):
                self._set_json_headers(429)
                self.wfile.write(json.dumps({"error": "too many voice inputs, slow down a moment"}).encode())
                return
            content_length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(content_length)
            try:
                data = json.loads(raw)
            except Exception:
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": "invalid JSON"}).encode())
                return
            _gk = (_ekeys_t or {}).get("groq") or ""
            if not _gk:
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": "no Groq key configured for voice input"}).encode())
                return
            _aud = data.get("audio") or ""
            _mime = "audio/webm"
            if _aud.startswith("data:"):
                _hdr, _, _aud = _aud.partition(",")
                _mime = _hdr[5:].split(";")[0] or _mime
            try:
                _raw_audio = base64.b64decode(_aud)
            except Exception:
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": "invalid audio data"}).encode())
                return
            if len(_raw_audio) > 8 * 1024 * 1024:
                self._set_json_headers(413)
                self.wfile.write(json.dumps({"error": "audio too large"}).encode())
                return
            _ext = {"audio/webm": "webm", "audio/mp4": "m4a", "audio/ogg": "ogg", "audio/wav": "wav", "audio/mpeg": "mp3"}.get(_mime, "webm")
            _mdl = data.get("model") or "whisper-large-v3-turbo"
            if "whisper" not in str(_mdl):
                _mdl = "whisper-large-v3-turbo"
            import uuid as _uuid_t
            _b = "----nx" + _uuid_t.uuid4().hex
            _parts = []
            _parts.append(f"--{_b}\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\n{_mdl}\r\n".encode())
            _parts.append(f"--{_b}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"voice.{_ext}\"\r\nContent-Type: {_mime}\r\n\r\n".encode() + _raw_audio + b"\r\n")
            _parts.append(f"--{_b}--\r\n".encode())
            try:
                _rq = Request("https://api.groq.com/openai/v1/audio/transcriptions",
                    data=b"".join(_parts),
                    headers={"Authorization": f"Bearer {_gk}",
                             "Content-Type": f"multipart/form-data; boundary={_b}",
                             "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}, method="POST")
                with urlopen(_rq, timeout=60) as _rs:
                    _txt = json.loads(_rs.read().decode()).get("text", "")
                self._set_json_headers(200)
                self.wfile.write(json.dumps({"text": _txt}).encode())
            except HTTPError as e:
                self._set_json_headers(502)
                self.wfile.write(json.dumps({"error": "transcription failed, try again"}).encode())
            except Exception:
                self._set_json_headers(500)
                self.wfile.write(json.dumps({"error": "transcription failed, try again"}).encode())
            return
        if parsed.path == "/api/chat":
            if not self._require_session():
                return
            # NO blanket lock here. While the owner keys are locked, the
            # effective keys below are exactly the caller's own vault keys,
            # so keyless providers and BYOK lanes keep working; a per-lane
            # gate at dispatch returns the locked 503 only when NO attempt
            # lane can run without the owner's key.
            if not _rl_ok("chat", self._get_session(), 40, 60):
                self._set_json_headers(429)
                self.wfile.write(json.dumps({"error": "you're sending messages too fast — give it a few seconds"}).encode())
                return
            # Effective keys: friend's own vault if they have one, else shared keys
            _ekeys = self._effective_keys()
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
            # Input limits: cap message size so one request can't burn huge token quotas
            if isinstance(message, str) and len(message) > 50000:
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": "message too long (max 50000 chars)"}).encode())
                return
            if image is not None and (not isinstance(image, str) or len(image) > 8 * 1024 * 1024
                                      or not image.startswith("data:image/")):
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": "invalid image"}).encode())
                return
            # Mode-specific message preprocessing
            if mode == "auto":
                # Auto intent detection: route the message to the mode that fits —
                # video / image / voice (media generation), agent (needs current
                # or external facts, or a link to fetch), code, else plain text.
                import re as _re_auto
                ml = (message or "").lower()
                has_url = "http://" in ml or "https://" in ml
                video_kw = ["video of", "make a video", "create a video", "generate a video",
                            "video clip", "text to video", "timelapse", "animate a", "animate this",
                            "animation of", "short film"]
                image_verb = _re_auto.search(r"\b(draw|paint|sketch|generate|create|make|design|render)\b[^.?!]{0,40}\b(image|picture|photo|drawing|painting|artwork|illustration|logo|wallpaper|poster|icon|portrait)\b", ml)
                image_kw = ["image of", "picture of", "photo of", "drawing of", "painting of",
                            "wallpaper of", "logo for", "draw me", "paint me", "sketch me"]
                image_start = _re_auto.match(r"\s*(draw|paint|sketch|illustrate)\b", ml)
                voice_kw = ["read aloud", "read it out", "read this out", "say it out loud",
                            "say aloud", "text to speech", "text-to-speech", "voice note",
                            "speak this", "speak the following"]
                agent_kw = ["search for", "search the web", "look up", "look it up", "find out",
                            "research", "latest news", "current price", "price of", "weather in",
                            "who won", "score of", "news about", "fetch ", "open this link",
                            "check online", "google "]
                code_kw = ["code", "function", "class", "def ", "import ", "debug", "python",
                           "javascript", "java ", " bug", "error in", "script", "algorithm",
                           "write a program", "fix this code"]
                # "Generate lewis hamilton with his f1 car" — a bare create-verb at
                # the start means media generation UNLESS the object is text/code.
                gen_start = _re_auto.match(r"\s*(generate|create|make|render|produce|imagine)\b", ml)
                text_object = any(k in ml for k in ["website", "web page", "webpage", "landing page",
                            " app ", "application", "code", "function", "script", "program", "software",
                            "essay", "story", "poem", "song", "email", "letter", "report", "summary",
                            "resume", "list", "plan", "itinerary", "database", "table", "presentation",
                            "slides", "document", "article", "blog", "video", "audio", "voice", "speech",
                            "recipe", "joke", "quote", "caption", "tweet", "greeting"])
                if any(k in ml for k in video_kw):
                    mode = "video"
                elif any(k in ml for k in voice_kw):
                    mode = "voice"
                elif image_verb or image_start or any(k in ml for k in image_kw) or (gen_start and not text_object):
                    mode = "image"
                elif has_url or any(k in ml for k in agent_kw):
                    mode = "agent"
                elif any(k in ml for k in code_kw):
                    mode = "code"
                else:
                    mode = "text"
            if mode == "code":
                message = ("You are an expert coding assistant. Provide clean, working code with brief explanations. "
                          "Use markdown code blocks with language tags.\n\n" + (message or ""))
            elif mode == "image":
                # Image generation routed by the picked provider/model:
                #   aihorde           -> AI Horde async queue (Pollinations if too slow)
                #   google/relay_gemini -> Gemini native image call (Pollinations on failure)
                #   pollinations/etc  -> Pollinations image service (flux/turbo)
                import urllib.parse as _up2
                _prompt = (message or "").strip()[:1000]
                _img = None
                _used_p, _used_m = provider, model
                def _pollinations(mdl):
                    pm = mdl if mdl in ("flux", "turbo") else "flux"
                    u = ("https://image.pollinations.ai/prompt/" + _up2.quote(_prompt)
                         + f"?width=1024&height=1024&nologo=true&model={pm}&seed={secrets.randbelow(999999) + 1}")
                    # Pollinations is fast but flaky (queue spikes, per-IP rate
                    # limits on shared datacenter IPs) — retry a few times. On
                    # success return the image INLINE as a data URI: a second
                    # browser request to Pollinations often fails (broken image),
                    # while an inlined image always displays. If it still won't
                    # fetch, return the URL anyway as a last resort.
                    for _att in range(3):
                        try:
                            rq = Request(u, headers={"User-Agent": "Mozilla/5.0", "Referer": "https://nexus-local.onrender.com/"})
                            with urlopen(rq, timeout=40) as rs:
                                _ct = rs.headers.get("Content-Type") or ""
                                if rs.status == 200 and "image" in _ct:
                                    _bytes = rs.read()
                                    if _bytes:
                                        return "data:" + _ct.split(";")[0] + ";base64," + base64.b64encode(_bytes).decode()
                        except Exception:
                            pass
                        if _att < 2:
                            time.sleep(3)
                    return u
                try:
                    if provider == "aihorde" and model:
                        try:
                            hk = ((_ekeys or {}).get("aihorde") or "0000000000")
                            sub_req = Request("https://stablehorde.net/api/v2/generate/async",
                                data=json.dumps({"prompt": _prompt,
                                    "params": {"width": 512, "height": 512, "steps": 25, "sampler_name": "k_euler", "n": 1},
                                    "models": [model], "nsfw": False, "censor_nsfw": True}).encode(),
                                headers={"Content-Type": "application/json", "apikey": hk, "Client-Agent": "NexusLocal:1.0"}, method="POST")
                            with urlopen(sub_req, timeout=30) as rs:
                                rid = json.loads(rs.read().decode()).get("id")
                            _t0 = time.time()
                            _deadline = _t0 + 110
                            while rid and time.time() < _deadline:
                                time.sleep(6)
                                chk_req = Request(f"https://stablehorde.net/api/v2/generate/check/{rid}", headers={"Client-Agent": "NexusLocal:1.0"})
                                with urlopen(chk_req, timeout=20) as rs:
                                    chk = json.loads(rs.read().decode())
                                if chk.get("faulted"):
                                    break
                                # Anonymous queue can mean a 5+ min wait — bail to
                                # Pollinations fast instead of holding the user.
                                if (chk.get("wait_time") or 0) > 240 and time.time() > _t0 + 10:
                                    break
                                if chk.get("done"):
                                    st_req = Request(f"https://stablehorde.net/api/v2/generate/status/{rid}", headers={"Client-Agent": "NexusLocal:1.0"})
                                    with urlopen(st_req, timeout=20) as rs:
                                        gens = json.loads(rs.read().decode()).get("generations", [])
                                    if gens and gens[0].get("img"):
                                        _img = gens[0]["img"]
                                        # Inline it like Pollinations — hotlinked
                                        # images can fail to load in the browser.
                                        try:
                                            _irq = Request(_img, headers={"User-Agent": "Mozilla/5.0"})
                                            with urlopen(_irq, timeout=30) as _irs:
                                                _ict = _irs.headers.get("Content-Type") or "image/webp"
                                                _ib = _irs.read()
                                            if _ib:
                                                _img = "data:" + _ict.split(";")[0] + ";base64," + base64.b64encode(_ib).decode()
                                        except Exception:
                                            pass
                                    break
                        except Exception:
                            _img = None
                    elif provider == "cloudflare" and model:
                        try:
                            _ck = (_ekeys or {}).get("cloudflare") or ""
                            _acct, _, _tok = _ck.partition(":")
                            if _acct and _tok:
                                _creq = Request(f"https://api.cloudflare.com/client/v4/accounts/{_acct}/ai/run/{model}",
                                    data=json.dumps({"prompt": _prompt}).encode(),
                                    headers={"Authorization": f"Bearer {_tok}", "Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}, method="POST")
                                with urlopen(_creq, timeout=90) as _crs:
                                    _cd = json.loads(_crs.read().decode())
                                _cimg = (_cd.get("result") or {}).get("image")
                                if _cimg:
                                    _img = "data:image/jpeg;base64," + _cimg
                        except Exception:
                            _img = None
                    elif provider in ("google", "relay_gemini") and model:
                        try:
                            gk = (_ekeys or {}).get("google") or (_ekeys or {}).get("relay_gemini") or ""
                            if gk:
                                gurl = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={_urlquote(gk, safe='')}"
                                gbody = {"contents": [{"parts": [{"text": _prompt}]}], "generationConfig": {"responseModalities": ["TEXT", "IMAGE"]}}
                                greq = Request(gurl, data=json.dumps(gbody).encode(), headers={"Content-Type": "application/json"}, method="POST")
                                with urlopen(greq, timeout=90) as rs:
                                    gd = json.loads(rs.read().decode())
                                for part in gd.get("candidates", [{}])[0].get("content", {}).get("parts", []):
                                    if "inlineData" in part:
                                        _img = "data:" + part["inlineData"]["mimeType"] + ";base64," + part["inlineData"]["data"]
                                        break
                        except Exception:
                            _img = None
                    if not _img:
                        _img = _pollinations(model if provider in ("pollinations", "relay_pollinations") else "flux")
                        if _img and provider not in ("pollinations", "relay_pollinations"):
                            _used_p, _used_m = "pollinations", "flux"
                    if _img:
                        self._set_json_headers(200)
                        self.wfile.write(json.dumps({"reply": f"![Generated image]({_img})", "image_url": _img, "used_provider": _used_p, "used_model": _used_m}).encode())
                    else:
                        self._set_json_headers(502)
                        self.wfile.write(json.dumps({"error": "image generation failed, try again"}).encode())
                except Exception:
                    self._set_json_headers(500)
                    self.wfile.write(json.dumps({"error": "image generation failed, try again"}).encode())
                return
            elif mode == "voice":
                # Text-to-speech via Groq Orpheus (direct call — the relay is
                # text-shaped). Long text is chunked (Orpheus caps ~200 chars
                # per call) and the WAV pieces are merged into one clip.
                import io as _io, wave as _wave, uuid as _uuid, re as _re_v
                _UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
                _text = (message or "").strip()[:1200]
                _prov = provider if provider in ("groq", "relay_groq") else "groq"
                _gk = (_ekeys or {}).get(_prov) or (_ekeys or {}).get("groq") or ""
                _mdl = model if (model and "orpheus" in model) else "canopylabs/orpheus-v1-english"
                _voice = "sami" if "arabic" in _mdl else "troy"
                if not _gk:
                    if Handler.keys is None:
                        # Voice needs a Groq key and none is available
                        # without the owner's unlock (no vault key either).
                        self._send_locked()
                        return
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "no Groq key configured for voice"}).encode())
                    return
                if not _text:
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "type something to speak"}).encode())
                    return
                # Chunk on sentence boundaries, <=180 chars each
                _chunks, _cur = [], ""
                for _piece in _re_v.split(r"(?<=[.!?])\s+", _text):
                    while len(_piece) > 180:
                        if _cur:
                            _chunks.append(_cur); _cur = ""
                        _chunks.append(_piece[:180]); _piece = _piece[180:]
                    if len(_cur) + len(_piece) + 1 > 180:
                        if _cur:
                            _chunks.append(_cur)
                        _cur = _piece
                    else:
                        _cur = (_cur + " " + _piece).strip()
                if _cur:
                    _chunks.append(_cur)
                try:
                    _wavs = []
                    for _c in _chunks[:8]:
                        _rq = Request("https://api.groq.com/openai/v1/audio/speech",
                            data=json.dumps({"model": _mdl, "input": _c, "voice": _voice, "response_format": "wav"}).encode(),
                            headers={"Authorization": f"Bearer {_gk}", "Content-Type": "application/json", **_UA}, method="POST")
                        with urlopen(_rq, timeout=60) as _rs:
                            _wavs.append(_rs.read())
                    # Merge WAV chunks at the byte level (no wave module:
                    # Groq returns a streaming header — RIFF/data sizes are
                    # 0xFFFFFFFF and nframes claims 2.1 billion — which the
                    # stdlib wave reader/writer chokes on, differently across
                    # Python versions). Parse the RIFF chunks manually,
                    # concatenate the PCM, rebuild a clean 44-byte header.
                    import struct as _struct
                    def _parse_wav(_wb):
                        _pos = 12
                        _fmt = None
                        _pcm = b""
                        while _pos + 8 <= len(_wb):
                            _cid = _wb[_pos:_pos + 4]
                            _csz = int.from_bytes(_wb[_pos + 4:_pos + 8], "little")
                            if _cid == b"fmt ":
                                _fmt = _wb[_pos + 8:_pos + 8 + min(_csz, 16)]
                            elif _cid == b"data":
                                _pcm = _wb[_pos + 8:] if _csz >= len(_wb) else _wb[_pos + 8:_pos + 8 + _csz]
                                break
                            _pos += 8 + _csz + (_csz % 2)
                        return _fmt, _pcm
                    _fmt = None
                    _pcm_all = b""
                    for _wb in _wavs:
                        _f, _p = _parse_wav(_wb)
                        if _fmt is None:
                            _fmt = _f
                        _pcm_all += _p
                    if _fmt is None or not _pcm_all:
                        raise ValueError("unparseable wav")
                    _afmt = int.from_bytes(_fmt[0:2], "little")
                    _nch = int.from_bytes(_fmt[2:4], "little")
                    _rate = int.from_bytes(_fmt[4:8], "little")
                    _brate = int.from_bytes(_fmt[8:12], "little")
                    _balign = int.from_bytes(_fmt[12:14], "little")
                    _bits = int.from_bytes(_fmt[14:16], "little")
                    _hdr = (b"RIFF" + _struct.pack("<I", 36 + len(_pcm_all)) + b"WAVEfmt "
                            + _struct.pack("<IHHIIHH", 16, _afmt, _nch, _rate, _brate, _balign, _bits)
                            + b"data" + _struct.pack("<I", len(_pcm_all)))
                    _b64 = base64.b64encode(_hdr + _pcm_all).decode()
                    self._set_json_headers(200)
                    self.wfile.write(json.dumps({"audio": "data:audio/wav;base64," + _b64,
                        "reply": "\U0001f50a " + _text[:120], "used_provider": _prov, "used_model": _mdl}).encode())
                except HTTPError as e:
                    try:
                        _eb = e.read().decode(errors="replace")
                    except Exception:
                        _eb = ""
                    if "terms acceptance" in _eb:
                        _msg = "Voice is one click away: the Orpheus model needs its terms accepted once in the Groq console (console.groq.com -> Playground -> canopylabs/orpheus-v1-english -> Accept)."
                    elif e.code == 429:
                        _msg = "Voice rate limit hit. Try again in a moment."
                    else:
                        _msg = "Voice generation failed. Try again."
                    self._set_json_headers(e.code if e.code in (400, 429) else 502)
                    self.wfile.write(json.dumps({"error": _msg}).encode())
                except Exception:
                    self._set_json_headers(500)
                    self.wfile.write(json.dumps({"error": "voice generation failed, try again"}).encode())
                return
            elif mode == "video":
                # Text-to-video via the official LTX-Video Space on HuggingFace
                # (ZeroGPU free quota tied to the HF token). HF's inference API
                # no longer serves video models for free. Gradio queue protocol:
                # join with a client session_hash, then stream events until done.
                import uuid as _uuid_v
                _prompt_v = (message or "").strip()[:1000]
                _hk = (_ekeys or {}).get("huggingface") or ""
                if not _prompt_v:
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "describe the video you want"}).encode())
                    return
                _BASE = "https://lightricks-ltx-video-distilled.hf.space"
                _H = {"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"}
                if _hk:
                    _H["Authorization"] = f"Bearer {_hk}"
                _sess = _uuid_v.uuid4().hex[:12]
                _neg = "worst quality, inconsistent motion, blurry, jittery, distorted"
                _data = [_prompt_v, _neg, None, None, 512, 704, "text-to-video", 3, 9, 42, True, 1, True]
                try:
                    _rq = Request(_BASE + "/gradio_api/queue/join",
                        data=json.dumps({"data": _data, "fn_index": 4, "session_hash": _sess}).encode(),
                        headers=_H, method="POST")
                    with urlopen(_rq, timeout=60) as _rs:
                        json.loads(_rs.read().decode())
                    _file_url = None
                    _rq2 = Request(_BASE + f"/gradio_api/queue/data?session_hash={_sess}",
                        headers={"User-Agent": "Mozilla/5.0", **({"Authorization": f"Bearer {_hk}"} if _hk else {})})
                    _deadline = time.time() + 240
                    with urlopen(_rq2, timeout=250) as _rs2:
                        for _raw in _rs2:
                            if time.time() > _deadline:
                                break
                            _line = _raw.decode(errors="replace").strip()
                            if not _line.startswith("data:"):
                                continue
                            try:
                                _ev = json.loads(_line[5:])
                            except Exception:
                                continue
                            if _ev.get("msg") == "process_completed":
                                _out = (_ev.get("output") or {}).get("data") or []
                                if _out and isinstance(_out[0], dict):
                                    _file_url = (_out[0].get("video") or {}).get("url")
                                break
                            if _ev.get("msg") == "process_failed" or _ev.get("success") is False:
                                break
                    if not _file_url:
                        self._set_json_headers(502)
                        self.wfile.write(json.dumps({"error": "video generation failed — the free GPU queue may be busy, try again"}).encode())
                        return
                    _rq3 = Request(_file_url, headers={"User-Agent": "Mozilla/5.0"})
                    with urlopen(_rq3, timeout=120) as _rs3:
                        _vid = _rs3.read()
                    if len(_vid) > 14 * 1024 * 1024:
                        self._set_json_headers(502)
                        self.wfile.write(json.dumps({"error": "generated video was too large"}).encode())
                        return
                    _b64 = base64.b64encode(_vid).decode()
                    self._set_json_headers(200)
                    self.wfile.write(json.dumps({"video": "data:video/mp4;base64," + _b64,
                        "reply": "\U0001f3ac " + _prompt_v[:120],
                        "used_provider": "huggingface", "used_model": "Lightricks/LTX-Video"}).encode())
                except Exception:
                    self._set_json_headers(500)
                    self.wfile.write(json.dumps({"error": "video generation failed, try again"}).encode())
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
            # Per-session routing mode (each user has their own)
            _sess = SESSIONS.get(self._get_session() or "", {})
            routing = _sess.get("routing", "quality") if isinstance(_sess, dict) else "quality"
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
            _fallback_candidates = []
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
                    if (_ekeys or {}).get(cand) or cand in RELAY_KEYLESS:
                        cand_model = model or _DEFAULT_MODELS.get(cand, "")
                        if cand_model:
                            _auto_candidates.append((cand, cand_model))
                # Health first: providers recently failing go to the back
                _healthy = [(p, m) for (p, m) in _auto_candidates if not _provider_down(p)]
                _down = [(p, m) for (p, m) in _auto_candidates if _provider_down(p)]
                _auto_candidates = _healthy + _down
                if _auto_candidates:
                    provider, model = _auto_candidates[0]
                # Store remaining for fallback
                _fallback_candidates = _auto_candidates[1:]
            if not provider or not model or not message:
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": "provider, model, message required"}).encode())
                return
            # ---- Failover dispatch ----
            # _attempt() runs ONE provider/model and returns (ok, reply_or_err...).
            # The loop below tries the chosen provider first, then fallbacks, so a
            # dead key / retired model / rate limit routes around automatically.
            def _attempt(prov, mdl, timeout, msgs=None):
                akey = _ekeys.get(prov) if _ekeys else None
                if not akey and prov not in RELAY_KEYLESS:
                    return (False, 400, f"no key configured for {prov}")
                # Cohere uses its native API (not OpenAI-compatible)
                if prov == "cohere":
                    try:
                        cohere_body = {"model": mdl, "message": message}
                        req = Request("https://api.cohere.com/v1/chat",
                                      data=json.dumps(cohere_body).encode(),
                                      headers={"Content-Type": "application/json",
                                               "Authorization": f"Bearer {akey}"},
                                      method="POST")
                        with urlopen(req, timeout=timeout) as resp:
                            resp_data = json.loads(resp.read().decode())
                            return (True, resp_data.get("text", ""))
                    except HTTPError as e:
                        return (False, e.code, f"provider returned an error ({e.code})")
                    except Exception:
                        return (False, 502, "Could not reach the provider.")
                # Base URL per provider type
                if prov.startswith("relay_") or prov in RELAY_UPSTREAMS:
                    base = f"http://127.0.0.1:{RELAY_PORT}/{prov}/v1"
                elif prov == "freellmapi":
                    gw_url = ((_ekeys or {}).get("freellmapi_url") or "").strip()
                    if not gw_url:
                        return (False, 400, "Set your gateway URL in setup")
                    base = gw_url.rstrip("/")
                elif prov.startswith("custom_fl_"):
                    gw_url = ((_ekeys or {}).get("freellmapi_url") or "").strip()
                    if not gw_url:
                        return (False, 400, "Set your gateway URL in setup")
                    base = gw_url.rstrip("/")
                elif prov.startswith("custom_relay_"):
                    cname = prov[len("custom_relay_"):]
                    base = f"http://127.0.0.1:{RELAY_PORT}/{cname}/v1"
                else:
                    return (False, 400, f"chat not supported for {prov} in local version")
                headers = {"Content-Type": "application/json"}
                if prov.startswith("relay_") or prov in RELAY_UPSTREAMS or prov.startswith("custom_relay_"):
                    headers["X-Relay-Token"] = RELAY_TOKEN
                    if akey:
                        headers["X-Vault-Key"] = akey
                if prov == "freellmapi" or prov.startswith("custom_fl_"):
                    headers["Authorization"] = f"Bearer {akey}"
                if prov == "openrouter" or prov == "relay_openrouter":
                    headers["X-Title"] = "NexusLocal"
                body = {
                    "model": mdl,
                    "messages": msgs if msgs else [{"role": "user", "content": ([{"type": "text", "text": message}] + ([{"type": "image_url", "image_url": {"url": image}}] if image else [])) if image else message}],
                    "max_tokens": 4096,
                }
                try:
                    req = Request(f"{base}/chat/completions", data=json.dumps(body).encode(), headers=headers, method="POST")
                    with urlopen(req, timeout=timeout) as resp:
                        resp_data = json.loads(resp.read().decode())
                        reply = resp_data["choices"][0]["message"]["content"]
                        usage = resp_data.get("usage", {})
                        _append_usage({
                            "ts": datetime.datetime.now().isoformat(),
                            "provider": prov, "model": mdl,
                            "prompt_tokens": usage.get("prompt_tokens", 0),
                            "completion_tokens": usage.get("completion_tokens", 0),
                        })
                        return (True, reply)
                except HTTPError as e:
                    if e.code == 503:
                        msg = "Provider is temporarily overloaded. Try again in a moment."
                    elif e.code == 429:
                        msg = "Rate limit hit. Try again in a moment."
                    elif e.code == 402:
                        msg = "This model requires payment. Try a different model."
                    elif e.code in (401, 403):
                        msg = "Provider rejected the request. Check the API key."
                    elif e.code == 404:
                        msg = "Model not found for this provider."
                    else:
                        msg = f"Provider returned an error ({e.code})."
                    return (False, e.code if e.code in (401, 403, 404, 429, 503) else 502, msg)
                except URLError:
                    return (False, 502, "Could not reach the provider.")
                except Exception:
                    return (False, 500, "server error, try again")

            # Build the attempt list: chosen provider first, then fallbacks.
            _attempts = [(provider, model)]
            _fb = list(_fallback_candidates)
            if not _fb:
                # Explicit pick: fall back across known-good providers (default models),
                # skipping any currently marked down.
                _pref = ["relay_openrouter", "openrouter", "groq", "relay_groq",
                         "google", "relay_gemini", "mistral", "cohere",
                         "nvidia", "relay_nvidia", "pollinations", "relay_pollinations"]
                for cand in _pref:
                    if cand == provider:
                        continue
                    cm = _DEFAULT_MODELS.get(cand, "")
                    if cm and ((_ekeys or {}).get(cand) or cand in RELAY_KEYLESS):
                        _fb.append((cand, cm))
            healthy = [(p, m) for (p, m) in _fb if not _provider_down(p)]
            _attempts += (healthy if healthy else _fb)
            if Handler.keys is None:
                # Locked server: _ekeys holds ONLY the caller's own vault
                # keys, so an attempt lane can run iff it is keyless or
                # vault-keyed (gateway lanes also need the gateway URL,
                # which lives in the owner's key store). If no lane can
                # run, this request genuinely requires the owner's unlock.
                def _lane_open(p):
                    if p in RELAY_KEYLESS:
                        return True
                    if not (_ekeys or {}).get(p):
                        return False
                    if p == "freellmapi" or p.startswith("custom_fl_"):
                        return bool((_ekeys or {}).get("freellmapi_url"))
                    return True
                if not any(_lane_open(p) for p, _m in _attempts):
                    self._send_locked()
                    return
            if mode == "agent":
                # Agentic mode: the model can call tools (web search via Bing,
                # guarded page fetch, exact calculator) in a loop before answering.
                import re as _re_a, html as _html_a, socket as _sock_a, ipaddress as _ip_a, ast as _ast_a, operator as _op_a, urllib.parse as _uparse_a, urllib.request as _ureq_a
                _BROWSER_UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"}
                def _clean(s):
                    return _html_a.unescape(_re_a.sub(r"<[^>]+>", "", s or "")).strip()
                def _tool_search(query):
                    q = _uparse_a.quote_plus(str(query)[:200])
                    req = Request(f"https://www.bing.com/search?q={q}&count=6", headers=_BROWSER_UA)
                    with urlopen(req, timeout=25) as r:
                        page = r.read().decode(errors="replace")
                    out = []
                    for block in page.split('<li class="b_algo"')[1:7]:
                        m = _re_a.search(r'<h2><a href="([^"]+)"[^>]*>(.*?)</a></h2>', block, _re_a.S)
                        if not m:
                            continue
                        url = _html_a.unescape(m.group(1))
                        um = _re_a.search(r"[?&]u=a1([A-Za-z0-9_-]+)", url)
                        if um:
                            try:
                                url = base64.b64decode(um.group(1) + "==").decode(errors="replace")
                            except Exception:
                                pass
                        sn = _re_a.search(r"<p[^>]*>(.*?)</p>", block, _re_a.S)
                        out.append(f"- {_clean(m.group(2))}\n  {url}\n  {_clean(sn.group(1))[:300] if sn else ''}")
                    return "\n".join(out) if out else "No results found."
                def _safe_url(u):
                    p = _uparse_a.urlparse(str(u))
                    if p.scheme not in ("http", "https") or not p.hostname:
                        return False
                    host = p.hostname.lower()
                    if host == "localhost":
                        return False
                    try:
                        infos = _sock_a.getaddrinfo(host, None)
                    except Exception:
                        return False
                    for info in infos:
                        ip = _ip_a.ip_address(info[4][0])
                        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                            return False
                    return True
                class _GuardedRedirect(_ureq_a.HTTPRedirectHandler):
                    def redirect_request(self, req, fp, code, msg, headers, newurl):
                        if not _safe_url(newurl):
                            return None
                        return super().redirect_request(req, fp, code, msg, headers, newurl)
                def _tool_fetch(url):
                    if not _safe_url(url):
                        return "Blocked: URL is not a public web address."
                    opener = _ureq_a.build_opener(_GuardedRedirect)
                    req = Request(str(url)[:2000], headers=_BROWSER_UA)
                    with opener.open(req, timeout=20) as r:
                        raw = r.read(1500000)
                    text = raw.decode(errors="replace")
                    text = _re_a.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", text)
                    text = _clean(text)
                    text = _re_a.sub(r"\s+", " ", text)
                    return text[:8000] if text else "Page had no readable text."
                _OPS = {_ast_a.Add: _op_a.add, _ast_a.Sub: _op_a.sub, _ast_a.Mult: _op_a.mul, _ast_a.Div: _op_a.truediv, _ast_a.Mod: _op_a.mod, _ast_a.Pow: _op_a.pow, _ast_a.USub: _op_a.neg, _ast_a.FloorDiv: _op_a.floordiv}
                def _calc(node):
                    if isinstance(node, _ast_a.Expression):
                        return _calc(node.body)
                    if isinstance(node, _ast_a.Constant) and isinstance(node.value, (int, float)):
                        return node.value
                    if isinstance(node, _ast_a.BinOp) and type(node.op) in _OPS:
                        return _OPS[type(node.op)](_calc(node.left), _calc(node.right))
                    if isinstance(node, _ast_a.UnaryOp) and type(node.op) in _OPS:
                        return _OPS[type(node.op)](_calc(node.operand))
                    raise ValueError("unsupported expression")
                def _tool_calc(expr):
                    return str(_calc(_ast_a.parse(str(expr)[:200], mode="eval")))
                _TOOLS = {"web_search": _tool_search, "fetch_url": _tool_fetch, "calculate": _tool_calc}
                _sys = ("You are Nexus Agent, an assistant with tools. To use a tool, reply with ONLY a fenced block like:\n"
                        "```tool\n{\"name\": \"web_search\", \"args\": {\"query\": \"...\"}}\n```\n"
                        "Tools: web_search {query} - search the web; fetch_url {url} - read a web page; calculate {expression} - exact math.\n"
                        "Use tools when facts may be current or external, or for exact math. One tool per reply. "
                        "When you have enough information, answer normally with the final answer (no tool block).")
                _msgs = [{"role": "system", "content": _sys}, {"role": "user", "content": message}]
                _agent_list = [(p, m) for (p, m) in _attempts if p != "cohere"] or _attempts
                _used_tools = []
                _final = None
                _ap2, _am2 = _agent_list[0]
                for _round in range(5):
                    _ok = False
                    _reply = ""
                    for (_cp, _cm) in _agent_list[:3]:
                        _res = _attempt(_cp, _cm, 60, _msgs)
                        if _res[0]:
                            _ok = True
                            _ap2, _am2 = _cp, _cm
                            _reply = _res[1]
                            break
                        _note_failure(_cp)
                    if not _ok:
                        self._set_json_headers(502)
                        self.wfile.write(json.dumps({"error": "agent could not reach a model, try again"}).encode())
                        return
                    _note_success(_ap2)
                    _tm = _re_a.search(r"```tool\s*(\{.*?\})\s*```", _reply or "", _re_a.S)
                    if not _tm:
                        _final = _reply
                        break
                    try:
                        _call = json.loads(_tm.group(1))
                        _tname = _call.get("name", "")
                        _targs = _call.get("args", {}) or {}
                    except Exception:
                        _tname, _targs = "", {}
                    _fn = _TOOLS.get(_tname)
                    if not _fn:
                        _tres = "Unknown tool. Available: web_search, fetch_url, calculate."
                        _used_tools.append(_tname or "?")
                        _arg = ""
                    else:
                        try:
                            _arg = _targs.get("query") or _targs.get("url") or _targs.get("expression") or ""
                            _tres = _fn(_arg)
                        except Exception as _te:
                            _tres = f"Tool error: {type(_te).__name__}"
                            _arg = ""
                        _used_tools.append(f"{_tname}({str(_arg)[:60]})")
                    _msgs.append({"role": "assistant", "content": _reply})
                    _msgs.append({"role": "user", "content": f"Tool result ({_tname}):\n{str(_tres)[:7000]}\n\nContinue: use another tool if needed, else give the final answer."})
                if _final is None:
                    _msgs.append({"role": "user", "content": "Give your final answer now, without any tool block."})
                    _res = _attempt(_ap2, _am2, 60, _msgs)
                    _final = _res[1] if _res[0] else "I couldn't complete that. Try again."
                if _used_tools:
                    _final = (_final or "") + "\n\n---\n\U0001f527 Tools used: " + ", ".join(_used_tools)
                self._set_json_headers(200)
                self.wfile.write(json.dumps({"reply": _final, "used_provider": _ap2, "used_model": _am2}).encode())
                return
            _last = (502, "Could not reach the provider.")
            _answered = None
            for _i, (_ap, _am) in enumerate(_attempts[:4]):
                _ok, *_rest = _attempt(_ap, _am, 45 if _i == 0 else 30)
                if _ok:
                    _note_success(_ap)
                    _answered = (_ap, _am, _rest[0])
                    break
                _note_failure(_ap)
                _last = (_rest[0], _rest[1])
            if _answered:
                self._set_json_headers(200)
                self.wfile.write(json.dumps({"reply": _answered[2],
                                             "used_provider": _answered[0],
                                             "used_model": _answered[1]}).encode())
            else:
                self._set_json_headers(_last[0])
                self.wfile.write(json.dumps({"error": _last[1]}).encode())
            return
        if parsed.path == "/api/refresh":
            if not self._require_admin():
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
                    req = Request(base + "/models", headers={"User-Agent": "Mozilla/5.0", "X-Relay-Token": RELAY_TOKEN})
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
            # Step 2 of 2FA: verify TOTP code with pending token
            # NOTE: only consume the pending token on SUCCESS so wrong codes can be retried
            if data.get("tmp") and data.get("code"):
                tmp = data["tmp"]
                # Rate limit: max 10 code attempts per 5 min per pending token
                now = time.time()
                attempts = [t for t in _2FA_ATTEMPTS.get(tmp, []) if now - t < 300]
                if len(attempts) >= 10:
                    _pend0 = _PENDING_2FA.pop(tmp, None)
                    if _pend0:
                        _drop_chat_unlock(_pend0.get("chat_unlock"))
                    self._set_json_headers(429)
                    self.wfile.write(json.dumps({"error": "too many attempts, start login again"}).encode())
                    return
                pend = _PENDING_2FA.get(tmp)
                if not pend or now - pend["ts"] > 300:
                    if pend:
                        _drop_chat_unlock(pend.get("chat_unlock"))
                    _PENDING_2FA.pop(tmp, None)
                    _2FA_ATTEMPTS.pop(tmp, None)
                    self._set_json_headers(401)
                    self.wfile.write(json.dumps({"error": "2FA session expired, log in again"}).encode())
                    return
                # Pending session holds already-decrypted keys (no password stored)
                dec_keys = pend.get("keys")
                secret = (dec_keys or {}).get("_totp_secret", "")
                _step = _totp_match_step(secret, data["code"]) if secret else None
                if _step is None or _step <= _TOTP_LAST_STEP["v"]:
                    attempts.append(now)
                    _2FA_ATTEMPTS[tmp] = attempts
                    # Prune stale trackers
                    for k in [k for k, v in _2FA_ATTEMPTS.items()
                              if not v or now - v[-1] > 300]:
                        _2FA_ATTEMPTS.pop(k, None)
                    self._set_json_headers(401)
                    self.wfile.write(json.dumps({"error": "wrong 2FA code"}).encode())
                    return
                _TOTP_LAST_STEP["v"] = _step  # this code can never be replayed
                _PENDING_2FA.pop(tmp, None)  # consume only on success
                _2FA_ATTEMPTS.pop(tmp, None)
                _login_attempts.pop(ip, None)
                token = secrets.token_hex(32)
                sess = {"ts": time.time(), "label": "Rudra", "admin": True}
                # Chat authorization travels as the opaque unlock handle
                # minted at the password step — never the password itself.
                _uid = pend.get("chat_unlock")
                if _uid and _uid in _CHAT_UNLOCKS:
                    sess["chat_unlock"] = _uid
                    _bind_chat_unlock(_uid, token)
                SESSIONS[token] = sess
                Handler.keys = dec_keys
                register_custom_providers(dec_keys)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Set-Cookie", f"session={token}; HttpOnly; Secure; SameSite=Lax; Path=/")
                self.end_headers()
                self.wfile.write(json.dumps({"ok": True, "admin": True, "label": "Rudra"}).encode())
                return
            password = data.get("password")
            if not password:
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": "password required"}).encode())
                return
            key_path = Path(__file__).parent / "keys.enc"
            try:
                dec_keys = decrypt_keys(key_path, password)
                master_ok = True
            except Exception:
                master_ok = False
                dec_keys = None
            if master_ok:
                label, is_admin = "Rudra", True
            else:
                access = _load_access()
                label = None
                for l, h in access.items():
                    ok, needs_up = _verify_password(password, h)
                    if ok:
                        label = l
                        if needs_up:
                            # Legacy unsalted hash — upgrade in place (the
                            # encrypted backup refreshes on the next
                            # master-password save; access.json covers the
                            # running instance).
                            access[l] = _hash_password(password)
                            _save_access(access)
                        break
                if not label:
                    recent.append(now)
                    _login_attempts[ip] = recent
                    time.sleep(1)
                    self._set_json_headers(401)
                    self.wfile.write(json.dumps({"error": "wrong password"}).encode())
                    return
                is_admin = False
                # Friends may log in even before the admin unlock: their
                # session simply can't use provider keys until then (the
                # chat/transcribe/models endpoints say so clearly).
            # Successful
            _login_attempts.pop(ip, None)
            if master_ok and dec_keys.get("_totp_secret"):
                # 2FA enabled for admin — issue pending token, ask for code.
                # Restore access list now (we have the password); pending holds
                # decrypted keys only, never the plaintext password.
                _restore_access(password)
                tmp = secrets.token_hex(16)
                # Mint the admin chat unlock NOW, while the proven master
                # password is in scope; only its opaque handle is kept in
                # the pending record (the DEK stays in _CHAT_UNLOCKS).
                _uid = _create_admin_chat_unlock(password)
                _PENDING_2FA[tmp] = {"ts": time.time(), "keys": dec_keys, "chat_unlock": _uid}
                for k in [k for k, v in _PENDING_2FA.items() if time.time() - v["ts"] > 300]:
                    _drop_chat_unlock(_PENDING_2FA[k].get("chat_unlock"))
                    del _PENDING_2FA[k]
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"ok": True, "need_2fa": True, "tmp": tmp}).encode())
                return
            token = secrets.token_hex(32)
            sess = {"ts": time.time(), "label": label, "admin": is_admin}
            if is_admin:
                # Same wrapped-DEK chat unlock as the 2FA path: the master
                # password itself is never stored in an admin session.
                _uid = _create_admin_chat_unlock(password)
                if _uid:
                    sess["chat_unlock"] = _uid
                    _bind_chat_unlock(_uid, token)
            else:
                sess["chat_pw"] = password
                # Load friend's personal key vault (if they added their own keys)
                uk = _load_userkeys(label, password)
                if uk:
                    sess["userkeys"] = uk
            SESSIONS[token] = sess
            if master_ok:
                Handler.keys = dec_keys
                register_custom_providers(dec_keys)
                # Restore friend access list if a redeploy wiped access.json
                _restore_access(password)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            cookie = f"session={token}; HttpOnly; Secure; SameSite=Lax; Path=/"
            self.send_header("Set-Cookie", cookie)
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True, "admin": is_admin, "label": label}).encode())
            return
        if parsed.path == "/api/logout":
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            token = cookie.get("session").value if cookie.get("session") else None
            if token and token in SESSIONS:
                _old = SESSIONS[token]
                _drop_chat_unlock(_old.get("chat_unlock") if isinstance(_old, dict) else None)
                del SESSIONS[token]
            # Expire cookie
            self.send_response(200)
            self.send_header("Set-Cookie", "session=; Max-Age=0; Secure; Path=/")
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True}).encode())
            return
        if parsed.path == "/api/routing":
            if not self._require_session():
                return
            content_length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(content_length) if content_length else b"{}"
            try:
                data = json.loads(raw)
            except Exception:
                data = {}
            mode = data.get("set", "")
            if mode not in ("quality", "save", "auto"):
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": "invalid routing mode"}).encode())
                return
            if mode in ("quality", "save", "auto"):
                token = self._get_session()
                if token and token in SESSIONS:
                    sess = SESSIONS[token]
                    if isinstance(sess, dict):
                        sess["routing"] = mode
            self._set_json_headers()
            self.wfile.write(json.dumps({"ok": True, "routing": mode}).encode())
            return
        if parsed.path == "/api/access":
            content_length = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(content_length) if content_length else b"{}"
            try:
                data = json.loads(raw_body)
            except Exception:
                data = {}
            if not isinstance(data, dict):
                data = {}
            action = data.get("action", "list")
            _ainfo = self._session_info()
            if _ainfo and _ainfo.get("viewer"):
                # Viewers may only READ here: the friend list / sessions
                # and the 2FA state line the admin page renders.
                if action not in ("list", "2fa_state"):
                    self._set_json_headers(403)
                    self.wfile.write(json.dumps({"error": "read-only access"}).encode())
                    return
            elif not self._require_admin():
                return
            if action == "list":
                access = _load_access()
                sessions = []
                for tok, sess in SESSIONS.items():
                    if isinstance(sess, dict):
                        sessions.append({"label": sess.get("label", "?"), "admin": sess.get("admin", False)})
                self._set_json_headers()
                self.wfile.write(json.dumps({
                    "access": [{"label": l} for l in sorted(access.keys())],
                    "sessions": sessions,
                }).encode())
                return
            if action == "viewpass_create":
                master_pw = data.get("master_pw") or ""
                try:
                    decrypt_keys(Path(__file__).parent / "keys.enc", master_pw)
                except Exception:
                    self._set_json_headers(401)
                    self.wfile.write(json.dumps({"error": "wrong master password"}).encode())
                    return
                name = (data.get("name") or "").strip()
                hours = data.get("hours")
                if not _VIEWPASS_NAME_RE.match(name):
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "name must be 1-24 chars (letters, numbers, spaces, - _)"}).encode())
                    return
                if hours not in _VIEWPASS_HOURS:
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "duration must be 1, 6 or 24 hours"}).encode())
                    return
                _sweep_view_grants()
                if len(_VIEW_GRANTS) >= _VIEWPASS_MAX:
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "too many active view passes (max 5) — revoke one first"}).encode())
                    return
                raw_token = secrets.token_urlsafe(32)
                now = time.time()
                _VIEW_GRANTS[hashlib.sha256(raw_token.encode()).hexdigest()] = {
                    "name": name, "created": now, "expires": now + hours * 3600}
                self._set_json_headers()
                self.wfile.write(json.dumps({
                    "ok": True, "url": f"/view/{raw_token}",
                    "expires": now + hours * 3600}).encode())
                return
            if action == "viewpass_list":
                _sweep_view_grants()
                grants = []
                for h, g in sorted(_VIEW_GRANTS.items(),
                                   key=lambda kv: kv[1]["created"]):
                    grants.append({
                        "id": h[:12], "name": g["name"],
                        "created": g["created"], "expires": g["expires"],
                        "watching": sum(
                            1 for s in SESSIONS.values()
                            if isinstance(s, dict) and s.get("grant") == h),
                    })
                self._set_json_headers()
                self.wfile.write(json.dumps({"ok": True, "grants": grants}).encode())
                return
            if action == "viewpass_revoke":
                master_pw = data.get("master_pw") or ""
                try:
                    decrypt_keys(Path(__file__).parent / "keys.enc", master_pw)
                except Exception:
                    self._set_json_headers(401)
                    self.wfile.write(json.dumps({"error": "wrong master password"}).encode())
                    return
                gid = data.get("id") or ""
                target = next((h for h in _VIEW_GRANTS
                               if len(gid) >= 8 and h.startswith(gid)), None)
                if not target:
                    self._set_json_headers(404)
                    self.wfile.write(json.dumps({"error": "view pass not found"}).encode())
                    return
                del _VIEW_GRANTS[target]
                # Kill any live viewer sessions riding on this pass.
                for tok in [t for t, s in SESSIONS.items()
                            if isinstance(s, dict) and s.get("grant") == target]:
                    del SESSIONS[tok]
                self._set_json_headers()
                self.wfile.write(json.dumps({"ok": True}).encode())
                return
            if action == "add":
                label = (data.get("label") or "").strip().lower()
                password = data.get("password") or ""
                master_pw = data.get("master_pw") or ""
                if not label or not password or len(password) < 6:
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "label and password (min 6 chars) required"}).encode())
                    return
                if not _LABEL_RE.match(label):
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "label must be a-z, 0-9, _ (max 30 chars)"}).encode())
                    return
                if not master_pw:
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "master password required to persist"}).encode())
                    return
                access = _load_access()
                if label in access or label.lower() == "rudra":
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "label already exists"}).encode())
                    return
                # Verify master password by decrypting keys.enc
                try:
                    decrypt_keys(Path(__file__).parent / "keys.enc", master_pw)
                except Exception:
                    self._set_json_headers(401)
                    self.wfile.write(json.dumps({"error": "wrong master password"}).encode())
                    return
                access[label] = _hash_password(password)
                _save_access(access, master_pw)
                self._set_json_headers()
                self.wfile.write(json.dumps({"ok": True}).encode())
                return
            if action == "revoke":
                label = (data.get("label") or "").strip()
                master_pw = data.get("master_pw") or ""
                if not master_pw:
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "master password required"}).encode())
                    return
                access = _load_access()
                # Match stored label case-insensitively (labels keep original case)
                stored_label = None
                for k in access.keys():
                    if k.lower() == label.lower():
                        stored_label = k
                        break
                if stored_label is not None:
                    label = stored_label
                    # Verify master password by decrypting keys.enc
                    try:
                        decrypt_keys(Path(__file__).parent / "keys.enc", master_pw)
                    except Exception:
                        self._set_json_headers(401)
                        self.wfile.write(json.dumps({"error": "wrong master password"}).encode())
                        return
                    del access[label]
                    _save_access(access, master_pw)
                    # Delete their personal key vault too
                    try:
                        vp = _userkey_path(label)
                        if vp.exists():
                            vp.unlink()
                    except Exception:
                        pass
                    # And their saved chats
                    try:
                        cp = _chat_path(label)
                        if cp.exists():
                            cp.unlink()
                    except Exception:
                        pass
                    for tok in [t for t, s in SESSIONS.items()
                                if isinstance(s, dict) and s.get("label") == label]:
                        del SESSIONS[tok]
                self._set_json_headers()
                self.wfile.write(json.dumps({"ok": True}).encode())
                return
            if action == "change_master":
                # Rotate the master password: re-encrypt BOTH vaults (provider
                # keys incl. the TOTP secret, and the friend access blob) with
                # the new password, then sign out every session so the old
                # password is dead everywhere.
                cur = data.get("master_pw") or ""
                new = data.get("new_master_pw") or ""
                if len(new) < 10:
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "new password must be at least 10 characters"}).encode())
                    return
                if new == cur:
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "new password must be different"}).encode())
                    return
                key_path = Path(__file__).parent / "keys.enc"
                try:
                    kd = decrypt_keys(key_path, cur)
                except Exception:
                    self._set_json_headers(401)
                    self.wfile.write(json.dumps({"error": "wrong master password"}).encode())
                    return
                encrypt_keys(kd, new, key_path)
                _save_access(_load_access(), new)
                # Admin saved chats: re-wrap their DEK under the NEW
                # password (chat data stays encrypted under the same DEK).
                # A legacy password-direct store is migrated to v2 under
                # the new password. A store that cannot be opened with the
                # current password is left byte-identical — never
                # overwritten with an empty one.
                _chats_note = ""
                try:
                    _cp = _chat_path("Rudra")
                    if _cp.exists():
                        _env = json.loads(_cp.read_text(encoding="utf-8"))
                        if isinstance(_env, dict) and _env.get("v") == 2:
                            _dek = decrypt_raw(_chat_kek(cur, _b64d(_env["wrap_salt"])),
                                               _b64d(_env["wrap_nonce"]),
                                               _b64d(_env["wrapped_dek"]),
                                               _CHAT_V2_AAD_WRAP)
                            _ws = os.urandom(16)
                            _wn, _wc = encrypt_raw(_chat_kek(new, _ws), _dek,
                                                   _CHAT_V2_AAD_WRAP)
                            _env["wrap_salt"] = _b64e(_ws)
                            _env["wrap_nonce"] = _b64e(_wn)
                            _env["wrapped_dek"] = _b64e(_wc)
                            _write_chat_file_atomic(_cp, _env)
                        else:
                            _legacy = decrypt_keys(_cp, cur)
                            if isinstance(_legacy, dict) and isinstance(_legacy.get("chats"), list):
                                _dek, _fields = _wrap_new_dek(new)
                                _save_admin_chats({"dek": _dek, **_fields}, _legacy)
                except Exception:
                    _chats_note = "; saved chats could not be carried over and were left unchanged"
                Handler.keys = kd
                SESSIONS.clear()
                _CHAT_UNLOCKS.clear()
                self._set_json_headers()
                self.wfile.write(json.dumps({"ok": True, "note": "password changed; all sessions signed out" + _chats_note}).encode())
                return
            if action == "2fa_state":
                # Session-based status for the admin panel: Handler.keys was
                # decrypted at this admin's own login, so it mirrors the live
                # keys file — the panel can show the truth on load without
                # asking for the master password again.
                self._set_json_headers()
                self.wfile.write(json.dumps({"enabled": bool(Handler.keys and Handler.keys.get("_totp_secret")),
                               "pending": bool(Handler.keys and Handler.keys.get("_totp_pending"))}).encode())
                return
            if action == "2fa_status":
                try:
                    keys = decrypt_keys(Path(__file__).parent / "keys.enc",
                                        (data.get("master_pw") or ""))
                except Exception:
                    self._set_json_headers(401)
                    self.wfile.write(json.dumps({"error": "wrong master password"}).encode())
                    return
                self._set_json_headers()
                self.wfile.write(json.dumps({"enabled": bool(keys.get("_totp_secret")),
                                             "pending": bool(keys.get("_totp_pending"))}).encode())
                return
            if action == "2fa_enable":
                master_pw = data.get("master_pw") or ""
                try:
                    key_path = Path(__file__).parent / "keys.enc"
                    keys = decrypt_keys(key_path, master_pw)
                except Exception:
                    self._set_json_headers(401)
                    self.wfile.write(json.dumps({"error": "wrong master password"}).encode())
                    return
                secret = _totp_secret()
                # PENDING only — 2FA activates after a code verifies (2fa_confirm).
                # Prevents lockout if the QR/secret was entered wrong.
                keys["_totp_pending"] = secret
                encrypt_keys(keys, master_pw, key_path)
                os.chmod(key_path, 0o600)
                if Handler.keys is not None:
                    Handler.keys["_totp_pending"] = secret
                otpauth = (f"otpauth://totp/NexusLocal:admin?secret={secret}"
                           f"&issuer=NexusLocal")
                self._set_json_headers()
                self.wfile.write(json.dumps({"ok": True, "secret": secret,
                                             "otpauth": otpauth, "pending": True}).encode())
                return
            if action == "2fa_confirm":
                # Verify a code against the pending secret; only then activate.
                master_pw = data.get("master_pw") or ""
                code = (data.get("code") or "").strip()
                try:
                    key_path = Path(__file__).parent / "keys.enc"
                    keys = decrypt_keys(key_path, master_pw)
                except Exception:
                    self._set_json_headers(401)
                    self.wfile.write(json.dumps({"error": "wrong master password"}).encode())
                    return
                pending = keys.get("_totp_pending", "")
                if not pending:
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "no pending 2FA setup"}).encode())
                    return
                if not code or not _totp_verify(pending, code):
                    self._set_json_headers(401)
                    self.wfile.write(json.dumps({"error": "wrong code — check your authenticator app"}).encode())
                    return
                keys["_totp_secret"] = pending
                keys.pop("_totp_pending", None)
                encrypt_keys(keys, master_pw, key_path)
                os.chmod(key_path, 0o600)
                if Handler.keys is not None:
                    Handler.keys["_totp_secret"] = pending
                    Handler.keys.pop("_totp_pending", None)
                self._set_json_headers()
                self.wfile.write(json.dumps({"ok": True, "enabled": True}).encode())
                return
            if action == "2fa_disable":
                master_pw = data.get("master_pw") or ""
                code = data.get("code") or ""
                try:
                    key_path = Path(__file__).parent / "keys.enc"
                    keys = decrypt_keys(key_path, master_pw)
                except Exception:
                    self._set_json_headers(401)
                    self.wfile.write(json.dumps({"error": "wrong master password"}).encode())
                    return
                secret = keys.get("_totp_secret", "")
                if secret and not _totp_verify(secret, code):
                    self._set_json_headers(401)
                    self.wfile.write(json.dumps({"error": "wrong 2FA code"}).encode())
                    return
                keys.pop("_totp_secret", None)
                keys.pop("_totp_pending", None)
                encrypt_keys(keys, master_pw, key_path)
                os.chmod(key_path, 0o600)
                if Handler.keys is not None:
                    Handler.keys.pop("_totp_secret", None)
                    Handler.keys.pop("_totp_pending", None)
                self._set_json_headers()
                self.wfile.write(json.dumps({"ok": True}).encode())
                return
            self._set_json_headers(400)
            self.wfile.write(json.dumps({"error": "unknown action"}).encode())
            return
        if parsed.path == "/api/chats":
            # Saved conversations, per user, encrypted with their login
            # password. Actions: list / get / save / delete.
            info = self._session_info()
            if not info:
                self._set_json_headers(401)
                self.wfile.write(json.dumps({"error": "not logged in"}).encode())
                return
            label = info.get("label", "")
            _admin_rec = None
            chat_pw = None
            if info.get("admin"):
                # Admin chats authorize via the wrapped-DEK unlock minted
                # at login: the session holds only an opaque handle, bound
                # to this exact session token. No master password is (or
                # can be) reconstructed here.
                _uid = info.get("chat_unlock")
                _rec = _CHAT_UNLOCKS.get(_uid) if _uid else None
                _tok = self._get_session()
                if (label != "Rudra" or not _rec or not _rec.get("admin")
                        or _rec.get("label") != "Rudra"
                        or _rec.get("bound_token") != _tok
                        or _rec.get("expires", 0) <= time.time()):
                    if _rec and _rec.get("expires", 0) <= time.time():
                        _drop_chat_unlock(_uid)
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "chat storage unavailable in this session — log in again"}).encode())
                    return
                _admin_rec = _rec
            else:
                chat_pw = info.get("chat_pw")
                if not chat_pw:
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "chat storage unavailable in this session — log in again"}).encode())
                    return
            content_length = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(content_length) if content_length else b"{}"
            try:
                data = json.loads(raw_body)
            except Exception:
                data = {}
            action = data.get("action", "list")
            if _admin_rec is not None:
                try:
                    store = _load_admin_chats_strict(_admin_rec["dek"])
                except Exception:
                    # Fail closed: an undecryptable admin store is NOT an
                    # empty store — a save here would destroy the history.
                    self._set_json_headers(500)
                    self.wfile.write(json.dumps({"error": "saved chats could not be decrypted"}).encode())
                    return
            else:
                store = _load_chats(label, chat_pw)
            chats = store.get("chats", [])

            def _persist():
                if _admin_rec is not None:
                    _save_admin_chats(_admin_rec, store)
                else:
                    _save_chats(label, store, chat_pw)
            if action == "list":
                out = [{"id": c.get("id"), "title": c.get("title", "Chat"),
                        "ts": c.get("ts", 0), "updated": c.get("updated", 0),
                        "count": len(c.get("messages", []))}
                       for c in sorted(chats, key=lambda c: -c.get("updated", 0))]
                self._set_json_headers()
                self.wfile.write(json.dumps({"chats": out}).encode())
                return
            if action == "get":
                cid = str(data.get("id") or "")
                found = next((c for c in chats if c.get("id") == cid), None)
                if not found:
                    self._set_json_headers(404)
                    self.wfile.write(json.dumps({"error": "chat not found"}).encode())
                    return
                self._set_json_headers()
                self.wfile.write(json.dumps({"chat": found}).encode())
                return
            if action == "save":
                import re as _re2
                msgs_in = data.get("messages")
                if not isinstance(msgs_in, list) or not msgs_in:
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "no messages"}).encode())
                    return
                msgs = []
                for m in msgs_in[:200]:
                    if not isinstance(m, dict):
                        continue
                    t = m.get("t")
                    if not isinstance(t, str) or not t:
                        continue
                    # Media data URIs are far too large to persist; note them.
                    t = _re2.sub(r"data:[A-Za-z0-9/;,=+_-]{40000,}", "[media too large to store]", t)
                    item = {"r": "user" if m.get("r") == "user" else "ai",
                            "t": t[:120000]}
                    if isinstance(m.get("m"), str) and m.get("m"):
                        item["m"] = m["m"][:200]
                    msgs.append(item)
                if not msgs:
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "no messages"}).encode())
                    return
                title = str(data.get("title") or "").strip()
                if not title:
                    first = next((m["t"] for m in msgs if m["r"] == "user"), "Chat")
                    title = first[:48]
                now = int(time.time())
                cid = str(data.get("id") or "")
                existing = next((c for c in chats if c.get("id") == cid), None) if cid else None
                if existing:
                    existing["messages"] = msgs
                    existing["updated"] = now
                    if title:
                        existing["title"] = title
                    cid = existing["id"]
                else:
                    cid = f"{now}-{secrets.token_hex(3)}"
                    chats.append({"id": cid, "title": title, "ts": now,
                                  "updated": now, "messages": msgs})
                chats = sorted(chats, key=lambda c: -c.get("updated", 0))[:50]
                store["chats"] = chats
                try:
                    _persist()
                except Exception:
                    self._set_json_headers(500)
                    self.wfile.write(json.dumps({"error": "could not save chat"}).encode())
                    return
                self._set_json_headers()
                self.wfile.write(json.dumps({"ok": True, "id": cid}).encode())
                return
            if action == "delete":
                cid = str(data.get("id") or "")
                store["chats"] = [c for c in chats if c.get("id") != cid]
                try:
                    _persist()
                except Exception:
                    pass
                self._set_json_headers()
                self.wfile.write(json.dumps({"ok": True}).encode())
                return
            self._set_json_headers(400)
            self.wfile.write(json.dumps({"error": "unknown action"}).encode())
            return
        if parsed.path == "/api/mykeys":
            # Friend's own key vault: view (names only) and save. Admins use /settings.
            info = self._session_info()
            if not info:
                self._set_json_headers(401)
                self.wfile.write(json.dumps({"error": "not logged in"}).encode())
                return
            if info.get("admin"):
                self._set_json_headers(403)
                self.wfile.write(json.dumps({"error": "admins use Update Keys"}).encode())
                return
            label = info.get("label", "")
            if not _LABEL_RE.match(label):
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": "invalid label"}).encode())
                return
            content_length = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(content_length) if content_length else b"{}"
            try:
                data = json.loads(raw_body)
            except Exception:
                data = {}
            action = data.get("action", "view")
            if action == "view":
                uk = info.get("userkeys") or {}
                # Also check disk in case session is stale
                self._set_json_headers()
                self.wfile.write(json.dumps({
                    "configured": sorted([k for k in uk.keys() if not k.startswith("_")]),
                    "has_vault": _userkey_path(label).exists(),
                }).encode())
                return
            if action == "save":
                password = data.get("password") or ""
                if not password:
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "password required to encrypt"}).encode())
                    return
                # Verify password against stored hash
                access = _load_access()
                stored = access.get(label, "")
                ok, needs_up = _verify_password(password, stored)
                if ok and needs_up and label in access:
                    access[label] = _hash_password(password)
                    _save_access(access)
                if not ok:
                    self._set_json_headers(401)
                    self.wfile.write(json.dumps({"error": "wrong password"}).encode())
                    return
                keys_in = data.get("keys") or {}
                if not isinstance(keys_in, dict):
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "invalid keys"}).encode())
                    return
                # Load existing vault, merge (blank = keep, explicit empty = delete)
                vault = _load_userkeys(label, password) or {}
                for k, v in keys_in.items():
                    if not isinstance(k, str) or not _re.match(r"^[a-z0-9_]+$", k):
                        continue
                    if k.startswith("_"):
                        continue
                    v = (v or "").strip() if isinstance(v, str) else ""
                    if v:
                        vault[k] = v
                    elif k in vault:
                        del vault[k]
                _save_userkeys(label, vault, password)
                # Refresh session copy
                for tok, s in SESSIONS.items():
                    if isinstance(s, dict) and s.get("label") == label and not s.get("admin"):
                        s["userkeys"] = dict(vault)
                self._set_json_headers()
                self.wfile.write(json.dumps({"ok": True,
                    "configured": sorted([k for k in vault.keys() if not k.startswith("_")])}).encode())
                return
            self._set_json_headers(400)
            self.wfile.write(json.dumps({"error": "unknown action"}).encode())
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
    _boot_restore_access()
    httpd = ThreadingHTTPServer(addr, Handler)
    print(f"Serving on {addr[0]}:{addr[1]} – press Ctrl-C to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutdown requested")


if __name__ == "__main__":
    main()
