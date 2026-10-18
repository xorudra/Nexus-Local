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
  * GET  /            -> landing.html (the public home page, the default page)
  * GET  /home        -> landing.html (public home page)
  * GET  /dashboard   -> dashboard.html (requires login)
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
import shutil
import time
import threading
import ipaddress
import math
import socket
import http.client
import urllib.parse
from pathlib import Path

QUOTAS_PATH = Path(__file__).parent / "quotas.json"
from http.cookies import SimpleCookie
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, quote as _urlquote, urlencode as _urlencode
from urllib.request import Request, urlopen, build_opener, HTTPRedirectHandler, HTTPHandler, HTTPSHandler, ProxyHandler
from urllib.error import HTTPError, URLError

from getpass import getpass
from key_security import encrypt_keys, decrypt_keys, encrypt_raw, decrypt_raw

USAGE_PATH = Path(__file__).parent / "usage.jsonl"
SESSIONS = {}
_login_attempts = {}
# Per-session API rate limits: (bucket, session token) -> [timestamps].
# Stops a single session (friend or hijacked) from burning provider quota.
_RL = {}
_RL_LOCK = threading.Lock()
_RL_MAX_WINDOW = 900  # largest window any bucket uses (oauth/invite)

def _rl_ok(bucket, token, limit, window=60):
    now = time.time()
    key = (bucket, token or "?")
    with _RL_LOCK:
        # pop + re-store below refreshes recency: overflow eviction is
        # least-recently-used, never oldest-inserted (an active window
        # must not be evicted while idle keys survive).
        hits = [t for t in _RL.pop(key, []) if now - t < window]
        if len(hits) >= limit:
            _RL[key] = hits
            return False
        hits.append(now)
        _RL[key] = hits
        if len(_RL) > 5000:
            # Prune only fully-expired keys; evict oldest-inserted if
            # still oversized. NEVER clear the whole map: that would
            # reset every principal's active window at once.
            dead = [kk for kk, vv in _RL.items()
                    if not vv or now - vv[-1] >= _RL_MAX_WINDOW]
            for kk in dead:
                _RL.pop(kk, None)
            while len(_RL) > 5000:
                _RL.pop(next(iter(_RL)), None)
        return True

def _rl_refund(bucket, token):
    """Give back one consumed budget hit (wave 11, F11): a SUCCESSFUL
    redemption is observable anyway (the account exists), so refunding
    its hit does not reopen the taken/free oracle — but junk signups
    must not be able to burn the budget a legitimate signup needs."""
    key = (bucket, token or "?")
    with _RL_LOCK:
        hits = _RL.get(key) or []
        if hits:
            hits.pop()
            _RL[key] = hits

# Serializes every load-modify-save of the friend access store:
# redemption's lookup -> claim -> create must be atomic (one single-use
# invite must never become many accounts), and no other writer (console
# add/revoke, password reset, legacy-hash upgrades) may save a stale
# snapshot over a concurrent change — that erases just-created accounts
# and resurrects just-reset passwords. RLock: helpers called inside a
# critical section may re-enter.
_ACCESS_LOCK = threading.RLock()
# keys.enc read-modify-write lock (audit run-5): the access store
# got this discipline in run-2; the shared-vault writers (settings,
# setup, custom providers, master rotation, 2FA toggles) each did
# unlocked decrypt -> mutate -> encrypt, so two overlapping admin
# actions could silently lose a write - or revert a master rotation
# in the file while users.enc moved on, a desync a restart does
# not heal. Every keys.enc RMW below runs under this lock, with
# the decrypt INSIDE it (no stale snapshots).
_KEYS_LOCK = threading.RLock()
# Per-store locks for the remaining load->mutate->save vaults (audit
# run-6: parallel saves against one stale snapshot silently erased
# each other in the chats, integrations and userkeys stores, and the
# usage/audit rewrites resurrected purged rows).
_CHATS_LOCK = threading.RLock()
_INTG_LOCK = threading.RLock()
_USERKEYS_LOCK = threading.RLock()
_USAGE_LOCK = threading.RLock()
_CHATS_STORE_CAP = 32 * 1024 * 1024  # serialized per-account chat store
_USERKEY_VALUE_CAP = 512
_USERKEY_COUNT_CAP = 200

# Provider health (circuit breaker): provider -> {"fails": int, "down_until": float}
_PROVIDER_HEALTH = {}

def _provider_down(p):
    h = _PROVIDER_HEALTH.get(p)
    return bool(h) and h.get("down_until", 0) > time.time()

def _note_failure(p, err=""):
    # Threshold + cooldown are console settings (defaults reproduce the
    # original behaviour: down for 3 min after 2 straight failures).
    try:
        need = int(_SETTINGS.get("cb_failures") or 2)
        cd = int(_SETTINGS.get("cb_cooldown_s") or 180)
    except Exception:
        need, cd = 2, 180
    h = _PROVIDER_HEALTH.setdefault(p, {"fails": 0, "down_until": 0.0})
    h["fails"] = h.get("fails", 0) + 1
    h["last_fail"] = time.time()
    if err:
        h["last_error"] = str(err)[:120]
    if h["fails"] >= need:
        if h.get("down_until", 0) <= time.time():
            _cdtxt = f"{cd // 60} min" if cd >= 60 else f"{cd} sec"
            _audit("Providers", f"{p} marked down (circuit breaker, {_cdtxt})")
            _alert("provider_down", "provider_down",
                   {"provider": p, "cooldown_s": cd})
        h["down_until"] = time.time() + cd

def _note_success(p):
    h = _PROVIDER_HEALTH.get(p)
    if h is None:
        return
    h["fails"] = 0
    h["down_until"] = 0.0
    h["last_ok"] = time.time()


def _health_fields(p):
    """Last success/failure detail for the console's provider cards."""
    h = _PROVIDER_HEALTH.get(p) or {}
    return {"last_ok": h.get("last_ok"), "last_fail": h.get("last_fail"),
            "last_error": h.get("last_error")}

# ---- Admin console settings (owner-ordered 2026-10-10) ----
# One settings dict drives the admin console's working controls:
# maintenance mode, per-friend suspension and daily caps, failover
# attempts/order/provider enable+limits, session lifetime, audit
# retention and the instance name. Persisted like the friend list:
# a plaintext working copy on disk plus an encrypted mirror
# (settings.enc, restore key) that rides the friend_blob sync, so
# settings survive redeploys. Defaults reproduce the pre-console
# behaviour exactly, so nothing changes until the admin flips a switch.
SETTINGS_PATH = Path(__file__).parent / "settings.json"
SETTINGS_ENC_PATH = Path(__file__).parent / "settings.enc"
_SETTINGS_DEFAULTS = {
    "maintenance": False,
    "suspended": [],
    "max_attempts": 4,
    "daily_cap": 200,
    "user_caps": {},
    "provider_order": [],
    "provider_disabled": [],
    "provider_limits": {},
    "session_minutes": None,  # None = follow NEXUS_SESSION_EXPIRY env
    "retention_days": 30,
    "instance_name": "Nexus",
    # Console v2 (owner design 2026-10-10): every default below
    # reproduces the pre-v2 behaviour until the admin changes it.
    "global_cap": 0,            # instance-wide friend requests/day; 0 = off
    "chain_mode": "priority",   # priority | fastest | round_robin
    "provider_timeouts": {},    # provider -> per-attempt timeout seconds
    "cb_failures": None,        # failures before the breaker trips (def 2)
    "cb_cooldown_s": None,      # breaker cooldown seconds (default 180)
    "chat_rate": None,          # chat messages/min per session (def 40; 0=off)
    "webhook_url": "",          # alert webhook (http/https, public hosts)
    "alert_email": "",          # alert contact of record (rides webhooks)
    "alerts": {"provider_down": True, "cap": True, "signup": True},
    "digest_daily": False,      # webhook digest of yesterday's usage
    "digest_weekly": False,     # webhook digest of last week's usage
    "announcement": "",         # banner shown to every user at sign-in
    "allowed_ips": [],          # sign-in + console allowlist (CIDRs)
    "registration": "invite",   # open | invite | closed — self-signup mode
    "signup_role": "friend",    # role open-mode signups receive
    "pw_min": 8,                # min password length for new friend passwords
    "latency_alert_s": 0,       # console alert when a provider avg exceeds
    "quota_alert_pct": 90,      # console alert when a friend nears their cap
    "skip_failing": True,       # failover skips breaker-down providers
    "login_lockout": True,      # throttle repeated failed sign-ins per IP
    "audit_ips": True,          # record client IPs in the audit log
    "log_prompts": False,       # keep a short prompt snippet in usage rows
    "friends_byok": True,       # friends may keep their own key vaults
    "auto_backup": "off",       # off | daily | weekly config snapshots
    "oauth_admin_emails": [],   # verified OAuth emails that sign in as owner
    "oauth_links": [],          # [{email, label}] OAuth email -> friend label
    # Internal state (never patchable through settings_set):
    "roles": {},                # label -> moderator | viewer (default friend)
    "invites": [],              # {h, role, created, expires, used_by}
    "terms_seen": [],           # labels shown the first-login terms notice
    "vault_meta": {},           # label -> [{provider, last4}] (metadata only)
    "backup_snapshot": None,    # last auto-backup {ts, config}
    "last_digest": "",          # date/week stamp of the last digest sent
    "last_backup": "",          # date stamp of the last auto-backup
    # Wave 19 (run-18 D18-2): users.enc divergence record —
    # None, or {"ts":…, "intended_labels":[…]} written when a
    # users.enc backup write failed; see _note_backup_diverged.
    "access_backup_diverged": None,
}
_SETTINGS = dict(_SETTINGS_DEFAULTS)
_BOOT_TS = time.time()

# Settings restore (console Backup panel): only instance POLICY keys
# may come back from a backup file. Accounts, roles, per-user caps,
# suspensions, invites, the IP allowlist and every auth-shaped value
# are never restorable from JSON — the encrypted mirror stays the
# only recovery path for those.
_RESTORE_ALLOWED = {
    "instance_name", "maintenance", "max_attempts", "daily_cap",
    "global_cap", "chain_mode", "provider_order", "provider_disabled",
    "provider_limits", "provider_timeouts", "retention_days", "alerts",
    "digest_daily", "digest_weekly", "webhook_url", "alert_email",
    "announcement", "skip_failing", "friends_byok", "log_prompts",
    "audit_ips", "login_lockout", "cb_failures", "cb_cooldown_s",
    "chat_rate", "quota_alert_pct", "latency_alert_s", "auto_backup",
}
_RESTORE_NONCES = {}


_SETTINGS_LOCK = threading.RLock()
_SETTINGS_IO_LOCK = threading.Lock()
_SETTINGS_GEN = [0]
_SETTINGS_WRITTEN_GEN = [0]
_SETTINGS_ACTIVE = [0]


def _save_settings_impl():
    """Persist settings atomically and report success (audit run-7):
    the old direct write_text tore under concurrent writers (a torn
    file at boot was silently dropped) and swallowed every failure
    behind ok:true responses. Returns True only when the change
    actually landed.
    Run-8 shape: the snapshot is taken under _SETTINGS_LOCK but the
    ~0.3-0.7s PBKDF2 mirror encrypt happens OUTSIDE it (holding the
    RMW lock across the encrypt convoyed every settings writer
    behind each save — worst observed 11.75s), and the encrypted
    mirror is written FIRST (boot reads it as the source of truth,
    so a crash between the writes must leave the NEWER state in the
    mirror — plain-first silently reverted an acknowledged change
    at boot). A failed mirror fails the save when a restore key is
    configured. A generation guard keeps a slow save from
    overwriting a newer one that landed meanwhile; the newer
    snapshot necessarily includes this change (its mutation was
    applied before this snapshot was taken)."""
    with _SETTINGS_LOCK:
        _SETTINGS_GEN[0] += 1
        gen = _SETTINGS_GEN[0]
        snap_text = json.dumps(_SETTINGS, indent=2)
    enc_tmp = None
    if RESTORE_KEY:
        enc_tmp = "%s.%d.tmp" % (SETTINGS_ENC_PATH, threading.get_ident())
        try:
            encrypt_keys(json.loads(snap_text), RESTORE_KEY,
                         Path(enc_tmp))
        except Exception:
            return False
    with _SETTINGS_IO_LOCK:
        if gen < _SETTINGS_WRITTEN_GEN[0]:
            if enc_tmp:
                try:
                    os.unlink(enc_tmp)
                except Exception:
                    pass
            return True
        ok = True
        try:
            if enc_tmp:
                os.chmod(enc_tmp, 0o600)
                os.replace(enc_tmp, SETTINGS_ENC_PATH)
                # Audit run-9 (S1): the mirror is the boot source of
                # truth and it has LANDED — advance the watermark
                # NOW, before the plain write. A plain-write fault
                # after this point leaves this save reporting False,
                # but a slower OLDER save must never be allowed to
                # overwrite the newer mirror that is already on disk.
                _SETTINGS_WRITTEN_GEN[0] = max(_SETTINGS_WRITTEN_GEN[0],
                                               gen)
            tmp = "%s.%d.tmp" % (SETTINGS_PATH, threading.get_ident())
            with open(tmp, "w") as f:
                f.write(snap_text)
            os.chmod(tmp, 0o600)
            os.replace(tmp, SETTINGS_PATH)
        except Exception:
            ok = False
        if ok:
            _SETTINGS_WRITTEN_GEN[0] = max(_SETTINGS_WRITTEN_GEN[0], gen)
        return ok


def _save_settings():
    """Wave 12 (D2): count in-flight saves so _settings_outcome can
    tell "not yet landed" (a covering save is still in its encrypt
    phase) from "never landed", instead of reading a stale persisted
    snapshot mid-flight and manufacturing a ghost."""
    _SETTINGS_ACTIVE[0] += 1
    try:
        return _save_settings_impl()
    finally:
        _SETTINGS_ACTIVE[0] -= 1


def _wait_settings_settled(timeout=3.0):
    """Bounded wait for in-flight settings saves to settle (D2):
    generation-ordered and IO-serialised saves mean that once no
    save is active, the persisted state is final for every mutation
    applied so far."""
    deadline = time.time() + timeout
    while _SETTINGS_ACTIVE[0] > 0 and time.time() < deadline:
        time.sleep(0.02)


def _persisted_settings():
    """The settings state that actually landed on disk: the encrypted
    mirror first (it is the boot source of truth), then the plain
    working copy. None when neither can be read."""
    if RESTORE_KEY:
        try:
            if SETTINGS_ENC_PATH.exists():
                d = decrypt_keys(SETTINGS_ENC_PATH, RESTORE_KEY)
                if isinstance(d, dict):
                    return d
        except Exception:
            pass
    try:
        if SETTINGS_PATH.exists():
            d = json.loads(SETTINGS_PATH.read_text())
            if isinstance(d, dict):
                return d
    except Exception:
        pass
    return None


# Wave 13 (run-12 data): while _settings_outcome runs a rollback it
# pushes the PERSISTED snapshot it judged against here; the CAS
# helpers then skip any entry whose persisted value already equals
# the caller's intended value — that entry LANDED (a peer's
# acknowledged change to the SAME value is state-identical), and
# rolling it back would clobber the peer's change, not the caller's.
_OUTCOME_PERSISTED = []


def _cas_rollback_dict_entry(container, entry, prior, new):
    """Wave 12 (D1): compare-and-restore ONE dict entry — restore the
    caller's prior value for `entry` ONLY if the live entry still
    equals the caller's own mutation; a concurrent writer's entry
    (same container, or the same entry since re-saved) is never
    clobbered. The old whole-container restore silently undid a
    concurrent acknowledged change, and the next unrelated save then
    persisted the clobber. Runs under _SETTINGS_LOCK (the outcome
    helper invokes rollbacks under it)."""
    live = _SETTINGS.get(container)
    if not isinstance(live, dict):
        return
    new_has = entry in (new or {})
    if _OUTCOME_PERSISTED:
        _pc = (_OUTCOME_PERSISTED[-1] or {}).get(container)
        if isinstance(_pc, dict) and (entry in _pc) == new_has \
                and (not new_has
                     or _pc.get(entry) == (new or {}).get(entry)):
            return  # the entry landed in the persisted state
    if (entry in live) != new_has:
        return
    if new_has and live.get(entry) != (new or {}).get(entry):
        return
    live = dict(live)
    if entry in (prior or {}):
        live[entry] = prior[entry]
    else:
        live.pop(entry, None)
    _SETTINGS[container] = live


def _cas_rollback_list_entry(container, entry, prior, new):
    """D1 compare-and-restore for a membership list (suspended):
    restore `entry`'s presence to its prior state only if live
    presence still equals the caller's own mutation."""
    live = _SETTINGS.get(container)
    if not isinstance(live, list):
        return
    if _OUTCOME_PERSISTED:
        _pl = (_OUTCOME_PERSISTED[-1] or {}).get(container)
        if isinstance(_pl, list) and (entry in _pl) == (entry in (new or [])):
            return  # the membership landed in the persisted state
    if (entry in live) != (entry in (new or [])):
        return
    live = list(live)
    if entry in (prior or []):
        if entry not in live:
            live.append(entry)
    else:
        live = [x for x in live if x != entry]
    _SETTINGS[container] = live


def _cas_rollback_invite_add(code_hash):
    """D1: undo an invite_create by removing ONLY the caller's own
    invite (matched by hash) if it is still live."""
    if _OUTCOME_PERSISTED:
        _pi = (_OUTCOME_PERSISTED[-1] or {}).get("invites")
        if isinstance(_pi, list) and any(
                i.get("h") == code_hash for i in _pi):
            return  # a peer re-created/kept this invite persistently
    live = _SETTINGS.get("invites")
    if isinstance(live, list):
        _SETTINGS["invites"] = [i for i in live
                                if i.get("h") != code_hash]


def _cas_rollback_invite_remove(removed):
    """D1: undo an invite_revoke by re-adding ONLY the entries this
    caller removed, and only those still absent live."""
    live = _SETTINGS.get("invites")
    if not isinstance(live, list):
        return
    have = {i.get("h") for i in live}
    # Wave 14 (run-13 settings): NO union with the judged persisted
    # snapshot here. This helper's pred is NEGATIVE (revoke success =
    # the invite ABSENT from persisted), so an entry present in the
    # persisted snapshot is exactly the failure state this rollback
    # exists to re-add live — the wave-13 union made the rollback an
    # exact no-op precisely when the revoke save faulted.
    add = [i for i in (removed or []) if i.get("h") not in have]
    if add:
        _SETTINGS["invites"] = list(live) + add


def _cas_rollback_invite_claim(code_hash, label):
    """D4: undo an invite claim — clear used_by only if the live
    invite still carries THIS caller's claim."""
    if _OUTCOME_PERSISTED:
        _pi = (_OUTCOME_PERSISTED[-1] or {}).get("invites")
        if isinstance(_pi, list) and any(
                i.get("h") == code_hash and i.get("used_by") == label
                for i in _pi):
            return  # the claim itself landed in the persisted state
    live = _SETTINGS.get("invites")
    if isinstance(live, list):
        for i in live:
            if i.get("h") == code_hash and i.get("used_by") == label:
                i["used_by"] = None


def _cas_rollback_keys(prior, new, snapshot_prior=None,
                       snapshot_new=None):
    """D1 per-key compare-and-restore (settings_set / restore_apply):
    each key is restored only if live still equals the caller's own
    value for that key — a concurrent writer's acknowledged change
    to the SAME key (persisted under them) otherwise survived in the
    persisted state but was rolled back in live memory and then
    clobbered by the next save. The restore backup_snapshot rides
    the same compare on its own value."""
    _ps13 = _OUTCOME_PERSISTED[-1] if _OUTCOME_PERSISTED else None
    for k, v in (new or {}).items():
        if isinstance(_ps13, dict) and k in _ps13 and _ps13.get(k) == v:
            continue  # this key landed (possibly via a peer's save)
        try:
            if _SETTINGS.get(k) == v:
                _SETTINGS[k] = (prior or {}).get(k)
        except Exception:
            continue
    if snapshot_new is not None \
            and not (isinstance(_ps13, dict)
                     and _ps13.get("backup_snapshot") == snapshot_new) \
            and _SETTINGS.get("backup_snapshot") == snapshot_new:
        _SETTINGS["backup_snapshot"] = snapshot_prior


def _settings_outcome(sv, pred, rollback=None):
    """Wave 11 (F1/F2): verify the OUTCOME of a consequential settings
    save, not the save call's return value. _save_settings can return
    True via the generation-guard superseded branch while a concurrent
    save has already replaced this caller's mutation on disk, and it
    can return False after a concurrent save already persisted this
    caller's mutation. Returns "ok" (the intended mutation IS the
    persisted state), "conflict" (a concurrent change superseded it —
    the caller must answer 409, never hand out a dead result), or
    "failed" (genuinely unpersisted; the in-memory mutation is rolled
    back via rollback() under _SETTINGS_LOCK so a later unrelated save
    cannot resurrect it and the caller's 500 text becomes true).
    Wave 12 (D2/D3): BOTH branches verify against the PERSISTED
    state, and a verdict first waits (bounded) for in-flight saves
    to settle.
    Wave 13 (run-12 data): the settle-wait is now a real BARRIER,
    not a one-shot wait. The judge-and-rollback step runs inside one
    _SETTINGS_LOCK hold that re-reads the persisted state, re-checks
    _SETTINGS_ACTIVE==0 and compares _SETTINGS_GEN before and after
    the read; if a save started or the generation moved during the
    check, the verdict is discarded, the loop re-waits and
    re-judges. On overall bound expiry with a save still in flight
    the answer is "conflict" with NO rollback (the mutation may yet
    land — rolling it back would manufacture the ghost)."""
    _deadline = time.time() + 12.0
    while True:
        _remaining = _deadline - time.time()
        if _remaining <= 0:
            return "conflict"
        _wait_settings_settled(timeout=min(3.0, _remaining))
        with _SETTINGS_LOCK:
            if _SETTINGS_ACTIVE[0] == 0:
                _gen0 = _SETTINGS_GEN[0]
                persisted = _persisted_settings()
                if _SETTINGS_ACTIVE[0] == 0 \
                        and _SETTINGS_GEN[0] == _gen0:
                    if persisted is not None:
                        try:
                            if pred(persisted):
                                return "ok"
                        except Exception:
                            pass
                        if sv:
                            return "conflict"
                        if rollback is not None:
                            _OUTCOME_PERSISTED.append(persisted)
                            try:
                                rollback()
                            finally:
                                _OUTCOME_PERSISTED.pop()
                        return "failed"
                    if sv:
                        try:
                            return "ok" if pred(_SETTINGS) \
                                else "conflict"
                        except Exception:
                            return "conflict"
                    if rollback is not None:
                        rollback()
                    return "failed"
        # A save started, or the generation moved, during the check:
        # loop back to the wait and re-judge on settled state.
        if time.time() >= _deadline:
            return "conflict"
        time.sleep(0.02)


def _label_settings_absent(s, label):
    """The clean-slate predicate over a settings document (live or
    persisted): the label carries NO per-user entry in any of the
    six containers the creation clear governs."""
    return (label not in (s.get("roles") or {})
            and label not in (s.get("user_caps") or {})
            and label not in (s.get("vault_meta") or {})
            and label not in (s.get("suspended") or [])
            and label not in (s.get("terms_seen") or [])
            and not any(
                isinstance(e, dict) and e.get("label") == label
                for e in (s.get("oauth_links") or [])))


# Wave 17 (run-16 settings D16-2): the settings generation
# triple the creation clear last judged, kept per calling
# thread — read by the in-lock creation recheck (see
# _clear_stranded_label's return paths).
_CLEAR_JUDGED17 = threading.local()


def _clear_stranded_label(label):
    """Wave 15 (run-14 settings): the ONE shared clean-slate clear
    for account creation. A label that provably has NO account can
    still carry per-user settings stranded by a faulted revoke
    cleanup + restart (roles / user_caps / vault_meta dicts,
    suspended / terms_seen lists, oauth_links label-keyed entries);
    left in place they become the next account's effective state at
    creation. Both creation paths (console add, invite redeem /
    open signup) call this BEFORE the account exists and abort on a
    non-ok outcome — no rollback is needed or wanted: the honest
    end state after a faulted clear is no account at all. Returns
    the _settings_outcome verdict ("ok" when there was nothing to
    clear)."""
    with _ACCESS_LOCK:
        # Wave 17 (run-16 settings AUTH16-1/D16-1):
        # re-verify account existence INSIDE the lock
        # that serializes creation, BEFORE any mutation.
        # Wave 16 moved the clear before _ACCESS_LOCK on
        # a stale lock-free snapshot, and a refused loser's
        # clear then wiped a concurrently-created live
        # account's persisted role/terms (its in-lock
        # recheck read the wiped store and certified it).
        # Judged under the lock, the clear can only ever
        # touch a label that has no account at mutation
        # time. Lock order stays ACCESS -> SETTINGS (the
        # established order; _ACCESS_LOCK is an RLock and
        # both creation callsites hold neither lock).
        # Accepted narrowing of run-15's D15-3: a genuinely
        # stranded label's clear save sits in-lock again;
        # the happy path (nothing stranded in memory or
        # persisted) performs NO save here.
        if label in _load_access():
            _CLEAR_JUDGED17.triple = None
            return "conflict"
        # Wave 18 (run-17 settings D17-1): capture the generation
        # triple HERE — at/before the judgement reads below —
        # not at the return. Wave 17 recorded it at the return,
        # ~one full persisted decrypt after the fast path's
        # snapshot (the file read at the START of
        # _persisted_settings), so a per-label save landing in
        # that window was folded into the recorded triple and
        # both in-lock rechecks skipped their decrypt over a
        # re-stranded store. Recorded now, any save completing
        # after this point moves the counters (or is in flight,
        # ACTIVE>0) and the recheck re-pays the decrypt. Failure
        # and conflict exits keep recording None; the "ok" exit
        # below assigns this captured triple. Accepted cost: a
        # genuinely stranded label's own slow-path save moves
        # the counters too, so stranded creations re-pay the
        # recheck decrypt — the D16-2 happy path (no save in
        # the helper) is untouched.
        _judged18 = (_SETTINGS_GEN[0], _SETTINGS_WRITTEN_GEN[0],
                     _SETTINGS_ACTIVE[0])
        with _SETTINGS_LOCK:
            _cl15 = False
            for _k15 in ("roles", "user_caps", "vault_meta"):
                _d15 = dict(_SETTINGS.get(_k15) or {})
                if label in _d15:
                    _d15.pop(label, None)
                    _SETTINGS[_k15] = _d15
                    _cl15 = True
            for _k15 in ("suspended", "terms_seen"):
                _l15 = [x for x in (_SETTINGS.get(_k15) or [])
                        if x != label]
                if _l15 != (_SETTINGS.get(_k15) or []):
                    _SETTINGS[_k15] = _l15
                    _cl15 = True
            _ol15 = [e for e in (_SETTINGS.get("oauth_links") or [])
                     if not (isinstance(e, dict)
                             and e.get("label") == label)]
            if _ol15 != (_SETTINGS.get("oauth_links") or []):
                _SETTINGS["oauth_links"] = _ol15
                _cl15 = True
        if not _cl15:
            # Wave 16 (run-15 settings): the fast path must judge the
            # PERSISTED store, not live memory alone. After a faulted
            # first clear the two diverge (memory cleared / disk
            # stranded, no rollback by design); a same-process retry
            # that trusted memory created the account over the
            # still-stranded store, and the next restart resurrected
            # suspension + moderator + cap onto it. On disagreement
            # fall through to the save + outcome check — saving the
            # cleared memory persists the clear.
            _ps16 = _persisted_settings()
            if _ps16 is None or _label_settings_absent(_ps16, label):
                _v16 = "ok"
            else:
                _v16 = None
        else:
            _v16 = None
        if _v16 is None:
            _v16 = _settings_outcome(
                _save_settings(),
                lambda s: _label_settings_absent(s, label))
        if _v16 != "ok":
            _CLEAR_JUDGED17.triple = None
            return _v16
        # Wave 16 (run-15 settings AUTH15-3): the file-resident
        # per-label stores are part of the clean slate too. A stranded
        # chats/userkeys/userintegrations file (revoke's unlinks are
        # bare try/except-pass, so stranding is silent) permanently
        # bricks the innocent next holder's saves — or, under a
        # same-password re-registration, revives the revoked holder's
        # vault wholesale, defeating revoke's stated non-revival
        # intent. The label provably has no account at this point, so
        # the files are orphans; each deletion is verified by a
        # post-delete existence re-check, and a file that cannot be
        # removed aborts creation exactly like a failed settings
        # outcome.
        for _pf16 in (_chat_path(label), _userkey_path(label),
                      _intg_path(label)):
            try:
                if _pf16.exists():
                    _pf16.unlink()
            except Exception:
                pass
            if _pf16.exists():
                _CLEAR_JUDGED17.triple = None
                return "failed"
        # Wave 17 (run-16 settings D16-2): record
        # the judged generation triple — the in-lock
        # creation recheck reuses this judgement while
        # the triple is unmoved and no save is in
        # flight, instead of paying a second full
        # persisted decrypt on every clean creation.
        # Wave 18 (D17-1): the value recorded is the
        # triple captured at the judgement (see above),
        # NOT the counters as they stand now.
        _CLEAR_JUDGED17.triple = _judged18
        return "ok"


def _boot_restore_settings():
    """Load settings at startup: encrypted mirror first (it is the
    synced source of truth), then the local working copy."""
    global _SETTINGS
    try:
        if RESTORE_KEY and SETTINGS_ENC_PATH.exists():
            d = decrypt_keys(SETTINGS_ENC_PATH, RESTORE_KEY)
            if isinstance(d, dict) and d:
                merged = dict(_SETTINGS_DEFAULTS)
                merged.update({k: v for k, v in d.items()
                               if k in _SETTINGS_DEFAULTS})
                _SETTINGS = merged
                _load_diverged_sidecar_boot()
                return
    except Exception:
        pass
    try:
        if SETTINGS_PATH.exists():
            d = json.loads(SETTINGS_PATH.read_text())
            if isinstance(d, dict) and d:
                merged = dict(_SETTINGS_DEFAULTS)
                merged.update({k: v for k, v in d.items()
                               if k in _SETTINGS_DEFAULTS})
                _SETTINGS = merged
    except Exception:
        pass
    _load_diverged_sidecar_boot()


def _friend_blocked(label):
    """Maintenance mode blocks every friend; suspension blocks one.
    Admins and view-pass viewers are never blocked."""
    if _SETTINGS.get("maintenance"):
        return "maintenance"
    if label and label in (_SETTINGS.get("suspended") or []):
        return "suspended"
    return None


def _session_seconds():
    # An explicit console setting wins; until the admin sets one, the
    # NEXUS_SESSION_EXPIRY env default rules (unchanged behaviour).
    try:
        v = _SETTINGS.get("session_minutes")
        if v:
            return max(60, int(v) * 60)
    except Exception:
        pass
    return SESSION_EXPIRY


def _ordered_provider_names():
    order = [n for n in (_SETTINGS.get("provider_order") or [])
             if n in PROVIDER_NAMES]
    return order + [n for n in PROVIDER_NAMES if n not in order]


def _disabled_providers():
    return set(_SETTINGS.get("provider_disabled") or [])


def _governance():
    """Wave 13 (run-12 caps): ONE governance snapshot per check —
    the disabled-set and the limits are read together under
    _SETTINGS_LOCK (the lock the writer, settings_set, applies both
    keys under), so a save landing between two separate unlocked
    reads can no longer compose a verdict from two different
    governance states (the torn read)."""
    with _SETTINGS_LOCK:
        return (_disabled_providers(),
                dict(_SETTINGS.get("provider_limits") or {}))


def _provider_verdict_locked(provider, exclude, also, _dis13,
                             _lims13):
    """Wave 16 (run-15 caps): the completed+rank verdict of
    _provider_blocked, evaluated with _INFLIGHT_LOCK ALREADY HELD
    by the caller — factored out so the image substitution path
    can evaluate the check AND retag its reservation inside one
    hold (CAPS15-3: the wave-15 check-then-retag pair was two
    statements, and a forced interleave admitted 2 at limit 1).
    Returns True/False, or None when no limit judges the provider
    (the disabled term still returns True)."""
    if provider in _dis13 or (also and also in _dis13):
        return True
    _l = _lims13.get(provider)
    if not _l:
        return None
    _names15 = {provider} if not also else {provider, also}
    # Prune expired first (the inline form of _inflight_n's prune;
    # _inflight_n itself takes the lock, so it cannot run here).
    _now16 = time.time()
    for _e15p in [x for x in _INFLIGHT if _now16 - x["ts"] > 900]:
        _inflight_drop_locked(_e15p)
    # Wave 15 (run-14 caps CAPS14-3/4): completed + rank are ONE
    # snapshot inside this hold, and completed comes from the
    # in-memory provider counter — the wave-14 shape read a full
    # usage scan BEFORE the hold, so a peer completing in the gap
    # was counted zero times.
    _done15 = sum(_provider_counts_today().get(n, 0)
                  for n in _names15)
    # Wave 14 (run-13 caps): a born-tagged caller (the media
    # surfaces) is judged with the spend-leg form: its RANK among
    # the provider's live reservations (in reservation order)
    # takes the place of the raw in-flight count, and it is
    # refused only when completed + rank passes the limit. Two
    # concurrent spends at the last slot therefore admit exactly
    # one — the earlier reservation — whichever check runs first.
    _rank15 = 0
    _found15 = False
    for _e15 in _INFLIGHT:
        if _e15["provider"] in _names15:
            _rank15 += 1
            if _e15 is exclude:
                _found15 = True
                break
        elif exclude is not None \
                and _e15["provider"] is None \
                and "surface" not in _e15:
            # Wave 15 (run-14 caps CAPS14-1): an untagged base
            # reservation OLDER than the caller (list order is
            # birth order and the loop stops at the caller) may be
            # a media spend whose body is still arriving — count
            # it as a rank slot, so it cannot be invisible to this
            # check and then rank 1st itself once it tags.
            # Wave 17 (run-16 caps CAPS16-2): the test is the
            # parse-time surface stamp, NOT an age — wave 16's
            # 45s bound (run-15 CAPS15-5's fix) let a body
            # trickled past 45s stop ranking before it tagged,
            # reopening the trickle leapfrog, and no age bound
            # can satisfy both findings (body arrival has no
            # enforced total bound for the handler's single-read
            # shape). An UNSTAMPED base counts regardless of age
            # — its body may still be arriving, however long a
            # steady trickle lasts; a base STAMPED with a
            # non-media surface (a post-parse text chat and kin,
            # which keep provider=None for life and can never
            # spend this lane) never counts.
            _rank15 += 1
    if exclude is not None and _found15:
        return _done15 + _rank15 > int(_l)
    if exclude is not None:
        # The caller's reservation is not tagged with this
        # provider (a funding-lane side check): the full-count
        # form over the judged name set.
        return _done15 + sum(
            sum(1 for _e15 in _INFLIGHT
                if _e15 is not exclude
                and _e15["provider"] == _n15)
            for _n15 in _names15) >= int(_l)
    return _done15 + sum(
        1 for _e15 in _INFLIGHT
        if _e15 is not exclude
        and _e15["provider"] == provider) >= int(_l)


def _provider_blocked(provider, exclude=None, also=None):
    """Admin provider governance for the non-chat surfaces (media,
    transcription): True when the provider is disabled in settings or
    today's provider_limits allowance for it is used up. Mirrors text
    chat's _lane_ok exactly — same disabled set, same limits table,
    same usage accounting — so a provider the admin stopped for chat
    cannot keep spending through media or voice. `also` names a
    second lane whose spends this provider's limit must ALSO judge
    (the TTS funding lane: rows metered under the picked lane are
    paid for by the funding lane's key)."""
    _dis13, _lims13 = _governance()
    try:
        with _INFLIGHT_LOCK:
            return bool(_provider_verdict_locked(
                provider, exclude, also, _dis13, _lims13))
    except Exception:
        return False


def _provider_blocked_and_tag(provider, res):
    """Wave 16 (run-15 caps CAPS15-3): the image substitution
    check+retag as ONE _INFLIGHT_LOCK hold — evaluate the
    full-count form for the substitute provider and, on a pass,
    retag the reservation before the lock releases, so no peer's
    check can observe the state between the two. Preserves the
    wave-15 check-before-retag anti-leapfrog ordering. Returns
    True when the reservation now carries the substitute tag."""
    _dis13, _lims13 = _governance()
    try:
        with _INFLIGHT_LOCK:
            try:
                _v16 = _provider_verdict_locked(
                    provider, res, None, _dis13, _lims13)
            except Exception:
                _v16 = None  # mirror _provider_blocked's fail-open
            if _v16:
                return False
            res["provider"] = provider
            return True
    except Exception:
        return False


def _friend_role(label):
    """Console role for a friend account: 'moderator' or 'viewer' when
    the admin granted one, else 'friend' (chat only, no console)."""
    r = (_SETTINGS.get("roles") or {}).get(label or "")
    return r if r in ("moderator", "viewer") else "friend"


def _client_ip(headers, fallback=""):
    """The client address the platform edge actually observed: the LAST
    X-Forwarded-For entry (earlier entries are client-supplied)."""
    try:
        xff = (headers.get("X-Forwarded-For") or "") if headers else ""
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            return parts[-1]
    except Exception:
        pass
    return fallback or ""


def _ip_allowed(ip):
    """Sign-in/console allowlist. Empty list = anywhere. Entries may be
    plain IPs or CIDR ranges."""
    lst = _SETTINGS.get("allowed_ips") or []
    if not lst:
        return True
    try:
        addr = ipaddress.ip_address((ip or "").strip())
    except Exception:
        return False
    for entry in lst:
        try:
            if addr in ipaddress.ip_network(str(entry).strip(), strict=False):
                return True
        except Exception:
            continue
    return False


def _webhook_url_ok(url):
    """Alert webhooks must be http(s) to a public host. Delegates to the
    resolver-based guard below: the host is resolved and EVERY address
    must be public, so encoded IP literals (2130706433, 0x7f000001)
    and DNS names that resolve privately are rejected too — a textual
    dotted-quad check alone let those through."""
    return _public_base_url_ok(url)


class _WebhookRedirect(HTTPRedirectHandler):
    """Redirect handler for webhook delivery: every redirect target is
    re-validated with the same resolver-based guard before following."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _public_base_url_ok(newurl):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _is_site_local(ip):
    return ip.version == 6 and ip.is_site_local


def _public_base_url_ok(url):
    """SSRF guard for user-supplied provider/gateway base URLs
    (custom_relay_*_url, freellmapi_url): the server fetches these
    with credentials attached, so the target must resolve ONLY to
    public addresses (Launch Safety Standard A5). Same resolve-and-
    validate rule as the agent fetch_url tool: scheme http/https, the
    hostname must resolve, and EVERY resolved address must be public —
    private, loopback (localhost included), link-local, reserved and
    multicast targets are rejected. Built-in providers never pass
    through here; only URLs a user typed in."""
    try:
        u = urllib.parse.urlparse((url or "").strip())
        if u.scheme not in ("http", "https") or not u.hostname:
            return False
        host = u.hostname.lower()
        if host == "localhost" or host.endswith(".local"):
            return False
        try:
            infos = socket.getaddrinfo(host, None)
        except Exception:
            return False
        if not infos:
            return False
        for info in infos:
            addr = ipaddress.ip_address(info[4][0])
            if addr.is_private or addr.is_loopback or addr.is_link_local \
                    or addr.is_reserved or addr.is_multicast \
                    or _is_site_local(addr) or not addr.is_global:
                return False
        return True
    except Exception:
        return False


def _safe_url(u):
    """Public-URL guard shared by the agent fetch tool and the media
    branches (hoisted from the agent block): http(s) only, no localhost,
    the hostname must resolve, and EVERY resolved address must be
    public — private, loopback, link-local, reserved and multicast
    targets are rejected. Non-http(s) schemes (file:, gopher:, …)
    never pass."""
    try:
        p = urllib.parse.urlparse(str(u))
        if p.scheme not in ("http", "https") or not p.hostname:
            return False
        host = p.hostname.lower()
        if host == "localhost":
            return False
        infos = socket.getaddrinfo(host, None)
        if not infos:
            return False
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local \
                    or ip.is_reserved or ip.is_multicast or _is_site_local(ip) or not ip.is_global:
                return False
        return True
    except Exception:
        return False


class _GuardedRedirect(HTTPRedirectHandler):
    """Follow redirects only to targets that still pass _safe_url,
    and strip credential headers when a hop changes origin (audit
    run-6: the integration lanes ride this opener carrying Basic /
    Bearer tokens, and re-validating the target's address class
    does nothing to stop the token itself moving to a new origin)."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _safe_url(newurl):
            return None
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and _origin_of(newurl) != _origin_of(req.full_url):
            _strip_cred_headers(new)
        return new


def _addr_is_public(a):
    try:
        ip = ipaddress.ip_address(a)
    except Exception:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or _is_site_local(ip) or not ip.is_global)


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection that resolves ONCE, requires every resolved
    address to be public, and connects to a validated IP — a resolver
    that answers differently at connect time (DNS rebinding) reaches
    nothing."""
    def connect(self):
        infos = socket.getaddrinfo(self.host, self.port, 0, socket.SOCK_STREAM)
        addrs = []
        for info in infos:
            if info[4][0] not in addrs:
                addrs.append(info[4][0])
        if not addrs or not all(_addr_is_public(a) for a in addrs):
            raise OSError("host resolves to a non-public address")
        last = None
        for ip in addrs:
            try:
                self.sock = socket.create_connection(
                    (ip, self.port), self.timeout, self.source_address)
                return
            except OSError as e:
                last = e
        raise last or OSError("connect failed")


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        infos = socket.getaddrinfo(self.host, self.port, 0, socket.SOCK_STREAM)
        addrs = []
        for info in infos:
            if info[4][0] not in addrs:
                addrs.append(info[4][0])
        if not addrs or not all(_addr_is_public(a) for a in addrs):
            raise OSError("host resolves to a non-public address")
        raw = None
        last = None
        for ip in addrs:
            try:
                raw = socket.create_connection(
                    (ip, self.port), self.timeout, self.source_address)
                break
            except OSError as e:
                last = e
        if raw is None:
            raise last or OSError("connect failed")
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


class _PinnedHTTPHandler(HTTPHandler):
    def http_open(self, req):
        return self.do_open(_PinnedHTTPConnection, req)


class _PinnedHTTPSHandler(HTTPSHandler):
    def https_open(self, req):
        return self.do_open(_PinnedHTTPSConnection, req, context=self._context)


def _strip_cred_headers(req_obj):
    """Remove credential headers from a redirected request (both the
    header dict and the unredirected-headers dict urllib keeps)."""
    for _hdrs in (req_obj.headers, getattr(req_obj, "unredirected_hdrs", {})):
        for _k in list(_hdrs.keys()):
            if _k.lower() in ("authorization", "x-api-key", "api-key",
                              "x-goog-api-key", "x-relay-token",
                              "x-vault-key", "apikey", "cookie",
                              "chatgpt-account-id"):
                del _hdrs[_k]


def _origin_of(url):
    p = urllib.parse.urlparse(url)
    return (p.scheme.lower(), (p.hostname or "").lower(),
            p.port or (443 if p.scheme.lower() == "https" else 80))


class _CredentialRedirect(_GuardedRedirect):
    """Redirect guard for credential-bearing fetches: hops are
    re-validated like _GuardedRedirect, and credential headers are
    stripped when the redirect changes ORIGIN (scheme, host or port) —
    a validated public base that 302s elsewhere, downgrades to http,
    or hops ports must not carry the lane's key with it."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and _origin_of(newurl) != _origin_of(req.full_url):
            _strip_cred_headers(new)
        return new


class _LoopbackRedirect(HTTPRedirectHandler):
    """Redirects for first-party loopback services (the relay, the
    gateway): follow only hops that stay on loopback, and strip
    credentials whenever the host changes - 127.0.0.1 and localhost
    are different origins to the receiving service's logs even here."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        host = (urllib.parse.urlparse(newurl).hostname or "").lower()
        if host not in ("127.0.0.1", "localhost", "::1"):
            return None
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None:
            # Origin = scheme + host + port (audit run-7): the
            # host-only test forwarded credentials cross-PORT to a
            # different loopback service.
            if _origin_of(newurl) != _origin_of(req.full_url):
                _strip_cred_headers(new)
        return new


def _open_loopback(req, timeout):
    return build_opener(ProxyHandler({}),
                        _LoopbackRedirect()).open(req, timeout=timeout)


def _cred_opener():
    if (os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")
            or os.environ.get("http_proxy") or os.environ.get("HTTP_PROXY")):
        # A configured egress proxy resolves names on its own side, so
        # connection pinning cannot apply (the proxy IS the resolution
        # authority there). The credential redirect guard still
        # re-validates every hop and strips keys cross-host. With no
        # proxy configured (the production service), fetches are pinned.
        return build_opener(_CredentialRedirect())
    return _pinned_opener(_CredentialRedirect())


def _open_cred(req, timeout):
    """Open a credential-bearing provider request. Loopback targets
    (the app's own relay / FreeLLMAPI gateway) go direct — they are
    first-party services on this machine. Everything else goes through
    the pinned, credential-guarded opener: a user-influenced or
    redirecting upstream cannot pull the lane key to an internal or
    third-party host."""
    host = (urllib.parse.urlparse(req.full_url).hostname or "").lower()
    if host in ("127.0.0.1", "localhost", "::1"):
        return _open_loopback(req, timeout)
    return _cred_opener().open(req, timeout=timeout)


def _pinned_opener(redirect=None):
    """Opener for fetches that must not be rebound: no ambient proxy
    (ProxyHandler({}) — a proxy resolving on its own side would un-pin
    the check), connections pinned to validated IPs, redirects
    re-validated by the given handler (_GuardedRedirect default)."""
    return build_opener(ProxyHandler({}),
                        redirect if redirect is not None else _GuardedRedirect(),
                        _PinnedHTTPHandler(), _PinnedHTTPSHandler())


# Bounded reads for upstream media bodies (generation-time caps; the
# saved-chat per-URI budget is a persistence limit, not this).
_MEDIA_IMAGE_CAP = 14 * 1024 * 1024
_MEDIA_VOICE_CHUNK_CAP = 8 * 1024 * 1024
_MEDIA_VOICE_TOTAL_CAP = 16 * 1024 * 1024


def _fire_webhook(event, data=None):
    """POST an alert event to the configured webhook, off-thread so a
    slow receiver never blocks a request. Best-effort: failures are
    silent (the audit log is the record of truth)."""
    url = (_SETTINGS.get("webhook_url") or "").strip()
    if not url or not _webhook_url_ok(url):
        return False
    payload = {"event": event, "ts": datetime.datetime.now().isoformat(),
               "instance": _SETTINGS.get("instance_name", "Nexus"),
               "alert_email": _SETTINGS.get("alert_email", "")}
    if data:
        payload.update(data)

    def _send():
        try:
            req = Request(url, data=json.dumps(payload).encode(),
                          headers={"Content-Type": "application/json",
                                   "User-Agent": "NexusLocal/1.0"},
                          method="POST")
            opener = _pinned_opener(_WebhookRedirect())
            with opener.open(req, timeout=5) as resp:
                resp.read(512)
        except Exception:
            pass
    threading.Thread(target=_send, daemon=True).start()
    return True


def _alert(event, gate_key, data=None):
    """Fire a webhook for an alert event when its toggle is on."""
    try:
        if (_SETTINGS.get("alerts") or {}).get(gate_key, True):
            return _fire_webhook(event, data)
    except Exception:
        pass
    return False


# Recent per-provider latency (avg ms over the newest usage rows),
# cached for a minute — drives the failover chain's "fastest" mode.
_LAT_CACHE = {"ts": 0.0, "map": {}}


def _provider_latency():
    now = time.time()
    if now - _LAT_CACHE["ts"] < 60:
        return _LAT_CACHE["map"]
    sums, counts = {}, {}
    try:
        if os.path.exists(USAGE_PATH):
            with open(USAGE_PATH) as f:
                lines = f.readlines()[-2000:]
            for line in lines:
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                if not isinstance(e, dict) or e.get("type"):
                    continue
                p, ms = e.get("provider"), e.get("ms")
                if isinstance(p, str) and isinstance(ms, (int, float)) and ms > 0:
                    sums[p] = sums.get(p, 0) + ms
                    counts[p] = counts.get(p, 0) + 1
    except Exception:
        pass
    _LAT_CACHE.update({"ts": now,
                       "map": {p: sums[p] / counts[p] for p in sums}})
    return _LAT_CACHE["map"]


_RR_COUNTER = {"i": 0}  # round-robin rotation for the failover chain


def _usage_stats(days_back=1):
    """Aggregate usage.jsonl for the digest: totals + top provider for
    the window ending today (days_back=1 → yesterday only)."""
    today = datetime.date.today()
    if days_back == 1:
        want = {(today - datetime.timedelta(days=1)).isoformat()}
    else:
        want = {(today - datetime.timedelta(days=i)).isoformat()
                for i in range(7)}
    tot_r = tot_t = 0
    per_p = {}
    try:
        if os.path.exists(USAGE_PATH):
            with open(USAGE_PATH) as f:
                for line in f:
                    try:
                        e = json.loads(line)
                    except Exception:
                        continue
                    if not isinstance(e, dict) or e.get("type"):
                        continue
                    if str(e.get("ts", ""))[:10] not in want:
                        continue
                    tot_r += 1
                    tot_t += (e.get("prompt_tokens", 0) or 0) \
                        + (e.get("completion_tokens", 0) or 0)
                    p = e.get("provider") or "?"
                    per_p[p] = per_p.get(p, 0) + 1
    except Exception:
        pass
    top = max(per_p.items(), key=lambda kv: kv[1])[0] if per_p else None
    return {"requests": tot_r, "tokens": tot_t, "top_provider": top}


def _public_settings_snapshot():
    """The settings an auto-backup snapshot keeps: policy only — never
    invites, vault metadata or anything secret-shaped."""
    keys = ("maintenance", "suspended", "max_attempts", "daily_cap",
            "global_cap", "user_caps", "provider_order",
            "provider_disabled", "provider_limits", "provider_timeouts",
            "chain_mode", "session_minutes", "retention_days",
            "instance_name", "roles", "registration", "signup_role",
            "pw_min", "chat_rate", "cb_failures", "cb_cooldown_s")
    return {k: _SETTINGS.get(k) for k in keys}


def _housekeeper():
    """Hourly background chores (console v2): webhook usage digests and
    config auto-backups. Everything here is opt-in via settings and
    best-effort; the loop must never die on a bad tick."""
    while True:
        try:
            time.sleep(3600)
            today = datetime.date.today()
            iso = today.isoformat()
            changed = False
            if _SETTINGS.get("digest_daily") \
                    and _SETTINGS.get("last_digest") != iso:
                stats = _usage_stats(1)
                if _fire_webhook("digest_daily", stats):
                    _SETTINGS["last_digest"] = iso
                    changed = True
                    _audit("System", "Daily usage digest sent "
                           f"({stats['requests']} requests yesterday)")
            wk = f"{today.isocalendar()[0]}-W{today.isocalendar()[1]}"
            if _SETTINGS.get("digest_weekly") \
                    and _SETTINGS.get("last_digest") != wk:
                stats = _usage_stats(7)
                if _fire_webhook("digest_weekly", stats):
                    _SETTINGS["last_digest"] = wk
                    changed = True
                    _audit("System", "Weekly usage digest sent "
                           f"({stats['requests']} requests in 7 days)")
            ab = _SETTINGS.get("auto_backup", "off")
            due = (ab == "daily"
                   and _SETTINGS.get("last_backup") != iso) or \
                  (ab == "weekly"
                   and _SETTINGS.get("last_backup") != wk)
            if due:
                with _SETTINGS_LOCK:
                    _SETTINGS["backup_snapshot"] = {
                        "ts": datetime.datetime.now().isoformat(),
                        "config": _public_settings_snapshot()}
                    _SETTINGS["last_backup"] = iso if ab == "daily" else wk
                changed = True
                _audit("System", f"Auto-backup completed ({ab})")
            if changed:
                _save_settings()
        except Exception:
            pass


def _ua_short(ua):
    """'Chrome · Android' style device label for the sessions list."""
    u = (ua or "")
    os_ = ("Android" if "Android" in u else
           "iPhone" if "iPhone" in u else
           "iPad" if "iPad" in u else
           "Windows" if "Windows" in u else
           "macOS" if "Macintosh" in u or "Mac OS" in u else
           "Linux" if "Linux" in u else "")
    br = ("Edge" if "Edg/" in u else
          "Firefox" if "Firefox" in u else
          "Chrome" if "Chrome" in u else
          "Safari" if "Safari" in u else "")
    out = " · ".join(x for x in (br, os_) if x)
    return out or "Unknown device"


# ---- Audit log (admin console) ----
# Append-only JSONL of admin + system events: sign-ins, friend and
# view-pass changes, settings changes, provider downs and failovers.
# Lives on local disk like usage.jsonl (resets on redeploy, same as
# sessions and view passes); never holds secrets — labels, provider
# names and counts only.
AUDIT_PATH = Path(__file__).parent / "audit.jsonl"


_AUDIT_LOCK = threading.RLock()


def _audit(category, event, ip=None):
    # Audit run-7: appends and the >512 KB trim are serialized, and
    # the trim rewrites via a unique temp name — the unlocked
    # fixed-.tmp trim lost and spliced rows under concurrency.
    with _AUDIT_LOCK:
        _audit_locked(category, event, ip)


def _audit_locked(category, event, ip=None):
    try:
        row = {
            "ts": datetime.datetime.now().isoformat(),
            "cat": str(category)[:24],
            "event": str(event)[:300],
        }
        # Client IPs are recorded only when the admin keeps the
        # "record IPs in audit log" toggle on (console v2 setting).
        if ip and _SETTINGS.get("audit_ips", True):
            row["ip"] = str(ip)[:45]
        with open(AUDIT_PATH, "a") as f:
            f.write(json.dumps(row) + "\n")
        _TELEMETRY["dirty"] = True
        if os.path.getsize(AUDIT_PATH) > 512 * 1024:
            with open(AUDIT_PATH) as f:
                lines = f.readlines()
            _cut = (datetime.datetime.now()
                    - datetime.timedelta(days=int(_SETTINGS.get("retention_days") or 30))).isoformat()
            lines = [ln for ln in lines[-1000:] if _fresh_line(ln, _cut)]
            _rewrite_lines(AUDIT_PATH, lines)
    except Exception:
        pass


def _read_audit(limit=200):
    out = []
    try:
        if AUDIT_PATH.exists():
            with open(AUDIT_PATH) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        e = json.loads(line)
                    except Exception:
                        continue
                    if isinstance(e, dict) and e.get("ts"):
                        out.append(e)
    except Exception:
        pass
    return out[-limit:][::-1]


# ---- Durable telemetry (owner order 2026-10-10, post-review) ----
# usage.jsonl / audit.jsonl live on Render's ephemeral disk, so every
# deploy used to zero the console's numbers AND the daily caps (which
# are counted from usage.jsonl). The tails of both files are kept in a
# restore-key-encrypted telemetry.enc, flushed at most every few
# minutes by a daemon thread, carried by the friend_blob sync to a
# DEDICATED git branch (nexus-telemetry — never main, so a flush can
# never trigger a redeploy), and hydrated back at boot. Bounded by
# line caps; holds no prompts beyond what usage rows already carry.
TELEMETRY_ENC_PATH = Path(__file__).parent / "telemetry.enc"
_TELEMETRY = {"dirty": False, "saved": "", "last_flush": 0.0}
_TELEMETRY_LOCK = threading.RLock()
_TELEMETRY_BRANCH_URL = ("https://raw.githubusercontent.com/xorudra/"
                         "Nexus-Local/nexus-telemetry/telemetry.enc")
_TELEMETRY_USAGE_LINES = 3000
_TELEMETRY_AUDIT_LINES = 500


def _tail_text(path, max_lines):
    try:
        if not path.exists():
            return ""
        with open(path) as f:
            lines = f.readlines()
        return "".join(lines[-max_lines:])
    except Exception:
        return ""


def _flush_telemetry():
    if not RESTORE_KEY:
        return False
    # Audit run-7: the flush is serialized against purges and
    # factory resets — an unlocked flush racing a purge wrote the
    # pre-purge tails into the mirror and cleared the dirty flag,
    # stranding the purged rows in the mirror for good.
    with _TELEMETRY_LOCK:
        return _flush_telemetry_locked()


def _flush_telemetry_locked():
    # Audit run-8: clear dirty BEFORE snapshotting the tails. The
    # old order set it after the ~0.7s encrypt, so a row appended
    # mid-flush landed after the snapshot yet had its flag cleared
    # anyway — never mirrored, and lost on the next redeploy. Rows
    # appended from here on re-set the flag and ride the next flush.
    _was_dirty = _TELEMETRY["dirty"]
    _TELEMETRY["dirty"] = False
    try:
        payload = {"v": 1,
                   "saved": datetime.datetime.now().isoformat(),
                   "usage": _tail_text(USAGE_PATH, _TELEMETRY_USAGE_LINES),
                   "audit": _tail_text(AUDIT_PATH, _TELEMETRY_AUDIT_LINES)}
        encrypt_keys(payload, RESTORE_KEY, TELEMETRY_ENC_PATH)
        _TELEMETRY["saved"] = payload["saved"]
        _TELEMETRY["last_flush"] = time.time()
        return True
    except Exception:
        _TELEMETRY["dirty"] = _was_dirty
        return False


_TELEMETRY_FLUSH_S = float(os.environ.get("NEXUS_TELEMETRY_FLUSH_S")
                           or 240)


def _telemetry_flusher():
    tick = 60 if _TELEMETRY_FLUSH_S >= 60 else max(1.0, _TELEMETRY_FLUSH_S)
    while True:
        try:
            time.sleep(tick)
            if _TELEMETRY["dirty"] \
                    and time.time() - _TELEMETRY["last_flush"] \
                    >= _TELEMETRY_FLUSH_S:
                _flush_telemetry()
        except Exception:
            pass


def _boot_restore_telemetry():
    """Hydrate usage/audit history at boot when the local files are
    missing (fresh deploy): local telemetry.enc first, then — on
    Render only — the copy mirrored to the nexus-telemetry branch."""
    try:
        usage_ok = USAGE_PATH.exists() and USAGE_PATH.stat().st_size > 0
        audit_ok = AUDIT_PATH.exists() and AUDIT_PATH.stat().st_size > 0
        if usage_ok and audit_ok:
            return
        data = None
        if RESTORE_KEY and TELEMETRY_ENC_PATH.exists():
            try:
                data = decrypt_keys(TELEMETRY_ENC_PATH, RESTORE_KEY)
            except Exception:
                data = None
        if data is None and RESTORE_KEY and os.environ.get("RENDER"):
            try:
                import urllib.request as _u
                with _open_cred(Request(_TELEMETRY_BRANCH_URL), 5) as r:
                    TELEMETRY_ENC_PATH.write_bytes(_read_capped_bytes(r))
                data = decrypt_keys(TELEMETRY_ENC_PATH, RESTORE_KEY)
            except Exception:
                data = None
        if not isinstance(data, dict):
            return
        if not usage_ok and data.get("usage"):
            USAGE_PATH.write_text(data["usage"])
            # Wave 16 (run-15 caps): the import-time counter seed
            # ran BEFORE this restore, so restored same-day spends
            # were invisible to provider_limits for the rest of the
            # day. Resync the counter from exactly the restored
            # text (one callsite covers both restore paths).
            with _USAGE_LOCK:
                _provider_counts_resync(data['usage'].splitlines(keepends=True))
        if not audit_ok and data.get("audit"):
            AUDIT_PATH.write_text(data["audit"])
        _TELEMETRY["saved"] = data.get("saved", "")
    except Exception:
        pass


def _audit_count_today(prefix, cat=None):
    today = datetime.date.today().isoformat()
    n = 0
    try:
        if AUDIT_PATH.exists():
            with open(AUDIT_PATH) as f:
                for line in f:
                    try:
                        e = json.loads(line)
                    except Exception:
                        continue
                    if str(e.get("ts", ""))[:10] != today:
                        continue
                    if cat and e.get("cat") != cat:
                        continue
                    if str(e.get("event", "")).startswith(prefix):
                        n += 1
    except Exception:
        pass
    return n


# Today's usage counts (providers + users), cached briefly: the file
# is bounded (20k lines) and chat is rate-limited, so a 20 s cache
# keeps caps/limits cheap without drifting far from the truth.
_TODAY_CACHE = {"ts": 0.0, "providers": {}, "users": {}, "v1": 0}

# Wave 15 (run-14 caps CAPS14-4): today's per-provider spend counts
# as an IN-MEMORY counter — the same numbers
# _today_counts(fresh=True)["providers"] returns from a full
# usage.jsonl scan, but maintained incrementally by
# _append_usage_locked on the single writer path and seeded by one
# scan per day. Reading completed spend inside _INFLIGHT_LOCK (the
# reserve primitive, _provider_blocked) is then a dict lookup; the
# wave-14 callable form ran the whole scan inside that global lock
# and stalled every surface's adds/drops behind it.
_PROVIDER_COUNTS = {"date": None, "providers": {}}


def _today_counts(fresh=False):
    now = time.time()
    if not fresh and now - _TODAY_CACHE["ts"] < 20:
        return _TODAY_CACHE
    providers, users = {}, {}
    v1n = 0
    today = datetime.date.today().isoformat()
    try:
        if os.path.exists(USAGE_PATH):
            with open(USAGE_PATH) as f:
                for line in f:
                    try:
                        e = json.loads(line)
                    except Exception:
                        continue
                    if not isinstance(e, dict) or e.get("type"):
                        continue
                    if str(e.get("ts", ""))[:10] != today:
                        continue
                    p = e.get("provider")
                    if isinstance(p, str) and p:
                        providers[p] = providers.get(p, 0) + 1
                    if e.get("via") == "v1" and not (
                            isinstance(p, str) and p.startswith("v1:")):
                        v1n += 1
                    u = e.get("user")
                    if isinstance(u, str) and u:
                        users[u] = users.get(u, 0) + 1
    except Exception:
        pass
    _TODAY_CACHE.update({"ts": now, "providers": providers, "users": users, "v1": v1n})
    return _TODAY_CACHE


def _provider_counts_today():
    """Today's per-provider counts from the in-memory counter
    (CAPS14-4): seeded by ONE scan on first use / date rollover,
    incremented by _append_usage_locked per append, rebuilt by the
    trim/purge rewrites — exactly the provider map a fresh
    _today_counts scan returns, with no file I/O on the read path."""
    today = datetime.date.today().isoformat()
    if _PROVIDER_COUNTS["date"] != today:
        counts = _today_counts(fresh=True)["providers"]
        with _USAGE_LOCK:
            if _PROVIDER_COUNTS["date"] != today:
                _PROVIDER_COUNTS["date"] = today
                _PROVIDER_COUNTS["providers"] = dict(counts)
    return _PROVIDER_COUNTS["providers"]


def _provider_counts_note(entry):
    """Increment the counter for one appended row (the
    _today_counts counting predicate: no "type", provider a
    non-empty string, row date = the counter's day). Caller holds
    _USAGE_LOCK (the _append_usage_locked writer path)."""
    try:
        if not isinstance(entry, dict) or entry.get("type"):
            return
        p = entry.get("provider")
        if not isinstance(p, str) or not p:
            return
        d = str(entry.get("ts", ""))[:10]
        # Wave 16 (run-15 caps): mirror the scan predicate exactly
        # — a row dated anything but today is IGNORED, never a
        # rollover. The old shape treated a backdated row (a
        # request straddling midnight) or a missing-ts row as a
        # day flip and wiped today's counts, and a follow-on today
        # row then defeated the reseed-on-read: a fail-open
        # under-count for the rest of the day.
        if d != datetime.date.today().isoformat():
            return
        if _PROVIDER_COUNTS["date"] != d:
            _PROVIDER_COUNTS["date"] = d
            _PROVIDER_COUNTS["providers"] = {}
        _PROVIDER_COUNTS["providers"][p] = \
            _PROVIDER_COUNTS["providers"].get(p, 0) + 1
    except Exception:
        pass


def _provider_counts_resync(lines):
    """Rebuild the counter from usage-log lines — every writer
    that removes or replaces rows (trim, purge, friend usage
    reset, factory truncate, boot telemetry restore) resyncs
    from exactly the lines that survive it. Caller holds
    _USAGE_LOCK."""
    today = datetime.date.today().isoformat()
    counts = {}
    for ln in lines:
        try:
            e = json.loads(ln)
        except Exception:
            continue
        if not isinstance(e, dict) or e.get("type"):
            continue
        if str(e.get("ts", ""))[:10] != today:
            continue
        p = e.get("provider")
        if isinstance(p, str) and p:
            counts[p] = counts.get(p, 0) + 1
    _PROVIDER_COUNTS["date"] = today
    _PROVIDER_COUNTS["providers"] = counts


# Boot seed (CAPS14-4): the one scan happens here, at import, so the
# locked read paths above never scan under _INFLIGHT_LOCK.
try:
    _provider_counts_today()
except Exception:
    pass


def _today_total_requests(fresh=False):
    """Today's counted requests across both surfaces: dashboard chat
    (counted per user) plus /v1 API rows (which carry no user and
    are tagged via="v1"; legacy rows used 'v1:<lane>' providers)."""
    c = _today_counts(fresh)
    total = sum(c["users"].values())
    # Audit run-7: current /v1 writers tag rows via="v1" with the
    # bare lane as provider; the old sum matched only the legacy
    # "v1:<lane>" names, so /v1 spend counted as ZERO here and the
    # global cap never bound the /v1 surface at all.
    total += c.get("v1", 0)
    total += sum(v for k, v in c["providers"].items()
                 if k.startswith("v1:"))
    return total


_INFLIGHT = []
# Wave 11 (F5): every add/drop/count/prune of _INFLIGHT runs under
# this one lock — the unlocked snapshot-then-assign prune could
# destroy a concurrent add (or resurrect a concurrent drop) whenever
# the list length changed inside the window. Holds are microscopic:
# no I/O and no upstream calls ever happen under it.
_INFLIGHT_LOCK = threading.Lock()


def _inflight_add_locked(user, provider=None, attempt=False):
    """Append a reservation; caller holds _INFLIGHT_LOCK."""
    e = {"user": user, "provider": provider, "ts": time.time(),
         "att": bool(attempt)}
    _INFLIGHT.append(e)
    return e


def _inflight_drop_locked(e):
    """Drop a reservation by identity; caller holds _INFLIGHT_LOCK."""
    for i, x in enumerate(_INFLIGHT):
        if x is e:
            del _INFLIGHT[i]
            break


def _inflight_count_locked(provider=None):
    """Count live reservations for a provider (attempt entries
    included, as in _inflight_n); caller holds _INFLIGHT_LOCK.
    Expired entries are pruned by identity, as in _inflight_n."""
    now = time.time()
    for e in [x for x in _INFLIGHT if now - x["ts"] > 900]:
        _inflight_drop_locked(e)
    return sum(1 for e in _INFLIGHT
               if provider is None or e["provider"] == provider)


def _inflight_reserve_capped(user, provider, completed, limit):
    # Wave 14 (run-13 caps): `completed` may be a zero-arg callable;
    # it is then invoked INSIDE the lock hold below, so completed +
    # in-flight are ONE snapshot. Callers used to compute it before
    # the call, and a peer completing in that gap left the count
    # stale (2 spends against a limit of 1). A callable that raises
    # falls back to the callers' old no-cap shape (reservation kept).
    """Wave 13 (run-12 caps): ONE locked reserve+count primitive.
    The old reserve-then-count shape added, counted and dropped in
    three separate operations, so two concurrent spends at a limit
    of 1 each counted the other and refused EACH OTHER (0 upstream
    hits where exactly 1 is allowed). Here the append, the count
    (completed + in-flight including this reservation) and the
    refuse-drop are indivisible under a single _INFLIGHT_LOCK hold,
    held only across this one segment — never across a caller's
    early-return branches. Returns the reservation, or None when
    the limit is already spent."""
    with _INFLIGHT_LOCK:
        res = _inflight_add_locked(user, provider, attempt=True)
        if limit:
            try:
                _lim13 = int(limit)
            except Exception:
                return res
            if callable(completed):
                try:
                    completed = completed()
                except Exception:
                    return res
            if completed + _inflight_count_locked(provider) > _lim13:
                _inflight_drop_locked(res)
                return None
        return res


def _inflight_add(user, provider=None, attempt=False):
    with _INFLIGHT_LOCK:
        return _inflight_add_locked(user, provider, attempt)


def _inflight_drop(e):
    with _INFLIGHT_LOCK:
        _inflight_drop_locked(e)


def _inflight_n(user=None, provider=None, exclude=None):
    """Admitted-but-not-yet-counted requests (audit run-6): the cap
    checks used to read only COMPLETED usage rows through a 20s
    cache, so a parallel burst all passed the same stale snapshot.
    Checks now read fresh counts PLUS these reservations; entries
    expire after 15 minutes so a wedged request cannot reserve
    forever (expired entries are pruned here, audit run-8).
    Counting rules (audit run-8): a caller checking its OWN admission
    passes exclude=<its reservation> — wave 8 reserved before the
    checks and then counted the caller's own slot, so cap=1 refused
    the first request of the day. Unfiltered counts (per-user and
    instance totals) count LOGICAL requests: per-attempt entries
    (att=True) belong to a request already counted by its base
    reservation and are skipped; provider-filtered counts include
    them, since a provider limit binds attempts."""
    now = time.time()
    with _INFLIGHT_LOCK:
        # Prune expired entries BY IDENTITY under the lock (wave 11,
        # F5): never overwrite the list from an unlocked snapshot.
        for e in [x for x in _INFLIGHT if now - x["ts"] > 900]:
            for i, x in enumerate(_INFLIGHT):
                if x is e:
                    del _INFLIGHT[i]
                    break
        live = list(_INFLIGHT)
    n = 0
    for e in live:
        if exclude is not None and e is exclude:
            continue
        if user is not None and e["user"] != user:
            continue
        if provider is not None:
            if e["provider"] != provider:
                continue
        elif e.get("att"):
            continue
        n += 1
    return n


def _inflight_rank(res, user=None):
    """Wave 15 (run-14 caps CAPS14-6): the caller's RANK among the
    live base reservations of one cap scope (1-based, reservation
    order; attempt entries skipped, matching _inflight_n's rules
    for base scopes), keyed by user for the per-user cap or
    unfiltered for the instance-global cap. Judged as
    completed + rank > cap, exactly one of a concurrent pair at
    the last slot is admitted — the wave-14 rank form the provider
    limits already had, which the per-user/global predicates
    missed (their exclude-self + count-peers form refused BOTH).
    A caller whose reservation already expired is ranked as the
    scope's newest entry."""
    now = time.time()
    with _INFLIGHT_LOCK:
        for e in [x for x in _INFLIGHT if now - x["ts"] > 900]:
            _inflight_drop_locked(e)
        rank = 0
        for e in _INFLIGHT:
            if e.get("att"):
                continue
            if user is not None and e["user"] != user:
                continue
            rank += 1
            if e is res:
                return rank
        return rank + 1


def _instance_cap_reached():
    """True when the owner's instance-wide daily cap (console setting
    global_cap, 0 = off) is set and today's total has reached it."""
    try:
        gcap = int(_SETTINGS.get("global_cap") or 0)
    except Exception:
        gcap = 0
    return bool(gcap) and _today_total_requests(fresh=True) >= gcap


_V1_CAP_AUDIT = [0.0]


def _ts_or(x, dflt=0):
    """int(x) that never raises (audit run-8): a stored OAuth token
    whose expires field is not numeric used to raise straight
    through the chat attempt path — a 500 that also orphaned the
    attempt's cap reservation. Unparseable reads as dflt, which
    for an expiry means 'expired': refresh is attempted and a
    failed refresh fails closed."""
    try:
        return int(x)
    except Exception:
        return dflt


def _finite_num(x):
    """A real, finite JSON number — not a bool, not NaN/Infinity
    (audit run-6: int(nan) raised inside the dict-valued branches
    below and 500'd the settings endpoint; JSON has no business
    carrying non-finite numbers into persisted settings)."""
    return isinstance(x, (int, float)) and not isinstance(x, bool) \
        and x == x and abs(x) != float("inf")


def _validate_settings_patch(patch):
    """Whitelist + type-check a settings patch from the admin console.
    Returns (clean_dict, error) — error None on success."""
    clean = {}
    for k, v in patch.items():
        # The console's segmented controls read values from DOM dataset,
        # which are always strings ("60", not 60) — a valid pill choice
        # was refused for its type ("session_minutes must be 30, 60, 480
        # or 1440" when picking 1h). Coerce integer strings for the
        # numeric settings here; the per-key checks below still enforce
        # the allowed values and ranges.
        if k in ("session_minutes", "retention_days", "cb_failures",
                 "cb_cooldown_s", "chat_rate", "pw_min", "latency_alert_s",
                 "quota_alert_pct", "max_attempts", "daily_cap",
                 "global_cap") and isinstance(v, str) \
                and v.strip().lstrip("-").isdigit():
            v = int(v.strip())
        if k == "maintenance":
            if not isinstance(v, bool):
                return None, "maintenance must be true or false"
            clean[k] = v
        elif k == "suspended":
            if not isinstance(v, list):
                return None, "suspended must be a list"
            clean[k] = [str(x)[:30] for x in v if isinstance(x, str)][:50]
        elif k == "max_attempts":
            if (not isinstance(v, int) or isinstance(v, bool)) or not 1 <= v <= 8:
                return None, "max_attempts must be 1-8"
            clean[k] = v
        elif k == "daily_cap":
            if (not isinstance(v, int) or isinstance(v, bool)) or not 0 <= v <= 100000:
                return None, "daily_cap must be 0-100000"
            clean[k] = v
        elif k == "user_caps":
            if not isinstance(v, dict):
                return None, "user_caps must be an object"
            clean[k] = {str(a)[:30]: max(0, min(100000, int(b)))
                        for a, b in v.items() if _finite_num(b)}
        elif k == "provider_order":
            if not isinstance(v, list):
                return None, "provider_order must be a list"
            clean[k] = [x for x in v if x in PROVIDER_NAMES]
        elif k == "provider_disabled":
            if not isinstance(v, list):
                return None, "provider_disabled must be a list"
            clean[k] = [x for x in v if isinstance(x, str)][:64]
        elif k == "provider_limits":
            if not isinstance(v, dict):
                return None, "provider_limits must be an object"
            clean[k] = {str(a)[:64]: int(b) for a, b in v.items()
                        if _finite_num(b) and int(b) > 0}
        elif k == "session_minutes":
            if isinstance(v, bool) or not isinstance(v, int) or v not in (30, 60, 480, 1440):
                return None, "session_minutes must be 30, 60, 480 or 1440"
            clean[k] = v
        elif k == "retention_days":
            if isinstance(v, bool) or not isinstance(v, int) or v not in (7, 30, 90):
                return None, "retention_days must be 7, 30 or 90"
            clean[k] = v
        elif k == "instance_name":
            if not isinstance(v, str) or not v.strip() or len(v) > 40:
                return None, "instance_name must be 1-40 chars"
            clean[k] = v.strip()
        elif k == "global_cap":
            if (not isinstance(v, int) or isinstance(v, bool)) or not 0 <= v <= 1000000:
                return None, "global_cap must be 0-1000000"
            clean[k] = v
        elif k == "chain_mode":
            if v not in ("priority", "fastest", "round_robin"):
                return None, "chain_mode must be priority, fastest or round_robin"
            clean[k] = v
        elif k == "provider_timeouts":
            if not isinstance(v, dict):
                return None, "provider_timeouts must be an object"
            clean[k] = {str(a)[:64]: max(5, min(600, int(b)))
                        for a, b in v.items() if _finite_num(b)}
        elif k == "cb_failures":
            if v is not None and ((not isinstance(v, int) or isinstance(v, bool)) or not 1 <= v <= 10):
                return None, "cb_failures must be 1-10"
            clean[k] = v
        elif k == "cb_cooldown_s":
            if v is not None and (isinstance(v, bool)
                                  or not isinstance(v, int)
                                  or v not in (30, 120, 180, 600)):
                return None, "cb_cooldown_s must be 30, 120, 180 or 600"
            clean[k] = v
        elif k == "chat_rate":
            if v is not None and (isinstance(v, bool)
                                  or not isinstance(v, int)
                                  or v not in (0, 10, 30, 40, 60)):
                return None, "chat_rate must be 10, 30, 40, 60 or 0 (off)"
            clean[k] = v
        elif k == "webhook_url":
            if not isinstance(v, str) or len(v) > 300:
                return None, "webhook_url must be a string up to 300 chars"
            v = v.strip()
            if v and not _webhook_url_ok(v):
                return None, "webhook_url must be http(s) to a public host"
            clean[k] = v
        elif k == "alert_email":
            if not isinstance(v, str) or len(v) > 120:
                return None, "alert_email must be a string up to 120 chars"
            clean[k] = v.strip()
        elif k == "alerts":
            if not isinstance(v, dict):
                return None, "alerts must be an object"
            clean[k] = {a: bool(b) for a, b in v.items()
                        if a in ("provider_down", "cap", "signup")}
        elif k in ("digest_daily", "digest_weekly"):
            if not isinstance(v, bool):
                return None, f"{k} must be true or false"
            clean[k] = v
        elif k == "announcement":
            if not isinstance(v, str) or len(v) > 160:
                return None, "announcement must be a string up to 160 chars"
            clean[k] = v.strip()
        elif k == "allowed_ips":
            if not isinstance(v, list) or len(v) > 20:
                return None, "allowed_ips must be a list of up to 20 entries"
            out = []
            for x in v:
                if not isinstance(x, str) or len(x) > 50:
                    return None, "allowed_ips entries must be IPs or CIDRs"
                try:
                    ipaddress.ip_network(x.strip(), strict=False)
                except Exception:
                    return None, f"invalid IP or CIDR: {x}"
                out.append(x.strip())
            clean[k] = out
        elif k == "registration":
            if v not in ("open", "invite", "closed"):
                return None, "registration must be open, invite or closed"
            clean[k] = v
        elif k == "signup_role":
            if v not in ("friend", "viewer"):
                return None, "signup_role must be friend or viewer"
            clean[k] = v
        elif k == "pw_min":
            if isinstance(v, bool) or not isinstance(v, int) or v not in (8, 12, 16):
                return None, "pw_min must be 8, 12 or 16"
            clean[k] = v
        elif k == "latency_alert_s":
            if isinstance(v, bool) or not isinstance(v, int) or v not in (0, 1, 2, 5):
                return None, "latency_alert_s must be 0, 1, 2 or 5"
            clean[k] = v
        elif k == "quota_alert_pct":
            if isinstance(v, bool) or not isinstance(v, int) or v not in (80, 90, 95):
                return None, "quota_alert_pct must be 80, 90 or 95"
            clean[k] = v
        elif k == "oauth_admin_emails":
            if not isinstance(v, list) or len(v) > 10:
                return None, "oauth_admin_emails must be a list of up to 10 emails"
            out = []
            for x in v:
                if not isinstance(x, str):
                    return None, "oauth_admin_emails entries must be emails"
                e = x.strip().lower()
                if len(e) > 120 or not _re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", e):
                    return None, f"invalid email: {x}"
                out.append(e)
            clean[k] = out
        elif k == "oauth_links":
            if not isinstance(v, list) or len(v) > 50:
                return None, "oauth_links must be a list of up to 50 entries"
            out = []
            for x in v:
                if not isinstance(x, dict):
                    return None, "oauth_links entries must be {email, label}"
                e = str(x.get("email") or "").strip().lower()
                lab = str(x.get("label") or "").strip()
                if len(e) > 120 or not _re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", e):
                    return None, f"invalid email in oauth_links: {e}"
                if not _LABEL_RE.match(lab):
                    return None, f"invalid label in oauth_links: {lab}"
                out.append({"email": e, "label": lab})
            clean[k] = out
        elif k in ("skip_failing", "login_lockout", "audit_ips",
                   "log_prompts", "friends_byok"):
            if not isinstance(v, bool):
                return None, f"{k} must be true or false"
            clean[k] = v
        elif k == "auto_backup":
            if v not in ("off", "daily", "weekly"):
                return None, "auto_backup must be off, daily or weekly"
            clean[k] = v
        else:
            return None, f"unknown setting: {k}"
    return clean, None


def _fresh_line(line, cut_iso):
    """Retention helper: keep a JSONL line whose ts is >= the cutoff
    (unparseable lines are kept — never delete data on a guess)."""
    try:
        return str(json.loads(line).get("ts", "")) >= cut_iso
    except Exception:
        return True


def _system_metrics():
    """Real host metrics for the console's Instance card: CPU from
    /proc/loadavg, RAM from /proc/meminfo, disk from the app volume,
    uptime from process start. Any source may be unavailable (None)."""
    m = {"cpu_pct": None, "ram_pct": None, "disk_pct": None,
         "uptime_s": int(time.time() - _BOOT_TS),
         "boot_ts": int(_BOOT_TS),
         "build": (os.environ.get("RENDER_GIT_COMMIT") or "")[:7],
         "vault_locked": Handler.keys is None,
         "telemetry_saved": _TELEMETRY.get("saved", "")}
    try:
        with open("/proc/loadavg") as f:
            load1 = float(f.read().split()[0])
        cpus = os.cpu_count() or 1
        m["cpu_pct"] = max(0, min(100, round(load1 / cpus * 100)))
    except Exception:
        pass
    try:
        info = {}
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] in ("MemTotal:", "MemAvailable:"):
                    info[parts[0]] = int(parts[1])
        if info.get("MemTotal:"):
            used = info["MemTotal:"] - info.get("MemAvailable:", 0)
            m["ram_pct"] = round(used / info["MemTotal:"] * 100)
    except Exception:
        pass
    try:
        du = shutil.disk_usage(str(Path(__file__).parent))
        m["disk_pct"] = round(du.used / du.total * 100) if du.total else None
    except Exception:
        pass
    return m


SESSION_EXPIRY = int(os.environ.get("NEXUS_SESSION_EXPIRY", "1800"))

# What each provider can actually serve in this app (chat / image /
# voice / video), from the routes the chat handler implements. Drives
# the admin console's capability filters and mesh-health groups.
_PROVIDER_CAPS = {
    "aihorde": ["image"],
    "pollinations": ["chat", "image"],
    "relay_pollinations": ["chat", "image"],
    "google": ["chat", "image"],
    "relay_gemini": ["chat", "image"],
    "huggingface": ["chat", "image", "video"],
    "groq": ["chat", "voice"],
    "relay_groq": ["chat", "voice"],
    "cloudflare": ["chat", "image", "voice"],
    "openrouter": ["chat", "image"],
    "relay_openrouter": ["chat", "image"],
}


def _provider_caps(name):
    if name.startswith("custom_"):
        return ["chat"]
    return _PROVIDER_CAPS.get(name, ["chat"])


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

def _load_userkeys_strict(label, password):
    """Strict variant for SAVE paths: a missing vault is an empty one,
    but an EXISTING vault that fails to decrypt (or has an unexpected
    shape) RAISES — the lenient loader would hand the save an empty
    dict and the save would permanently overwrite the real vault."""
    p = _userkey_path(label)
    if not p.exists():
        return {}
    d = decrypt_keys(p, password)  # raises on wrong password / corruption
    if not isinstance(d, dict):
        raise ValueError("user key vault has unexpected shape")
    return d

def _save_userkeys(label, keys_dict, password):
    p = _userkey_path(label)
    encrypt_keys(keys_dict, password, p)
    os.chmod(p, 0o600)
    # Vault metadata for the admin console (provider + last-4 only —
    # never key material): lets the owner see whose vault holds what
    # without anyone decrypting a friend's vault.
    try:
        meta = [{"provider": str(k), "last4": str(v)[-4:]}
                for k, v in sorted((keys_dict or {}).items())
                if isinstance(v, str) and len(v) >= 8
                and not str(k).endswith("_url")]
        with _SETTINGS_LOCK:
            vm = dict(_SETTINGS.get("vault_meta") or {})
            vm[label] = meta
            _SETTINGS["vault_meta"] = vm
        # Audit run-9 (S2): the save runs AFTER the lock releases —
        # _save_settings snapshots under its own acquisition, and
        # holding _SETTINGS_LOCK across its PBKDF2 encrypt convoyed
        # every other settings writer behind each save.
        _save_settings()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Integrations (owner order 2026-10-15: the shadcndashboard Integration
# page, implemented for real). Each user connects services with their
# OWN credentials; secrets live in a per-user vault
# app/userintegrations/<label>.enc encrypted with the account password
# (the My Keys pattern: the password is verified per request that
# persists, never stored; the decrypted vault rides the session after
# an explicit unlock). OAuth client apps (Google/Zoom) are the owner's
# — credentials come from the server env ONLY (NEXUS_INTG_GOOGLE_*,
# NEXUS_INTG_ZOOM_*), never the repo or settings.
# ---------------------------------------------------------------------------
INTG_DIR = Path(__file__).parent / "userintegrations"
INTG_DIR.mkdir(exist_ok=True)

# API-key services: field name -> label the page shows. The server
# validates presence + length only; the provider's own API is the
# judge (see the testers below).
_INTG_APIKEY_SERVICES = {
    "linear": ("api_key",),
    "notion": ("token",),
    "trello": ("api_key", "token"),
    "jira": ("site", "email", "token"),
    "mailchimp": ("api_key",),
}


def _intg_path(label):
    safe = _re.sub(r"[^a-z0-9_]", "", (label or "").lower())[:30]
    return INTG_DIR / f"{safe}.enc"


def _intg_label(info):
    """Vault label for a session: friends use their label, the owner
    a reserved one. None when the session has no usable identity."""
    if not info:
        return None
    if info.get("admin"):
        return "_owner"
    label = info.get("label", "")
    return label if _LABEL_RE.match(label) else None


def _load_intg(label, password):
    try:
        p = _intg_path(label)
        if not p.exists():
            return None
        d = decrypt_keys(p, password)
        return d if isinstance(d, dict) else None
    except Exception:
        return None


def _load_intg_strict(label, password):
    """Strict variant for SAVE paths, mirroring _load_chats_strict:
    missing file -> {}, existing-but-undecryptable -> raise, so a
    save can never turn a failed decrypt into an overwrite."""
    p = _intg_path(label)
    if not p.exists():
        return {}
    d = decrypt_keys(p, password)  # raises on wrong password / corruption
    if not isinstance(d, dict):
        raise ValueError("integrations vault has unexpected shape")
    return d


def _save_intg(label, data, password):
    p = _intg_path(label)
    encrypt_keys(data, password, p)
    os.chmod(p, 0o600)


_PW_FAILS = {}


def _pw_throttled(kind, key):
    """Audit run-6: the master/friend password proofs are offline-
    oracle shaped — PBKDF2 cost was the only brake (measured:
    thousands of guesses a day from one host). 10 failures per
    (kind, key) inside 15 minutes locks further proofs for that
    key; kind "master" uses ONE global bucket (the secret itself is
    global, so a per-IP split would multiply the budget) — an owner's
    successful proof refills it, and a guesser can lock the owner out
    until the window passes (<=900 s). The friend kinds key on the
    account label."""
    now = time.time()
    fails = [t for t in _PW_FAILS.get((kind, key), []) if now - t < 900]
    _PW_FAILS[(kind, key)] = fails
    return len(fails) >= 10


def _pw_failed(kind, key):
    _PW_FAILS.setdefault((kind, key), []).append(time.time())
    return len(_PW_FAILS[(kind, key)])


def _master_proof(pw):
    """The one master-password oracle (audit run-6): a keys.enc
    decrypt attempt behind the shared failure budget — returns the
    decrypted dict, or None for a wrong password AND while the
    budget is exhausted (callers already answer both the same way).
    Every console/inline site that used to decrypt directly goes
    through here. The only other keys.enc proofs are /api/login (its
    own per-IP attempt ledger) and the custom-provider save, which
    runs only after this proof passes in the same request."""
    if not pw or _pw_throttled("master", ""):
        return None
    try:
        keys = decrypt_keys(Path(__file__).parent / "keys.enc", pw)
    except Exception:
        _pw_failed("master", "")
        return None
    # A success clears the budget: the lockout exists to stop
    # GUESSING, and a guesser never succeeds — while the owner's
    # own correct proofs (and the console's negative probes that a
    # success follows) must not starve each other.
    _PW_FAILS.pop(("master", ""), None)
    return keys


def _intg_verify(info, password):
    """Verify an account password for a persistence operation —
    friends against their stored hash, the owner by decrypting the
    master vault (the same proof the login itself uses)."""
    if not password:
        return False
    if info.get("admin"):
        # The master proof is a single global secret: one shared
        # failure budget across every oracle that checks it.
        if _pw_throttled("master", ""):
            return False
        try:
            decrypt_keys(Path(__file__).parent / "keys.enc", password)
            _PW_FAILS.pop(("master", ""), None)
            return True
        except Exception:
            _pw_failed("master", "")
            return False
    label = info.get("label", "")
    if _pw_throttled("intg", label):
        return False
    stored = (_load_access() or {}).get(label, "")
    ok, _up = _verify_password(password, stored)
    if not ok:
        _pw_failed("intg", label)
    else:
        _PW_FAILS.pop(("intg", label), None)
    return bool(ok)


_INTG_READ_CAP = 8 * 1024 * 1024


_MODEL_SEGMENT_RE = _re.compile(r"^[A-Za-z0-9@._~-]+$")


def _safe_model_path(model):
    """A chat-supplied model id becomes path segments in provider
    URLs built with shared account tokens (audit run-5): reject dot
    segments and anything outside the model-id charset, so the id
    cannot traverse (../) or inject (?query) into another endpoint.
    Returns the id unchanged for legitimate names, else None."""
    parts = (model or "").split("/")
    if not parts or any(p in (".", "..")
                        or not _MODEL_SEGMENT_RE.match(p) for p in parts):
        return None
    return "/".join(parts)


def _read_capped(resp, cap=_INTG_READ_CAP):
    """Bounded body read for integration/provider JSON calls: an
    unbounded read lets any caller-reachable host stream the
    single-process server out of memory (audit run-5). Over-cap
    bodies are truncated; JSON parsing then fails soft into the
    callers' existing text/diagnostic paths."""
    data = resp.read(cap + 1)
    if len(data) > cap:
        data = data[:cap]
    return data.decode(errors="replace")


def _read_capped_bytes(resp, cap=_INTG_READ_CAP):
    """Bytes twin of _read_capped for callers that forward or store
    the body itself (the relay, the telemetry mirror)."""
    data = resp.read(cap + 1)
    if len(data) > cap:
        data = data[:cap]
    return data


def _intg_http(url, method="GET", headers=None, data=None, timeout=20):
    """One provider API call. Returns (status, parsed_json_or_text).
    Never raises for HTTP errors — the body is the diagnostic."""
    if isinstance(data, dict):
        # JSON callers pass dicts (functional fix, audit run-7): a
        # dict body died inside urllib before a byte was sent, which
        # silently broke the Claude OAuth exchange/refresh and the
        # Gemini project lookup. Serialize here, once.
        data = json.dumps(data).encode()
    req = Request(url, data=data, headers=headers or {}, method=method)
    try:
        # Pinned opener for remote hosts: redirects re-validated,
        # connections pinned to validated public IPs, no ambient proxy
        # — a caller-supplied host (the Jira site) or a redirect must
        # not reach internal addresses with the caller's credentials
        # attached. Loopback targets are first-party local services
        # (operator-configured overrides) and go direct.
        _host = (urllib.parse.urlparse(url).hostname or "").lower()
        _opener = _open_loopback if _host in ("127.0.0.1", "localhost", "::1") \
            else _pinned_opener().open
        with _opener(req, timeout=timeout) as resp:
            body = _read_capped(resp)
            try:
                return resp.status, json.loads(body)
            except Exception:
                return resp.status, body
    except HTTPError as e:
        body = _read_capped(e)
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, body
    except Exception as e:
        return 0, str(e)


def _intg_err_text(payload):
    if isinstance(payload, dict):
        for k in ("message", "error_description", "detail", "title"):
            v = payload.get(k)
            if isinstance(v, str) and v:
                return v[:200]
        err = payload.get("error")
        if isinstance(err, dict) and isinstance(err.get("message"), str):
            return err["message"][:200]
        if isinstance(err, str) and err:
            return err[:200]
        errs = payload.get("errors")
        if isinstance(errs, list) and errs and isinstance(errs[0], dict):
            return str(errs[0].get("message") or errs[0])[:200]
    return str(payload)[:200]


# -- Live connection testers: (entry) -> (ok, account, detail) --------
def _intg_test_linear(e):
    st, j = _intg_http("https://api.linear.app/graphql", "POST",
                       {"Authorization": e["api_key"],
                        "Content-Type": "application/json"},
                       json.dumps({"query": "{ viewer { name email } }"}).encode())
    v = ((j.get("data") or {}).get("viewer") if isinstance(j, dict) else None) or {}
    if st == 200 and v:
        return True, f"{v.get('name', '')} <{v.get('email', '')}>".strip(), "Linear workspace reachable"
    return False, "", f"Linear said ({st}): {_intg_err_text(j)}"


def _intg_test_notion(e):
    st, j = _intg_http("https://api.notion.com/v1/users/me", "GET",
                       {"Authorization": "Bearer " + e["token"],
                        "Notion-Version": "2022-06-28"})
    if st == 200 and isinstance(j, dict):
        bot = j.get("bot") or {}
        ws = bot.get("workspace_name") or j.get("name") or "Notion workspace"
        return True, str(ws), "Notion integration token accepted"
    return False, "", f"Notion said ({st}): {_intg_err_text(j)}"


def _intg_test_trello(e):
    q = urllib.parse.urlencode({"key": e["api_key"], "token": e["token"]})
    st, j = _intg_http(f"https://api.trello.com/1/members/me?{q}")
    if st == 200 and isinstance(j, dict) and j.get("username"):
        return True, f"{j.get('fullName', '')} (@{j['username']})".strip(), "Trello account reachable"
    return False, "", f"Trello said ({st}): {_intg_err_text(j)}"


def _intg_test_jira(e):
    site = e["site"]
    # The site is user-typed and lands in the URL's authority: it must
    # resolve publicly before any credential leaves the server (the
    # fetch itself is pinned + redirect-guarded via _intg_http).
    _url = f"https://{site}/rest/api/3/myself"
    if not _public_base_url_ok(_url):
        return False, "", "That Jira site does not resolve to a public address — the connection test was refused"
    auth = base64.b64encode(f"{e['email']}:{e['token']}".encode()).decode()
    st, j = _intg_http(_url, "GET",
                       {"Authorization": "Basic " + auth,
                        "Accept": "application/json"})
    if st == 200 and isinstance(j, dict) and j.get("displayName"):
        return True, f"{j['displayName']} · {site}", "Jira site reachable"
    return False, "", f"Jira said ({st}): {_intg_err_text(j)}"


def _intg_test_mailchimp(e):
    key = e["api_key"]
    dc = key.rsplit("-", 1)[-1] if "-" in key else ""
    # The fragment lands in the URL's AUTHORITY component: validate it
    # against Mailchimp's real data-centre format (us21, uk1, ...) —
    # a crafted suffix containing "/" or ":" would otherwise redefine
    # the host/port of the server's outbound request.
    if not dc or dc == key or not _re.fullmatch(r"[a-z]{2}\d{1,2}", dc):
        return False, "", "That key has no data-centre suffix (it should end in -us<N>)"
    _url = f"https://{dc}.api.mailchimp.com/3.0/lists?count=1"
    if not urllib.parse.urlparse(_url).hostname.endswith(".api.mailchimp.com"):
        return False, "", "That key has no data-centre suffix (it should end in -us<N>)"
    auth = base64.b64encode(("nexus:" + key).encode()).decode()
    st, j = _intg_http(_url, "GET",
                       {"Authorization": "Basic " + auth})
    if st == 200 and isinstance(j, dict):
        return True, f"{j.get('total_items', 0)} audience(s) · {dc}", "Mailchimp account reachable"
    return False, "", f"Mailchimp said ({st}): {_intg_err_text(j)}"


_INTG_TESTERS = {"linear": _intg_test_linear, "notion": _intg_test_notion,
                 "trello": _intg_test_trello, "jira": _intg_test_jira,
                 "mailchimp": _intg_test_mailchimp}


def _intg_creds(provider):
    cid = os.environ.get(f"NEXUS_INTG_{provider.upper()}_ID", "").strip()
    sec = os.environ.get(f"NEXUS_INTG_{provider.upper()}_SECRET", "").strip()
    return (cid, sec) if cid and sec else None

# ----------------------------------------------------------------------
# AI account sign-ins (owner order 2026-10-15, OmniRoute-style):
# users sign in with their ChatGPT / Claude / Google accounts through
# the OAuth flows the providers built for their own CLI tools (Codex,
# Claude Code, Gemini CLI). Tokens live in the integrations vault,
# ride the session after login/unlock, refresh in place, and power
# three extra chat lanes. The product shows the account-risk note:
# the providers reserve this access for their own tools.
_AIOAUTH_CARD = {"codex": "openai", "claude_oauth": "anthropic",
                 "gemini_cli": "google"}
_AIOAUTH_CLIENTS = {
    "codex": {
        "auth": "https://auth.openai.com/oauth/authorize",
        "token": "https://auth.openai.com/oauth/token",
        "client_id": "app_EMoamEEZ73f0CkXaXp7hrann",
        "redirect": "http://localhost:1455/auth/callback",
        "scope": "openid email profile offline_access", "pkce": True,
        "extra": {"prompt": "login", "id_token_add_organizations": "true",
                  "codex_cli_simplified_flow": "true"},
    },
    "claude_oauth": {
        "auth": "https://claude.ai/oauth/authorize",
        "token": "https://platform.claude.com/v1/oauth/token",
        "client_id": "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
        "redirect": "http://localhost:54545/callback",
        "scope": ("user:profile user:inference user:sessions:claude_code "
                  "user:mcp_servers user:file_upload"),
        "pkce": True, "extra": {"code": "true"}, "json_exchange": True,
    },
    "gemini_cli": {
        "auth": "https://accounts.google.com/o/oauth2/v2/auth",
        "token": "https://oauth2.googleapis.com/token",
        "client_id": ("681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j"
                      ".apps.googleusercontent.com"),
        "client_secret": "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",
        "redirect": "https://codeassist.google.com/authcode",
        "scope": ("https://www.googleapis.com/auth/cloud-platform "
                  "https://www.googleapis.com/auth/userinfo.email "
                  "https://www.googleapis.com/auth/userinfo.profile"),
        # PKCE on (audit run-6): the codeassist page shows a BARE
        # code, which carries no state to compare — without PKCE any
        # code minted for this public client exchanged into any
        # signed-in session that had clicked Sign in. With S256 the
        # code only exchanges against the verifier held by the
        # browser that started this flow.
        "pkce": True,
        "extra": {"access_type": "offline", "prompt": "consent"},
    },
}
_AIOAUTH_MODELS = {
    "codex": ["gpt-5.2-codex", "gpt-5.1-codex-max", "gpt-5.1-codex",
              "gpt-5-codex"],
    "claude_oauth": ["claude-sonnet-4-5-20250929", "claude-opus-4-5-20251101",
                     "claude-haiku-4-5-20251001"],
    "gemini_cli": ["gemini-2.5-pro", "gemini-2.5-flash",
                   "gemini-3-flash-preview", "gemini-3-pro-preview",
                   "gemini-3.5-flash"],
}


def _pkce_pair():
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


def _jwt_claims(token):
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:
        return {}


def _intg_http_form(url, fields):
    """POST application/x-www-form-urlencoded; (status, json|text)."""
    body = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/x-www-form-urlencoded",
        "User-Agent": "NexusLocal"})
    try:
        with _pinned_opener().open(req, timeout=25) as resp:
            raw = _read_capped(resp)
            try:
                return resp.status, json.loads(raw)
            except ValueError:
                return resp.status, raw[:300]
    except urllib.error.HTTPError as e:
        raw = _read_capped(e) if e.fp else ""
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw[:300]
    except Exception:
        return 0, ""


def _aioauth_url(lane, state, challenge):
    cfg = _AIOAUTH_CLIENTS[lane]
    q = {"client_id": cfg["client_id"], "response_type": "code",
         "redirect_uri": cfg["redirect"], "scope": cfg["scope"],
         "state": state}
    q.update(cfg.get("extra") or {})
    if cfg.get("pkce"):
        q["code_challenge"] = challenge
        q["code_challenge_method"] = "S256"
    return cfg["auth"] + "?" + urllib.parse.urlencode(q)


def _aioauth_exchange(lane, code, verifier):
    """Swap an auth code for a token dict. Raises ValueError(detail)."""
    cfg = _AIOAUTH_CLIENTS[lane]
    if cfg.get("json_exchange"):
        st, j = _intg_http(cfg["token"], "POST",
                           {"Content-Type": "application/json"},
                           {"grant_type": "authorization_code", "code": code,
                            "client_id": cfg["client_id"],
                            "redirect_uri": cfg["redirect"],
                            "code_verifier": verifier})
    else:
        body = {"grant_type": "authorization_code", "code": code,
                "client_id": cfg["client_id"],
                "redirect_uri": cfg["redirect"]}
        if cfg.get("pkce"):
            body["code_verifier"] = verifier
        if cfg.get("client_secret"):
            body["client_secret"] = cfg["client_secret"]
        st, j = _intg_http_form(cfg["token"], body)
    if st != 200 or not isinstance(j, dict) or not j.get("access_token"):
        raise ValueError("the provider refused the code (%s): %s"
                         % (st, _intg_err_text(j)))
    tok = {"access": j["access_token"],
           "refresh": j.get("refresh_token") or "",
           "expires": int(time.time()) + _ts_or(j.get("expires_in") or 3600, 3600),
           "email": "", "account_id": "", "project": "", "plan": ""}
    if lane == "codex" and j.get("id_token"):
        claims = _jwt_claims(j["id_token"])
        auth = claims.get("https://api.openai.com/auth") or {}
        tok["account_id"] = auth.get("chatgpt_account_id") or ""
        tok["plan"] = auth.get("chatgpt_plan_type") or ""
        tok["email"] = claims.get("email") or ""
    if lane == "claude_oauth" and isinstance(j.get("account"), dict):
        tok["email"] = j["account"].get("email_address") or ""
    return tok


def _aioauth_refresh(lane, tok):
    cfg = _AIOAUTH_CLIENTS[lane]
    rt = tok.get("refresh") or ""
    if not rt:
        return None
    if cfg.get("json_exchange"):
        st, j = _intg_http(cfg["token"], "POST",
                           {"Content-Type": "application/json"},
                           {"grant_type": "refresh_token",
                            "refresh_token": rt,
                            "client_id": cfg["client_id"]})
    else:
        body = {"grant_type": "refresh_token", "refresh_token": rt,
                "client_id": cfg["client_id"]}
        if cfg.get("client_secret"):
            body["client_secret"] = cfg["client_secret"]
        st, j = _intg_http_form(cfg["token"], body)
    if st != 200 or not isinstance(j, dict) or not j.get("access_token"):
        return None
    out = dict(tok)
    out["access"] = j["access_token"]
    if j.get("refresh_token"):
        out["refresh"] = j["refresh_token"]
    out["expires"] = int(time.time()) + _ts_or(j.get("expires_in") or 3600, 3600)
    if lane == "codex" and j.get("id_token"):
        claims = _jwt_claims(j["id_token"])
        auth = claims.get("https://api.openai.com/auth") or {}
        if auth.get("chatgpt_account_id"):
            out["account_id"] = auth["chatgpt_account_id"]
        if auth.get("chatgpt_plan_type"):
            out["plan"] = auth["chatgpt_plan_type"]
        if claims.get("email"):
            out["email"] = claims["email"]
    return out


def _aioauth_fresh(info, lane):
    """The session's token for a sign-in lane, refreshed in place
    when it is about to expire. None when not connected/expired."""
    store = (info or {}).get("integrations") or {}
    tok = (store.get("ai_oauth") or {}).get(lane)
    if not isinstance(tok, dict) or not tok.get("access"):
        return None
    if _ts_or(tok.get("expires")) < time.time() + 90:
        new = _aioauth_refresh(lane, tok)
        if new:
            store.setdefault("ai_oauth", {})[lane] = new
            return new
        if _ts_or(tok.get("expires")) < time.time():
            return None
    return tok


_CODEX_MODELS_CACHE = {}


def _codex_live_models(info):
    """The models this ChatGPT account may actually use, from
    OpenAI's own Codex catalog: entries the catalog hides, and
    entries whose available_in_plans excludes the account's plan,
    are dropped (owner ask 2026-10-15: show only eligible models).
    Cached 10 min per account. None when the catalog cannot be
    reached or yields nothing — the caller falls back to the
    static list, and chat still fails honestly per attempt."""
    tok = _aioauth_fresh(info, "codex")
    if not tok:
        return None
    key = (tok.get("account_id") or tok.get("email")
           or (tok.get("access") or "")[:24])
    now = time.time()
    hit = _CODEX_MODELS_CACHE.get(key)
    if hit and now - hit[0] < 600:
        return hit[1]
    hdr = {"Authorization": "Bearer " + tok["access"],
           "Accept": "application/json",
           "Originator": "codex-tui",
           "User-Agent": "codex-tui/0.154.0 (Mac OS 26.5.2; arm64)"}
    if tok.get("account_id"):
        hdr["Chatgpt-Account-Id"] = tok["account_id"]
    url = os.environ.get("NEXUS_CODEX_MODELS_URL") or (
        "https://chatgpt.com/backend-api/codex/models"
        "?client_version=0.154.0")
    st, j = _intg_http(url, "GET", hdr, None, timeout=12)
    if st != 200 or not isinstance(j, dict):
        return None
    plan = (tok.get("plan") or "").lower()
    if not plan:
        # Sign-ins made before plan capture carry no stored plan —
        # the access token itself is a JWT holding the same claim.
        auth = _jwt_claims(tok.get("access") or "").get(
            "https://api.openai.com/auth") or {}
        plan = (auth.get("chatgpt_plan_type") or "").lower()
    out = []
    for m in (j.get("models") or []):
        if not isinstance(m, dict):
            continue
        slug = m.get("slug") or m.get("id") or ""
        if not slug or m.get("visibility") == "hide":
            continue
        plans = m.get("available_in_plans")
        if plan and isinstance(plans, list) and plans and \
                plan not in [str(p).lower() for p in plans]:
            continue
        out.append(slug)
    if not out:
        return None
    _CODEX_MODELS_CACHE[key] = (now, out)
    return out


def _gemini_project(access):
    """Discover (or onboard) the Code Assist project for a token."""
    hdr = {"Authorization": "Bearer " + access,
           "Content-Type": "application/json", "User-Agent": "GeminiCLI/0.1"}
    meta = {"ideType": "IDE_UNSPECIFIED", "platform": "PLATFORM_UNSPECIFIED",
            "pluginType": "GEMINI"}
    st, j = _intg_http(
        "https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist",
        "POST", hdr, {"metadata": meta})
    if st != 200 or not isinstance(j, dict):
        return ""
    proj = j.get("cloudaicompanionProject")
    if isinstance(proj, dict):
        proj = proj.get("id") or ""
    if proj:
        return str(proj)
    tier = "free-tier"
    for t in (j.get("allowedTiers") or []):
        if isinstance(t, dict) and t.get("isDefault"):
            tier = t.get("id") or tier
    for _ in range(4):
        st2, j2 = _intg_http(
            "https://cloudcode-pa.googleapis.com/v1internal:onboardUser",
            "POST", hdr, {"tierId": tier, "metadata": meta})
        if st2 == 200 and isinstance(j2, dict) and j2.get("done"):
            p2 = (j2.get("response") or {}).get("cloudaicompanionProject")
            if isinstance(p2, dict):
                p2 = p2.get("id") or ""
            if p2:
                return str(p2)
        time.sleep(2)
    return ""



# AI provider connections (owner order 2026-10-15): users connect
# their OWN provider accounts (Gemini, ChatGPT, Claude, and the rest
# of the Nexus roster) so their chats can run on their own keys.
# These keys live in the EXISTING per-user key vault (userkeys) — the
# same store My Keys manages and chat already reads — never in the
# integrations vault. Keyless lanes need no connection at all.
_INTG_AI_PROVIDERS = ("aihorde", "anthropic", "cloudflare", "cohere",
                      "google", "groq", "huggingface", "kilo", "mistral",
                      "nvidia", "openai", "openrouter", "ovh",
                      "pollinations", "zhipu")
_INTG_AI_KEYLESS = {"aihorde", "kilo", "ovh", "pollinations"}


def _intg_test_ai(prov, key):
    """Live-check one provider key against the provider itself.
    Returns (ok, label, detail); label is what the card may show."""
    if prov == "anthropic":
        st, j = _intg_http("https://api.anthropic.com/v1/models", "GET",
                           {"x-api-key": key, "anthropic-version": "2023-06-01"})
        if st == 200 and isinstance(j, dict):
            return True, f"Key accepted · {len(j.get('data') or [])} models", "Anthropic accepted the key"
        return False, "", f"Anthropic said ({st}): {_intg_err_text(j)}"
    if prov == "google":
        st, j = _intg_http("https://generativelanguage.googleapis.com/v1beta/models?key="
                           + urllib.parse.quote(key, safe=""))
        if st == 200 and isinstance(j, dict):
            return True, f"Key accepted · {len(j.get('models') or [])} models", "Google accepted the key"
        return False, "", f"Google said ({st}): {_intg_err_text(j)}"
    if prov == "cloudflare":
        st, j = _intg_http("https://api.cloudflare.com/client/v4/user/tokens/verify",
                           "GET", {"Authorization": "Bearer " + key})
        if st == 200 and isinstance(j, dict) and (j.get("success") or
                                                  (j.get("result") or {}).get("status") == "active"):
            return True, "Token verified active", "Cloudflare verified the token"
        return False, "", f"Cloudflare said ({st}): {_intg_err_text(j)}"
    base = RELAY_UPSTREAMS.get(prov)
    if not base:
        return False, "", "no live check available for this provider"
    st, j = _intg_http(base.rstrip("/") + "/models", "GET",
                       {"Authorization": "Bearer " + key})
    if st == 200 and isinstance(j, dict):
        n = len(j.get("data") or j.get("models") or [])
        return True, f"Key accepted · {n} models", "The provider accepted the key"
    return False, "", f"The provider said ({st}): {_intg_err_text(j)}"


def _google_access_token(entry):
    """Refresh a stored Google connection. Returns an access token
    or raises ValueError with the provider's own words."""
    creds = _intg_creds("google")
    if not creds:
        raise ValueError("the owner's Google app is not configured on this server")
    data = urllib.parse.urlencode({
        "client_id": creds[0], "client_secret": creds[1],
        "refresh_token": entry.get("refresh_token", ""),
        "grant_type": "refresh_token"}).encode()
    st, j = _intg_http("https://oauth2.googleapis.com/token", "POST",
                       {"Content-Type": "application/x-www-form-urlencoded"}, data)
    if st == 200 and isinstance(j, dict) and j.get("access_token"):
        return j["access_token"]
    raise ValueError(f"Google token refresh failed ({st}): {_intg_err_text(j)}")


def _zoom_access_token(entry):
    creds = _intg_creds("zoom")
    if not creds:
        raise ValueError("the owner's Zoom app is not configured on this server")
    if entry.get("refresh_token"):
        data = urllib.parse.urlencode({
            "grant_type": "refresh_token",
            "refresh_token": entry["refresh_token"]}).encode()
        auth = base64.b64encode(f"{creds[0]}:{creds[1]}".encode()).decode()
        st, j = _intg_http("https://zoom.us/oauth/token", "POST",
                           {"Authorization": "Basic " + auth,
                            "Content-Type": "application/x-www-form-urlencoded"}, data)
        if st == 200 and isinstance(j, dict) and j.get("access_token"):
            entry["access_token"] = j["access_token"]
            if j.get("refresh_token"):
                entry["refresh_token"] = j["refresh_token"]
            return j["access_token"]
        raise ValueError(f"Zoom token refresh failed ({st}): {_intg_err_text(j)}")
    if entry.get("access_token"):
        return entry["access_token"]
    raise ValueError("the Zoom connection has no token — reconnect it")


def _session_meta(headers, fallback_ip=""):
    """Bookkeeping stamped onto a new session: a short id (safe to show
    and revoke by — never the token), the client IP and a device label."""
    return {
        "sid": secrets.token_hex(4),
        "ip": _client_ip(headers, fallback_ip),
        "ua": _ua_short(headers.get("User-Agent", "") if headers else ""),
    }

# Per-user saved chats: app/chats/<label>.enc, encrypted with the user's own
# login password (master password for the admin). Synced to GitHub through
# /api/friend_blob like users.enc and the key vaults, so chats survive
# redeploys. Format: {"chats": [{id, title, ts, updated, messages:[{r,t,m?}]}]}
CHATS_DIR = Path(__file__).parent / "chats"
CHATS_DIR.mkdir(exist_ok=True)

def _chat_path(label):
    safe = _re.sub(r"[^a-z0-9_]", "", (label or "").lower())[:30]
    return CHATS_DIR / f"{safe}.enc"

def _load_chats_strict(label, password):
    """Strict friend chat loader, mirroring _load_admin_chats_strict:
    a missing file is an empty store, but an EXISTING file that fails
    to decrypt (or has an unexpected shape) RAISES — a lenient loader would conflate the two, and a save/delete
    dispatched from that silent empty state would permanently
    overwrite the history."""
    p = _chat_path(label)
    if not p.exists():
        return {"chats": []}
    d = decrypt_keys(p, password)  # raises on wrong password / corruption
    if not isinstance(d, dict) or not isinstance(d.get("chats"), list):
        raise ValueError("friend chat store has unexpected shape")
    return d

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
    # Unique tmp name per call: a fixed name is shared by concurrent
    # saves of the same store and loses saves (audit run-4).
    tmp = path.parent / (path.name + "." + str(os.getpid()) + "."
                         + os.urandom(4).hex() + ".tmp")
    try:
        tmp.write_text(json.dumps(envelope), encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise

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

# Wave 19 (run-18 D18-2): persistent divergence record for the
# users.enc disaster backup. Invariant: the flag is present IFF
# users.enc MAY differ from the last dict a master-bearing save
# intended to persist there, and intended_labels is that dict's
# label set. Any successful users.enc write makes users.enc equal
# to the dict just written (which is also the live store at that
# moment), so success CLEARS the flag; a failed write RAISES it
# with the set that failed to land. The record lives in a
# _SETTINGS key: settings.enc rides the same friend_blob sync as
# users.enc and is readable without a master context, so the flag
# survives every restore shape users.enc itself survives. An
# in-memory copy backs it up when the settings save itself fails
# (if only the persisted copy survives a clear attempt, the
# idempotent login merge simply re-runs and re-clears it).
_BACKUP_DIVERGED_MEM = [None]

# Wave 20 (run-19 D19-1 + D19-2 — ONE unified patch, prescribed by
# verify-data19): the flag's write side is a SINGLE writer,
# _persist_diverged, with TWO durable channels:
#  (1) a PLAIN sidecar (access_diverged.json in the app data dir,
#      atomic tmp+replace) written FIRST — it does not share
#      _save_settings' encrypt-abort failure mode (its settings.enc
#      encrypt returns False BEFORE the plain settings.json write
#      is attempted), and plain writes provably land in the very
#      save where both encrypt paths fail (D19-2's correlated IO
#      fault, which used to leave the flag only in the
#      process-lifetime _BACKUP_DIVERGED_MEM, dead at restart);
#  (2) the _SETTINGS copy via _save_settings, kept as today — it
#      rides the friend_blob sync via settings.enc.
# Reads merge the channels by ts, newest wins (at boot via
# _load_diverged_sidecar_boot, and on every _backup_diverged
# read).
# Wave 21 (run-20 D20-DATA-1 + D20-DATA-2 — ONE combined patch,
# prescribed by verify-data20): a clear writes ONE shared ts'd
# TOMBSTONE dict to EVERY channel (memory, _SETTINGS and the
# sidecar alike), and the merged read ranks settings/memory
# tombstones as clear records exactly as it ranks the
# sidecar's. Wave 20 stored bare None on the settings/memory
# legs, which the merged read does not rank at all, so a clear
# landing only on settings left a stale sidecar raise as the
# ONLY record and it ruled unopposed (D20-DATA-1). And every
# record is stamped by the single writer with a LOGICAL ts —
# max(now, max_existing_ts_across_all_channels + 1), the max
# read from the persisted channels at write time, so a
# restart cannot reset the clock below a persisted future
# ts — never raw int-second wall clock alone, so a logically
# newer record can neither tie with nor be out-ranked by a
# stale future stamp from the same writer lineage
# (D20-DATA-2: clock step-backs and same-second ties).
# INVARIANT: every channel holds either nothing, a raise
# dict, or a tombstone dict, each with a writer-stamped
# logical ts; the merged read's newest record — raise or
# tombstone — is the truth, and a completed clear is
# verifiably the newest record or the failure is loud (see
# _clear_backup_diverged). A clear landing on only ONE
# channel still converges, because (a) the tombstone is the
# newest record and out-ranks the other channel's older raise
# at the next merged read, and (b) the pre-note ordering
# (below) re-persists the
# newest intended set before any later users.enc write, so a
# stale raise surviving on one channel is overwritten with a
# set that caps nothing before it can rule a restore. Total
# failure of BOTH channels is LOUD (_audit + _log_event), never
# silent. Honest residual: a true full-disk fault defeats every
# on-disk channel — visible after this fix, silent before it.
# PRE-NOTE INVARIANT (D19-1): wherever a users.enc write is
# about to happen while a flag exists (_save_access's backup
# write, _merge19's convergence refresh), the NEW dict's
# intended label set is persisted through _persist_diverged
# BEFORE the write executes. The pre-note is best-effort
# ordering, not a new failure mode: if its persist lands
# nowhere the write still proceeds (the in-memory flag already
# names the newest set, and the loud audit marks the episode).
# After any completed _save_access, the persisted flag (if
# any) names a label set that the current users.enc was
# written from, or is absent with users.enc current — the
# dangerous state (a persisted flag naming a set OLDER than
# the last successful users.enc write) is unreachable: the
# pre-note names the new set before the write lands, so a
# later clear failure, or a kill inside the clear window,
# leaves that pre-noted set persisted, which caps nothing.


def _diverged_sidecar_path():
    # Beside the settings files (the app data dir); anything
    # that relocates the settings files relocates the sidecar.
    return SETTINGS_PATH.parent / "access_diverged.json"


def _diverged_ts_ok(ts):
    """Wave 22 (run-21 D21-DATA-2): the ONE ts-validity
    predicate shared by both readers (_backup_diverged_record
    and _persist_diverged's max-read) — a ts counts only when
    it is an int/float, not a bool, and finite; anything else
    coerces to 0 like a non-numeric ts. Ints are finite by
    construction (math.isfinite would overflow on huge ints,
    which round-trip exactly and must keep ranking)."""
    if isinstance(ts, bool):
        return False
    if isinstance(ts, int):
        return True
    if isinstance(ts, float):
        return math.isfinite(ts)
    return False


def _read_diverged_sidecar():
    """The sidecar channel's record: ("rec", dict) for a raise,
    ("clear", dict) for a ts'd tombstone, None when the file is
    absent or holds no valid record, and ("unknown", None)
    when the file EXISTS but its read or parse failed
    (wave 22, run-21 D21-DATA-1: an unreadable-but-present
    channel must never be mistaken for an empty one by the
    clear verification, the logical-clock max-read, or the
    boot fold)."""
    try:
        d = json.loads(_diverged_sidecar_path().read_text())
    except Exception:
        try:
            if _diverged_sidecar_path().exists():
                return ("unknown", None)
        except Exception:
            pass
        return None
    if isinstance(d, dict) and _diverged_ts_ok(d.get("ts")):
        if isinstance(d.get("intended_labels"), list):
            return ("rec", {"ts": int(d["ts"]),
                            "intended_labels":
                                list(d["intended_labels"])})
        if d.get("intended_labels") is None:
            return ("clear", {"ts": int(d["ts"]),
                              "intended_labels": None})
    return None


def _diverged_sidecar_unknown():
    return _read_diverged_sidecar() == ("unknown", None)


def _audit_diverged_unpersisted(detail, intended):
    """The existing loud path for divergence persist failures
    (wave 22: shared by the unreadable-sidecar routes)."""
    try:
        _audit("System",
               "access_backup_diverged_unpersisted: " + detail)
    except Exception:
        pass
    try:
        _log_event("error",
                   "access_backup_diverged_unpersisted",
                   intended=intended)
    except Exception:
        pass


def _write_diverged_sidecar(rec):
    """Plain atomic write of the record AS GIVEN — the caller
    (_persist_diverged, the single writer) stamps the logical
    ts, for raises and tombstones alike; this channel never
    self-stamps (wave 21, D20-DATA-2). True only when it
    landed; never raises."""
    try:
        payload = rec
        p = _diverged_sidecar_path()
        tmp = "%s.%d.tmp" % (p, threading.get_ident())
        with open(tmp, "w") as f:
            f.write(json.dumps(payload))
        try:
            os.chmod(tmp, 0o600)
        except Exception:
            pass
        os.replace(tmp, p)
        return True
    except Exception:
        return False


def _load_diverged_sidecar_boot():
    """Wave 20: fold the sidecar channel in at boot (called at
    the end of _boot_restore_settings): the merged newest-ts
    record becomes the settings + in-memory state, so a
    divergence whose settings save died in a correlated IO
    fault survives the restart, and a tombstone that landed
    only in the sidecar clears a stale settings raise.
    Wave 21: the fold-in installs the merged winning RECORD
    (the raise dict or the tombstone dict, via
    _backup_diverged_record) — folding in the raise-or-None
    RESULT instead would erase a tombstone that reached only
    the settings channel, leaving the stale sidecar raise it
    out-ranked as the only record on the next merged read."""
    if _diverged_sidecar_unknown():
        # Wave 22 (run-21 D21-DATA-1, arm b): the sidecar is
        # present but unreadable — say so loudly and fold
        # NOTHING: folding the merged None here could erase a
        # RAM/settings record the blind channel cannot see.
        _audit_diverged_unpersisted(
            "the users.enc divergence sidecar is present but "
            "unreadable at boot; the boot fold was skipped",
            None)
        return
    rec = _backup_diverged_record()
    _BACKUP_DIVERGED_MEM[0] = rec
    try:
        _SETTINGS["access_backup_diverged"] = rec
    except Exception:
        pass


def _backup_diverged_record():
    # Wave 20 merged read: the NEWEST record across the
    # channels wins (settings copy, in-memory copy, plain
    # sidecar). Ties resolve sidecar > memory > settings:
    # within one _persist_diverged the sidecar is written
    # first, and memory is the in-process freshest copy by
    # construction. A tombstone is a clear WITH a ts on EVERY
    # channel (wave 21, D20-DATA-1: the settings/memory legs
    # below rank their tombstone dicts exactly as the sidecar
    # 'clear' kind is ranked), so a clear that landed on only
    # one channel out-ranks an older raise surviving on
    # another.
    best = [None]  # (ts, prio, rec-or-None, raw record)

    def _consider(ts, prio, rec, raw=None):
        if not _diverged_ts_ok(ts):
            ts = 0
        if best[0] is None or (ts, prio) >= (best[0][0],
                                             best[0][1]):
            best[0] = (ts, prio, rec, raw)

    v = None
    try:
        v = _SETTINGS.get("access_backup_diverged")
    except Exception:
        pass
    if isinstance(v, dict) \
            and isinstance(v.get("intended_labels"), list):
        _consider(v.get("ts"), 1, v, v)
    elif isinstance(v, dict) \
            and "intended_labels" in v \
            and v.get("intended_labels") is None \
            and isinstance(v.get("ts"), (int, float)):
        _consider(v.get("ts"), 1, None, v)
    m = _BACKUP_DIVERGED_MEM[0]
    if isinstance(m, dict) \
            and isinstance(m.get("intended_labels"), list):
        _consider(m.get("ts"), 2, m, m)
    elif isinstance(m, dict) \
            and "intended_labels" in m \
            and m.get("intended_labels") is None \
            and isinstance(m.get("ts"), (int, float)):
        _consider(m.get("ts"), 2, None, m)
    sc = _read_diverged_sidecar()
    if sc is not None and sc[1] is not None:
        kind, rec = sc
        _consider(rec["ts"], 3, rec if kind == "rec" else None,
                  rec)
    if best[0] is None:
        return None
    return best[0][3]


def _backup_diverged():
    """The merged read's public result: the ruling RAISE dict,
    or None when the newest record is a tombstone (a completed
    clear) or no record exists on any channel."""
    rec = _backup_diverged_record()
    if isinstance(rec, dict) \
            and isinstance(rec.get("intended_labels"), list):
        return rec
    return None


def _persist_diverged(rec):
    """Wave 20: the flag's ONE writer (rec dict, or None to
    clear). Updates both in-memory copies, persists to the
    plain sidecar FIRST and the settings mirror second, and
    returns True when at least one durable channel landed.
    Total failure is loud and keeps the in-memory record.

    Wave 21 (run-20 D20-DATA-1 + D20-DATA-2, ONE combined
    patch): the record is stamped HERE with a logical ts —
    max(int(time.time()), max_existing_ts_across_all_channels
    + 1), the max read across settings + memory + sidecar at
    persist time — so a record written later in logical order
    out-ranks every record it supersedes on every channel,
    under clock steps and within a single second alike.
    Caller-supplied records are RE-STAMPED (the _note,
    pre-note and _merge19 call sites build their own ts'd
    dicts). A clear constructs ONE shared tombstone dict
    {"ts": T, "intended_labels": None} and stores THAT SAME
    dict in memory, _SETTINGS and the sidecar."""
    if _diverged_sidecar_unknown():
        # Wave 22 (run-21 D21-DATA-1): never stamp a logical
        # ts from a max-read taken while a present sidecar is
        # unreadable — the unseen record could out-rank the
        # stamp. Route to the loud path, exactly as a total
        # persist failure is treated, and return False.
        _audit_diverged_unpersisted(
            "the users.enc divergence record could not be "
            "persisted — the sidecar channel is present but "
            "unreadable, so no logical ts was stamped",
            rec.get("intended_labels")
            if isinstance(rec, dict) else None)
        return False
    now = int(time.time())
    max_ts = 0
    try:
        for _v21 in (_SETTINGS.get("access_backup_diverged"),
                     _BACKUP_DIVERGED_MEM[0]):
            if isinstance(_v21, dict) \
                    and _diverged_ts_ok(_v21.get("ts")):
                max_ts = max(max_ts, int(_v21["ts"]))
    except Exception:
        pass
    _sc21 = _read_diverged_sidecar()
    if _sc21 is not None and _sc21[1] is not None:
        max_ts = max(max_ts, int(_sc21[1]["ts"]))
    ts = max(now, max_ts + 1)
    if rec is None:
        rec = {"ts": ts, "intended_labels": None}
    else:
        _labels21 = rec.get("intended_labels")
        rec = {"ts": ts,
               "intended_labels": (list(_labels21)
                                   if isinstance(_labels21, list)
                                   else _labels21)}
    _BACKUP_DIVERGED_MEM[0] = rec
    try:
        _SETTINGS["access_backup_diverged"] = rec
    except Exception:
        pass
    ok = _write_diverged_sidecar(rec)
    try:
        ok = _save_settings() or ok
    except Exception:
        pass
    if not ok:
        try:
            _audit("System",
                   "access_backup_diverged_unpersisted: the "
                   "users.enc divergence record could not be "
                   "persisted on any channel")
        except Exception:
            pass
        try:
            _log_event("error",
                       "access_backup_diverged_unpersisted",
                       intended=(rec or {}).get("intended_labels"))
        except Exception:
            pass
    return ok


def _note_backup_diverged(intended_labels):
    _persist_diverged({"ts": int(time.time()),
                       "intended_labels": sorted(intended_labels)})


def _clear_backup_diverged():
    """Clear the flag through the single writer, then VERIFY
    the clear took (wave 21, AUTH20-1's prescription, merged
    into D20-DATA-1): re-read the merged state — if a raise
    still rules (a channel's clear failed while another
    channel's older raise out-ranks), report the failure
    through the same loud path as a total persist failure
    and return False. Callers currently ignore the return by
    design; the loud audit is the deliverable, plus honest
    return semantics for future callers."""
    if _backup_diverged() is None:
        if _diverged_sidecar_unknown():
            # Wave 22 (run-21 D21-DATA-1, arm A): the merged
            # read is blind, not empty — a raise may sit on
            # the unreadable sidecar. Never early-return a
            # silent True; the failure is loud, the return
            # an honest False.
            _audit_diverged_unpersisted(
                "the users.enc divergence clear could not be "
                "verified — the sidecar channel is present "
                "but unreadable", None)
            return False
        return True
    ok = _persist_diverged(None)
    if _backup_diverged() is not None:
        try:
            _audit("System",
                   "access_backup_diverged_unpersisted: the "
                   "users.enc divergence clear did not take "
                   "— a raise still rules the merged record")
        except Exception:
            pass
        try:
            _log_event("error",
                       "access_backup_diverged_unpersisted",
                       intended=None)
        except Exception:
            pass
        return False
    return ok


def _save_access(d, master_pw=None):
    # Mirror FIRST, working file second (audit run-5): at boot the
    # mirror is the source of truth, so a crash between the two
    # writes must leave the NEWER state in the mirror, not in the
    # file the boot is about to overwrite.
    _write_access_enc(d)
    ACCESS_PATH.write_text(json.dumps(d, indent=2))
    # Persist encrypted backup so it survives redeploys (users.enc is tracked in git)
    if master_pw:
        # Wave 20 pre-note (D19-1): a divergence flag exists, so
        # persist THIS dict's intended set BEFORE the users.enc
        # write below — see the invariant at _persist_diverged.
        if _backup_diverged() is not None:
            _persist_diverged(
                {"ts": int(time.time()),
                 "intended_labels": sorted(d.keys())})
        try:
            encrypt_keys(d, master_pw, USERS_PATH)
            os.chmod(USERS_PATH, 0o600)
            # Wave 19 (D18-2): a successful users.enc write IS
            # proven convergence — users.enc now equals the dict
            # just written to the live stores — so any recorded
            # divergence is healed by this write.
            _clear_backup_diverged()
        except Exception:
            # Wave 19 (D18-2): never swallow silently — record
            # the divergence and the intended label set, so a
            # later login restore can exclude stale backup
            # labels (a revoked label stays revoked) instead of
            # treating the stale backup as truth.
            _note_backup_diverged(sorted(d.keys()))

def _carry_over_master_rotation(cur, new):
    """Re-encrypt every master-keyed artefact under a NEW master
    password (wave 12, A1): the friend access backup (users.enc via
    _save_access), the owner integrations vault, and the admin chat
    store's DEK wrap (or its legacy migration). SHARED by
    change_master and a proven /setup rotation — the two rotation
    paths must never diverge again: /setup used to perform none of
    these, stranding all three artefacts under the old password
    (owner chats + integrations inaccessible until an undiscoverable
    rotate-back, and the friend-list disaster backup silently dead).
    An artefact that cannot be opened with the current password is
    left byte-identical, never overwritten. Returns (chats_note,
    intg_note) for the caller's response text."""
    with _ACCESS_LOCK:
        _save_access(_load_access(), new)
    # Owner integrations vault: it is encrypted directly
    # under the master password, so re-encrypt it too —
    # otherwise it strands under the OLD password, silently
    # loads as empty, and the next save overwrites it. A
    # vault that cannot be opened with the current password
    # is left byte-identical, never overwritten.
    _intg_note = ""
    try:
        # Audit run-8: the carry-over takes _INTG_LOCK —
        # without it, a concurrent integrations save
        # landing mid-rotation re-encrypted the vault
        # under the OLD password after rotation reported
        # success, stranding every owner connection.
        with _INTG_LOCK:
            _ipath = _intg_path("_owner")
            if _ipath.exists():
                _ivault = decrypt_keys(_ipath, cur)
                if isinstance(_ivault, dict):
                    encrypt_keys(_ivault, new, _ipath)
                    os.chmod(_ipath, 0o600)
    except Exception:
        _intg_note = "; integrations vault could not be carried over and was left unchanged"
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
    return _chats_note, _intg_note


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
        # Wave 19 (run-18 D18-2): a recorded users.enc
        # divergence also forces the merge — the live store may
        # be non-empty while the backup is stale in either
        # direction, and the needs-gate alone would never retry.
        if _backup_diverged() is not None:
            needs = True
        if needs and USERS_PATH.exists():
            # Wave 18 (run-17 AUTH17-1): decrypt OUTSIDE the lock
            # (the ~0.7s PBKDF2 must not stall creations), then
            # MERGE under _ACCESS_LOCK — the old blind whole-store
            # write clobbered any account created during the
            # decrypt (or was itself clobbered by it), and the
            # hunter's skip-on-nonempty shape was rejected: it
            # deterministically sacrifices the restored friends
            # instead. Current store wins every label conflict.
            # Wave 19 (run-18 D18-1): the bytes guard is an
            # OUTSIDE-LOCK RETRY LOOP — if users.enc changed
            # mid-decrypt, the lock is released, the fresh bytes
            # are re-decrypted outside it, and the merge retries
            # (bounded 3 attempts, then fall back to judging the
            # freshest bytes under the lock, the wave-18 shape).
            # No decrypt runs inside the lock on the retry path.
            # The two in-lock encrypts (mirror + backup
            # convergence, inside _merge19) stay: the merged dict
            # depends on the in-lock current-store read, so they
            # cannot be pre-computed — their ~0.65s divergent-case
            # hold is the documented accepted cost.
            def _merge19(d19):
                # Runs under _ACCESS_LOCK. Wave 19 (D18-2): when
                # a divergence flag is set, backup-sourced labels
                # are capped to the flag's intended set — labels
                # the last intended dict did not contain (e.g. one
                # revoked before the fault) stay excluded; labels
                # in the intended set but missing from the backup
                # are recovered from the live store via the
                # current-wins update below.
                flag19 = _backup_diverged()
                if flag19 is not None:
                    keep19 = set(flag19.get("intended_labels")
                                 or [])
                    d19 = {k: v for k, v in d19.items()
                           if k in keep19}
                _cur19 = _load_access()
                if not isinstance(_cur19, dict):
                    _cur19 = {}
                merged19 = dict(d19)
                merged19.update(_cur19)
                _write_access_enc(merged19)
                ACCESS_PATH.write_text(
                    json.dumps(merged19, indent=2))
                try:
                    # Wave 20 pre-note (D19-1): same ordering as
                    # _save_access — persist the merged set as
                    # the flag's intended set BEFORE the
                    # convergence write, so a faulted or killed
                    # clear below leaves a persisted cap that
                    # names the just-written set, excluding
                    # nothing.
                    if flag19 is not None:
                        _persist_diverged(
                            {"ts": int(time.time()),
                             "intended_labels":
                                 sorted(merged19.keys())})
                    # Converge the backup too, or a second wipe
                    # episode re-loses the merged creation.
                    encrypt_keys(merged19, master_pw, USERS_PATH)
                    # Proven convergence: the backup now equals
                    # the live store this merge just wrote.
                    _clear_backup_diverged()
                except Exception:
                    _note_backup_diverged(sorted(merged19.keys()))
                return merged19

            _done19 = False
            for _attempt19 in range(3):
                _b19 = USERS_PATH.read_bytes()
                d = decrypt_keys(USERS_PATH, master_pw)
                if not isinstance(d, dict):
                    return
                with _ACCESS_LOCK:
                    if USERS_PATH.read_bytes() == _b19:
                        _merge19(d)
                        _done19 = True
                if _done19:
                    break
                # Bytes changed mid-decrypt (a master-bearing
                # save landed in the window): loop and re-decrypt
                # OUTSIDE the lock — this is what keeps a label
                # revoked inside the window from being
                # resurrected, without holding the lock across
                # the PBKDF2 decrypt.
            if not _done19:
                # Bounded retries exhausted: fall back to judging
                # the freshest bytes under the lock (wave-18
                # shape), rather than failing the restore.
                with _ACCESS_LOCK:
                    d = decrypt_keys(USERS_PATH, master_pw)
                    if not isinstance(d, dict):
                        return
                    _merge19(d)
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
            # A successfully decrypted EMPTY mirror is authoritative
            # too (audit run-5): the last friend was revoked and the
            # mirror faithfully says so - treating {} as "no mirror"
            # resurrected them from the stale working file.
            if isinstance(d, dict):
                ACCESS_PATH.write_text(json.dumps(d, indent=2))
                return
        # No usable mirror: keep an existing valid access.json as-is.
    except Exception:
        pass

# ---- TOTP 2FA (admin only) ----
import hmac as _hmac, struct as _struct, base64 as _base64

_PENDING_2FA = {}  # tmp_token -> {ts, keys}
_2FA_ATTEMPTS = {}  # tmp_token -> [timestamps] (rate limit code guesses)
_2FA_FAILS_GLOBAL = []  # failed TOTP guesses across ALL pending tokens:
_2FA_FAILS_CONSOLE = []  # same idea for the console 2FA actions
# (audit run-7): its OWN list, so an attacker spamming the login
# budget cannot also lock the owner out of disabling 2FA with a
# correct code after proving the master password.
# the per-token cap alone let the budget grow with every fresh login
# (audit run-5); ten failures in ten minutes account-wide is the cap.

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

def _password_taken(access, password, skip_label=None):
    """True when some OTHER friend account already uses this password.
    Password-only friend login resolves identity BY password, so a
    shared password would sign the caller into the first matching
    account — collisions are refused at every password-set site.
    _verify_password returns an (ok, needs_upgrade) tuple; the verdict
    must be indexed [0] (the bare tuple is always truthy)."""
    return any(l != skip_label and _verify_password(password, h)[0]
               for l, h in (access or {}).items())

def _is_master_password(password, quiet=False):
    """True when the candidate IS the master password (it decrypts the
    shared vault). A friend password must never equal it: password-only
    login tries the master branch first, so such an account would be
    permanently shadowed — and its holder would land in an admin
    session. Checked at every friend-password set site and, in reverse,
    when the master password itself is rotated.
    quiet=True performs the same decrypt test WITHOUT the shared
    budget's side effects (audit run-8): _master_proof records every
    miss in the GLOBAL master budget, so the password-collision
    probes an unproven caller (a moderator, an invite holder) is
    allowed to make could exhaust it and lock the owner out of every
    master proof for up to 900s. The check itself must stay — it is
    what stops a friend password shadowing the master."""
    if quiet:
        if not password:
            return False
        try:
            decrypt_keys(Path(__file__).parent / "keys.enc", password)
            return True
        except Exception:
            return False
    return _master_proof(password) is not None

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


def _rewrite_lines(path, lines):
    """Atomically replace a line file via a UNIQUE temp name — the
    old shared `.tmp` let two concurrent rewrites clobber each other
    mid-replace (audit run-6)."""
    tmp = "%s.%d.tmp" % (path, threading.get_ident())
    with open(tmp, "w") as f:
        f.writelines(lines)
    os.replace(tmp, path)


def _append_usage(entry):
    with _USAGE_LOCK:
        _append_usage_locked(entry)


def _append_usage_locked(entry):
    """Append one usage record, trimming the log when it grows past the
    cap so it stays bounded forever (usage stats read the newest data;
    the trim keeps far more than the 7-day history window). Never raises:
    a logging failure must not fail the chat that produced the record."""
    try:
        with open(USAGE_PATH, "a") as f:
            f.write(json.dumps(entry) + "\n")
        _provider_counts_note(entry)  # CAPS14-4: single writer path
        _TELEMETRY["dirty"] = True
        if os.path.getsize(USAGE_PATH) > _USAGE_MAX_BYTES:
            with open(USAGE_PATH) as f:
                lines = f.readlines()
            _cut = (datetime.datetime.now()
                    - datetime.timedelta(days=int(_SETTINGS.get("retention_days") or 30))).isoformat()
            lines = [ln for ln in lines[-_USAGE_KEEP_LINES:]
                     if _fresh_line(ln, _cut)]
            _rewrite_lines(USAGE_PATH, lines)
            _provider_counts_resync(lines)
    except Exception:
        pass


def _purge_label_history(label):
    # Lock order is always USAGE -> TELEMETRY -> AUDIT (the flush
    # takes TELEMETRY alone, _audit takes AUDIT alone, and AUDIT is
    # a leaf), so this cannot deadlock. Run-8: the audit rewrite
    # below used to run WITHOUT _AUDIT_LOCK, so audit rows appended
    # between its read and its replace were silently dropped.
    with _USAGE_LOCK, _TELEMETRY_LOCK, _AUDIT_LOCK:
        return _purge_label_history_locked(label)


def _purge_label_history_locked(label):
    """Revoke cleanup (Launch Safety Standard F28): drop the label's
    rows from usage.jsonl (rows carry "user") and from audit.jsonl
    (rows whose event names the label), so a removed account leaves no
    per-user history behind. Other users' rows are untouched; the
    caller audits the revoke itself AFTER this runs, so that one
    admin-action record remains. Telemetry is marked dirty so the
    encrypted mirror re-flushes without the purged rows. Returns the
    number of usage rows removed."""
    n = 0
    if not label:
        return 0
    try:
        if os.path.exists(USAGE_PATH):
            with open(USAGE_PATH) as f:
                lines = f.readlines()
            keep = []
            for line in lines:
                try:
                    e = json.loads(line)
                except Exception:
                    keep.append(line)
                    continue
                if isinstance(e, dict) and e.get("user") == label:
                    n += 1
                    continue
                keep.append(line)
            _rewrite_lines(USAGE_PATH, keep)
            _provider_counts_resync(keep)
    except Exception:
        pass
    try:
        if os.path.exists(AUDIT_PATH):
            pat = _re.compile(r"(?<![a-z0-9_])" + _re.escape(label)
                              + r"(?![a-z0-9_])", _re.IGNORECASE)
            with open(AUDIT_PATH) as f:
                lines = f.readlines()
            keep = []
            for line in lines:
                try:
                    e = json.loads(line)
                except Exception:
                    keep.append(line)
                    continue
                if isinstance(e, dict) \
                        and pat.search(str(e.get("event", ""))):
                    continue
                keep.append(line)
            _rewrite_lines(AUDIT_PATH, keep)
    except Exception:
        pass
    _TELEMETRY["dirty"] = True
    _TODAY_CACHE["ts"] = 0.0
    return n


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
    "anthropic",
    "claude_oauth",
    "cloudflare",
    "codex",
    "cohere",
    "gemini_cli",
    "google",
    "groq",
    "huggingface",
    "kilo",
    "mistral",
    "nvidia",
    "openai",
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
    "openai": "https://api.openai.com/v1",
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
# Shared memory (owner order 2026-10-11): ONE conversation memory inside
# Nexus, shared by every provider/model. The providers themselves are
# stateless — Nexus owns the memory. The client sends the conversation
# history with each /api/chat request (it already stores that history in
# the per-user encrypted saved chats; no new server-side store and no
# plaintext copy is created here), and Nexus rebuilds the full message
# list for whichever provider actually answers. When a provider hits its
# limit or fails and the existing failover chain moves to another one,
# the next provider receives the SAME history plus an explicit handover
# note, so it continues the task where the previous one stopped instead
# of starting over. Long histories are compressed deterministically
# (older turns summarised locally, newest turns verbatim) so the memory
# stays inside a fixed character budget on free-tier context windows.
# ---------------------------------------------------------------------------
SHARED_MEMORY_MAX_CHARS = 26000   # total history budget per request
SHARED_MEMORY_MSG_CAP = 8000      # per-message cap
SHARED_MEMORY_RECENT = 10         # newest messages always kept verbatim
SHARED_MEMORY_SUMMARY_CAP = 6000  # cap for the compressed older-turns note

_SHARED_MEMORY_SYSTEM = (
    "You are answering inside Nexus, where several AI models share ONE "
    "conversation memory owned by Nexus. The conversation below may "
    "include replies written by other models. Treat the whole "
    "conversation as your own shared context: use it, continue the "
    "user's task seamlessly, do not claim you cannot see earlier "
    "messages, and do not mention a model switch unless it is relevant."
)


def _sm_text(content):
    """Plain text from a message content: a string, or OpenAI-style
    content parts ([{type:text,...}, {type:image_url,...}])."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, dict) and part.get("type") == "text":
                t = part.get("text")
                if isinstance(t, str):
                    parts.append(t)
        return "\n".join(parts)
    return ""


def _normalize_history(raw):
    """Sanitise a client-supplied history into [{role, content, by}].
    Accepts the dashboard's saved-chat shape ({r: user|ai, t, m, p}) and
    the OpenAI shape ({role, content}). Client-supplied system entries
    are dropped — a client must never inject its own system prompt.
    Media data URIs are dropped: history is text memory."""
    out = []
    if not isinstance(raw, list):
        return out
    for item in raw[:80]:
        if not isinstance(item, dict):
            continue
        role = item.get("role") or item.get("r")
        if role in ("user",):
            role = "user"
        elif role in ("assistant", "ai"):
            role = "assistant"
        else:
            continue
        text = item.get("content")
        if text is None:
            text = item.get("t")
        text = _sm_text(text).strip()
        if not text or text.startswith("data:"):
            continue
        by = item.get("p") or item.get("by") or ""
        if not by and isinstance(item.get("m"), str):
            by = item["m"].split("·")[0].strip()
        out.append({"role": role, "content": text[:SHARED_MEMORY_MSG_CAP],
                    "by": str(by)[:80]})
    return out


def _handover_note(handover_from, for_provider):
    return (f"[Handover] {handover_from} could not continue this "
            f"task (limit reached or provider failure). You "
            f"({for_provider}) are taking over with the full "
            f"shared memory above. Continue exactly where it "
            f"left off — do not restart, do not repeat work "
            f"already done, and finish the user's request.")


def _last_assistant_by(history):
    for h in reversed(history or []):
        if h.get("role") == "assistant" and h.get("by"):
            return h["by"]
    return ""


def _build_shared_messages(history, current_text, current_content=None,
                           handover_from=None, for_provider=None):
    """Build the OpenAI-shaped message list carrying the shared memory.

    Returns (messages, info) — messages is None when there is no history
    and no handover (callers keep their legacy single-message payload);
    info = {"turns": int, "compressed": bool}. `handover_from` is who
    could not continue (a provider id or label); when it differs from
    `for_provider`, an explicit continue-from-here note is injected.
    """
    hist = list(history or [])
    info = {"turns": len(hist), "compressed": False}
    if not hist and not handover_from:
        return None, info
    total = sum(len(h["content"]) for h in hist)
    older, recent = [], hist
    if total > SHARED_MEMORY_MAX_CHARS and len(hist) > 2:
        # Keep the newest turns verbatim within ~60% of the budget;
        # everything older becomes one deterministic summary note.
        keep, acc = [], 0
        budget = int(SHARED_MEMORY_MAX_CHARS * 0.6)
        for h in reversed(hist):
            if len(keep) >= SHARED_MEMORY_RECENT and acc >= budget // 2:
                break
            if acc + len(h["content"]) > budget and keep:
                break
            keep.append(h)
            acc += len(h["content"])
        recent = list(reversed(keep))
        older = hist[:len(hist) - len(recent)]
        info["compressed"] = bool(older)
    msgs = [{"role": "system", "content": _SHARED_MEMORY_SYSTEM}]
    if older:
        lines = []
        used = 0
        for h in older:
            who = "User" if h["role"] == "user" else "Assistant"
            if h.get("by") and h["role"] == "assistant":
                who = f"Assistant ({h['by']})"
            snippet = h["content"][:400].replace("\n", " ")
            line = f"- {who}: {snippet}"
            if used + len(line) > SHARED_MEMORY_SUMMARY_CAP:
                lines.append("- … (earlier turns truncated to fit the "
                             "shared-memory budget)")
                break
            lines.append(line)
            used += len(line)
        msgs.append({"role": "system", "content":
                     "[Shared memory — summary of earlier turns in this "
                     "conversation]\n" + "\n".join(lines)})
    for h in recent:
        msgs.append({"role": h["role"], "content": h["content"]})
    if handover_from and for_provider and handover_from != for_provider:
        msgs.append({"role": "system",
                     "content": _handover_note(handover_from, for_provider)})
    msgs.append({"role": "user",
                 "content": current_content if current_content is not None
                 else current_text})
    return msgs, info


def _cohere_history(msgs):
    """Convert shared-memory messages to Cohere's shape: returns
    (chat_history, final_user_text). System notes are folded into a
    preamble entry so Cohere gets the same context other lanes get."""
    history, final = [], ""
    items = list(msgs or [])
    for i, m in enumerate(items):
        role, text = m.get("role"), _sm_text(m.get("content"))
        if not text:
            continue
        if i == len(items) - 1 and role == "user":
            final = text
        elif role == "system":
            history.append({"role": "USER",
                            "message": f"[Context] {text}"[:2000]})
        elif role == "user":
            history.append({"role": "USER", "message": text})
        elif role == "assistant":
            history.append({"role": "CHATBOT", "message": text})
    return history, final


def _trim_messages(messages, budget=SHARED_MEMORY_MAX_CHARS):
    """Budget-trim an OpenAI-shaped message list (the /v1 surface):
    caller system messages and the newest turns are preserved; older
    middle turns are replaced by one summary system note. Returns the
    (possibly new) list; a short list is returned unchanged."""
    if not isinstance(messages, list):
        return []
    clean = []
    for m in messages[:120]:
        if not isinstance(m, dict):
            continue
        role = m.get("role")
        if role not in ("system", "user", "assistant"):
            continue
        text = _sm_text(m.get("content"))
        if not text and not isinstance(m.get("content"), list):
            continue
        entry = dict(m)
        if isinstance(m.get("content"), str):
            entry["content"] = text[:SHARED_MEMORY_MSG_CAP]
        clean.append(entry)
    total = sum(len(_sm_text(m.get("content"))) for m in clean)
    if total <= budget or len(clean) <= 3:
        return clean
    systems = [m for m in clean if m["role"] == "system"]
    convo = [m for m in clean if m["role"] != "system"]
    keep, acc = [], 0
    for m in reversed(convo):
        if acc + len(_sm_text(m.get("content"))) > int(budget * 0.6) and keep:
            break
        keep.append(m)
        acc += len(_sm_text(m.get("content")))
    keep.reverse()
    dropped = convo[:len(convo) - len(keep)]
    lines, used = [], 0
    for m in dropped:
        who = "User" if m["role"] == "user" else "Assistant"
        line = f"- {who}: {_sm_text(m.get('content'))[:400]}".replace("\n", " ")
        if used + len(line) > SHARED_MEMORY_SUMMARY_CAP:
            break
        lines.append(line)
        used += len(line)
    note = {"role": "system", "content":
            "[Shared memory — summary of earlier turns]\n" + "\n".join(lines)}
    return systems + [note] + keep

# ---------------------------------------------------------------------------
# OAuth sign-in (owner order 2026-10-15): "Sign in with Google / GitHub"
# as an alternative login for Nexus itself. Credentials come from the
# server environment ONLY (NEXUS_OAUTH_GOOGLE_ID/SECRET,
# NEXUS_OAUTH_GITHUB_ID/SECRET) — never from the repo or settings.
# An OAuth identity is only an identity: the provider's VERIFIED email
# is resolved against admin-configured mappings — oauth_admin_emails
# (owner) and oauth_links (email -> existing friend label). An unlinked
# email gets NO account and NO session: OAuth never creates accounts,
# never unlocks the key vault (that still needs the master password),
# and a friend OAuth session has no password, so password-encrypted
# saved chats and BYOK vaults stay unavailable in it — chat itself
# works on the shared lanes exactly like a pre-unlock friend session.
# ---------------------------------------------------------------------------
_OAUTH_PROVIDERS = ("google", "github")


def _oauth_creds(provider):
    cid = os.environ.get(f"NEXUS_OAUTH_{provider.upper()}_ID", "").strip()
    sec = os.environ.get(f"NEXUS_OAUTH_{provider.upper()}_SECRET", "").strip()
    return (cid, sec) if cid and sec else None


def _oauth_public_base(headers):
    host = (headers.get("Host", "") if headers else "").strip()
    proto = ""
    if headers:
        proto = (headers.get("X-Forwarded-Proto", "") or "").split(",")[0].strip()
    if not proto:
        proto = "http" if host.startswith(("127.", "localhost")) else "https"
    return f"{proto}://{host}"


def _oauth_http_json(url, data=None, headers=None, timeout=20):
    req = Request(url, data=data, headers=headers or {},
                  method="POST" if data is not None else "GET")
    with _open_cred(req, timeout) as resp:
        return json.loads(_read_capped(resp))


def _oauth_fetch_email(provider, code, redirect_uri):
    """Exchange an auth code for the account's VERIFIED email.
    Returns (email, display_name); raises on any failure."""
    cid, sec = _oauth_creds(provider)
    form = urllib.parse.urlencode({
        "client_id": cid, "client_secret": sec, "code": code,
        "redirect_uri": redirect_uri,
        **({"grant_type": "authorization_code"} if provider == "google" else {}),
    }).encode()
    tok = _oauth_http_json(
        "https://oauth2.googleapis.com/token" if provider == "google"
        else "https://github.com/login/oauth/access_token",
        data=form,
        headers={"Content-Type": "application/x-www-form-urlencoded",
                 "Accept": "application/json"})
    at = tok.get("access_token")
    if not at:
        raise ValueError("no access token")
    if provider == "google":
        info = _oauth_http_json(
            "https://openidconnect.googleapis.com/v1/userinfo",
            headers={"Authorization": f"Bearer {at}"})
        if info.get("email_verified") not in (True, "true") or not info.get("email"):
            raise ValueError("email not verified")
        return info["email"].strip().lower(), str(info.get("name") or "")
    emails = _oauth_http_json(
        "https://api.github.com/user/emails",
        headers={"Authorization": f"Bearer {at}",
                 "Accept": "application/vnd.github+json",
                 "User-Agent": "NexusLocal"})
    verified = [e for e in emails if isinstance(e, dict) and e.get("verified")
                and isinstance(e.get("email"), str)]
    if not verified:
        raise ValueError("no verified email")
    pick = next((e for e in verified if e.get("primary")), verified[0])
    return pick["email"].strip().lower(), ""


def _oauth_resolve(email):
    """Map a verified OAuth email to ('admin', 'Rudra') or
    ('friend', label) via the admin-configured mappings, else None."""
    email = (email or "").strip().lower()
    if not email:
        return None
    if email in [str(e).lower() for e in (_SETTINGS.get("oauth_admin_emails") or [])]:
        return ("admin", "Rudra")
    access = None
    for link in (_SETTINGS.get("oauth_links") or []):
        if isinstance(link, dict) and str(link.get("email") or "").lower() == email:
            label = link.get("label")
            if access is None:
                access = _load_access()
            if isinstance(label, str) and label in access:
                return ("friend", label)
    return None


# ---------------------------------------------------------------------------
# External API (owner order 2026-10-09): an OpenAI-compatible surface so
# Rudra's other project (DSRclone's AI service) can be supplied by Nexus.
# Disabled until a service key exists: one the admin generates on the API
# Access page (v1key.enc, restore-key encrypted — the admin can view it
# there; it never appears in the repo, logs or chat) or the
# NEXUS_V1_API_KEY env var as fallback. Requests ride the integrated
# relay lanes with failover; when the shared vault is locked, keyed lanes
# cannot run yet — exactly like the dashboard's own pre-unlock behaviour
# — while keyless lanes keep working.
# ---------------------------------------------------------------------------
_V1_LANES = [
    ("relay_gemini", "gemini-3.5-flash-lite"),
    ("relay_openrouter", "nvidia/nemotron-3-super-120b-a12b:free"),
    ("relay_groq", "openai/gpt-oss-20b"),
    ("relay_nvidia", "google/gemma-3-12b-it"),
    # FreeLLMAPI provider key set (owner order 2026-10-09: "in supply lane
    # also add FreeLLMAPI providers") — same relay, the vault's plain slots.
    ("google", "gemini-3.5-flash-lite"),
    ("openrouter", "nvidia/nemotron-3-super-120b-a12b:free"),
    ("groq", "openai/gpt-oss-20b"),
    ("nvidia", "google/gemma-3-12b-it"),
    ("relay_pollinations", "openai"),
]
_V1_MODELS_CACHE = {"at": 0.0, "ids": []}

# The service keys an admin creates on the API Access page live in
# v1key.enc, encrypted under the server restore key and mirrored through
# the friend sync exactly like access.enc, so they survive redeploys.
# Since 2026-10-16 (owner order: implement the reference design's key
# features) the file holds a LIST of named keys, each with its own
# created / last-used stamps and a disabled flag. The list takes
# precedence over the NEXUS_V1_API_KEY env var, which stays as the
# fallback for installs without any stored keys. The original
# single-key shape ({"key": ...}) is migrated in place on load — the
# key value is preserved, so existing consumers keep working.
V1KEY_PATH = Path(__file__).parent / "v1key.enc"
_V1KEYS = {"keys": []}
_V1KEYS_TOUCH = {"at": 0.0}
# Audit run-8: the store had NO lock at all — a /v1 request's
# last_used touch-save could land after an admin's delete and write
# the pre-delete list back, resurrecting a revoked bearer key (the
# same hole defeated the factory-reset / change-master wipes).
# Every mutation, save and wipe of the store takes this lock; it is
# an RLock so helpers may compose.
_V1KEYS_LOCK = threading.RLock()


def _save_v1keys():
    if not RESTORE_KEY:
        return False
    with _V1KEYS_LOCK:
        try:
            encrypt_keys({"keys": _V1KEYS["keys"]}, RESTORE_KEY, V1KEY_PATH)
            os.chmod(V1KEY_PATH, 0o600)
            return True
        except Exception:
            return False


def _load_v1key():
    if not (RESTORE_KEY and V1KEY_PATH.exists()):
        return
    try:
        d = decrypt_keys(V1KEY_PATH, RESTORE_KEY)
    except Exception:
        return
    with _V1KEYS_LOCK:
        _load_v1key_locked(d)


def _load_v1key_locked(d):
    if isinstance(d, dict) and isinstance(d.get("keys"), list):
        _V1KEYS["keys"] = [k for k in d["keys"]
                           if isinstance(k, dict) and k.get("key")]
    elif isinstance(d, dict) and d.get("key"):
        created = d.get("created")
        if not created:
            try:
                created = int(V1KEY_PATH.stat().st_mtime)
            except Exception:
                created = int(time.time())
        _V1KEYS["keys"] = [{"id": secrets.token_hex(4),
                            "name": "Nexus service key",
                            "key": d["key"], "created": created,
                            "last_used": None, "disabled": False}]
        _save_v1keys()


def _create_v1key(name):
    """Mint a new named service key alongside the existing ones,
    persist the list, and make it effective immediately. Returns the
    entry, or None when this host has no restore key to store it
    under."""
    if not RESTORE_KEY:
        return None
    entry = {"id": secrets.token_hex(4),
             "name": (name or "").strip()[:60] or "Service key",
             "key": "nxk-" + secrets.token_hex(24),
             "created": int(time.time()), "last_used": None,
             "disabled": False}
    with _V1KEYS_LOCK:
        _V1KEYS["keys"].append(entry)
        if not _save_v1keys():
            # Audit run-7: a key that could not be persisted must not be
            # handed out — it would die at the next restart while the
            # caller believes it works (and a "deleted" key came back).
            _V1KEYS["keys"].remove(entry)
            return None
    return entry


def _v1_key_source():
    if _V1KEYS["keys"]:
        return "generated"
    if os.environ.get("NEXUS_V1_API_KEY"):
        return "env"
    return "none"


def _v1_api_key():
    """One usable key for status / self-test purposes: the first
    enabled stored key, else the env fallback."""
    for k in _V1KEYS["keys"]:
        if not k.get("disabled"):
            return k["key"]
    if _V1KEYS["keys"]:
        return ""
    return os.environ.get("NEXUS_V1_API_KEY", "")


def _v1_match(bearer):
    """Resolve a bearer token: the stored key entry it belongs to,
    the string "env" for the environment fallback, or None. Stored
    keys win outright — once any exist, the env fallback no longer
    authenticates (the pre-list contract). A match on a stored key
    stamps its last_used; the stamp is persisted at most about once
    a minute, the in-memory value is immediate."""
    if not bearer:
        return None
    if _V1KEYS["keys"]:
        with _V1KEYS_LOCK:
            for k in _V1KEYS["keys"]:
                if k.get("disabled"):
                    continue
                if _hmac.compare_digest(bearer, k["key"]):
                    k["last_used"] = int(time.time())
                    now = time.time()
                    if now - _V1KEYS_TOUCH["at"] > 60:
                        _V1KEYS_TOUCH["at"] = now
                        _save_v1keys()
                    return k
        return None
    env = os.environ.get("NEXUS_V1_API_KEY", "")
    if env and _hmac.compare_digest(bearer, env):
        return "env"
    return None


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
    with _open_loopback(req, timeout) as resp:
        return json.loads(_read_capped(resp))


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
    Returns (status_code, openai_shaped_dict, lane_used). The caller's
    messages ARE the shared memory: they are budget-trimmed once and the
    same list rides every lane, so a lane that takes over mid-request
    sees the full conversation; lanes after the first attempted one get
    an explicit handover note."""
    messages = _trim_messages(messages)
    last_error = "no lane available"
    _attempted = []
    for lane, mdl in _v1_route(model):
        if _provider_down(lane):
            continue
        # Wave 13: one governance snapshot judges this lane (the
        # disabled read and the limits read below are the same
        # snapshot, never two states torn apart).
        _dis13, _lims13 = _governance()
        if lane in _dis13:
            continue
        # Provider governance applies to /v1 exactly as to chat
        # (audit run-5): a lane whose daily provider_limits allowance
        # is spent is skipped, and the spend below is metered under
        # the lane's own name so the limit checks can see it.
        # Wave 12 (C1): reserve FIRST, then run the limit check
        # counting this reservation (the _lane_spend_ok shape:
        # completed + in-flight including this attempt must not
        # EXCEED the limit). The old shape checked _provider_blocked
        # first and reserved after, so a natural burst all passed the
        # same check snapshot and overshot a lane limit of 1 up to
        # the burst size (verifier: 4 hits against a limit of 1).
        # Wave 13: reserve+count is ONE locked primitive — the
        # wave-12 add->count->drop sequence let two concurrent
        # spends at a limit of 1 refuse each other (both counted
        # the peer's reservation, both dropped: 0 hits).
        _lim = _lims13.get(lane)
        if _lim:
            _vres = _inflight_reserve_capped(
                "v1", lane,
                lambda: _provider_counts_today().get(lane, 0),
                _lim)
            if _vres is None:
                continue
        else:
            _vres = _inflight_add("v1", lane, attempt=True)
        if lane not in RELAY_KEYLESS and getattr(Handler, "keys", None) is None:
            _inflight_drop(_vres)
            last_error = "vault locked"
            continue
        lane_msgs = messages
        if _attempted:
            _note = _handover_note(_attempted[-1], lane)
            lane_msgs = (list(messages[:-1])
                         + [{"role": "system", "content": _note}]
                         + list(messages[-1:]))
        _attempted.append(lane)
        payload = {"model": mdl, "messages": lane_msgs, "max_tokens": 4096}
        if temperature is not None:
            payload["temperature"] = temperature
        # The provider-tagged reservation was taken above, before
        # the governance check (wave 12, C1); it is held across the
        # lane attempt and dropped in the finally below.
        try:
            try:
                data = _v1_relay_call(lane, "/chat/completions", payload)
                reply = data["choices"][0]["message"]["content"]
                if not isinstance(reply, str):
                    raise ValueError("unexpected upstream shape")
                _note_success(lane)
                usage = data.get("usage") or {}
                _append_usage({"ts": datetime.datetime.now().isoformat(),
                               "provider": lane, "via": "v1", "model": mdl,
                               "prompt_tokens": usage.get("prompt_tokens", 0),
                               "completion_tokens": usage.get("completion_tokens", 0)})
                data.setdefault("model", mdl)
                return 200, data, lane
            except HTTPError as e:
                _note_failure(lane, f"HTTP {e.code}")
                last_error = f"{lane} returned {e.code}"
                continue
            except Exception:
                _note_failure(lane, "unreachable")
                last_error = f"{lane} unreachable"
                continue
        finally:
            _inflight_drop(_vres)
    return 502, {"error": {"message": f"all Nexus lanes failed ({last_error})",
                           "type": "upstream_error"}}, ""


_CUSTOM_RELAY_NAMES = set()


def register_custom_providers(keys):
    """Register custom relay providers from keys dict into RELAY_UPSTREAMS.

    The registry mirrors the keys dict exactly (audit run-5): a
    changed URL REPLACES the old upstream (an add-only registry sent
    rotated keys to the previous host for the process lifetime), and
    a removed provider is unregistered."""
    if not keys:
        return
    present = {}
    for k, v in keys.items():
        if k.startswith("custom_relay_") and not k.endswith("_url"):
            name = k[len("custom_relay_"):]
            url = keys.get(k + "_url", "").strip()
            if url:
                present[name] = url
    for name in list(_CUSTOM_RELAY_NAMES):
        if name not in present:
            RELAY_UPSTREAMS.pop(name, None)
            _CUSTOM_RELAY_NAMES.discard(name)
    for name, url in present.items():
        if name in RELAY_UPSTREAMS and name not in _CUSTOM_RELAY_NAMES:
            continue  # built-in upstream names are not overridable
        # Registration-time SSRF guard (A5): a stored URL that
        # resolves to a non-public address is never registered,
        # even if it predates the save-time validation.
        if not _public_base_url_ok(url):
            continue
        RELAY_UPSTREAMS[name] = url.rstrip("/")
        _CUSTOM_RELAY_NAMES.add(name)


class _DeadlineReader:
    """Bounds the TOTAL time a request may spend arriving (audit
    run-6): the per-read socket timeout restarts on every trickled
    byte, so a 1-byte-per-2s sender held handler threads forever.
    This wrapper re-arms the socket timeout to the request's
    remaining budget before every read — trickling cannot push the
    total past the deadline. Raising TimeoutError here is
    indistinguishable from a socket timeout to http.server, which
    closes the connection quietly."""
    def __init__(self, raw, conn, budget):
        self._raw = raw
        self._conn = conn
        self._deadline = time.time() + budget

    def _arm(self):
        left = self._deadline - time.time()
        if left <= 0:
            raise TimeoutError("request took too long to arrive")
        try:
            # The 10s per-read idle timeout still applies to each
            # individual read; the budget only caps the TOTAL.
            self._conn.settimeout(min(10, left))
        except Exception:
            pass

    def read(self, n=-1):
        self._arm()
        return self._raw.read(n)

    def readline(self, limit=-1):
        self._arm()
        return self._raw.readline(limit)

    def __getattr__(self, name):
        return getattr(self._raw, name)


class RelayHandler(BaseHTTPRequestHandler):
    timeout = 10  # per-read socket deadline: stalled connections close

    def setup(self):
        super().setup()
        self.rfile = _DeadlineReader(self.rfile, self.connection, 120)

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
            with _open_cred(req, 60) as resp:
                data = _read_capped_bytes(resp)
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
            data = _read_capped_bytes(e)
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
    # Per-read socket deadline (BaseHTTPRequestHandler.timeout): a
    # pre-auth Slowloris — partial headers or a partial body — must not
    # hold a handler thread indefinitely.
    timeout = 10

    def setup(self):
        super().setup()
        # Total-arrival deadline on top of the per-read one (audit
        # run-6): generous enough for a 12 MB upload on a slow link,
        # finite enough that trickle floods cannot pin threads.
        self.rfile = _DeadlineReader(self.rfile, self.connection, 300)
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
                if now - sess["ts"] < _session_seconds():
                    # Maintenance mode / suspension: a friend session
                    # stops being valid the moment the admin flips it.
                    if not sess.get("admin") and not sess.get("viewer") \
                            and _friend_blocked(sess.get("label", "")):
                        return None
                    sess["ts"] = now  # sliding window
                    _rec = _CHAT_UNLOCKS.get(sess.get("chat_unlock") or "")
                    if _rec and _rec.get("bound_token") == token:
                        _rec["expires"] = now + _session_seconds()
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
            if not sess.get("admin") and not sess.get("viewer") \
                    and _friend_blocked(sess.get("label", "")):
                return None
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
        # AI sign-in tokens ride as JSON strings under their lane
        # names; the chat branches parse them back.
        ao = (info.get("integrations") or {}).get("ai_oauth") or {}
        if isinstance(ao, dict):
            for lane, tok in ao.items():
                if isinstance(tok, dict) and tok.get("access"):
                    base[lane] = json.dumps(tok)
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

    def _console_kind(self):
        """Who is calling the admin console: (kind, label) with kind in
        admin | moderator | viewer | None. View-pass grants and
        viewer-role friends are both read-only 'viewer'."""
        info = self._session_info()
        if not info:
            return None, ""
        label = info.get("label", "")
        if info.get("admin"):
            return "admin", label
        if info.get("viewer"):
            return "viewer", label
        role = _friend_role(label)
        if role in ("moderator", "viewer"):
            return role, label
        return None, label

    def _ip_gate(self):
        """Allowed-IPs gate for sign-in + console surfaces. Returns True
        when the request may proceed; otherwise answers 403 itself."""
        if _ip_allowed(_client_ip(self.headers, self.client_address[0])):
            return True
        _audit("System", "Console/sign-in blocked by IP allowlist",
               ip=_client_ip(self.headers, self.client_address[0]))
        self._set_json_headers(403)
        self.wfile.write(json.dumps({
            "error": "this instance only accepts sign-ins from allowed networks"}).encode())
        return False

    def _master_ok(self, data):
        """The console's master-password proof: decrypting keys.enc."""
        pw = (data or {}).get("master_pw") or ""
        return _master_proof(pw) is not None

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
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        return _v1_match(auth[len("Bearer "):].strip()) is not None

    def _v1_gate(self):
        """Shared gate for /v1 routes. Returns True when the request may
        proceed; otherwise the error response has already been written.
        A disabled endpoint (no key configured) answers 404 so the
        surface stays invisible."""
        if not _V1KEYS["keys"] and not os.environ.get("NEXUS_V1_API_KEY"):
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
        # Audit run-8: reserve BEFORE the cap gate and hold the
        # reservation across dispatch (do_POST's finally drops it).
        # The gate read only COMPLETED rows, so a concurrent burst
        # all passed inside one in-flight window — global_cap=2
        # waved 6 simultaneous calls through and the day total
        # landed at 6.
        # Audit run-9 (S10): the reservation is labelled per v1 KEY
        # and the same per-account in-flight ceiling of 4 that
        # chat/transcribe enforce applies here — the base is taken
        # before the body read, so with a shared unlabelled bucket
        # slow-trickled bodies could pin bases up to the WHOLE
        # global_cap on one key. Reserve-first, then count including
        # this reservation (the S11 shape): over 4 = refuse.
        _auth10 = self.headers.get("Authorization", "") or ""
        _match10 = _v1_match(_auth10[len("Bearer "):].strip()) \
            if _auth10.startswith("Bearer ") else None
        _v1_label = "v1:" + (_match10.get("id")
                             if isinstance(_match10, dict) else "env")
        self._cap_res = _inflight_add(_v1_label)
        if _inflight_n(user=_v1_label) > 4:
            self._set_json_headers(429)
            self.wfile.write(json.dumps({"error": {"message": "too many requests already in flight for this key", "type": "rate_limit_error"}}).encode())
            return
        # Hard daily stop (reel-risk fix 2026-10-10): the instance-wide
        # cap the owner sets in the console also binds the /v1 API —
        # a looping consumer or a leaked service key must not be able
        # to burn the whole day's provider quota at 60 requests/min.
        if _instance_cap_reached() or (
                int(_SETTINGS.get("global_cap") or 0)
                and _today_total_requests(fresh=True)
                + _inflight_rank(self._cap_res)
                > int(_SETTINGS.get("global_cap") or 0)):
            if time.time() - _V1_CAP_AUDIT[0] >= 600:
                _V1_CAP_AUDIT[0] = time.time()
                _audit("System", "/v1 stopped: instance daily cap hit "
                       f"({int(_SETTINGS.get('global_cap') or 0)}/day)")
            self._set_json_headers(429)
            self.wfile.write(json.dumps({"error": {"message": "instance daily limit reached", "type": "rate_limit_error"}}).encode())
            return
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
            data = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            self._set_json_headers(400)
            self.wfile.write(json.dumps({"error": {"message": "invalid JSON", "type": "invalid_request_error"}}).encode())
            return
        # Wave 17 (run-16 caps CAPS16-2): /v1 is a text-only
        # surface — stamp the base reservation post-parse so it
        # never ranks against a media lane (see /api/chat).
        self._cap_res["surface"] = "v1"
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
        """Admin-only status for the API Access page. The admin sees the
        full service key here (owner order 2026-10-09: "allow admin to
        generate api key and see api key") — this endpoint is admin-gated,
        and the key is never written to logs, chat or any other surface."""
        info = self._session_info()
        if not info or not info.get("admin"):
            self._set_json_headers(403)
            self._send_body(json.dumps({"error": "admin only"}).encode())
            return
        if not self._ip_gate():
            # Audit run-6 critic: the session-mint guard set honors
            # the IP allowlist; these key-management routes skipped it.
            return
        key = _v1_api_key()
        proto = self.headers.get("X-Forwarded-Proto", "http")
        host = self.headers.get("Host", "nexus-local.onrender.com")
        unlocked = getattr(Handler, "keys", None) is not None
        lanes = [{"lane": lane, "model": mdl,
                  "ready": (lane in RELAY_KEYLESS) or unlocked}
                 for lane, mdl in _V1_LANES]
        # The keys table (owner's supplied design, 2026-10-15;
        # multi-key features 2026-10-16): every stored key with its
        # real created / last-used stamps. The env fallback appears
        # as a row only while it is the live key (no stored keys) —
        # once stored keys exist it no longer authenticates.
        keys = []
        for k in _V1KEYS["keys"]:
            keys.append({"id": k["id"], "name": k["name"],
                         "key_full": k["key"],
                         "key_last4": k["key"][-4:],
                         "created": k.get("created"),
                         "last_used": k.get("last_used"),
                         "disabled": bool(k.get("disabled")),
                         "source": "generated"})
        env = os.environ.get("NEXUS_V1_API_KEY", "")
        if env and not _V1KEYS["keys"]:
            keys.append({"id": "env", "name": "Environment key",
                         "key_full": env, "key_last4": env[-4:],
                         "created": None, "last_used": None,
                         "disabled": False, "source": "env"})
        body = {"enabled": bool(key),
                "keys": keys,
                "key_last4": key[-4:] if key else "",
                "key_full": key,
                "key_source": _v1_key_source(),
                "key_created": keys[0]["created"] if keys else None,
                "can_generate": bool(RESTORE_KEY),
                "base_url": f"{proto}://{host}/v1",
                "consumer": "DSRclone AI service",
                "vault_unlocked": unlocked,
                "lanes": lanes}
        self._set_json_headers()
        self._send_body(json.dumps(body).encode())

    def _v1_access_generate(self):
        """Admin-only: create a NEW named /v1 service key alongside
        the existing ones (multi-key, owner order 2026-10-16; this
        endpoint's name predates it). Stored restore-key encrypted
        (v1key.enc) and synced like the friend list."""
        info = self._session_info()
        if not info or not info.get("admin"):
            self._set_json_headers(403)
            self._send_body(json.dumps({"error": "admin only"}).encode())
            return
        if not self._ip_gate():
            # Audit run-6 critic: the session-mint guard set honors
            # the IP allowlist; these key-management routes skipped it.
            return
        data = {}
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length:
                data = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            data = {}
        if _master_proof((data or {}).get("master_pw")) is None:
            # Audit run-6: a session alone could mint bearer keys —
            # and rotation minted fresh ones even after the master
            # password changed. The proof matches the console's.
            self._set_json_headers(401)
            self._send_body(json.dumps({"error": "master password required"}).encode())
            return
        entry = _create_v1key(data.get("name", ""))
        if not entry:
            self._set_json_headers(400)
            self._send_body(json.dumps({"error": "key creation needs the server restore key (NEXUS_RESTORE_KEY) to store the key safely; on this host, set the key via the NEXUS_V1_API_KEY environment variable instead"}).encode())
            return
        _append_usage({"ts": datetime.datetime.now().isoformat(),
                       "type": "v1key_created"})
        _audit("Vault", f"/v1 service key created: {entry['name']}")
        self._set_json_headers()
        self._send_body(json.dumps({"ok": True, "key": entry["key"],
                                    "id": entry["id"],
                                    "name": entry["name"],
                                    "source": "generated",
                                    "key_created": entry["created"]}).encode())

    def _v1_access_keystate(self, action):
        """Admin-only: disable / enable / delete / rotate one
        stored key by id (owner orders 2026-10-16). The env
        fallback is not a stored key and cannot be managed here."""
        info = self._session_info()
        if not info or not info.get("admin"):
            self._set_json_headers(403)
            self._send_body(json.dumps({"error": "admin only"}).encode())
            return
        if not self._ip_gate():
            # Audit run-6 critic: the session-mint guard set honors
            # the IP allowlist; these key-management routes skipped it.
            return
        data = {}
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length:
                data = json.loads(self.rfile.read(length) or b"{}")
        except Exception:
            data = {}
        if _master_proof((data or {}).get("master_pw")) is None:
            self._set_json_headers(401)
            self._send_body(json.dumps({"error": "master password required"}).encode())
            return
        # Audit run-8: lookup, mutation and save are one locked
        # unit, and a failed save now ROLLS BACK the in-memory
        # mutation — wave 8 answered an honest 500 but left memory
        # and disk diverged until restart (a "deleted" key was dead
        # in memory yet alive again after the next boot).
        with _V1KEYS_LOCK:
            entry = None
            for k in _V1KEYS["keys"]:
                if k["id"] == data.get("id", ""):
                    entry = k
                    break
            if entry is None:
                self._set_json_headers(404)
                self._send_body(json.dumps({"error": "no such key"}).encode())
                return
            _snap = [dict(k) for k in _V1KEYS["keys"]]
            if action == "delete":
                _V1KEYS["keys"].remove(entry)
            elif action == "rotate":
                # The reference design's per-row refresh button, for
                # real: same key entry, brand-new secret, and the
                # last-used stamp resets — the new secret has never
                # been used.
                entry["key"] = "nxk-" + secrets.token_hex(24)
                entry["last_used"] = None
            else:
                entry["disabled"] = (action == "disable")
            if not _save_v1keys():
                _V1KEYS["keys"] = _snap
                self._set_json_headers(500)
                self._send_body(json.dumps({"error": "key change could not be saved — it will not survive a restart"}).encode())
                return
        verb = {"disable": "disabled", "enable": "enabled",
                "delete": "deleted", "rotate": "rotated"}[action]
        _audit("Vault", f"/v1 service key {verb}: {entry['name']}")
        self._set_json_headers()
        self._send_body(json.dumps({"ok": True}).encode())

    def _v1_access_test(self):
        """Admin-only live self-test: one tiny nexus-auto completion
        through the same path external clients use."""
        info = self._session_info()
        if not info or not info.get("admin"):
            self._set_json_headers(403)
            self.wfile.write(json.dumps({"error": "admin only"}).encode())
            return
        if not self._ip_gate():
            return
        # Audit run-8: each self-test spends a REAL completion and
        # the route was session-only with no throttle — an admin
        # session alone could loop it against the provider quotas.
        # Audit run-9 (S9): the bucket is keyed on the ADMIN identity,
        # not the client IP — the route is admin-only, and an
        # IP-keyed bucket refilled on every source rotation.
        if not _rl_ok("v1test", "admin", 10, 900):
            self._set_json_headers(429)
            self.wfile.write(json.dumps({"ok": False, "error": "too many self-tests — try again later"}).encode())
            return
        if not _v1_api_key():
            self._set_json_headers(200)
            self.wfile.write(json.dumps({"ok": False, "error": "endpoint not enabled (no service key — generate one above or set NEXUS_V1_API_KEY)"}).encode())
            return
        # Audit run-9 (S14): the self-test gets the /v1 treatment —
        # it was the one spending surface outside the reservation
        # system and the global-cap gate, so the in-flight terms
        # never saw it and global_cap never bound it. do_POST's
        # finally drops the reservation on every exit.
        # Wave 11 (F6): the gate must match the real /v1 gate —
        # _instance_cap_reached reads COMPLETED rows only, so held
        # /v1 requests were invisible here, and the base reservation
        # used the plain shared "v1" label with no ceiling. Reserve
        # first under a per-principal label ("v1:test"), apply the
        # same ceiling of 4 as every other surface, and count
        # in-flight terms against the global cap exactly like
        # _v1_chat_completions does.
        self._cap_res = _inflight_add("v1:test")
        # Wave 17 (run-16 caps CAPS16-2): a text-only surface —
        # stamp the base reservation so it never ranks against a
        # media lane (see /api/chat).
        self._cap_res["surface"] = "v1"
        if _inflight_n(user="v1:test") > 4:
            self._set_json_headers(200)
            self.wfile.write(json.dumps({"ok": False, "error": "too many requests already in flight"}).encode())
            return
        _gcap_t = int(_SETTINGS.get("global_cap") or 0)
        if _gcap_t and _today_total_requests(fresh=True) \
                + _inflight_rank(self._cap_res) > _gcap_t:
            self._set_json_headers(200)
            self.wfile.write(json.dumps({"ok": False, "error": "instance daily limit reached"}).encode())
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

    def send_header(self, keyword, value):
        # Choke point for Launch Safety G33: EVERY JSON response this
        # handler sends is private per-user data, so pin
        # Cache-Control: no-store the moment a JSON Content-Type goes
        # out — including manual sends that bypass _set_json_headers
        # (e.g. _require_session's 401). Non-JSON responses (HTML
        # pages, icons, vendor JS) keep their own cache headers.
        super().send_header(keyword, value)
        if keyword.lower() == "content-type" and value.startswith("application/json"):
            super().send_header("Cache-Control", "no-store")

    def _set_json_headers(self, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

    def _send_404_page(self):
        # A useful, on-brand 404 for unknown paths (Launch Safety H39)
        # instead of the bare BaseHTTPRequestHandler error page.
        body = (
            "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            "<title>404 — Nexus</title>"
            "<link rel=\"icon\" href=\"/favicon.ico\" sizes=\"any\"></head>"
            "<body style=\"margin:0;min-height:100vh;display:flex;align-items:center;"
            "justify-content:center;background:#050505;color:#fff;"
            "font-family:'Space Grotesk',system-ui,sans-serif;text-align:center;padding:20px\">"
            "<main><p style=\"font-size:56px;font-weight:700;margin:0\">404</p>"
            "<p style=\"color:#a1a1aa;margin:10px 0 22px\">This page doesn't exist — "
            "it may have moved, or the link is wrong.</p>"
            "<a href=\"/\" style=\"color:#fff;border:1px solid #3f3f46;border-radius:8px;"
            "padding:10px 18px;text-decoration:none\">Go to Nexus</a></main>"
            "</body></html>"
        ).encode()
        self.send_response(404)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self._send_body(body)

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
        _hp = urlparse(self.path).path
        if _hp.startswith("/view/") or _hp.startswith("/api/oauth/") \
                or (_hp.startswith("/api/integrations/")
                    and (_hp.endswith("/start")
                         or _hp.endswith("/callback"))):
            # Audit run-6: these GET routes have side effects (they
            # mint sessions or start OAuth flows) — a HEAD request
            # must never trigger them. Monitors only need plain pages.
            self.send_response(405)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
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
        if parsed.path in ("/favicon.ico", "/favicon.svg",
                           "/favicon-32.png", "/apple-touch-icon.png"):
            # Public brand icons — browsers fetch them before login.
            # Small sizes use a zoomed bat so the silhouette survives
            # at tab size; the SVG and touch icon carry the full mark.
            _icons = {
                "/favicon.ico": ("favicon.ico", "image/x-icon"),
                "/favicon.svg": ("favicon.svg", "image/svg+xml"),
                "/favicon-32.png": ("favicon-32.png", "image/png"),
                "/apple-touch-icon.png": ("apple-touch-icon.png",
                                          "image/png"),
            }
            _fname, _ctype = _icons[parsed.path]
            try:
                _data = (Path(__file__).parent / _fname).read_bytes()
            except OSError:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", _ctype)
            self.send_header("Cache-Control", "public, max-age=86400")
            self.send_header("Content-Length", str(len(_data)))
            self.end_headers()
            self._send_body(_data)
            return
        if parsed.path == "/vendor/three.min.js":
            # The admin console's 3D background library, served from
            # Nexus itself. It used to load from a public CDN — when
            # that request was blocked (browser extension, network),
            # the console silently lost its whole 3D layer. Same-origin
            # now: no outside dependency, cacheable for a week.
            try:
                _data = (Path(__file__).parent / "vendor"
                         / "three.min.js").read_bytes()
            except OSError:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/javascript")
            self.send_header("Cache-Control", "public, max-age=604800")
            self.send_header("Content-Length", str(len(_data)))
            self.end_headers()
            self._send_body(_data)
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
                **_session_meta(self.headers, self.client_address[0]),
            }
            self.send_response(302)
            self.send_header("Location", "/dashboard")
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
                "<details style='background:#050505;border:1px solid rgba(255,255,255,.25);border-radius:10px;padding:16px;margin-bottom:16px'>"
                "<summary style='color:#f2f2f2;cursor:pointer;font-size:16px;font-weight:600;font-family:Space Grotesk,sans-serif;letter-spacing:.06em'>Relay Providers</summary>"
                "<p style='color:#8e8e8e;font-size:14px;margin:12px 0'>Your outside keys via the built-in relay. Pollinations needs no key.</p>"
                + relay_fields +
                "</details>"
            )
            fields = "".join(
                '<label>' + n + '<input type="password" name="k_' + n + '" autocomplete="off"></label>'
                for n in other_names
            )
            freellmapi_section = (
                "<details style='background:#050505;border:1px solid rgba(255,255,255,.25);border-radius:10px;padding:16px;margin-bottom:16px'>"
                "<summary style='color:#f2f2f2;cursor:pointer;font-size:16px;font-weight:600;font-family:Space Grotesk,sans-serif;letter-spacing:.06em'>FreeLLMAPI Gateway</summary>"
                "<p style='color:#8e8e8e;font-size:14px;margin:12px 0'>One key for all providers. "
                "The gateway starts automatically with Nexus-Local on 127.0.0.1:3001.</p>"
                "<label>FreeLLMAPI unified API key"
                "<input type=\"password\" name=\"k_freellmapi\" autocomplete=\"off\"></label>"
                "<label>Gateway URL"
                "<input type=\"text\" name=\"url_freellmapi\" placeholder=\"http://127.0.0.1:3001\" autocomplete=\"off\"></label>"
                "<details style='margin-top:16px'>"
                "<summary style='color:#8e8e8e;cursor:pointer'>Or enter FreeLLMAPI providers keys manually</summary>"
                "<div style='margin-top:12px'>"
                + fields +
                "</div></details>"
                "</details>"
            )
            _cm_field = ("<label>Current master password<input type='password' name='current_master' required></label>"
                         "<p class='hint'>Replacing the shared keys requires proving the current master password.</p>"
                         ) if (keys_exist and info and info.get("admin")) else ""
            secure_card = (
                "<div class='card'><h3>Confirm it\u2019s you</h3>"
                "<p class='hint'>Your account password encrypts your personal key vault. Keys are stored only for your account and are never shared.</p>"
                "<label>Your account password<input type='password' name='password' required id='pw1'></label>"
            ) if user_mode else (
                "<div class='card'><h3>Secure your keys</h3>"
                    "<p class='hint'>This password encrypts everything and unlocks your dashboard</p>"
                    "<label>Password (min 10 chars)<input type='password' name='password' required minlength='10' id='pw1'></label>"
                    "<label>Confirm password<input type='password' name='confirm' required id='pw2'></label>"
                    + _cm_field +
                    "<div id='pwm' style='font-size:13px;margin-top:6px'></div>"
                    "<script>"
                    "document.getElementById('pw2').addEventListener('input',function(){"
                    "var a=document.getElementById('pw1').value,b=this.value;"
                    "document.getElementById('pwm').innerHTML=a===b&&a.length>=10?'<span style=\"color:#f2f2f2\">✓ Match</span>':'<span style=\"color:#ef4444\">Must match (10+ chars)</span>';"
                    "if(a===b&&a.length>=10)document.getElementById('st3').className='st on';});"
                    "</script>"
            )
            page = ("<!DOCTYPE html><html><head><meta charset='utf-8'>"
                    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                    "<title>Nexus - Setup</title><link rel='icon' href='/favicon.ico' sizes='any'><link rel='icon' type='image/svg+xml' href='/favicon.svg'><link rel='apple-touch-icon' href='/apple-touch-icon.png'><style>@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=JetBrains+Mono:wght@400;500&display=swap');"
                    "*{box-sizing:border-box}"
                    "body{background-color:#050507;background-image:radial-gradient(ellipse 90% 45% at 50% -5%, rgba(255,255,255,.07), transparent 70%);color:#e6e9f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;margin:0;padding:0}"
                    ".wrap{max-width:600px;margin:0 auto;padding:20px 16px 40px}"
                    ".hero{text-align:center;padding:24px 0 16px}"
                    ".eyebrow{font-family:'Space Grotesk',sans-serif;letter-spacing:.32em;font-size:15px;color:#f2f2f2;margin-bottom:10px}"
                    "h1{font-family:'Space Grotesk',sans-serif;font-size:34px;margin:0 0 8px;color:#fff;letter-spacing:.08em;line-height:1.2}h1 span{color:#f2f2f2}"
                    ".sub{color:#8e8e8e;font-size:14px;margin:0}"
                    ".steps{display:flex;justify-content:center;align-items:center;gap:6px;margin:18px 0}"
                    ".st{display:flex;align-items:center;gap:6px;font-size:12px;color:#6b7280}"
                    ".sn{width:24px;height:24px;border-radius:50%;background:#050505;border:1px solid #3a3a42;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:600}"
                    ".st.on{color:#fff}.st.on .sn{background:#f2f2f2;border-color:#000;color:#fff}"
                    ".st.done .sn{background:#8e8e8e;border-color:#8e8e8e;color:#050505}"
                    ".ln{width:24px;height:1px;background:#2a3142}"
                    ".tabs{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:16px}"
                    ".tab{background:#101014;border:1px solid #1a1a1e;border-radius:10px;padding:14px 8px;text-align:center;cursor:pointer;transition:all .18s;color:#f2f2f2}"
                    ".tab:hover{border-color:rgba(255,255,255,.4)}"
                    ".tab.sel{border-color:#f2f2f2;background:rgba(255,255,255,.07);box-shadow:0 0 20px rgba(255,255,255,.12)}"
                    ".tab b{display:block;font-size:13px;margin-bottom:2px;font-family:Space Grotesk,sans-serif;letter-spacing:.08em;text-transform:uppercase}"
                    ".tab span{font-size:11px;color:#8a8a92}"
                    ".card{background:#101014;border:1px solid rgba(255,255,255,.14);border-radius:12px;padding:20px;margin-bottom:14px;box-shadow:0 12px 32px rgba(0,0,0,.5),inset 0 1px 0 rgba(255,255,255,.05)}"
                    ".card h3{margin:0 0 6px;font-size:20px;font-family:'Space Grotesk',sans-serif;letter-spacing:.08em}"
                    ".hint{color:#8e8e8e;font-size:13px;margin:0 0 12px;line-height:1.45}"
                    "label{display:block;margin:10px 0 4px;color:#8e8e8e;font-size:13px}"
                    "input,textarea{width:100%;background:#050505;border:1px solid #1a1a1e;border-radius:8px;color:#f2f2f2;padding:11px 13px;font-size:14px}"
                    "input:focus,textarea:focus{outline:none;border-color:#f2f2f2;box-shadow:0 0 0 3px rgba(255,255,255,.15)}"
                    "textarea{font-family:ui-monospace,monospace}"
                    "button[type='submit']{font-family:Space Grotesk,sans-serif;font-weight:600;font-size:14px;letter-spacing:.22em;text-transform:uppercase;background:linear-gradient(#ffffff,#a8a8b0);color:#050505;border:1px solid #050505;border-radius:8px;box-shadow:0 0 28px rgba(255,255,255,.28),inset 0 1px 0 rgba(255,255,255,.5);padding:16px;width:100%;margin-top:14px;cursor:pointer}"
                    "button[type='submit']:hover{filter:brightness(1.12)}"
                    "details{background:#050505;border:1px solid #1a1a1e;border-radius:10px;margin-bottom:8px}"
                    "details summary{padding:12px 14px;cursor:pointer;font-weight:600;font-size:13px;list-style:none}"
                    "details summary::-webkit-details-marker{display:none}"
                    ".dbody{padding:0 14px 14px}"
                    ".warn{background:rgba(245,158,11,.08);border:1px solid #f59e0b;border-radius:12px;padding:13px 15px;margin-bottom:16px}"
                    ".warn p{margin:0;color:#fbbf24;font-size:13px}"
                    ".sec{display:none}.sec.on{display:block;animation:fi .25s}"
                    "@keyframes fi{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}"
                    "@media(max-width:480px){.tabs{grid-template-columns:1fr}}"
                    ".gold-div{height:2px;background:linear-gradient(90deg,transparent,rgba(255,255,255,.7),transparent);margin:0 -16px 16px}"
                    "@keyframes fadeUp{from{opacity:0;transform:translateY(18px)}to{opacity:1;transform:none}}""@keyframes grainShift{0%,100%{transform:translate(0,0)}12%{transform:translate(-3%,-5%)}25%{transform:translate(-8%,3%)}37%{transform:translate(4%,-8%)}50%{transform:translate(-3%,8%)}62%{transform:translate(-8%,3%)}75%{transform:translate(6%,0)}87%{transform:translate(0,6%)}}""@keyframes batDrift{0%,100%{transform:translateY(-50%) translateX(0)}50%{transform:translateY(-60%) translateX(-26px)}}""@keyframes tabGlow{0%,100%{box-shadow:0 0 14px rgba(255,255,255,.10)}50%{box-shadow:0 0 26px rgba(255,255,255,.28)}}""body::before{content:\"\";position:fixed;inset:0;z-index:2000;pointer-events:none;background:radial-gradient(ellipse at center,transparent 52%,rgba(0,0,0,.62) 100%)}""body::after{content:\"\";position:fixed;inset:-120px;z-index:2001;pointer-events:none;opacity:.05;background-image:url(\"data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A//www.w3.org/2000/svg%27%20width%3D%27140%27%20height%3D%27140%27%3E%3Cfilter%20id%3D%27n%27%3E%3CfeTurbulence%20type%3D%27fractalNoise%27%20baseFrequency%3D%270.85%27%20numOctaves%3D%272%27/%3E%3C/filter%3E%3Crect%20width%3D%27140%27%20height%3D%27140%27%20filter%3D%27url%28%23n%29%27%20opacity%3D%270.55%27/%3E%3C/svg%3E\");animation:grainShift 7s steps(8) infinite}"".hero{position:relative;overflow:hidden;animation:fadeUp .7s cubic-bezier(.2,.7,.3,1) both}"".hero::after{content:\"\";position:absolute;right:-34px;top:50%;width:280px;height:101px;background:url(\"data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A//www.w3.org/2000/svg%27%20viewBox%3D%270%200%20100%2036%27%3E%3Cpath%20d%3D%27M0%2C14%20L24%2C3%20L39%2C9%20L44%2C1%20L46.5%2C7%20L50%2C5%20L53.5%2C7%20L56%2C1%20L61%2C9%20L76%2C3%20L100%2C14%20L90%2C20%20L83%2C16%20L75%2C24%20L67%2C18%20L59%2C28%20L54%2C22%20L50%2C30%20L46%2C22%20L41%2C28%20L33%2C18%20L25%2C24%20L17%2C16%20L10%2C20%20Z%27%20fill%3D%27%23f2f2f2%27/%3E%3C/svg%3E\") no-repeat center/contain;opacity:.07;pointer-events:none;animation:batDrift 11s ease-in-out infinite}"".steps{animation:fadeUp .7s .08s cubic-bezier(.2,.7,.3,1) both}"".tabs{animation:fadeUp .7s .14s cubic-bezier(.2,.7,.3,1) both}"".tab.sel{animation:tabGlow 2.6s ease-in-out infinite}"".sec.on .card{animation:fadeUp .5s cubic-bezier(.2,.7,.3,1) both}"
                    "</style></head><body><div class='wrap'>"
                    "<div class='hero'><div class='eyebrow'>NEXUS</div>" +
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
                    "<h3 style='color:#f2f2f2'>Quick Import</h3>"
                    "<p style='color:#8e8e8e;font-size:14px;margin:0 0 12px'>Paste all keys at once, one per line as <code style=\"background:#1a1f2a;padding:2px 6px;border-radius:4px\">name: key</code>. Expand below to see valid names:</p>"
                    "<details style='margin-bottom:8px;background:#050505;border:1px solid #1a1a1e;border-radius:8px;padding:10px 14px'>"
                    "<summary style='color:#f2f2f2;cursor:pointer;font-size:14px;font-weight:600'>Relay Providers (5)</summary>"
                    "<div style='display:flex;flex-wrap:wrap;gap:6px;margin-top:10px'>"
                    "<span style='background:#050505;color:#d9d9de;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid rgba(255,255,255,.25);font-family:monospace'>relay_groq</span>"
                    "<span style='background:#050505;color:#d9d9de;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid rgba(255,255,255,.25);font-family:monospace'>relay_gemini</span>"
                    "<span style='background:#050505;color:#d9d9de;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid rgba(255,255,255,.25);font-family:monospace'>relay_openrouter</span>"
                    "<span style='background:#050505;color:#d9d9de;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid rgba(255,255,255,.25);font-family:monospace'>relay_nvidia</span>"
                    "<span style='background:#050505;color:#d9d9de;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid rgba(255,255,255,.25);font-family:monospace'>relay_pollinations</span>"
                    "</div></details>"
                    "<details style='margin-bottom:12px;background:#050505;border:1px solid #1a1a1e;border-radius:8px;padding:10px 14px'>"
                    "<summary style='color:#f2f2f2;cursor:pointer;font-size:14px;font-weight:600'>FreeLLMAPI Providers (14)</summary>"
                    "<div style='display:flex;flex-wrap:wrap;gap:6px;margin-top:10px'>"
                    "<span style='background:#050505;color:#f2f2f2;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid rgba(255,255,255,.12);font-family:monospace'>freellmapi</span>"
                    "<span style='background:#050505;color:#f2f2f2;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid rgba(255,255,255,.12);font-family:monospace'>groq</span>"
                    "<span style='background:#050505;color:#f2f2f2;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid rgba(255,255,255,.12);font-family:monospace'>google</span>"
                    "<span style='background:#050505;color:#f2f2f2;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid rgba(255,255,255,.12);font-family:monospace'>openrouter</span>"
                    "<span style='background:#050505;color:#f2f2f2;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid rgba(255,255,255,.12);font-family:monospace'>nvidia</span>"
                    "<span style='background:#050505;color:#f2f2f2;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid rgba(255,255,255,.12);font-family:monospace'>cloudflare</span>"
                    "<span style='background:#050505;color:#f2f2f2;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid rgba(255,255,255,.12);font-family:monospace'>cohere</span>"
                    "<span style='background:#050505;color:#f2f2f2;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid rgba(255,255,255,.12);font-family:monospace'>huggingface</span>"
                    "<span style='background:#050505;color:#f2f2f2;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid rgba(255,255,255,.12);font-family:monospace'>mistral</span>"
                    "<span style='background:#050505;color:#f2f2f2;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid rgba(255,255,255,.12);font-family:monospace'>zhipu</span>"
                    "<span style='background:#050505;color:#f2f2f2;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid rgba(255,255,255,.12);font-family:monospace'>aihorde</span>"
                    "<span style='background:#050505;color:#f2f2f2;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid rgba(255,255,255,.12);font-family:monospace'>kilo</span>"
                    "<span style='background:#050505;color:#f2f2f2;font-size:12px;padding:4px 10px;border-radius:20px;border:1px solid rgba(255,255,255,.12);font-family:monospace'>ovh</span>"
                    "</div></details>"
                    "<textarea id='bulk' rows='6' oninput='previewKeys()' style='width:100%;box-sizing:border-box;background:#050505;border:1px solid #1a1a1e;border-radius:8px;color:#f2f2f2;padding:14px;font-size:14px;font-family:monospace' placeholder='freellmapi: sk-...&#10;relay_groq: gsk_...&#10;groq: gsk_...&#10;openrouter: sk-or-v1-...'></textarea>"
                    "<div id='bulk-preview' style='margin:12px 0;font-size:13px'></div>"
                    "<div style='display:flex;gap:10px'>"
                    "<button type='button' onclick='fillKeys()' style='background:linear-gradient(#ffffff,#a8a8b0);color:#050505;border:1px solid #050505;border-radius:8px;box-shadow:0 0 20px rgba(255,255,255,.25);padding:14px 24px;font-size:13px;font-family:Space Grotesk,sans-serif;font-weight:600;letter-spacing:.14em;text-transform:uppercase;flex:1;cursor:pointer' onmousedown=\"this.style.transform='scale(.97)'\" onmouseup=\"this.style.transform='scale(1)'\">Fill Fields Below</button>"
                    "<button type='button' onclick=\"document.getElementById('bulk').value='';previewKeys()\" style='background:#141418;color:#8a8a92;border:1px solid rgba(255,255,255,.12);border-radius:8px;padding:14px 20px;font-size:13px;font-family:Space Grotesk,sans-serif;letter-spacing:.1em;cursor:pointer'>Clear</button>"
                    "</div>"
                    "</div>"
                    "<script>"
                    "var VALID_KEYS=['freellmapi','relay_groq','relay_gemini','relay_openrouter','relay_nvidia','groq','google','openrouter','openai','anthropic','nvidia','cloudflare','cohere','huggingface','mistral','zhipu','aihorde','kilo','ovh','pollinations'];"
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
                    "if(p.found.length>0){h+='<div style=\"color:#f2f2f2;margin-bottom:6px\">Will fill: <b>'+p.found.join(', ')+'</b> ('+p.found.length+')</div>';}"
                    "if(p.unknown.length>0){h+='<div style=\"color:#ef4444\">Unknown names (skipped): <b>'+p.unknown.join(', ')+'</b></div>';}"
                    "if(p.found.length==0&&p.unknown.length==0&&document.getElementById('bulk').value.trim()){h='<div style=\"color:#8e8e8e\">Type lines as <code>name: key</code>...</div>';}"
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
                    "if(el){el.value=v;el.style.border='2px solid #f2f2f2';el.style.background='#0f1f0f';n++;setTimeout(function(){el.style.border='';el.style.background='';},3000);}"
                    "else{skipped.push(k);}"
                    "});"
                    "var msg=document.getElementById('bulk-preview');"
                    "if(n>0){msg.innerHTML='<div style=\"background:#0f2f0f;border:1px solid #f2f2f2;border-radius:8px;padding:12px;color:#f2f2f2\"><b>'+n+' keys filled!</b> Fields are highlighted in green below. Scroll down to review.</div>';}"
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
                    "<summary style='color:#f2f2f2'>Via Relay</summary><div class='dbody'>"
                    "<p class='hint'>Your own endpoint + key, routed through the built-in relay</p>"
                    "<div id='custom-relay-list'></div>"
                    "<button type='button' onclick='addCustomRelay()' style='background:#141418;color:#f2f2f2;border:1px solid rgba(255,255,255,.35);border-radius:8px;padding:10px 20px;font-size:13px;font-family:Space Grotesk,sans-serif;letter-spacing:.1em;cursor:pointer;margin-top:8px'>+ Add Provider</button>"
                    "</div></details>"
                    "<details>"
                    "<summary style='color:#f2f2f2'>Via FreeLLMAPI</summary><div class='dbody'>"
                    "<p class='hint'>Routed through your FreeLLMAPI gateway</p>"
                    "<div id='custom-fl-list'></div>"
                    "<button type='button' onclick='addCustomFL()' style='background:#141418;color:#f2f2f2;border:1px solid rgba(255,255,255,.35);border-radius:8px;padding:10px 20px;font-size:13px;font-family:Space Grotesk,sans-serif;letter-spacing:.1em;cursor:pointer;margin-top:8px'>+ Add Provider</button>"
                    "</div></details>"
                    "<script>"
                    "var crCount=0;var cfCount=0;"
                    "function addCustomRelay(){"
                    "crCount++;"
                    "var d=document.createElement('div');"
                    "d.style.cssText='background:#0a0c11;border:1px solid #121214;border-radius:8px;padding:12px;margin-bottom:10px';"
                    "d.innerHTML='<label>Provider name (lowercase, no spaces)<input type=\"text\" name=\"cr_name_'+crCount+'\" placeholder=\"myprovider\" pattern=\"[a-z0-9_]+\"></label>'"
                    "+'<label>API endpoint (base URL)<input type=\"text\" name=\"cr_url_'+crCount+'\" placeholder=\"https://api.example.com/v1\"></label>'"
                    "+'<label>API key<input type=\"password\" name=\"cr_key_'+crCount+'\" autocomplete=\"off\"></label>'"
                    "+'<button type=\"button\" onclick=\"this.parentElement.remove()\" style=\"background:none;color:#ef4444;border:0;cursor:pointer;font-size:13px;padding:4px\">Remove</button>';"
                    "document.getElementById('custom-relay-list').appendChild(d);"
                    "}"
                    "function addCustomFL(){"
                    "cfCount++;"
                    "var d=document.createElement('div');"
                    "d.style.cssText='background:#0a0c11;border:1px solid #121214;border-radius:8px;padding:12px;margin-bottom:10px';"
                    "d.innerHTML='<label>Provider name (lowercase, no spaces)<input type=\"text\" name=\"cf_name_'+cfCount+'\" placeholder=\"myprovider\" pattern=\"[a-z0-9_]+\"></label>'"
                    "+'<label>API key<input type=\"password\" name=\"cf_key_'+cfCount+'\" autocomplete=\"off\"></label>'"
                    "+'<button type=\"button\" onclick=\"this.parentElement.remove()\" style=\"background:none;color:#ef4444;border:0;cursor:pointer;font-size:13px;padding:4px\">Remove</button>';"
                    "document.getElementById('custom-fl-list').appendChild(d);"
                    "}"
                    "</script></div></div>"
                    + secure_card
                    + ("<button type='submit'>Save My Keys</button>" if user_mode else "<button type='submit'>Encrypt and Finish Setup</button>")
                    + "</form>"
                    + ("<p style='text-align:center;margin-top:20px;color:#8e8e8e'>Your saved keys live under <a href='/mykeys' style='color:#f2f2f2'>My Keys</a> \u00b7 <a href='/' style='color:#f2f2f2'>Back to dashboard \u2192</a></p>" if user_mode else "<p style='text-align:center;margin-top:20px;color:#8e8e8e'>Already have keys set up? <a href='/login' style='color:#f2f2f2'>Log in →</a></p>")
                    + "</div></body></html>")
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
            self.end_headers()
            self._send_body(page.encode())
            return
        # Public announcement (login + invite pages render the banner;
        # carries no secrets — just the admin's notice + mode flags).
        if parsed.path == "/api/announcement":
            self._set_json_headers()
            self._send_body(json.dumps({
                "announcement": _SETTINGS.get("announcement", ""),
                "maintenance": bool(_SETTINGS.get("maintenance")),
                "instance_name": _SETTINGS.get("instance_name", "Nexus"),
            }).encode())
            return
        if parsed.path == "/api/invite/info":
            self._set_json_headers()
            self._send_body(json.dumps({
                "registration": _SETTINGS.get("registration", "invite"),
                "instance_name": _SETTINGS.get("instance_name", "Nexus"),
                "pw_min": int(_SETTINGS.get("pw_min") or 8),
            }).encode())
            return
        # AI account sign-in starts: bounce to the provider's own
        # OAuth page (the Codex / Claude Code / Gemini CLI client
        # registrations). No server-side app of ours is involved —
        # the code comes back to the user, who pastes it into the
        # Integrations page, where it is exchanged and vaulted.
        _aio = _re.match(r"^/api/integrations/aioauth/"
                         r"(codex|claude_oauth|gemini_cli)/start$",
                         parsed.path)
        if _aio:
            if not self._session_info():
                self.send_response(302)
                self.send_header("Location", "/integrations?error="
                                 + _urlquote("Sign in to Nexus first, "
                                             "then connect."))
                self.end_headers()
                return
            _lane = _aio.group(1)
            _nonce = secrets.token_hex(8)
            _verifier, _challenge = _pkce_pair()
            self.send_response(302)
            self.send_header("Location",
                             _aioauth_url(_lane, _nonce, _challenge))
            self.send_header("Set-Cookie",
                             f"aio_state={_lane}:{_nonce}:{_verifier}; "
                             "Path=/; HttpOnly; Max-Age=900; SameSite=Lax; Secure")
            self.end_headers()
            return
        # OAuth sign-in (public): which providers are configured, the
        # start redirect (sets a state cookie), and the callback that
        # turns a verified provider email into a normal Nexus session.
        if parsed.path.startswith("/api/integrations/") and (
                parsed.path.endswith("/start") or parsed.path.endswith("/callback")):
            # OAuth connect flows for integrations (Gmail/Meet via
            # Google, Zoom). The user must already be signed in with
            # their integrations vault unlocked; tokens land in the
            # SESSION first and persist only when the user saves with
            # their password (a callback has no password to encrypt
            # with — the My Keys pattern, never a stored password).
            _iparts = parsed.path.strip("/").split("/")
            _isvc = _iparts[2] if len(_iparts) > 2 else ""
            _iact = _iparts[3] if len(_iparts) > 3 else ""
            _iprov = "google" if _isvc in ("google", "gmail", "meet") else (
                "zoom" if _isvc == "zoom" else "")
            _icreds = _intg_creds(_iprov) if _iprov else None

            def _intg_fail(msg):
                self.send_response(302)
                self.send_header("Location", "/integrations?error=" + _urlquote(msg))
                self.send_header("Set-Cookie", "intg_state=; Max-Age=0; Secure; Path=/")
                self.end_headers()
            if not _iprov or not _icreds:
                _intg_fail("That connection isn't set up on this server yet.")
                return
            _iinfo = self._session_info()
            if not _iinfo:
                _intg_fail("Sign in to Nexus first, then connect.")
                return
            if not isinstance(_iinfo.get("integrations"), dict):
                _intg_fail("Unlock your integrations vault on this page first, then connect.")
                return
            _ibase = _oauth_public_base(self.headers)
            _icb = f"{_ibase}/api/integrations/{_iprov}/callback"
            if _iact == "start":
                _istate = secrets.token_urlsafe(24)
                if _iprov == "google":
                    _ip = {"client_id": _icreds[0], "redirect_uri": _icb,
                           "response_type": "code",
                           "scope": "https://www.googleapis.com/auth/gmail.modify https://www.googleapis.com/auth/calendar.events openid email",
                           "state": _istate, "access_type": "offline",
                           "prompt": "consent"}
                    _iurl = "https://accounts.google.com/o/oauth2/v2/auth?" + _urlencode(_ip)
                else:
                    _ip = {"client_id": _icreds[0], "redirect_uri": _icb,
                           "response_type": "code", "state": _istate}
                    _iurl = "https://zoom.us/oauth/authorize?" + _urlencode(_ip)
                self.send_response(302)
                self.send_header("Location", _iurl)
                self.send_header("Set-Cookie",
                                 f"intg_state={_iprov}:{_istate}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600")
                self.end_headers()
                return
            # callback
            _iq = parse_qs(parsed.query or "")
            _icode = (_iq.get("code") or [""])[0]
            _istate_q = (_iq.get("state") or [""])[0]
            _ick = SimpleCookie(self.headers.get("Cookie", ""))
            _istate_c = _ick.get("intg_state").value if _ick.get("intg_state") else ""
            if not _icode or not _istate_q or not _istate_c \
                    or not secrets.compare_digest(f"{_iprov}:{_istate_q}", _istate_c):
                _intg_fail("The connection didn't complete — try again.")
                return
            try:
                if _iprov == "google":
                    _idata = urllib.parse.urlencode({
                        "code": _icode, "client_id": _icreds[0],
                        "client_secret": _icreds[1], "redirect_uri": _icb,
                        "grant_type": "authorization_code"}).encode()
                    _ist, _ij = _intg_http("https://oauth2.googleapis.com/token", "POST",
                                           {"Content-Type": "application/x-www-form-urlencoded"}, _idata)
                    if _ist != 200 or not isinstance(_ij, dict) or not _ij.get("refresh_token"):
                        raise ValueError(_intg_err_text(_ij) if isinstance(_ij, dict)
                                         else "Google returned no refresh token")
                    _pst, _pj = _intg_http("https://gmail.googleapis.com/gmail/v1/users/me/profile",
                                           "GET", {"Authorization": "Bearer " + _ij["access_token"]})
                    _iinfo["integrations"]["google"] = {
                        "type": "oauth", "refresh_token": _ij["refresh_token"],
                        "email": (_pj.get("emailAddress") if isinstance(_pj, dict) else "") or "",
                        "saved": False}
                else:
                    _idata = urllib.parse.urlencode({
                        "grant_type": "authorization_code", "code": _icode,
                        "redirect_uri": _icb}).encode()
                    _iauth = base64.b64encode(f"{_icreds[0]}:{_icreds[1]}".encode()).decode()
                    _ist, _ij = _intg_http("https://zoom.us/oauth/token", "POST",
                                           {"Authorization": "Basic " + _iauth,
                                            "Content-Type": "application/x-www-form-urlencoded"}, _idata)
                    if _ist != 200 or not isinstance(_ij, dict) or not _ij.get("access_token"):
                        raise ValueError(_intg_err_text(_ij) if isinstance(_ij, dict)
                                         else "Zoom returned no token")
                    _pst, _pj = _intg_http("https://api.zoom.us/v2/users/me", "GET",
                                           {"Authorization": "Bearer " + _ij["access_token"]})
                    _iinfo["integrations"]["zoom"] = {
                        "type": "oauth", "access_token": _ij["access_token"],
                        "refresh_token": _ij.get("refresh_token", ""),
                        "email": (_pj.get("email") if isinstance(_pj, dict) else "") or "",
                        "saved": False}
            except Exception as _ie:
                _intg_fail(f"Connection failed: {str(_ie)[:120]}")
                return
            self.send_response(302)
            self.send_header("Location", f"/integrations?connected={_iprov}")
            self.send_header("Set-Cookie", "intg_state=; Max-Age=0; Secure; Path=/")
            self.end_headers()
            return
        if parsed.path == "/api/oauth/providers":
            self._set_json_headers()
            self._send_body(json.dumps(
                {p: bool(_oauth_creds(p)) for p in _OAUTH_PROVIDERS}).encode())
            return
        if parsed.path.startswith("/api/oauth/"):
            _oparts = parsed.path.strip("/").split("/")
            _oprov = _oparts[2] if len(_oparts) > 2 else ""
            _oaction = _oparts[3] if len(_oparts) > 3 else ""
            _ocreds = _oauth_creds(_oprov) if _oprov in _OAUTH_PROVIDERS else None
            if not _ocreds or _oaction not in ("start", "callback"):
                self._set_json_headers(404)
                self._send_body(json.dumps({"error": "oauth not available"}).encode())
                return
            if not _rl_ok("oauth", _client_ip(self.headers, self.client_address[0]), 30, 900):
                self._set_json_headers(429)
                self._send_body(json.dumps({"error": "too many attempts, try again later"}).encode())
                return
            if not self._ip_gate():
                # Audit run-6: every other session-minting route
                # honors the IP allowlist; the (dormant) login OAuth
                # mint skipped it.
                return
            _obase = _oauth_public_base(self.headers)
            _ocb = f"{_obase}/api/oauth/{_oprov}/callback"
            if _oaction == "start":
                _ostate = secrets.token_urlsafe(24)
                if _oprov == "google":
                    _op = {"client_id": _ocreds[0], "redirect_uri": _ocb,
                           "response_type": "code", "scope": "openid email profile",
                           "state": _ostate, "access_type": "online",
                           "prompt": "select_account"}
                    _ourl = "https://accounts.google.com/o/oauth2/v2/auth?" + _urlencode(_op)
                else:
                    _op = {"client_id": _ocreds[0], "redirect_uri": _ocb,
                           "scope": "read:user user:email", "state": _ostate}
                    _ourl = "https://github.com/login/oauth/authorize?" + _urlencode(_op)
                self.send_response(302)
                self.send_header("Location", _ourl)
                self.send_header("Set-Cookie",
                                 f"oauth_state={_ostate}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=600")
                self.end_headers()
                return
            # callback
            _oq = parse_qs(parsed.query or "")
            _ocode = (_oq.get("code") or [""])[0]
            _ostate_q = (_oq.get("state") or [""])[0]
            _ock = SimpleCookie(self.headers.get("Cookie", ""))
            _ostate_c = _ock.get("oauth_state").value if _ock.get("oauth_state") else ""

            def _oauth_fail(msg):
                self.send_response(302)
                self.send_header("Location", "/login?oauth_error=" + _urlquote(msg))
                self.send_header("Set-Cookie", "oauth_state=; Max-Age=0; Secure; Path=/")
                self.end_headers()
            if not _ocode or not _ostate_q or not _ostate_c \
                    or not secrets.compare_digest(_ostate_q, _ostate_c):
                _oauth_fail("Sign-in didn't complete — try again.")
                return
            try:
                _oemail, _oname = _oauth_fetch_email(_oprov, _ocode, _ocb)
            except Exception:
                _oauth_fail("That provider couldn't verify your account — try again.")
                return
            _ores = _oauth_resolve(_oemail)
            if not _ores:
                _audit("System", f"OAuth sign-in refused (unlinked email) via {_oprov}",
                       ip=_client_ip(self.headers, self.client_address[0]))
                _oauth_fail("That account isn't linked to a Nexus user — "
                            "ask the admin to link your email first.")
                return
            _okind, _olabel = _ores
            _ois_admin = _okind == "admin"
            if not _ois_admin:
                _blocked = _friend_blocked(_olabel)
                if _blocked:
                    _oauth_fail("Maintenance mode is on — try again later."
                                if _blocked == "maintenance"
                                else "This account is suspended.")
                    return
            _otoken = secrets.token_hex(32)
            _osess = {"ts": time.time(), "label": _olabel,
                      "admin": _ois_admin, "oauth": _oprov}
            _osess.update(_session_meta(self.headers, self.client_address[0]))
            SESSIONS[_otoken] = _osess
            _audit("System", f"Signed in via OAuth ({_oprov}): {_olabel} "
                             f"({'admin' if _ois_admin else 'friend'})",
                   ip=_client_ip(self.headers, self.client_address[0]))
            self.send_response(302)
            self.send_header("Location", "/dashboard")
            self.send_header("Set-Cookie",
                             f"session={_otoken}; HttpOnly; Secure; SameSite=Lax; Path=/")
            self.send_header("Set-Cookie", "oauth_state=; Max-Age=0; Secure; Path=/")
            self.end_headers()
            return
        # Public invite signup page (the redeem POST does the real work).
        if parsed.path == "/invite":
            try:
                content = (Path(__file__).parent / "invite.html").read_text(encoding="utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.end_headers()
                self._send_body(content.encode())
            except Exception:
                self.send_error(500, "internal error")
            return
        # Public legal pages (plain-language terms + privacy, written
        # for how this instance actually handles data).
        if parsed.path in ("/terms", "/privacy"):
            try:
                content = (Path(__file__).parent
                           / (parsed.path[1:] + ".html")).read_text(encoding="utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.end_headers()
                self._send_body(content.encode())
            except Exception:
                self.send_error(500, "internal error")
            return
        # Public home page (owner order 2026-10-15: "a Home page
        # like other webs have", after the Aceternity Proactiv
        # template). Pure presentation — no data, no session.
        if parsed.path == "/home":
            try:
                content = (Path(__file__).parent / "landing.html").read_text(encoding="utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.end_headers()
                self._send_body(content.encode())
            except Exception:
                self.send_error(500, "internal error")
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
                return (f"<label>{disp_name(n)} <span style='color:#f2f2f2;font-size:12px'>({masked(n)})</span>"
                        f"<input type='password' name='k_{n}' autocomplete='off' placeholder='Leave blank to keep current'></label>")
            relay_rows = "".join(key_row(n) for n in PROVIDER_NAMES if n.startswith("relay_"))
            fl_rows = "".join(key_row(n) for n in PROVIDER_NAMES if not n.startswith("relay_"))
            det_style = ("background:#050505;border:1px solid rgba(255,255,255,.25);border-radius:10px;"
                         "padding:16px;margin-bottom:14px")
            sum_style = ("color:#f2f2f2;cursor:pointer;font-size:15px;font-weight:600;"
                         "font-family:Space Grotesk,sans-serif;letter-spacing:.06em")
            rows = (
                f"<details style='{det_style}'><summary style='{sum_style}'>FreeLLMAPI Providers</summary>"
                f"<div style='margin-top:12px'>{fl_rows}</div></details>"
                f"<details style='{det_style}'><summary style='{sum_style}'>Relay Providers</summary>"
                f"<div style='margin-top:12px'>{relay_rows}</div></details>"
            )
            page = ("<!DOCTYPE html><html><head><meta charset='utf-8'>"
                    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                    "<title>Nexus - Update Keys</title><link rel='icon' href='/favicon.ico' sizes='any'><link rel='icon' type='image/svg+xml' href='/favicon.svg'><link rel='apple-touch-icon' href='/apple-touch-icon.png'><style>@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;700&family=JetBrains+Mono:wght@400;500&display=swap');"
                    "*{box-sizing:border-box}"
                    "body{background-color:#050507;background-image:radial-gradient(ellipse 90% 45% at 50% -5%, rgba(255,255,255,.07), transparent 70%);color:#e6e9f0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;margin:0;padding:0}"
                    ".wrap{max-width:600px;margin:0 auto;padding:20px 16px 40px}"
                    ".hero{text-align:center;padding:24px 0 16px}"
                    ".eyebrow{font-family:'Space Grotesk',sans-serif;letter-spacing:.32em;font-size:15px;color:#f2f2f2;margin-bottom:10px}"
                    "h1{font-family:'Space Grotesk',sans-serif;font-size:32px;margin:0 0 8px;color:#fff;letter-spacing:.08em}"
                    ".sub{color:#8e8e8e;font-size:14px;margin:0}"
                    ".card{background:#101014;border:1px solid rgba(255,255,255,.14);border-radius:12px;padding:20px;margin-bottom:14px;margin-top:20px;box-shadow:0 12px 32px rgba(0,0,0,.5),inset 0 1px 0 rgba(255,255,255,.05)}"
                    "label{display:block;margin:10px 0 4px;color:#8e8e8e;font-size:13px}"
                    "input{width:100%;background:#050505;border:1px solid #1a1a1e;border-radius:8px;color:#f2f2f2;padding:11px 13px;font-size:14px}"
                    "input:focus{outline:none;border-color:#f2f2f2;box-shadow:0 0 0 3px rgba(255,255,255,.15)}"
                    "button[type='submit']{font-family:Space Grotesk,sans-serif;font-weight:600;font-size:14px;letter-spacing:.22em;text-transform:uppercase;background:linear-gradient(#ffffff,#a8a8b0);color:#050505;border:1px solid #050505;border-radius:8px;box-shadow:0 0 28px rgba(255,255,255,.28),inset 0 1px 0 rgba(255,255,255,.5);padding:16px;width:100%;margin-top:16px;cursor:pointer}"
                    "button[type='submit']:hover{filter:brightness(1.12)}"
                    ".key-hint{color:#f2f2f2;font-size:11px;font-weight:600}"
                    ".back{text-align:center;margin-top:16px}"
                    ".back a{color:#f2f2f2;text-decoration:none;font-size:14px}"
                    "@keyframes fadeUp{from{opacity:0;transform:translateY(18px)}to{opacity:1;transform:none}}""@keyframes grainShift{0%,100%{transform:translate(0,0)}12%{transform:translate(-3%,-5%)}25%{transform:translate(-8%,3%)}37%{transform:translate(4%,-8%)}50%{transform:translate(-3%,8%)}62%{transform:translate(-8%,3%)}75%{transform:translate(6%,0)}87%{transform:translate(0,6%)}}""@keyframes batDrift{0%,100%{transform:translateY(-50%) translateX(0)}50%{transform:translateY(-60%) translateX(-26px)}}""@keyframes tabGlow{0%,100%{box-shadow:0 0 14px rgba(255,255,255,.10)}50%{box-shadow:0 0 26px rgba(255,255,255,.28)}}""body::before{content:\"\";position:fixed;inset:0;z-index:2000;pointer-events:none;background:radial-gradient(ellipse at center,transparent 52%,rgba(0,0,0,.62) 100%)}""body::after{content:\"\";position:fixed;inset:-120px;z-index:2001;pointer-events:none;opacity:.05;background-image:url(\"data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A//www.w3.org/2000/svg%27%20width%3D%27140%27%20height%3D%27140%27%3E%3Cfilter%20id%3D%27n%27%3E%3CfeTurbulence%20type%3D%27fractalNoise%27%20baseFrequency%3D%270.85%27%20numOctaves%3D%272%27/%3E%3C/filter%3E%3Crect%20width%3D%27140%27%20height%3D%27140%27%20filter%3D%27url%28%23n%29%27%20opacity%3D%270.55%27/%3E%3C/svg%3E\");animation:grainShift 7s steps(8) infinite}"".hero{position:relative;overflow:hidden;animation:fadeUp .7s cubic-bezier(.2,.7,.3,1) both}"".hero::after{content:\"\";position:absolute;right:-34px;top:50%;width:280px;height:101px;background:url(\"data:image/svg+xml,%3Csvg%20xmlns%3D%27http%3A//www.w3.org/2000/svg%27%20viewBox%3D%270%200%20100%2036%27%3E%3Cpath%20d%3D%27M0%2C14%20L24%2C3%20L39%2C9%20L44%2C1%20L46.5%2C7%20L50%2C5%20L53.5%2C7%20L56%2C1%20L61%2C9%20L76%2C3%20L100%2C14%20L90%2C20%20L83%2C16%20L75%2C24%20L67%2C18%20L59%2C28%20L54%2C22%20L50%2C30%20L46%2C22%20L41%2C28%20L33%2C18%20L25%2C24%20L17%2C16%20L10%2C20%20Z%27%20fill%3D%27%23f2f2f2%27/%3E%3C/svg%3E\") no-repeat center/contain;opacity:.07;pointer-events:none;animation:batDrift 11s ease-in-out infinite}"".steps{animation:fadeUp .7s .08s cubic-bezier(.2,.7,.3,1) both}"".tabs{animation:fadeUp .7s .14s cubic-bezier(.2,.7,.3,1) both}"".tab.sel{animation:tabGlow 2.6s ease-in-out infinite}"".sec.on .card{animation:fadeUp .5s cubic-bezier(.2,.7,.3,1) both}"
                    "</style></head><body>" + sidebar + "<div class='wrap'>"
                    "<div class='hero'><div class='eyebrow'>NEXUS</div>"
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
        if parsed.path == "/integrations":
            # Integrations overview: what Nexus is connected to (external
            # API, alert channels, provider lanes, backup mirror). Any
            # signed-in user; the page's data endpoints gate themselves
            # (owner data renders as "Owner-managed" for friends).
            info = self._session_info()
            if not info:
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
                return
            try:
                content = (Path(__file__).parent / "integrations.html").read_text(encoding="utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.end_headers()
                self._send_body(content.encode())
            except Exception as e:
                self.send_error(500, "internal error")
            return
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
        # Root: the public home page is Nexus's default page
        # (owner order 2026-10-16 — "make home page default page
        # of nexus"). Everyone lands here first, signed in or
        # not; the app itself lives at /dashboard below.
        if parsed.path == "/":
            key_path = Path(__file__).parent / "keys.enc"
            if not key_path.exists():
                self.send_response(302)
                self.send_header("Location", "/setup")
                self.end_headers()
                return
            try:
                content = (Path(__file__).parent / "landing.html").read_text(encoding="utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                self.end_headers()
                self._send_body(content.encode())
            except Exception:
                self.send_error(500, "internal error")
            return
        # The app itself: the dashboard, session-gated as always.
        if parsed.path == "/dashboard":
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
            # Returns every encrypted store (friend blob, personal key
            # vaults, chats, provider keys + the 2FA secret, the access
            # and v1-key mirrors). AUTHENTICATED: a live admin session,
            # or the dedicated sync token (X-Sync-Token header, from env
            # NEXUS_SYNC_TOKEN) that the friend-sync job/hook presents.
            # Each store's confidentiality rests on its own protecting
            # secret (a friend's password, the master password, the
            # restore key), so the ciphertext is no longer served to
            # anonymous callers.
            _sync_tok = os.environ.get("NEXUS_SYNC_TOKEN", "")
            _given_tok = self.headers.get("X-Sync-Token", "")
            if not (_given_tok and _sync_tok
                    and secrets.compare_digest(_given_tok, _sync_tok)):
                if not self._require_admin():
                    return
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
                # v1key.enc too (the admin-generated /v1 service key,
                # restore-key encrypted like access.enc) so a generated key
                # survives redeploys instead of dying with the disk.
                v1key_b64 = None
                if V1KEY_PATH.exists():
                    v1key_b64 = _b64.b64encode(V1KEY_PATH.read_bytes()).decode()
                # settings.enc too (admin console settings, restore-key
                # encrypted like access.enc) so console policy survives
                # redeploys instead of resetting with the disk.
                settings_b64 = None
                if SETTINGS_ENC_PATH.exists():
                    settings_b64 = _b64.b64encode(SETTINGS_ENC_PATH.read_bytes()).decode()
                # telemetry.enc too (usage/audit tails, restore-key
                # encrypted) — the sync parks it on the nexus-telemetry
                # branch so history survives deploys without ever
                # triggering one.
                telemetry_b64 = None
                if TELEMETRY_ENC_PATH.exists():
                    telemetry_b64 = _b64.b64encode(TELEMETRY_ENC_PATH.read_bytes()).decode()
            except Exception:
                blob, vaults, chats, keys_b64, access_b64, v1key_b64, settings_b64, telemetry_b64 = None, {}, {}, None, None, None, None, None
            self._set_json_headers(200)
            self._send_body(json.dumps({"blob": blob, "vaults": vaults, "chats": chats, "keys": keys_b64, "access": access_b64, "v1key": v1key_b64, "settings": settings_b64, "telemetry": telemetry_b64}).encode())
            return
        if parsed.path == "/api/2fa_qr":
            # A bare GET can carry no master-password proof, so it must
            # never disclose secret material (previously it served the
            # ACTIVE TOTP secret to any admin session). The QR is served
            # only by the POST branch in _do_post, after _master_ok
            # passes, and only for a PENDING enrollment secret.
            self._set_json_headers(405)
            self._send_body(json.dumps({"error": "use POST /api/2fa_qr with master_pw"}).encode())
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
                for name in _ordered_provider_names():
                    provider_data = base.get(name, {})
                    quotas["providers"].append({
                        "provider": name,
                        "display_name": provider_data.get("display_name", name.title()),
                        "caps": _provider_caps(name),
                        "reset": provider_data.get("reset", ""),
                        "disabled": name in _disabled_providers(),
                        "history": history.get(name, {"requests": [0] * 7, "tokens": [0] * 7}),
                        "limits": {
                            "daily_requests": provider_data.get("daily_requests", {"limit": None, "notes": "", "source": ""}),
                            "monthly_requests": provider_data.get("monthly_requests", {"limit": None, "notes": "", "source": ""}),
                            "daily_tokens": provider_data.get("daily_tokens", {"limit": None, "notes": "", "source": ""}),
                            "monthly_tokens": provider_data.get("monthly_tokens", {"limit": None, "notes": "", "source": ""}),
                        },
                        "key_configured": bool(_ekeys_q.get(name)) or name in ("aihorde", "kilo", "ovh", "pollinations", "relay_pollinations"),
                        "down": _provider_down(name),
                        "health": _health_fields(name),
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
                            "caps": ["chat"],
                            "disabled": k in _disabled_providers(),
                            "reset": "",
                            "history": {"requests": [0] * 7, "tokens": [0] * 7},
                            "limits": {},
                            "key_configured": True,
                            "down": _provider_down(k),
                            "health": _health_fields(k),
                            "daily_usage": {"requests": 0, "tokens": 0},
                            "monthly_usage": {"requests": 0, "tokens": 0},
                        })
                    elif k.startswith("custom_fl_"):
                        cname = k[len("custom_fl_"):]
                        quotas["providers"].append({
                            "provider": k,
                            "display_name": f"FreeLLMAPI: {cname.title()} (Custom)",
                            "caps": ["chat"],
                            "disabled": k in _disabled_providers(),
                            "reset": "",
                            "history": {"requests": [0] * 7, "tokens": [0] * 7},
                            "limits": {},
                            "key_configured": True,
                            "down": _provider_down(k),
                            "health": _health_fields(k),
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
        if parsed.path == "/api/audit":
            # Readable by every console role (owner, moderator, viewer) —
            # the design's permission table gives viewers the audit log.
            _akind = self._console_kind()[0]
            if _akind is None:
                return self._require_admin()
            if not self._ip_gate():
                return
            _events = _read_audit(200)
            if _akind == "viewer":
                # The permission table grants viewers the events, not
                # the client IPs inside them (audit run-6; same
                # principle as the run-5 access-list strip).
                _events = [{k: v for k, v in e.items() if k != "ip"}
                           if isinstance(e, dict) else e
                           for e in _events]
            self._set_json_headers()
            self._send_body(json.dumps({
                "events": _events,
                "failovers_today": _audit_count_today("Failover handled", "Providers"),
                "fails_today": _audit_count_today("Attempt failed", "Providers"),
            }).encode())
            return
        if parsed.path == "/api/analytics":
            if self._console_kind()[0] is None:
                return self._require_admin()
            if not self._ip_gate():
                return
            rng = parse_qs(parsed.query).get("range", ["7d"])[0]
            if rng not in ("24h", "7d", "30d"):
                rng = "7d"
            now = datetime.datetime.now()
            if rng == "24h":
                start = (now - datetime.timedelta(hours=23)).replace(minute=0, second=0, microsecond=0)
                bucket_keys = [(start + datetime.timedelta(hours=i)) for i in range(24)]
                bucket_fmt = lambda d: d.strftime("%H:00")
                bucket_of = lambda d: d.replace(minute=0, second=0, microsecond=0)
            else:
                days = 30 if rng == "30d" else 7
                start = (now - datetime.timedelta(days=days - 1)).replace(hour=0, minute=0, second=0, microsecond=0)
                bucket_keys = [(start + datetime.timedelta(days=i)) for i in range(days)]
                bucket_fmt = lambda d: d.strftime("%d %b")
                bucket_of = lambda d: d.replace(hour=0, minute=0, second=0, microsecond=0)
            series = {bucket_fmt(k): 0 for k in bucket_keys}
            series_ms = {bucket_fmt(k): [0, 0] for k in bucket_keys}
            all_ms = []
            per_provider, per_user = {}, {}
            tot_r = tot_t = 0
            ms_sum = ms_n = 0
            try:
                if os.path.exists(USAGE_PATH):
                    with open(USAGE_PATH) as f:
                        for line in f:
                            try:
                                e = json.loads(line)
                            except Exception:
                                continue
                            if not isinstance(e, dict) or e.get("type"):
                                continue
                            try:
                                ts = datetime.datetime.fromisoformat(str(e.get("ts", "")))
                            except Exception:
                                continue
                            if ts < start:
                                continue
                            tot_r += 1
                            tt = (e.get("prompt_tokens", 0) or 0) + (e.get("completion_tokens", 0) or 0)
                            tot_t += tt
                            p = e.get("provider") or "?"
                            pp = per_provider.setdefault(p, {"requests": 0, "tokens": 0, "avg_ms": None})
                            pp["requests"] += 1
                            pp["tokens"] += tt
                            if e.get("ms"):
                                cur = pp.get("_ms_sum", 0) + e["ms"]
                                pp["_ms_sum"] = cur
                                pp["_ms_n"] = pp.get("_ms_n", 0) + 1
                                pp["avg_ms"] = round(cur / pp["_ms_n"])
                            u = e.get("user") or ("API /v1" if e.get("via") == "v1" or str(p).startswith("v1:") else None)
                            if u:
                                per_user[u] = per_user.get(u, 0) + 1
                            if e.get("ms"):
                                ms_sum += e["ms"]
                                ms_n += 1
                                all_ms.append(e["ms"])
                            bk = bucket_fmt(bucket_of(ts))
                            if bk in series:
                                series[bk] += 1
                                if e.get("ms"):
                                    series_ms[bk][0] += e["ms"]
                                    series_ms[bk][1] += 1
            except OSError:
                pass
            fails = failovers = 0
            try:
                if AUDIT_PATH.exists():
                    with open(AUDIT_PATH) as f:
                        for line in f:
                            try:
                                e = json.loads(line)
                            except Exception:
                                continue
                            try:
                                ts = datetime.datetime.fromisoformat(str(e.get("ts", "")))
                            except Exception:
                                continue
                            if ts < start:
                                continue
                            ev = str(e.get("event", ""))
                            if ev.startswith("Attempt failed"):
                                fails += 1
                            elif ev.startswith("Failover handled"):
                                failovers += 1
            except OSError:
                pass
            denom = tot_r + fails
            self._set_json_headers()
            self._send_body(json.dumps({
                "range": rng,
                "totals": {"requests": tot_r, "tokens": tot_t},
                "per_provider": sorted(
                    ({"provider": k, "requests": v["requests"],
                      "tokens": v["tokens"], "avg_ms": v.get("avg_ms")}
                     for k, v in per_provider.items()),
                    key=lambda x: -x["requests"]),
                "per_user": sorted(
                    ({"label": k, "requests": v} for k, v in per_user.items()),
                    key=lambda x: -x["requests"]),
                "series": [{"label": k, "requests": v,
                            "avg_ms": round(series_ms[k][0] / series_ms[k][1]) if series_ms[k][1] else None}
                           for k, v in series.items()],
                "avg_ms": round(ms_sum / ms_n) if ms_n else None,
                "p95_ms": (sorted(all_ms)[min(len(all_ms) - 1, int(len(all_ms) * 0.95))] if all_ms else None),
                "fails": fails,
                "failovers": failovers,
                "success_rate": round(tot_r / denom * 100, 1) if denom else None,
            }).encode())
            return
        if parsed.path == "/api/usage_today":
            # Per-friend usage for the console's Friends view: today's
            # requests/tokens, top provider, a 7-day strip and (only when
            # the admin enabled prompt logging) the latest prompt snippet.
            _k, _me = self._console_kind()
            if _k not in ("admin", "moderator"):
                return self._require_admin()
            if not self._ip_gate():
                return
            today = datetime.date.today()
            days = [(today - datetime.timedelta(days=i)).isoformat()
                    for i in range(6, -1, -1)]
            users = {}
            try:
                if os.path.exists(USAGE_PATH):
                    with open(USAGE_PATH) as f:
                        for line in f:
                            try:
                                e = json.loads(line)
                            except Exception:
                                continue
                            if not isinstance(e, dict) or e.get("type"):
                                continue
                            u = e.get("user")
                            if not isinstance(u, str) or not u:
                                continue
                            d = str(e.get("ts", ""))[:10]
                            if d not in days:
                                continue
                            rec = users.setdefault(u, {
                                "requests": 0, "tokens": 0, "days": [0] * 7,
                                "providers": {}, "last_prompt": None})
                            rec["days"][days.index(d)] += 1
                            if d == days[-1]:
                                rec["requests"] += 1
                                rec["tokens"] += (e.get("prompt_tokens", 0) or 0) \
                                    + (e.get("completion_tokens", 0) or 0)
                                p = e.get("provider")
                                if isinstance(p, str) and p:
                                    rec["providers"][p] = rec["providers"].get(p, 0) + 1
                                if e.get("p"):
                                    rec["last_prompt"] = str(e["p"])[:120]
            except OSError:
                pass
            out = []
            for u, rec in users.items():
                top = max(rec["providers"].items(), key=lambda kv: kv[1])[0] \
                    if rec["providers"] else None
                out.append({"label": u, "requests": rec["requests"],
                            "tokens": rec["tokens"], "days": rec["days"],
                            "top_provider": top,
                            "last_prompt": rec["last_prompt"]
                            if _SETTINGS.get("log_prompts") else None})
            out.sort(key=lambda x: -x["requests"])
            self._set_json_headers()
            self._send_body(json.dumps({"users": out}).encode())
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
            if provider in _AIOAUTH_MODELS:
                # Sign-in lanes serve their known model lists —
                # except Codex, whose backend publishes a per-account
                # catalog: when connected, serve only the models the
                # account is eligible for (static list as fallback).
                # Claude Code / Gemini CLI expose no such catalog.
                _info = self._session_info() or {}
                _ao = _info.get("integrations") or {}
                _connected = isinstance(
                    (_ao.get("ai_oauth") or {}).get(provider), dict)
                _models = _AIOAUTH_MODELS[provider] if _connected else []
                if _connected and provider == "codex":
                    _live = _codex_live_models(_info)
                    if _live:
                        _models = _live
                self._set_json_headers(200)
                self.wfile.write(json.dumps({"models": _models}).encode())
                return
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
                elif provider == "anthropic":
                    # Native Messages API host; the model list is
                    # fetched directly with the effective key below.
                    url = "https://api.anthropic.com/v1/models"
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
                if provider == "anthropic":
                    if not vault_key:
                        raise ValueError("no key configured")
                    req.add_header("x-api-key", vault_key)
                    req.add_header("anthropic-version", "2023-06-01")
                with _open_cred(req, 10) as resp:
                    data = js.loads(_read_capped(resp))
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
            _role = _friend_role(_ainfo.get("label", "")) if _ainfo else "friend"
            if not _ainfo or not (_ainfo.get("admin") or _ainfo.get("viewer")
                                  or _role in ("moderator", "viewer")):
                self.send_response(302)
                self.send_header("Location", "/login")
                self.end_headers()
                return
            if not _ip_allowed(_client_ip(self.headers, self.client_address[0])):
                self.send_response(403)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self._send_body(b"<h1>This instance only accepts sign-ins from allowed networks.</h1>")
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
        self._send_404_page()

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
        if not _SETTINGS.get("friends_byok", True):
            self._set_json_headers(403)
            self.wfile.write(json.dumps({"error": "personal key vaults are disabled by the admin"}).encode())
            return
        if form is None:
            length = int(self.headers.get("Content-Length", 0))
            form = parse_qs(self.rfile.read(length).decode())
        password = form.get("password", [""])[0]
        if not password:
            self._set_json_headers(400)
            self.wfile.write(json.dumps({"error": "password required to encrypt your vault"}).encode())
            return
        if _pw_throttled("friend", label):
            self._set_json_headers(429)
            self.wfile.write(json.dumps({"error": "too many wrong passwords — try again in a few minutes"}).encode())
            return
        access = _load_access()
        stored = access.get(label, "")
        ok, needs_up = _verify_password(password, stored)
        if ok and needs_up and label in access:
            # Compare-and-swap under the access lock: write the upgrade
            # only if the stored hash is still the one just verified —
            # a concurrent reset/revoke must not be overwritten by
            # this stale snapshot.
            with _ACCESS_LOCK:
                _fresh = _load_access()
                if _fresh.get(label) == stored:
                    _fresh[label] = _hash_password(password)
                    _save_access(_fresh)
        if not ok:
            _pw_failed("friend", label)
            self._set_json_headers(401)
            self.wfile.write(json.dumps({"error": "wrong password"}).encode())
            return
        _PW_FAILS.pop(("friend", label), None)
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
                    if not _public_base_url_ok(url):
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": "custom provider URL must be a public http(s) address"}).encode())
                        return
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
            if not _public_base_url_ok(gw_url):
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": "gateway URL must be a public http(s) address"}).encode())
                return
            keys["freellmapi_url"] = gw_url
        if any(len(v) > _USERKEY_VALUE_CAP for v in keys.values()):
            self._set_json_headers(400)
            self.wfile.write(json.dumps({"error": "a key value is too long (512 characters max)"}).encode())
            return
        with _USERKEYS_LOCK:
            try:
                vault = _load_userkeys_strict(label, password)
            except Exception:
                self._set_json_headers(500)
                self.wfile.write(json.dumps({"error": "stored keys could not be decrypted — nothing was changed"}).encode())
                return
            vault.update(keys)
            if len([k for k in vault if not k.startswith("_")]) > _USERKEY_COUNT_CAP:
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": "too many keys in one vault"}).encode())
                return
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
        self._cap_res = None
        try:
            self._do_post()
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:
            self._handle_uncaught(exc)
        finally:
            if getattr(self, "_cap_res", None) is not None:
                _inflight_drop(self._cap_res)
                self._cap_res = None

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
        if parsed.path == "/api/v1-access/generate":
            self._v1_access_generate()
            return
        if parsed.path in ("/api/v1-access/disable",
                           "/api/v1-access/enable",
                           "/api/v1-access/delete",
                           "/api/v1-access/rotate"):
            self._v1_access_keystate(parsed.path.rsplit("/", 1)[1])
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
                ip = _client_ip(self.headers, self.client_address[0])
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
                    # Same fail-closed rule as /api/login: a password
                    # shared by two accounts identifies NEITHER.
                    _cands = [cand for cand, stored in _load_access().items()
                              if _verify_password(password, stored)[0]]
                    if len(_cands) == 1:
                        label = _cands[0]
                if not label:
                    recent.append(now)
                    _login_attempts[ip] = recent
                    time.sleep(1)
                    _audit("System", "Failed setup identification")
                    self._set_json_headers(401)
                    self.wfile.write(json.dumps({"error": "wrong password"}).encode())
                    return
                _login_attempts.pop(ip, None)
                # The gates /api/login enforces at mint apply here
                # too (audit run-5): identifying with a friend's
                # password is a sign-in, so the source-IP allowlist
                # and a suspension / maintenance hold bind it -
                # otherwise a suspended friend could keep using
                # (and saving vault keys through) a session minted
                # here while every login is refused.
                if not self._ip_gate():
                    return
                _blocked = _friend_blocked(label)
                if _blocked:
                    _audit("Auth", f"Friend setup sign-in blocked ({_blocked}): {label}")
                    self._set_json_headers(403)
                    self.wfile.write(json.dumps(
                        {"error": "maintenance mode is on" if _blocked == "maintenance"
                         else "account suspended"}).encode())
                    return
                token = secrets.token_hex(32)
                SESSIONS[token] = {"ts": time.time(), "label": label, "admin": False,
                                   **_session_meta(self.headers, self.client_address[0])}
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
            if not pw or pw != form.get("confirm", [""])[0] or len(pw) < 10:
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": "passwords must match and be 10+ chars"}).encode())
                return
            # Audit run-8 (HIGH): with keys already set up, this
            # branch REPLACES the master password and the whole
            # shared vault — and it asked only for an admin SESSION.
            # A stolen session cookie could overwrite keys.enc under
            # an attacker-chosen password, wiping every provider key
            # and the TOTP secret, with no proof and no audit row.
            # The current master must now be proven (the budgeted
            # _master_proof) whenever a master already exists;
            # first-time setup stays proof-free.
            _cur_keys = None
            _entry_keys_exist = keys_exist
            if keys_exist:
                _cur_keys = _master_proof(form.get("current_master", [""])[0])
                if _cur_keys is None:
                    self._set_json_headers(401)
                    self.wfile.write(json.dumps({"error": "current master password is wrong or missing"}).encode())
                    return
                # Wave 13 (run-12 auth): change_master's collision
                # guard applies here too — AFTER the proof, mirroring
                # its placement, so the verdict is not a free oracle.
                # A new master equal to a friend's password would
                # shadow that friend: password-only login tries the
                # master branch first. Same-master stays allowed (the
                # suite-tested key-replacement flow).
                if _password_taken(_load_access(), pw):
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "that password is already in use by a friend — pick a different master password"}).encode())
                    return
            # Audit run-9 (S4) / wave 11 (F10): the first-run re-check
            # is DEFERRED to the encrypt site below. S4 re-checked here,
            # but the provider-form loops after this point call
            # _public_base_url_ok (getaddrinfo on an attacker-supplied
            # hostname), so a held request could stall inside that
            # window and still land as an unproven replacement. Now
            # every slow validation runs BEFORE the re-check, and the
            # re-check itself runs INSIDE _KEYS_LOCK, atomic with the
            # encrypt: keys.enc appearing meanwhile turns this request
            # into a rotation that must prove the current master.
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
                        if not _public_base_url_ok(url):
                            self._set_json_headers(400)
                            self.wfile.write(json.dumps({"error": "custom provider URL must be a public http(s) address"}).encode())
                            return
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
                if not _public_base_url_ok(gw_url):
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "gateway URL must be a public http(s) address"}).encode())
                    return
                keys["freellmapi_url"] = gw_url
            if _cur_keys:
                # Internal entries the form does not carry (the TOTP
                # secret / pending secret) survive a key replacement.
                for _ik, _iv in _cur_keys.items():
                    if _ik.startswith("_") and _ik not in keys:
                        keys[_ik] = _iv
            with _KEYS_LOCK:
                if not _entry_keys_exist and key_path.exists():
                    # F10: re-stat + proof INSIDE the lock, immediately
                    # before the encrypt — nothing slow sits between
                    # the check and the write any more, and every other
                    # keys.enc writer is already proof-gated under this
                    # same lock. The loser of the first-run race gets
                    # the same 401 as any unproven rotation.
                    # Wave 12 (A3): this deferred re-check must
                    # NOT debit the shared global ("master", "")
                    # failure budget — race losers are
                    # unauthenticated requests that entered before
                    # any proof was owed, and ten of them used to
                    # lock the OWNER out of every master-proof
                    # console action for up to 900s (and a correct
                    # proof cannot clear a throttled bucket early).
                    # A quiet decrypt (the wave-9 pattern) proves the
                    # same fact with no budget side effects; the 401
                    # for losers stays byte-identical.
                    # Wave 13 (run-12 auth): the quiet proof stays
                    # quiet toward the shared ("master", "") budget
                    # (A3), but it is COUNTED in a dedicated
                    # ("firstrun", "") ledger with the same 10/900
                    # shape — past 10 first-run re-check failures the
                    # candidate is refused UNTESTED with the identical
                    # 401, instead of every held guess getting a real
                    # in-lock decrypt.
                    if _pw_throttled("firstrun", ""):
                        self._set_json_headers(401)
                        self.wfile.write(json.dumps({"error": "current master password is wrong or missing"}).encode())
                        return
                    try:
                        _rc_keys = decrypt_keys(
                            key_path,
                            form.get("current_master", [""])[0])
                    except Exception:
                        _rc_keys = None
                    if _rc_keys is None:
                        _pw_failed("firstrun", "")
                        self._set_json_headers(401)
                        self.wfile.write(json.dumps({"error": "current master password is wrong or missing"}).encode())
                        return
                    # Wave 13: the collision guard also binds this
                    # (deferred-proof) rotation — checked only after
                    # the proof above passes, as on change_master.
                    if _password_taken(_load_access(), pw):
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": "that password is already in use by a friend — pick a different master password"}).encode())
                        return
                    _cur_keys = _rc_keys
                    keys_exist = True
                    for _ik, _iv in _rc_keys.items():
                        if _ik.startswith("_") and _ik not in keys:
                            keys[_ik] = _iv
                encrypt_keys(keys, pw, key_path)
                os.chmod(key_path, 0o600)
            if keys_exist:
                # Wave 12 (A1): a proven /setup rotation is a master
                # rotation — carry the master-encrypted artefacts
                # over to the NEW password via the SAME helper
                # change_master uses, or users.enc (the friend-list
                # disaster backup), the owner integrations vault and
                # the admin chat DEK wrap stay stranded under the
                # old password, and _CHAT_UNLOCKS clear wholesale
                # for parity with change_master.
                _carry_over_master_rotation(
                    form.get("current_master", [""])[0], pw)
                _CHAT_UNLOCKS.clear()
                # Audit run-9 (S8): a PROVEN replacement is a master
                # rotation — mirror change_master: the in-memory
                # vault becomes the newly written one (it used to
                # keep serving the OLD keys until restart) and every
                # session minted under the old master dies.
                Handler.keys = keys
                register_custom_providers(keys)
                SESSIONS.clear()
                # Wave 11 (F7/F8/F9): S8 mirrored change_master
                # incompletely — a proven /setup rotation now revokes
                # credential state exactly like change_master does:
                # stored /v1 keys die (file + live set; the accepted
                # consequence, as with change_master, is that
                # DSRclone's copilot key must be re-wired afterwards),
                # pending-2FA completions minted under the old master
                # die with their chat unlocks, and /view grants stop
                # re-minting viewer sessions.
                for _pend in list(_PENDING_2FA.values()):
                    if isinstance(_pend, dict):
                        _drop_chat_unlock(_pend.get("chat_unlock"))
                _PENDING_2FA.clear()
                _2FA_ATTEMPTS.clear()
                _VIEW_GRANTS.clear()
                try:
                    if V1KEY_PATH.exists():
                        V1KEY_PATH.unlink()
                except Exception:
                    pass
                with _V1KEYS_LOCK:
                    _V1KEYS["keys"] = []
            _audit("System", "Shared keys replaced via /setup (current master proven)"
                   if keys_exist else "First-time setup completed")
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
            with _KEYS_LOCK:
                key_path = Path(__file__).parent / "keys.enc"
                keys = _master_proof(pw)
                if keys is None:
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
                    if not _public_base_url_ok(gw_url):
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": "gateway URL must be a public http(s) address"}).encode())
                        return
                    keys["freellmapi_url"] = gw_url
                    updated += 1
                encrypt_keys(keys, pw, key_path)
                os.chmod(key_path, 0o600)
                Handler.keys = keys  # refresh in-memory
                register_custom_providers(keys)
            self.send_response(302)
            self.send_header("Location", "/dashboard")
            self.end_headers()
            return
        if parsed.path == "/api/2fa_qr":
            # QR for a PENDING 2FA enrollment. POST only: the caller must
            # prove the master password (like every sibling 2FA route),
            # and only the pending secret is ever rendered — the ACTIVE
            # secret is never disclosed by this route.
            content_length = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(content_length) if content_length else b"{}"
            try:
                data = json.loads(raw_body)
            except Exception:
                data = {}
            if not self._require_admin():
                return
            if not self._master_ok(data):
                self._set_json_headers(401)
                self._send_body(json.dumps({"error": "wrong master password"}).encode())
                return
            _pend = (Handler.keys or {}).get("_totp_pending") or ""
            if not _pend:
                self._set_json_headers(404)
                self._send_body(json.dumps({"error": "no pending 2FA enrollment"}).encode())
                return
            try:
                import qrcode, io
                otpauth = ("otpauth://totp/NexusLocal:admin?secret=" + _pend
                           + "&issuer=NexusLocal")
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
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(png)))
            self.end_headers()
            self._send_body(png)
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
            _tinfo = self._session_info() or {}
            # Bucket keyed on the account LABEL, not the session token:
            # logins mint unlimited sessions, so a per-token bucket let
            # one account multiply its per-minute allowance at will.
            if not _rl_ok("transcribe", _tinfo.get("label") or self._get_session(), 12, 60):
                self._set_json_headers(429)
                self.wfile.write(json.dumps({"error": "too many voice inputs, slow down a moment"}).encode())
                return
            # Same daily accounting invariant as /api/chat: the per-user
            # cap and the instance global cap bind transcription too,
            # and a successful transcription records a usage row.
            _label_t = _tinfo.get("label", "")
            # Audit run-8: per-account in-flight ceiling — with the
            # reservation now taken before the body read, slow-body
            # requests pin a slot (and a thread) for the whole 300s
            # arrival window; the per-minute bucket alone allowed
            # ~200 held slots per account, enough to refuse the whole
            # instance whenever global_cap was set below that.
            # Audit run-9 (S11): reserve FIRST, then count including
            # this reservation — the old check-then-add let racing
            # admissions all pass the same snapshot (5 in flight
            # against a ceiling of 4, verifier-forced interleaving).
            self._cap_res = _inflight_add(_label_t, "groq")
            if _label_t and _inflight_n(user=_label_t) > 4:
                self._set_json_headers(429)
                self.wfile.write(json.dumps({"error": "too many requests already in flight — wait for them to finish"}).encode())
                return
            if not _tinfo.get("admin") and _label_t:
                _cap = (_SETTINGS.get("user_caps") or {}).get(
                    _label_t, _SETTINGS.get("daily_cap", 200))
                if _cap and _today_counts(fresh=True)["users"].get(_label_t, 0) + _inflight_rank(self._cap_res, user=_label_t) > int(_cap):
                    _audit("Users", f"Daily cap hit: {_label_t} ({_cap}/day)")
                    _alert("cap_hit", "cap", {"label": _label_t, "cap": int(_cap)})
                    self._set_json_headers(429)
                    self.wfile.write(json.dumps({"error": f"daily limit reached ({_cap} requests/day) — ask the admin to raise it"}).encode())
                    return
                _gcap = int(_SETTINGS.get("global_cap") or 0)
                if _gcap and _today_total_requests(fresh=True) + _inflight_rank(self._cap_res) > _gcap:
                    _audit("Users", f"Instance daily cap hit ({_gcap}/day)")
                    _alert("cap_hit", "cap", {"label": _label_t, "cap": _gcap, "scope": "instance"})
                    self._set_json_headers(429)
                    self.wfile.write(json.dumps({"error": f"the instance reached today's limit ({_gcap} requests/day)"}).encode())
                    return
            content_length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(content_length)
            try:
                data = json.loads(raw)
            except Exception:
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": "invalid JSON"}).encode())
                return
            if _provider_blocked("groq", exclude=self._cap_res) or _provider_blocked("relay_groq"):
                self._set_json_headers(403)
                self.wfile.write(json.dumps({"error": "voice input is unavailable — the Groq provider is disabled or over its daily limit"}).encode())
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
            # Both values are interpolated into a hand-built
            # multipart body (audit run-6): CR/LF in either would
            # forge extra parts/headers in the outbound request.
            _mdl = str(_mdl).replace("\r", "").replace("\n", "")
            _mime = str(_mime).replace("\r", "").replace("\n", "")
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
                with _open_cred(_rq, 60) as _rs:
                    _txt = json.loads(_read_capped(_rs)).get("text", "")
                _append_usage({"ts": datetime.datetime.now().isoformat(),
                               "provider": "groq", "model": _mdl,
                               "prompt_tokens": 0, "completion_tokens": 0,
                               "user": _label_t, "ok": True})
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
            _crate = _SETTINGS.get("chat_rate")
            _crate = 40 if _crate is None else int(_crate)
            _cinfo = self._session_info() or {}
            # Bucket keyed on the account label (see transcribe): all of
            # one account's sessions share a single per-minute allowance.
            if _crate and not _rl_ok("chat", _cinfo.get("label") or self._get_session(), _crate, 60):
                self._set_json_headers(429)
                self.wfile.write(json.dumps({"error": "you're sending messages too fast — give it a few seconds"}).encode())
                return
            # Effective keys: friend's own vault if they have one, else shared keys
            _ekeys = self._effective_keys()
            _sinfo = self._session_info() or {}
            _chat_label = _sinfo.get("label", "")
            # Per-account in-flight ceiling (audit run-8, see the
            # transcribe twin): bounds slow-body reservation hostage
            # to 4 held slots per account.
            # Reserve BEFORE the cap checks and the body read (audit
            # run-7): reserving after the parse let concurrent
            # requests with slow bodies all pass admission. The
            # checks exclude this request's own reservation (run-8):
            # counting it made every cap effectively cap-1, and
            # cap=1 refused the first request of the day outright.
            self._cap_res = _inflight_add(_chat_label)
            # Audit run-9 (S11): the ceiling is enforced AFTER the
            # reservation, counting it — check-then-add raced
            # (5 in flight against a ceiling of 4).
            if _chat_label and _inflight_n(user=_chat_label) > 4:
                self._set_json_headers(429)
                self.wfile.write(json.dumps({"error": "too many requests already in flight — wait for them to finish"}).encode())
                return
            # Daily cap (admin console policy): friends only, counted
            # from today's usage entries. Cap 0 = no cap.
            if not _sinfo.get("admin") and _chat_label:
                _cap = (_SETTINGS.get("user_caps") or {}).get(
                    _chat_label, _SETTINGS.get("daily_cap", 200))
                if _cap and _today_counts(fresh=True)["users"].get(_chat_label, 0) + _inflight_rank(self._cap_res, user=_chat_label) > int(_cap):
                    _audit("Users", f"Daily cap hit: {_chat_label} ({_cap}/day)")
                    _alert("cap_hit", "cap", {"label": _chat_label, "cap": int(_cap)})
                    self._set_json_headers(429)
                    self.wfile.write(json.dumps({"error": f"daily limit reached ({_cap} requests/day) — ask the admin to raise it"}).encode())
                    return
                _gcap = int(_SETTINGS.get("global_cap") or 0)
                if _gcap and _today_total_requests(fresh=True) + _inflight_rank(self._cap_res) > _gcap:
                    _audit("Users", f"Instance daily cap hit ({_gcap}/day)")
                    _alert("cap_hit", "cap", {"label": _chat_label, "cap": _gcap, "scope": "instance"})
                    self._set_json_headers(429)
                    self.wfile.write(json.dumps({"error": f"the instance reached today's limit ({_gcap} requests/day)"}).encode())
                    return
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
            _user_msg = message if isinstance(message, str) else ""
            mode = data.get("mode", "text")  # text, code, search, auto
            _img_explicit = (mode == "image")  # user picked Image mode on purpose
            image = data.get("image")  # base64 data URI, optional
            file_data = data.get("file")  # {name, text/data, type}, optional
            link = data.get("link")  # URL string, optional
            _history_raw = data.get("history")  # shared-memory turns, optional
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
            # Wave 17 (run-16 caps CAPS16-2): the mode is final
            # now — stamp the base reservation with its post-parse
            # surface for every surface that can never become a
            # media spend of a judged lane (text/code/agent/search
            # and any other non-media mode). Media modes are NOT
            # stamped: they tag a provider below, before their
            # governance checks. _provider_verdict_locked's rank
            # loop counts a provider=None base only while it is
            # unstamped.
            if mode not in ("image", "voice", "video"):
                self._cap_res["surface"] = mode
            if mode == "code":
                message = ("You are an expert coding assistant. Provide clean, working code with brief explanations. "
                          "Use markdown code blocks with language tags.\n\n" + (message or ""))
            elif mode == "image":
                # Image generation routed by the picked provider/model:
                #   aihorde           -> AI Horde async queue
                #   google/relay_gemini -> Gemini native image call
                #   pollinations/etc  -> Pollinations image service (flux/turbo)
                # Pollinations is the substitute only when no provider was
                # hand-picked for Image mode; explicit picks fail honestly.
                import urllib.parse as _up2
                _prompt = (message or "").strip()[:1000]
                _img = None
                _fail = None  # why the picked provider could not produce an image
                _used_p, _used_m = provider, model
                if provider in ("cloudflare", "google", "relay_gemini"):
                    # These branches interpolate the model id into a
                    # URL path with the shared token attached (run-5).
                    _mpath = _safe_model_path(model)
                    if _mpath is None:
                        _fail = "invalid model name"
                        model = ""
                    else:
                        model = _mpath
                        _used_m = _mpath
                _disp = {"google": "Google Gemini", "relay_gemini": "Relay Gemini",
                         "cloudflare": "Cloudflare", "aihorde": "AI Horde"}.get(provider, provider or "The picked provider")
                def _img_blocked(p):
                    # Google image spends land on the google slot or
                    # its relay twin — either being governed blocks it.
                    # Wave 12 (C2): the base reservation is tagged
                    # with the picked provider BEFORE this pre-check
                    # (below), so a peer's in-flight attempt is
                    # visible here; exclude=self keeps this request
                    # from counting itself (the transcribe pattern).
                    # Wave 16 (run-15 caps CAPS15-4): ONE google key
                    # funds BOTH picks while spends meter under the
                    # pick name, so the pair is judged SUMMED — the
                    # wave-15 TTS also= shape. The old OR of two
                    # single-name checks never saw the twin name's
                    # spends against this name's limit.
                    # Wave 17 (run-16 caps CAPS16-1): the summed
                    # form must ALSO judge both names' LIMITS — the
                    # wave-16 single call read only google's limit,
                    # so a relay_gemini-only (or stricter-relay)
                    # limit bound nothing. The two also= calls are
                    # OR'd: each sums both names' spends against
                    # its own name's limit. (NOT a TTS transplant:
                    # TTS's single-name pick-leg under-judges
                    # twin-metered image spends.)
                    if p in ("google", "relay_gemini"):
                        return (_provider_blocked("google", exclude=self._cap_res, also="relay_gemini")
                                or _provider_blocked("relay_gemini", exclude=self._cap_res, also="google"))
                    return _provider_blocked(p, exclude=self._cap_res)
                # Wave 12 (C2): born-tagged — tag the base
                # reservation with the picked provider BEFORE the
                # first governance check (_pblocked just below and
                # every branch recheck), so a peer's check can see
                # this in-flight attempt.
                if provider in ("aihorde", "cloudflare", "google",
                                "relay_gemini"):
                    self._cap_res["provider"] = provider
                elif provider in ("pollinations", "relay_pollinations"):
                    # Wave 13 (run-12 caps): tag the PICK name — the
                    # old normalisation to "pollinations" split the
                    # lane's accounting across two names, so the
                    # pre-check's in-flight term (keyed on the pick
                    # name) saw nobody and concurrent spends
                    # overshot a relay_pollinations limit by the
                    # whole burst. Tag, checks and metering now
                    # share the pick name (the console's limit key).
                    self._cap_res["provider"] = provider
                _pblocked = bool(_img_explicit and provider in (
                    "aihorde", "cloudflare", "google", "relay_gemini",
                    "pollinations", "relay_pollinations")
                    and _img_blocked(provider))
                if _pblocked:
                    _fail = "the admin has disabled that provider (or it reached its daily limit)"
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
                            with _open_cred(rq, 40) as rs:
                                _ct = rs.headers.get("Content-Type") or ""
                                if rs.status == 200 and "image" in _ct:
                                    _bytes = rs.read(_MEDIA_IMAGE_CAP + 1)
                                    if _bytes and len(_bytes) <= _MEDIA_IMAGE_CAP:
                                        return "data:" + _ct.split(";")[0] + ";base64," + base64.b64encode(_bytes).decode()
                        except Exception:
                            pass
                        if _att < 2:
                            time.sleep(3)
                    return u
                try:
                    if provider == "aihorde" and model and not _pblocked and not _provider_blocked("aihorde", exclude=self._cap_res):
                        _horde_rid = None
                        try:
                            hk = ((_ekeys or {}).get("aihorde") or "0000000000")
                            sub_req = Request("https://stablehorde.net/api/v2/generate/async",
                                data=json.dumps({"prompt": _prompt,
                                    "params": {"width": 512, "height": 512, "steps": 25, "sampler_name": "k_euler", "n": 1},
                                    "models": [model], "nsfw": False, "censor_nsfw": True}).encode(),
                                headers={"Content-Type": "application/json", "apikey": hk, "Client-Agent": "NexusLocal:1.0"}, method="POST")
                            with _open_cred(sub_req, 30) as rs:
                                rid = json.loads(_read_capped(rs)).get("id")
                            _horde_rid = rid
                            _t0 = time.time()
                            _deadline = _t0 + 110
                            while rid and time.time() < _deadline:
                                time.sleep(6)
                                chk_req = Request(f"https://stablehorde.net/api/v2/generate/check/{rid}", headers={"Client-Agent": "NexusLocal:1.0"})
                                with _open_cred(chk_req, 20) as rs:
                                    chk = json.loads(_read_capped(rs))
                                if chk.get("faulted"):
                                    break
                                # Anonymous queue can mean a 5+ min wait — bail to
                                # Pollinations fast instead of holding the user.
                                if (chk.get("wait_time") or 0) > 240 and time.time() > _t0 + 10:
                                    break
                                if chk.get("done"):
                                    st_req = Request(f"https://stablehorde.net/api/v2/generate/status/{rid}", headers={"Client-Agent": "NexusLocal:1.0"})
                                    with _open_cred(st_req, 20) as rs:
                                        gens = json.loads(_read_capped(rs)).get("generations", [])
                                    if gens and gens[0].get("img"):
                                        _img = gens[0]["img"]
                                        # Inline it like Pollinations — hotlinked
                                        # images can fail to load in the browser.
                                        # The URL comes from an untrusted
                                        # volunteer worker, so it is fetched
                                        # ONLY through the SSRF guard: public
                                        # http(s), redirects re-validated,
                                        # image bodies only, bounded read.
                                        # On any failure _img stays a URL.
                                        if _safe_url(_img):
                                            try:
                                                _irq = Request(_img, headers={"User-Agent": "Mozilla/5.0"})
                                                _iop = _pinned_opener()
                                                with _iop.open(_irq, timeout=30) as _irs:
                                                    _ict = _irs.headers.get("Content-Type") or ""
                                                    _ib = _irs.read(_MEDIA_IMAGE_CAP + 1) if _ict.startswith("image/") and not _ict.startswith("image/svg") else b""
                                                if _ib and len(_ib) <= _MEDIA_IMAGE_CAP:
                                                    _img = "data:" + _ict.split(";")[0] + ";base64," + base64.b64encode(_ib).decode()
                                            except Exception:
                                                pass
                                        # The raw worker URL is returned to
                                        # the dashboard when inlining fails:
                                        # only http(s) may reach the page —
                                        # any other scheme (javascript:,
                                        # data:text/html, ...) is dropped,
                                        # never rendered. data:image/ is
                                        # exempted for raster types only:
                                        # SVG is script-capable, and its
                                        # safety here rests on one <img>
                                        # sink in another file (run-5).
                                        if _img and not (_img.startswith("data:image/")
                                                          and not _img.startswith("data:image/svg")) \
                                                and _up2.urlparse(_img).scheme not in ("http", "https"):
                                            _img = None
                                            _fail = "the worker returned an image address that is not safe to load"
                                    break
                        except Exception:
                            _img = None
                        if _horde_rid and not _img:
                            # The job was accepted upstream but nothing
                            # was delivered (fault, queue bail, deadline,
                            # dropped result): the spend still counts
                            # (audit run-5 - the success-only metering
                            # below missed every one of these exits).
                            _append_usage({"ts": datetime.datetime.now().isoformat(),
                                           "provider": "aihorde", "model": model,
                                           "prompt_tokens": 0, "completion_tokens": 0,
                                           "user": _chat_label, "ok": True})
                    elif provider == "cloudflare" and model and not _pblocked and not _provider_blocked("cloudflare", exclude=self._cap_res):
                        _ck = (_ekeys or {}).get("cloudflare") or ""
                        _acct, _, _tok = _ck.partition(":")
                        if not (_acct and _tok):
                            _fail = ("no usable Cloudflare key is available — the shared vault is still locked "
                                     "or the stored value is not in account:token form")
                        else:
                            try:
                                _creq = Request(f"https://api.cloudflare.com/client/v4/accounts/{_acct}/ai/run/{model}",
                                    data=json.dumps({"prompt": _prompt}).encode(),
                                    headers={"Authorization": f"Bearer {_tok}", "Content-Type": "application/json", "User-Agent": "Mozilla/5.0"}, method="POST")
                                with _open_cred(_creq, 90) as _crs:
                                    _cd = json.loads(_read_capped(_crs))
                                _cimg = (_cd.get("result") or {}).get("image")
                                if _cimg:
                                    _img = "data:image/jpeg;base64," + _cimg
                                else:
                                    _fail = "Cloudflare answered without an image"
                                    _append_usage({"ts": datetime.datetime.now().isoformat(),
                                                   "provider": "cloudflare", "model": model,
                                                   "prompt_tokens": 0, "completion_tokens": 0,
                                                   "user": _chat_label, "ok": True})
                            except HTTPError as _he:
                                _fail = f"Cloudflare returned an error ({_he.code})"
                            except Exception:
                                _fail = "the request to Cloudflare failed (network or timeout)"
                    elif provider in ("google", "relay_gemini") and model and not _pblocked and not _img_blocked(provider):
                        gk = (_ekeys or {}).get("google") or (_ekeys or {}).get("relay_gemini") or ""
                        if not gk:
                            _fail = ("no Google key is available — the shared vault is still locked "
                                     "(an admin sign-in unlocks it) or no Google key is configured")
                        else:
                            try:
                                gurl = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={_urlquote(gk, safe='')}"
                                gbody = {"contents": [{"parts": [{"text": _prompt}]}], "generationConfig": {"responseModalities": ["TEXT", "IMAGE"]}}
                                greq = Request(gurl, data=json.dumps(gbody).encode(), headers={"Content-Type": "application/json"}, method="POST")
                                with _open_cred(greq, 90) as rs:
                                    gd = json.loads(_read_capped(rs))
                                for part in gd.get("candidates", [{}])[0].get("content", {}).get("parts", []):
                                    if "inlineData" in part:
                                        _img = "data:" + part["inlineData"]["mimeType"] + ";base64," + part["inlineData"]["data"]
                                        break
                                if not _img:
                                    _fail = "Google answered without an image — this model may not generate images"
                                    _append_usage({"ts": datetime.datetime.now().isoformat(),
                                                   "provider": provider, "model": model,
                                                   "prompt_tokens": 0, "completion_tokens": 0,
                                                   "user": _chat_label, "ok": True})
                            except HTTPError as _he:
                                if _he.code == 429:
                                    _fail = "Google hit its quota / rate limit (429)"
                                elif _he.code == 403:
                                    _fail = "Google refused the key (403) — image generation may not be enabled for its project"
                                elif _he.code in (400, 404):
                                    _fail = f"Google rejected the request ({_he.code}) — the model may not support image generation"
                                else:
                                    _fail = f"Google returned an error ({_he.code})"
                            except Exception:
                                _fail = "the request to Google failed (network or timeout)"
                    if not _img:
                        # Pollinations substitution is only for requests that
                        # did not hand-pick an image provider: Auto routing,
                        # auto-detected image intent, or a Pollinations pick.
                        # An explicit pick that failed gets an honest error
                        # naming why — never a silent swap (owner report
                        # 2026-10-10: picked Gemini, silently got Pollinations).
                        _may_substitute = (provider in ("pollinations", "relay_pollinations")
                                           or provider in (None, "", "auto") or not _img_explicit)
                        # Wave 13: a pollinations-pair pick substitutes
                        # under its OWN name; any other pick
                        # substitutes under "pollinations".
                        _sub_p = provider if provider in (
                            "pollinations", "relay_pollinations") \
                            else "pollinations"
                        # Wave 15 (run-14 caps CAPS14-2): check
                        # BEFORE re-tagging. Wave 12 tagged first,
                        # so the caller joined the substitute's
                        # rank queue with its earlier birth order
                        # and leapfrogged a later-born reservation
                        # that provider had already admitted.
                        # Checked while not tagged _sub_p, the
                        # caller takes the full-count form; only a
                        # passing check earns the tag.
                        # Wave 16 (run-15 caps CAPS15-3): the check
                        # and the retag are now ONE _INFLIGHT_LOCK
                        # hold inside the helper — as two adjacent
                        # statements, a forced interleave let two
                        # concurrent substitutions both pass the
                        # check before either retagged (2 at
                        # limit 1).
                        if _may_substitute and not _pblocked and _provider_blocked_and_tag(_sub_p, self._cap_res):
                            _img = _pollinations(model if provider in ("pollinations", "relay_pollinations") else "flux")
                            if _img and provider not in ("pollinations", "relay_pollinations"):
                                _used_p, _used_m = "pollinations", "flux"
                    # Trace for the composer: what was picked, whether it
                    # produced the image, and any fallback that ran.
                    _itr = []
                    _picked = provider or "auto"
                    _eff_fail = _fail or ("AI Horde did not finish the image in time"
                                          if provider == "aihorde" else
                                          "Nexus has no image-generation route for this provider"
                                          if provider not in ("cloudflare", "google", "relay_gemini")
                                          else "did not produce an image")
                    if _img:
                        if _used_p != _picked and _picked not in ("auto", ""):
                            _itr.append({"p": _picked, "m": model, "ok": False,
                                         "e": str(_eff_fail)[:160]})
                        _itr.append({"p": _used_p, "m": _used_m, "ok": True})
                    else:
                        _itr.append({"p": _picked, "m": model, "ok": False,
                                     "e": str(_eff_fail)[:160]})
                        if _may_substitute and _picked not in ("pollinations", "relay_pollinations"):
                            _itr.append({"p": "pollinations", "m": "flux",
                                         "ok": False, "e": "image generation failed"})
                    if _img:
                        # Media generations spend provider quota too:
                        # record them like the text path does, so the
                        # per-user and instance daily caps bind media.
                        _append_usage({"ts": datetime.datetime.now().isoformat(),
                                       "provider": _used_p, "model": _used_m,
                                       "prompt_tokens": 0, "completion_tokens": 0,
                                       "user": _chat_label, "ok": True})
                        self._set_json_headers(200)
                        self.wfile.write(json.dumps({"reply": f"![Generated image]({_img})", "image_url": _img, "used_provider": _used_p, "used_model": _used_m, "trace": _itr}).encode())
                    elif provider in ("pollinations", "relay_pollinations"):
                        self._set_json_headers(502)
                        self.wfile.write(json.dumps({"error": "image generation failed, try again", "trace": _itr}).encode())
                    else:
                        if _fail is None:
                            _fail = ("AI Horde did not finish the image in time" if provider == "aihorde"
                                     else "Nexus has no image-generation route for this provider")
                        self._set_json_headers(502)
                        self.wfile.write(json.dumps({"error": f"{_disp} couldn't generate this image — {_fail}. Nothing else was substituted; pick Pollinations (flux) under Image mode, or another image provider, and try again.", "trace": _itr}).encode())
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
                # Admin governance binds voice too. Audit run-9
                # (S12): the blocked-check and the reservation tag
                # key on _prov — the lane every usage row below is
                # METERED under. They used to key on the funding
                # slot (_fund: _prov when it holds the key, else
                # groq), so when the two differed, the disabled /
                # limit state of BOTH lanes was bypassed and the
                # in-flight term accrued to a lane that never spends.
                # Which key pays is unchanged.
                self._cap_res["provider"] = _prov  # wave 12 (C2): tag BEFORE the governance check (born-tagged, the transcribe pattern)
                if _provider_blocked(_prov, exclude=self._cap_res) or _provider_blocked(
                        _prov if (_ekeys or {}).get(_prov) else "groq",
                        exclude=self._cap_res,
                        # Wave 15 (run-14 caps CAPS14-5): when the
                        # groq key funds a relay_groq pick, groq's
                        # limit is judged on the SUM over both
                        # names — the spends are tagged and
                        # metered relay_groq, so the groq-named
                        # terms alone read zero forever.
                        also=None if (_ekeys or {}).get(_prov)
                        or _prov == "groq" else _prov):
                    # Wave 11 (F3): govern the lane that PAYS — when
                    # _prov holds no key of its own, _gk above fell
                    # back to the groq key, so the groq lane's own
                    # disabled/limit state binds the spend too (the
                    # transcribe branch already checks both lanes).
                    self._set_json_headers(403)
                    self.wfile.write(json.dumps({"error": "voice is unavailable — the Groq provider is disabled or over its daily limit"}).encode())
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
                _wavs = []
                try:
                    _vtot = 0
                    for _c in _chunks[:8]:
                        _rq = Request("https://api.groq.com/openai/v1/audio/speech",
                            data=json.dumps({"model": _mdl, "input": _c, "voice": _voice, "response_format": "wav"}).encode(),
                            headers={"Authorization": f"Bearer {_gk}", "Content-Type": "application/json", **_UA}, method="POST")
                        with _open_cred(_rq, 60) as _rs:
                            _wb = _rs.read(_MEDIA_VOICE_CHUNK_CAP + 1)
                        if len(_wb) > _MEDIA_VOICE_CHUNK_CAP:
                            raise ValueError("voice chunk too large")
                        _vtot += len(_wb)
                        if _vtot > _MEDIA_VOICE_TOTAL_CAP:
                            raise ValueError("voice response too large")
                        _wavs.append(_wb)
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
                    _append_usage({"ts": datetime.datetime.now().isoformat(),
                                   "provider": _prov, "model": _mdl,
                                   "prompt_tokens": 0, "completion_tokens": 0,
                                   "user": _chat_label, "ok": True})
                    self._set_json_headers(200)
                    self.wfile.write(json.dumps({"audio": "data:audio/wav;base64," + _b64,
                        "reply": "\U0001f50a " + _text[:120], "used_provider": _prov, "used_model": _mdl,
                        "trace": [{"p": _prov, "m": _mdl, "ok": True}]}).encode())
                except HTTPError as e:
                    if _wavs:
                        # Earlier chunks were generated upstream and are
                        # discarded here — they still spent quota.
                        _append_usage({"ts": datetime.datetime.now().isoformat(),
                                       "provider": _prov, "model": _mdl,
                                       "prompt_tokens": 0, "completion_tokens": 0,
                                       "user": _chat_label, "ok": True})
                    try:
                        _eb = _read_capped(e)
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
                    if _wavs:
                        _append_usage({"ts": datetime.datetime.now().isoformat(),
                                       "provider": _prov, "model": _mdl,
                                       "prompt_tokens": 0, "completion_tokens": 0,
                                       "user": _chat_label, "ok": True})
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
                self._cap_res["provider"] = "huggingface"  # wave 12 (C2): tag BEFORE the governance check (born-tagged)
                if _provider_blocked("huggingface", exclude=self._cap_res):
                    self._set_json_headers(403)
                    self.wfile.write(json.dumps({"error": "video is unavailable — the provider is disabled or over its daily limit"}).encode())
                    return
                _sess = _uuid_v.uuid4().hex[:12]
                _neg = "worst quality, inconsistent motion, blurry, jittery, distorted"
                _data = [_prompt_v, _neg, None, None, 512, 704, "text-to-video", 3, 9, 42, True, 1, True]
                _file_url = None
                try:
                    _rq = Request(_BASE + "/gradio_api/queue/join",
                        data=json.dumps({"data": _data, "fn_index": 4, "session_hash": _sess}).encode(),
                        headers=_H, method="POST")
                    with _open_cred(_rq, 60) as _rs:
                        json.loads(_read_capped(_rs))
                    _file_url = None
                    _rq2 = Request(_BASE + f"/gradio_api/queue/data?session_hash={_sess}",
                        headers={"User-Agent": "Mozilla/5.0", **({"Authorization": f"Bearer {_hk}"} if _hk else {})})
                    _deadline = time.time() + 240
                    with _open_cred(_rq2, 250) as _rs2:
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
                    # The file URL comes from the upstream Space: fetch
                    # it only through the SSRF guard (public http(s),
                    # redirects re-validated), require a video body, and
                    # bound the read itself — not just the check after.
                    if not _safe_url(_file_url):
                        # The generation completed upstream; only its
                        # delivery is refused — the spend still counts.
                        _append_usage({"ts": datetime.datetime.now().isoformat(),
                                       "provider": "huggingface", "model": "Lightricks/LTX-Video",
                                       "prompt_tokens": 0, "completion_tokens": 0,
                                       "user": _chat_label, "ok": True})
                        self._set_json_headers(502)
                        self.wfile.write(json.dumps({"error": "video generation failed — the free GPU queue may be busy, try again"}).encode())
                        return
                    _rq3 = Request(_file_url, headers={"User-Agent": "Mozilla/5.0"})
                    _vop = _pinned_opener()
                    with _vop.open(_rq3, timeout=120) as _rs3:
                        _vct = _rs3.headers.get("Content-Type") or ""
                        if not _vct.startswith("video/"):
                            raise ValueError("upstream file is not a video")
                        # The type token is concatenated into a data:
                        # URI the dashboard places in an src attribute:
                        # admit only a strict MIME shape - a hostile
                        # upstream header must not break out of the
                        # attribute (audit run-5, browser-proven).
                        _vctok = _vct.split(";")[0].strip().lower()
                        if not _re.fullmatch(r"video/[a-z0-9][a-z0-9.+-]*",
                                              _vctok):
                            _vctok = "video/mp4"
                        _vid = _rs3.read(14 * 1024 * 1024 + 1)
                    if len(_vid) > 14 * 1024 * 1024:
                        _append_usage({"ts": datetime.datetime.now().isoformat(),
                                       "provider": "huggingface", "model": "Lightricks/LTX-Video",
                                       "prompt_tokens": 0, "completion_tokens": 0,
                                       "user": _chat_label, "ok": True})
                        self._set_json_headers(502)
                        self.wfile.write(json.dumps({"error": "generated video was too large"}).encode())
                        return
                    _b64 = base64.b64encode(_vid).decode()
                    _append_usage({"ts": datetime.datetime.now().isoformat(),
                                   "provider": "huggingface", "model": "Lightricks/LTX-Video",
                                   "prompt_tokens": 0, "completion_tokens": 0,
                                   "user": _chat_label, "ok": True})
                    self._set_json_headers(200)
                    self.wfile.write(json.dumps({"video": "data:" + _vctok + ";base64," + _b64,
                        "reply": "\U0001f3ac " + _prompt_v[:120],
                        "used_provider": "huggingface", "used_model": "Lightricks/LTX-Video",
                        "trace": [{"p": "huggingface", "m": "Lightricks/LTX-Video", "ok": True}]}).encode())
                except Exception:
                    if _file_url:
                        _append_usage({"ts": datetime.datetime.now().isoformat(),
                                       "provider": "huggingface", "model": "Lightricks/LTX-Video",
                                       "prompt_tokens": 0, "completion_tokens": 0,
                                       "user": _chat_label, "ok": True})
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
                        with _open_cred(wreq, 10) as wresp:
                            wdata = json.loads(_read_capped(wresp))
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
            # Shared memory: sanitise the client-supplied history. If the
            # client's last history entry IS this request's message (the
            # dashboard appends the user turn before sending), drop that
            # duplicate — the current message is added back exactly once
            # when the provider payload is built.
            _shared_hist = _normalize_history(_history_raw)
            if _shared_hist and _shared_hist[-1]["role"] == "user" and \
                    _shared_hist[-1]["content"] in ((_user_msg or "").strip(),
                                                    (message or "").strip()):
                _shared_hist = _shared_hist[:-1]
            _prev_by = _last_assistant_by(_shared_hist)
            # Only a raw provider id proves a cross-turn switch; older
            # saved chats store just a display label in `m`, which must
            # not trigger a false "previous provider failed" note.
            _prev_by_id = _prev_by if _prev_by in PROVIDER_NAMES else ""
            # Routing mode: quality | save | auto (stored in keys dict)
            # Per-session routing mode (each user has their own)
            _sess = SESSIONS.get(self._get_session() or "", {})
            routing = _sess.get("routing", "quality") if isinstance(_sess, dict) else "quality"
            # Default models for auto-selection (known working)
            _DEFAULT_MODELS = {
                "groq": "openai/gpt-oss-20b",
                "relay_groq": "openai/gpt-oss-20b",
                "google": "gemini-3.5-flash-lite",
                "relay_gemini": "gemini-3.5-flash-lite",
                "openrouter": "nvidia/nemotron-3-super-120b-a12b:free",
                "relay_openrouter": "nvidia/nemotron-3-super-120b-a12b:free",
                "nvidia": "google/gemma-3-12b-it",
                "relay_nvidia": "google/gemma-3-12b-it",
                "mistral": "mistral-small-latest",
                "cohere": "command-a-03-2025",
                "openai": "gpt-5-mini",
                "anthropic": "claude-sonnet-4-5",
                "codex": "gpt-5.1-codex-max",
                "claude_oauth": "claude-sonnet-4-5-20250929",
                "gemini_cli": "gemini-2.5-pro",
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
                                  "relay_nvidia", "nvidia", "mistral", "cohere",
                                  "pollinations", "relay_pollinations"]
                                 if routing_eff == "quality" else
                                 ["groq", "relay_groq", "pollinations", "relay_pollinations"])
                else:  # quality
                    # Prefer reliable providers first (Google often 503s, nvidia 403s on all chat).
                    # Keyless lanes ride at the tail: without them an
                    # Auto request while the vault is locked (every
                    # restart, until the owner signs in) found NO
                    # candidates at all and died on a misleading 400.
                    pref_list = ["relay_openrouter", "openrouter",
                                 "mistral",
                                 "relay_gemini", "google", "cohere",
                                 "openai", "anthropic",
                                 "pollinations", "relay_pollinations"]
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
            # Shared memory: _base_msgs carries the whole conversation for
            # whichever provider answers; _msgs_for() rebuilds it with a
            # handover note when a different provider takes over — either
            # after a failed attempt in this request, or when this turn's
            # provider differs from the one that wrote the last reply.
            _cur_content = (([{"type": "text", "text": message}]
                             + ([{"type": "image_url",
                                  "image_url": {"url": image}}] if image else []))
                            if image else message)
            _base_msgs, _sm_info = _build_shared_messages(
                _shared_hist, message, current_content=_cur_content)

            def _msgs_for(prov, handover_from=None):
                if not handover_from or handover_from == prov:
                    return _base_msgs
                _m, _i = _build_shared_messages(
                    _shared_hist, message, current_content=_cur_content,
                    handover_from=handover_from, for_provider=prov)
                return _m

            def _attempt(prov, mdl, timeout, msgs=None):
                # Per-provider timeout override (console setting).
                _pto = (_SETTINGS.get("provider_timeouts") or {}).get(prov)
                if _pto:
                    timeout = int(_pto)
                _t0 = time.time()
                akey = _ekeys.get(prov) if _ekeys else None
                if not akey and prov not in RELAY_KEYLESS:
                    return (False, 400, f"no key configured for {prov}")

                def _meter(_pt=0, _ct=0):
                    # Every successful lane appends exactly one usage
                    # row — the per-user/global caps and provider_limits
                    # all read this ledger, so a lane that skips its row
                    # is a lane that escapes them.
                    _urow = {
                        "ts": datetime.datetime.now().isoformat(),
                        "provider": prov, "model": mdl,
                        "prompt_tokens": _pt or 0,
                        "completion_tokens": _ct or 0,
                        "user": _chat_label,
                        "ms": int((time.time() - _t0) * 1000),
                        "ok": True,
                    }
                    if _SETTINGS.get("log_prompts") and _user_msg:
                        _urow["p"] = _user_msg[:120]
                    _append_usage(_urow)
                # Cohere uses its native API (not OpenAI-compatible):
                # shared memory rides its chat_history parameter instead.
                if prov == "cohere":
                    try:
                        cohere_body = {"model": mdl, "message": message}
                        if msgs:
                            _chist, _cfinal = _cohere_history(msgs)
                            if _chist:
                                cohere_body["chat_history"] = _chist
                            if _cfinal:
                                cohere_body["message"] = _cfinal
                        req = Request("https://api.cohere.com/v1/chat",
                                      data=json.dumps(cohere_body).encode(),
                                      headers={"Content-Type": "application/json",
                                               "Authorization": f"Bearer {akey}"},
                                      method="POST")
                        with _open_cred(req, timeout) as resp:
                            resp_data = json.loads(_read_capped(resp))
                            _cu = resp_data.get("usage") or {}
                            _ct2 = _cu.get("tokens") or {}
                            _meter(_ct2.get("input_tokens",
                                            _cu.get("input_tokens", 0)),
                                   _ct2.get("output_tokens",
                                            _cu.get("output_tokens", 0)))
                            return (True, resp_data.get("text", ""))
                    except HTTPError as e:
                        return (False, e.code, f"provider returned an error ({e.code})")
                    except Exception:
                        return (False, 502, "Could not reach the provider.")
                # Anthropic uses its native Messages API (not
                # OpenAI-compatible): system turns lift into the
                # system field, text blocks join into the reply.
                if prov == "anthropic":
                    try:
                        _amsgs, _asys = [], []
                        for _m in (msgs or []):
                            _c = _m.get("content")
                            if not isinstance(_c, str):
                                continue
                            if _m.get("role") == "system":
                                _asys.append(_c)
                            elif _m.get("role") in ("user", "assistant"):
                                _amsgs.append({"role": _m["role"], "content": _c})
                        if not _amsgs or _amsgs[-1]["role"] != "user":
                            _amsgs.append({"role": "user", "content": message})
                        _abody = {"model": mdl, "max_tokens": 4096,
                                  "messages": _amsgs}
                        if _asys:
                            _abody["system"] = "\n\n".join(_asys)
                        req = Request("https://api.anthropic.com/v1/messages",
                                      data=json.dumps(_abody).encode(),
                                      headers={"Content-Type": "application/json",
                                               "x-api-key": akey,
                                               "anthropic-version": "2023-06-01"},
                                      method="POST")
                        with _open_cred(req, timeout) as resp:
                            resp_data = json.loads(_read_capped(resp))
                            _txt = "".join(
                                b.get("text", "") for b in resp_data.get("content", [])
                                if isinstance(b, dict) and b.get("type") == "text")
                            _au = resp_data.get("usage") or {}
                            _meter(_au.get("input_tokens", 0),
                                   _au.get("output_tokens", 0))
                            return (True, _txt)
                    except HTTPError as e:
                        return (False, e.code, f"provider returned an error ({e.code})")
                    except Exception:
                        return (False, 502, "Could not reach the provider.")
                # AI sign-in lanes (owner order 2026-10-15): the
                # stored OAuth token (a JSON string in _ekeys) is
                # refreshed when stale, then spent against the
                # provider's own CLI backend.
                if prov in _AIOAUTH_CLIENTS:
                    _info = self._session_info() or {}
                    _tok = _aioauth_fresh(_info, prov)
                    if not _tok:
                        return (False, 401, "sign-in expired — "
                                            "reconnect it on the "
                                            "Integrations page")
                    _access = _tok["access"]
                    try:
                        if prov == "claude_oauth":
                            _cmsgs, _csys = [], []
                            for _m in (msgs or []):
                                _c = _m.get("content")
                                if not isinstance(_c, str):
                                    continue
                                if _m.get("role") == "system":
                                    _csys.append(_c)
                                elif _m.get("role") in ("user", "assistant"):
                                    _cmsgs.append({"role": _m["role"],
                                                   "content": _c})
                            if not _cmsgs or _cmsgs[-1]["role"] != "user":
                                _cmsgs.append({"role": "user",
                                               "content": message})
                            _csystem = [{"type": "text", "text":
                                         "You are Claude Code, "
                                         "Anthropic's official CLI "
                                         "for Claude."}]
                            if _csys:
                                _csystem.append(
                                    {"type": "text",
                                     "text": "\n\n".join(_csys)})
                            _cbody = {"model": mdl, "max_tokens": 4096,
                                      "messages": _cmsgs,
                                      "system": _csystem}
                            req = Request(
                                "https://api.anthropic.com/v1/messages",
                                data=json.dumps(_cbody).encode(),
                                headers={
                                    "Content-Type": "application/json",
                                    "Authorization": f"Bearer {_access}",
                                    "anthropic-version": "2023-06-01",
                                    "anthropic-beta": "claude-code-20250219,"
                                                      "oauth-2025-04-20",
                                    "x-app": "cli",
                                    "User-Agent": "claude-cli/2.1.0 "
                                                  "(external, cli)"},
                                method="POST")
                            with _open_cred(req, timeout) as resp:
                                resp_data = json.loads(_read_capped(resp))
                                _txt = "".join(
                                    b.get("text", "")
                                    for b in resp_data.get("content", [])
                                    if isinstance(b, dict)
                                    and b.get("type") == "text")
                                _ou = resp_data.get("usage") or {}
                                _meter(_ou.get("input_tokens", 0),
                                       _ou.get("output_tokens", 0))
                                return (True, _txt)
                        if prov == "codex":
                            _xinstr, _xinput = [], []
                            for _m in (msgs or []):
                                _c = _m.get("content")
                                if not isinstance(_c, str):
                                    continue
                                if _m.get("role") == "system":
                                    _xinstr.append(_c)
                                elif _m.get("role") in ("user", "assistant"):
                                    _xt = "input_text" if _m["role"] == "user" \
                                        else "output_text"
                                    _xinput.append(
                                        {"type": "message",
                                         "role": _m["role"],
                                         "content": [{"type": _xt,
                                                      "text": _c}]})
                            if not _xinput:
                                _xinput.append(
                                    {"type": "message", "role": "user",
                                     "content": [{"type": "input_text",
                                                  "text": message}]})
                            _xbody = {
                                "model": mdl,
                                "instructions": "\n\n".join(_xinstr)
                                                or "You are a helpful "
                                                   "assistant.",
                                "input": _xinput,
                                "stream": True, "store": False}
                            _xhdr = {
                                "Content-Type": "application/json",
                                "Authorization": f"Bearer {_access}",
                                "Originator": "codex-tui",
                                "User-Agent": "codex-tui/0.154.0 "
                                              "(Mac OS 26.5.2; arm64)"}
                            if _tok.get("account_id"):
                                _xhdr["Chatgpt-Account-Id"] = \
                                    _tok["account_id"]
                            req = Request(
                                "https://chatgpt.com/backend-api/codex"
                                "/responses",
                                data=json.dumps(_xbody).encode(),
                                headers=_xhdr, method="POST")
                            with _open_cred(req, timeout) as resp:
                                _raw = _read_capped(resp)
                            _deltas, _final = [], ""
                            _xusage = {}
                            for _line in _raw.splitlines():
                                _line = _line.strip()
                                if not _line.startswith("data:"):
                                    continue
                                try:
                                    _ev = json.loads(_line[5:].strip())
                                except Exception:
                                    continue
                                if _ev.get("type") == \
                                        "response.output_text.delta":
                                    _deltas.append(_ev.get("delta") or "")
                                elif _ev.get("type") == "response.completed":
                                    _xusage = (_ev.get("response") or {}
                                               ).get("usage") or {}
                                    for _o in (_ev.get("response") or {}
                                               ).get("output") or []:
                                        for _cc in _o.get("content") or []:
                                            if isinstance(_cc, dict) and \
                                                    _cc.get("text"):
                                                _final += _cc["text"]
                            _txt = "".join(_deltas) or _final
                            if not _txt:
                                return (False, 502, "the provider "
                                                    "answered with no "
                                                    "text")
                            _meter(_xusage.get("input_tokens", 0),
                                   _xusage.get("output_tokens", 0))
                            return (True, _txt)
                        # gemini_cli: Code Assist wrapped format.
                        _gconts, _gsys = [], []
                        for _m in (msgs or []):
                            _c = _m.get("content")
                            if not isinstance(_c, str):
                                continue
                            if _m.get("role") == "system":
                                _gsys.append(_c)
                            elif _m.get("role") in ("user", "assistant"):
                                _gconts.append(
                                    {"role": "model"
                                             if _m["role"] == "assistant"
                                             else "user",
                                     "parts": [{"text": _c}]})
                        if not _gconts:
                            _gconts.append({"role": "user",
                                            "parts": [{"text": message}]})
                        _greq = {"contents": _gconts,
                                 "generationConfig":
                                     {"maxOutputTokens": 4096}}
                        if _gsys:
                            _greq["systemInstruction"] = \
                                {"parts": [{"text": "\n\n".join(_gsys)}]}
                        _gbody = {"model": mdl,
                                  "project": _tok.get("project") or "",
                                  "request": _greq}
                        req = Request(
                            "https://cloudcode-pa.googleapis.com"
                            "/v1internal:generateContent",
                            data=json.dumps(_gbody).encode(),
                            headers={
                                "Content-Type": "application/json",
                                "Authorization": f"Bearer {_access}",
                                "User-Agent": "GeminiCLI/0.1"},
                            method="POST")
                        with _open_cred(req, timeout) as resp:
                            resp_data = json.loads(_read_capped(resp))
                        _inner = resp_data.get("response") or resp_data
                        _txt = ""
                        for _cand in _inner.get("candidates") or []:
                            for _p in (_cand.get("content") or {}
                                       ).get("parts") or []:
                                if isinstance(_p, dict) and _p.get("text"):
                                    _txt += _p["text"]
                        if not _txt:
                            return (False, 502, "the provider answered "
                                                "with no text")
                        _gu = _inner.get("usageMetadata") or {}
                        _meter(_gu.get("promptTokenCount", 0),
                               _gu.get("candidatesTokenCount", 0))
                        return (True, _txt)
                    except HTTPError as e:
                        if e.code in (401, 403):
                            return (False, e.code,
                                    "provider rejected the sign-in "
                                    f"({e.code}) — reconnect it on the "
                                    "Integrations page")
                        return (False, e.code,
                                f"provider returned an error ({e.code})")
                    except Exception:
                        return (False, 502, "Could not reach the provider.")
                # Base URL per provider type
                if prov.startswith("relay_") or prov in RELAY_UPSTREAMS:
                    base = f"http://127.0.0.1:{RELAY_PORT}/{prov}/v1"
                elif prov == "freellmapi" or prov.startswith("custom_fl_"):
                    # URL and key are paired BY PROVENANCE: a URL from the
                    # caller's own vault may only be used with that same
                    # caller's lane key. A friend-supplied URL with no
                    # friend key for the lane falls back to the SHARED
                    # URL+key pair — the owner's shared gateway credential
                    # must never be sent to a user-supplied endpoint.
                    _shared = dict(Handler.keys or {})
                    _own = (self._session_info() or {}).get("userkeys") or {}
                    if _own.get("freellmapi_url") and not _own.get(prov):
                        gw_url = ((_shared.get("freellmapi_url") or "")).strip()
                    else:
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
                    # Defense in depth: never attach a shared-vault
                    # credential to a URL that is not the shared
                    # configured gateway URL.
                    _shared_url = ((dict(Handler.keys or {}).get("freellmapi_url") or "")).strip().rstrip("/")
                    if akey and akey == dict(Handler.keys or {}).get(prov) and base != _shared_url:
                        return (False, 403, "refusing to send a shared key to a user-supplied URL")
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
                    with _open_cred(req, timeout) as resp:
                        resp_data = json.loads(_read_capped(resp))
                        reply = resp_data["choices"][0]["message"]["content"]
                        usage = resp_data.get("usage", {})
                        _meter(usage.get("prompt_tokens", 0),
                               usage.get("completion_tokens", 0))
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
            if _SETTINGS.get("skip_failing", True):
                _attempts += (healthy if healthy else _fb)
            else:
                _attempts += _fb
            # Admin console policy: max attempts, provider order,
            # enable/disable and per-provider daily limits.
            _max_att = max(1, int(_SETTINGS.get("max_attempts") or 4))
            def _lane_ok(p):
                # Wave 12 (C3): governance is read LIVE on every
                # check. The build-time captures (_dis/_lims) went
                # stale the moment an admin changed provider_disabled
                # or provider_limits mid-request — validated saves
                # install NEW objects, so the captures never
                # refreshed — and this request's remaining spends
                # ignored the change entirely.
                # Wave 13: the live read is ONE _governance()
                # snapshot — disabled and limits from the same state.
                _dis13, _lims13 = _governance()
                if p in _dis13:
                    return False
                _l = _lims13.get(p)
                if not _l:
                    return True
                # Audit run-7: FRESH counts plus the in-flight term —
                # a cached snapshot with no reservation term let every
                # concurrent chat pass a nearly-spent provider limit.
                return (_today_counts(fresh=True)["providers"].get(p, 0)
                        + _inflight_n(provider=p)) < int(_l)

            def _lane_spend_ok(p):
                # Wave 11 (F4): the spend-leg twin of _lane_ok for a
                # caller that has ALREADY taken its attempt reservation
                # for p — the reservation is part of the in-flight term,
                # so the check and the reservation are atomic in effect:
                # completed + in-flight (including this attempt) must
                # not EXCEED the limit. The old shape checked first and
                # reserved after, and two rendezvoused spends both
                # passed a limit of 1.
                # Wave 13: judged on ONE _governance() snapshot.
                _dis13, _lims13 = _governance()
                if p in _dis13:
                    return False
                _l = _lims13.get(p)
                if not _l:
                    return True
                return (_today_counts(fresh=True)["providers"].get(p, 0)
                        + _inflight_n(provider=p)) <= int(_l)

            def _lane_spend_reserve(p):
                # Wave 13 (run-12 caps): reserve+count as ONE locked
                # primitive (the _v1_chat shape): the caller's attempt
                # reservation is taken AND counted indivisibly, so
                # concurrent spends at a limit of 1 admit exactly one
                # instead of refusing each other. Returns the
                # reservation, or None when the lane is disabled or
                # its limit is spent (nothing is held then).
                _dis13, _lims13 = _governance()
                if p in _dis13:
                    return None
                _l = _lims13.get(p)
                if not _l:
                    return _inflight_add(_chat_label, p, attempt=True)
                return _inflight_reserve_capped(
                    _chat_label, p,
                    lambda: _provider_counts_today().get(p, 0), _l)

            _kept = [(p, m) for (p, m) in _attempts if _lane_ok(p)]
            if not _kept:
                self._set_json_headers(503)
                self.wfile.write(json.dumps({"error": "no providers available — the admin has disabled them or they reached today's limit"}).encode())
                return
            _ord = {n: i for i, n in enumerate(_SETTINGS.get("provider_order") or [])}
            _attempts = [_kept[0]] + sorted(_kept[1:], key=lambda pm: _ord.get(pm[0], 999))
            # Chain mode (console v2): the chosen provider always goes
            # first; the fallback tail follows the instance's strategy.
            _cmode = _SETTINGS.get("chain_mode", "priority")
            if _cmode == "fastest" and len(_attempts) > 2:
                _lat = _provider_latency()
                _attempts = [_attempts[0]] + sorted(
                    _attempts[1:], key=lambda pm: _lat.get(pm[0], 1e9))
            elif _cmode == "round_robin" and len(_attempts) > 2:
                _tail = _attempts[1:]
                _k = _RR_COUNTER["i"] % len(_tail)
                _RR_COUNTER["i"] += 1
                _attempts = [_attempts[0]] + _tail[_k:] + _tail[:_k]
            # Keyless floor: the slice the loop will actually run must
            # contain a lane that needs no key. Without one, a run of
            # retired default models, rate limits and a hanging lane
            # fails the request outright while keyless lanes sit
            # healthy (owner report 2026-10-15: Auto quality burned
            # all 4 attempts — a retired OpenRouter model twice, a
            # Mistral rate limit, a Gemini default that hangs — and
            # Pollinations never got a slot). Swap the slice's last
            # slot for a keyless lane when none is in it.
            _slice = _attempts[:_max_att]
            if len(_slice) >= 2 and not any(p in RELAY_KEYLESS for p, _m in _slice):
                _floor = next(((p, m) for (p, m) in _attempts[_max_att:]
                               if p in RELAY_KEYLESS and _lane_ok(p)), None)
                if _floor is None and _lane_ok("pollinations"):
                    _floor = ("pollinations",
                              _DEFAULT_MODELS.get("pollinations", "openai"))
                if _floor is not None:
                    _attempts = (_slice[:-1] + [_floor]
                                 + _attempts[_max_att:])
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
                import re as _re_a, html as _html_a, socket as _sock_a, ipaddress as _ip_a, ast as _ast_a, operator as _op_a, urllib.parse as _uparse_a, urllib.request as _ureq_a, http.client as _http_a, math as _math_a
                _BROWSER_UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"}
                def _clean(s):
                    return _html_a.unescape(_re_a.sub(r"<[^>]+>", "", s or "")).strip()
                def _tool_search(query):
                    q = _uparse_a.quote_plus(str(query)[:200])
                    req = Request(f"https://www.bing.com/search?q={q}&count=6", headers=_BROWSER_UA)
                    with _open_cred(req, 25) as r:
                        page = _read_capped(r)
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
                # _safe_url and _GuardedRedirect are module-level (shared
                # with the media branches). fetch_url additionally PINS
                # the connection: the socket connects only to an address
                # from the same resolution that was validated, so a DNS
                # rebinding between check and connect reaches nothing.
                def _tool_fetch(url):
                    if not _safe_url(url):
                        return "Blocked: URL is not a public web address."
                    opener = _pinned_opener()
                    req = Request(str(url)[:2000], headers=_BROWSER_UA)
                    with opener.open(req, timeout=20) as r:
                        raw = r.read(1500000)
                    text = raw.decode(errors="replace")
                    text = _re_a.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", text)
                    text = _clean(text)
                    text = _re_a.sub(r"\s+", " ", text)
                    return text[:8000] if text else "Page had no readable text."
                def _check_pow(base, exp):
                    # Bound the power BEFORE computing it: a model-supplied
                    # tower like 9**9**9 must never pin a handler thread.
                    if isinstance(exp, int) and exp < 0:
                        raise ValueError("negative exponent")
                    if isinstance(base, int) and isinstance(exp, int):
                        if exp > 1000:
                            raise ValueError("exponent too large")
                        if base not in (0, 1, -1) and exp * max(1, int(_math_a.log10(abs(base))) + 1) > 5000:
                            raise ValueError("result would be too large")
                    if isinstance(base, float) or isinstance(exp, float):
                        if abs(exp) > 1000:
                            raise ValueError("exponent too large")
                    return _op_a.pow(base, exp)
                _OPS = {_ast_a.Add: _op_a.add, _ast_a.Sub: _op_a.sub, _ast_a.Mult: _op_a.mul, _ast_a.Div: _op_a.truediv, _ast_a.Mod: _op_a.mod, _ast_a.Pow: _check_pow, _ast_a.USub: _op_a.neg, _ast_a.FloorDiv: _op_a.floordiv}
                _MAX_CALC_BITS = 5000 * 4  # ~5000 decimal digits
                def _calc(node):
                    if isinstance(node, _ast_a.Expression):
                        if sum(1 for _ in _ast_a.walk(node)) > 100:
                            raise ValueError("expression too complex")
                        return _calc(node.body)
                    if isinstance(node, _ast_a.Constant) and isinstance(node.value, (int, float)):
                        if isinstance(node.value, int) and node.value.bit_length() > _MAX_CALC_BITS:
                            raise ValueError("number too large")
                        return node.value
                    if isinstance(node, _ast_a.BinOp) and type(node.op) in _OPS:
                        left, right = _calc(node.left), _calc(node.right)
                        for v in (left, right):
                            if isinstance(v, int) and v.bit_length() > _MAX_CALC_BITS:
                                raise ValueError("intermediate result too large")
                        result = _OPS[type(node.op)](left, right)
                        if isinstance(result, int) and result.bit_length() > _MAX_CALC_BITS:
                            raise ValueError("result too large")
                        return result
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
                _msgs = ([{"role": "system", "content": _sys}]
                         + [{"role": h["role"], "content": h["content"]}
                            for h in _shared_hist]
                         + [{"role": "user", "content": message}])
                _agent_list = [(p, m) for (p, m) in _attempts[:_max_att] if p != "cohere"] or _attempts[:_max_att]
                _used_tools = []
                _final = None
                _ap2, _am2 = _agent_list[0]
                for _round in range(5):
                    if _round and not _sinfo.get("admin") and _chat_label:
                        # Audit run-6: admission was a single
                        # pre-check for up to 16 upstream calls. Each
                        # round meters its own attempts, so a FRESH
                        # count binds the loop to the same caps as any
                        # other request before it spends more.
                        _uc = (_SETTINGS.get("user_caps") or {}).get(
                            _chat_label, _SETTINGS.get("daily_cap", 200))
                        if (_uc and _today_counts(fresh=True)["users"].get(_chat_label, 0) >= int(_uc)) \
                                or _instance_cap_reached():
                            self._set_json_headers(429)
                            self.wfile.write(json.dumps({"error": "daily limit reached — the agent stopped here"}).encode())
                            return
                    if _round and not any(_lane_ok(_p)
                                           for _p, _m in _agent_list):
                        # Audit run-9 (S13): the mid-loop recheck
                        # omitted PROVIDER limits entirely — one
                        # ordinary agent request spent 3 rows on a
                        # lane limited to 1 (verifier-proven). Every
                        # agent lane is now disabled or spent, so the
                        # loop stops BEFORE another spend, with the
                        # same _lane_ok admission applies (fresh
                        # counts + the in-flight term).
                        self._set_json_headers(429)
                        self.wfile.write(json.dumps({"error": "daily limit reached — the agent stopped here"}).encode())
                        return
                    _ok = False
                    _reply = ""
                    for (_cp, _cm) in _agent_list[:3]:
                        # Wave 11 (F4): reserve FIRST, then check with
                        # the reservation counted (S13 checked first and
                        # reserved after — the check-then-add window).
                        _ares = _lane_spend_reserve(_cp)
                        if _ares is None:
                            # S13: re-test the lane immediately
                            # before THIS spend — a lane that filled
                            # up since admission (or since the last
                            # round) is skipped, not spent on.
                            continue
                        try:
                            _res = _attempt(_cp, _cm, 60, _msgs)
                        finally:
                            _inflight_drop(_ares)
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
                    # Wave 11 (F4): reserve first, then check counted.
                    _ares = _lane_spend_reserve(_ap2)
                    if _ares is None:
                        # S13: the final call is a spend too — the
                        # lane's limit binds it like every other.
                        _final = "I couldn't complete that. Try again."
                    else:
                        try:
                            _res = _attempt(_ap2, _am2, 60, _msgs)
                        finally:
                            _inflight_drop(_ares)
                        _final = _res[1] if _res[0] else "I couldn't complete that. Try again."
                if _used_tools:
                    _final = (_final or "") + "\n\n---\n\U0001f527 Tools used: " + ", ".join(_used_tools)
                self._set_json_headers(200)
                self.wfile.write(json.dumps({"reply": _final, "used_provider": _ap2, "used_model": _am2,
                                             "trace": [{"p": _ap2, "m": _am2, "ok": True}],
                                             "memory_turns": len(_shared_hist)}).encode())
                return
            _last = (502, "Could not reach the provider.")
            _answered = None
            _handover_from = None
            _trace = []  # per-attempt record for the composer's Trace view
            for _i, (_ap, _am) in enumerate(_attempts[:_max_att]):
                # Who is handing over to this attempt? A failed attempt
                # earlier in THIS request, or — on the first attempt —
                # the different provider that wrote the previous reply.
                _hf = _attempts[0][0] if _i > 0 else (
                    _prev_by_id if _prev_by_id and _prev_by_id != _ap else None)
                _ta = time.time()
                # Wave 11 (F4): reserve FIRST, then re-verify with the
                # reservation counted — S13 checked first and reserved
                # after, leaving a microsecond check-then-add window
                # where two rendezvoused spends both passed.
                _ares = _lane_spend_reserve(_ap)
                if _ares is None:
                    # Audit run-9 (S13): _lane_ok was a snapshot
                    # taken at build time and never re-checked at
                    # spend — rendezvoused concurrent builds each
                    # passed it and overshot the lane's limit.
                    # Re-verify immediately before the spend,
                    # counting peer attempt reservations (the
                    # in-flight term inside _lane_ok); a lane that
                    # filled up meanwhile fails over, or refuses
                    # when it was the last one. (Wave 13: the
                    # reserve primitive already dropped the refused
                    # reservation — nothing is held here.)
                    _trace.append({"p": _ap, "m": _am, "ok": False,
                                   "ms": 0,
                                   "e": "provider daily limit reached"})
                    _last = (429, f"{_ap} reached today's provider limit")
                    continue
                try:
                    _ok, *_rest = _attempt(_ap, _am, 45 if _i == 0 else 30,
                                           msgs=_msgs_for(_ap, _hf))
                finally:
                    _inflight_drop(_ares)
                _trace.append({"p": _ap, "m": _am, "ok": bool(_ok),
                               "ms": int((time.time() - _ta) * 1000),
                               **({} if _ok else {"e": str(_rest[1])[:160]})})
                if _ok:
                    _note_success(_ap)
                    if _i > 0:
                        _audit("Providers", f"Failover handled: {_attempts[0][0]} → {_ap}")
                        _handover_from = _attempts[0][0]
                    elif _hf:
                        _handover_from = _hf
                    _answered = (_ap, _am, _rest[0])
                    break
                _note_failure(_ap, str(_rest[1]))
                _audit("Providers", f"Attempt failed: {_ap} ({_rest[1]})")
                _last = (_rest[0], _rest[1])
            if _answered:
                self._set_json_headers(200)
                self.wfile.write(json.dumps({"reply": _answered[2],
                                             "used_provider": _answered[0],
                                             "used_model": _answered[1],
                                             "trace": _trace,
                                             "handover": bool(_handover_from),
                                             "from_provider": _handover_from,
                                             "memory_turns": _sm_info["turns"],
                                             "memory_compressed": _sm_info["compressed"]}).encode())
            else:
                self._set_json_headers(_last[0])
                self.wfile.write(json.dumps({"error": _last[1],
                                             "trace": _trace}).encode())
            return
        if parsed.path == "/api/refresh":
            if not self._require_admin():
                return
            if not self._ip_gate():
                # Audit run-7: every other console surface honors
                # the IP allowlist; this one skipped it (and had no
                # throttle at all).
                return
            if not _rl_ok("refresh", _client_ip(self.headers, self.client_address[0]), 30, 900):
                self._set_json_headers(429)
                self.wfile.write(json.dumps({"error": "too many attempts, try again later"}).encode())
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
                    with _open_loopback(req, 8) as r:
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
        if parsed.path == "/api/invite/redeem":
            # Self-service signup: an invite code (or open registration)
            # creates a friend account and signs the new user in. Uses
            # the same per-IP ledger as /api/login against brute force.
            if not _rl_ok("invite", _client_ip(self.headers, self.client_address[0]), 10, 900):
                self._set_json_headers(429)
                self.wfile.write(json.dumps({"error": "too many attempts, try again later"}).encode())
                return
            # Same source-IP allowlist as the other minting routes
            # (audit run-5): an operator who restricted sign-ins to
            # an allowlist did not exempt sign-ups.
            if not self._ip_gate():
                return
            content_length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(content_length) if content_length else b"{}"
            try:
                data = json.loads(raw)
            except Exception:
                data = {}
            if not isinstance(data, dict):
                data = {}
            mode_reg = _SETTINGS.get("registration", "invite")
            if mode_reg == "closed":
                self._set_json_headers(403)
                self.wfile.write(json.dumps({"error": "signups are closed — ask the admin to add you"}).encode())
                return
            if _SETTINGS.get("maintenance"):
                self._set_json_headers(403)
                self.wfile.write(json.dumps({"error": "maintenance mode is on — try again later"}).encode())
                return
            label = (data.get("label") or "").strip().lower()
            password = data.get("password") or ""
            code = (data.get("code") or "").strip().upper()
            if not _LABEL_RE.match(label):
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": "username must be a-z, 0-9, _ (max 30 chars)"}).encode())
                return
            if label == "rudra" or label.startswith("_"):
                # "rudra" is the owner's label; a leading underscore is
                # the vault-internal namespace ("_owner" is the owner's
                # integrations-vault identity) — never registrable.
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": "that username is reserved"}).encode())
                return
            if len(password) < int(_SETTINGS.get("pw_min") or 8):
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": f"password must be at least {int(_SETTINGS.get('pw_min') or 8)} characters"}).encode())
                return
            # Wave 16 (run-15 settings): validate -> budget ->
            # verdict -> clear -> claim -> create. The invite is
            # validated BEFORE any password check: an unauthenticated
            # caller without a valid code must learn nothing about
            # which passwords are in use. The claim -> create
            # sequence still runs under _ACCESS_LOCK (the invite is
            # claimed, and the claim persisted, BEFORE the slow
            # password hash and account creation, so a concurrent
            # redemption of the same code always sees it as used;
            # claim rolls back if creation fails).
            _acc16 = _load_access()
            if label in _acc16:
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": "that username is taken"}).encode())
                return
            role = _SETTINGS.get("signup_role", "friend")
            invite = None
            h = None
            if code:
                h = hashlib.sha256(code.encode()).hexdigest()
                for inv in (_SETTINGS.get("invites") or []):
                    if inv.get("h") == h and not inv.get("used_by") \
                            and inv.get("expires", 0) > time.time():
                        invite = inv
                        break
                if not invite:
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "invite code is invalid, used or expired"}).encode())
                    return
                role = invite.get("role", "friend")
            elif mode_reg == "invite":
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": "an invite code is required"}).encode())
                return
            # Audit run-9 (S5): the per-code probe budget is
            # consulted AND consumed BEFORE the taken/free
            # verdict is evaluated — every attempt that reaches
            # the password check pays, taken or free. Run-8
            # consulted it only AFTER a taken verdict, so once
            # the budget ran out the 429 itself became the
            # verdict (taken -> 429, free -> account created).
            # Post-budget both now get the identical 429.
            # Wave 11 (F11): open mode no longer keys the budget
            # to one flat "open" bucket — ten junk signups from
            # distinct sources used to exhaust it and block the
            # 11th legitimate signup, renewable every 900s. Open
            # mode is now keyed per source (in addition to the
            # per-IP route ledger above): junk from other sources
            # cannot block a legitimate signup, while a same-source
            # oracle still exhausts its own bucket. Invite mode
            # keeps per-code keying exactly as S5 left it, and the
            # budget is still consumed BEFORE the verdict, so
            # post-budget taken and free stay indistinguishable.
            _probe_key = h if code else (
                "open:" + _client_ip(self.headers,
                                     self.client_address[0]))
            # Wave 12 (A2): open mode ALSO carries a flat
            # global ceiling alongside the per-source bucket —
            # F11's per-source keying stays exactly as shipped
            # (it is what keeps junk sources from blocking
            # legitimate signups), but per-source alone lets one
            # host rotate IPv6 sources for an unbounded
            # taken/free oracle, dropping the run-8 cross-source
            # budget invariant. 250 verdicts/900s across all
            # sources (100 until wave 14) is far above any
            # plausible legitimate signup volume for this
            # deployment. Both buckets
            # are consumed BEFORE the verdict, so post-budget
            # taken and free stay indistinguishable in scope.
            _probe_ok = _rl_ok("redeemprobe", _probe_key, 10, 900)
            if _probe_ok and not code:
                # Wave 13 (run-12 auth): a per-candidate global
                # sub-bucket, consulted BEFORE the global ceiling
                # so one manufactured known-taken candidate can
                # burn at most 10/900s of global budget across
                # ALL sources (it used to exhaust "open:all"
                # alone and 429 every legitimate signup).
                _cand13 = "open:cand:" + hashlib.sha256(
                    password.encode()).hexdigest()
                _probe_ok = _rl_ok("redeemprobe", _cand13, 10, 900)
            if _probe_ok and not code:
                # Wave 14 (run-13 auth, MITIGATION): the bound is
                # raised 100 -> 250/900 for headroom only —
                # successes still accrue against it exactly like
                # verdicts (no refund returns; run-12's closure
                # holds) and the per-candidate cap still binds.
                _probe_ok = _rl_ok("redeemprobe", "open:all",
                                   250, 900)
            if not _probe_ok:
                _audit("Auth", f"Invite signup refused, probe budget exhausted: {label}")
                self._set_json_headers(429)
                self.wfile.write(json.dumps({"error": "too many attempts, try again later"}).encode())
                return
            if _password_taken(_acc16, password) \
                    or _is_master_password(password, quiet=True):
                # Audit run-8: this verdict is a password-
                # collision oracle (it confirms even the MASTER
                # password), and the route's per-IP ledger fell
                # to source rotation — so taken-verdicts are
                # also budgeted per invite code across ALL
                # sources (a flat key in open mode), and every
                # refusal is audit-logged; the stealth was part
                # of the original bug.
                _audit("Auth", f"Invite signup refused, password already in use: {label}")
                self._set_json_headers(400)
                self.wfile.write(json.dumps({"error": "that password is already in use by another friend — pick a different one"}).encode())
                return
            # Wave 15 (run-14 settings): EVERY creation path starts
            # from the same clean slate — the label provably has no
            # account here, so any per-user settings it carries are
            # stranded. Wave 16 (run-15 settings D15-2/D15-3): the
            # clear runs only NOW — after invite validation, after
            # the probe budget was consumed, after the taken
            # verdict, immediately before the claim persists (the
            # wave-15 shape ran and persisted it before ANY
            # validation, so one unauthenticated bogus-code POST
            # wiped a stranded label, oauth pre-links included, at
            # no budget cost) — and BEFORE _ACCESS_LOCK, so its
            # save + outcome settle no longer stalls every
            # concurrent creation behind a slow store. On a non-ok
            # outcome the signup aborts with the invite UNCONSUMED
            # and no account created. The terms_seen append and
            # role set below then apply the signup's own state
            # fresh.
            _clr15 = _clear_stranded_label(label)
            if _clr15 != "ok":
                self._set_json_headers(
                    409 if _clr15 == "conflict" else 500)
                self.wfile.write(json.dumps(
                    {"error": "signup could not be saved — try again"}).encode())
                return
            with _ACCESS_LOCK:
                access = _load_access()
                if label in access:
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "that username is taken"}).encode())
                    return
                # Wave 16: the pre-lock clear is re-verified INSIDE
                # the lock against PERSISTED state (a memory-only
                # recheck would reopen the AUTH14-2 class): if the
                # persisted store disagrees with the clear — a
                # concurrent writer re-stranded the label in the
                # window — abort before the claim, invite still
                # unconsumed.
                # Wave 17 (run-16 settings D16-2): the re-decrypt is
                # generation-guarded — the wave-17 clear judged
                # persisted state INSIDE this same lock and recorded
                # the settings generation triple at its return; the
                # full decrypt is re-paid only when a save landed or
                # started since (every settings writer funnels
                # through _save_settings_impl, the counters' sole
                # bumper) or one is in flight now. On the happy
                # path the recheck reuses the clear's judgement.
                _judged17 = getattr(_CLEAR_JUDGED17, "triple", None)
                if _judged17 is None or _SETTINGS_ACTIVE[0] > 0 \
                        or (_SETTINGS_GEN[0],
                            _SETTINGS_WRITTEN_GEN[0],
                            _SETTINGS_ACTIVE[0]) != _judged17:
                    _ps16 = _persisted_settings()
                    if _ps16 is not None and not \
                            _label_settings_absent(_ps16, label):
                        self._set_json_headers(500)
                        self.wfile.write(json.dumps(
                            {"error": "signup could not be saved — try again"}).encode())
                        return
                if invite is not None:
                    # Re-verify + claim under _SETTINGS_LOCK (run-8):
                    # the find above read the live invites list
                    # unlocked, so a revoke landing in the window
                    # could be claimed against a detached dict.
                    with _SETTINGS_LOCK:
                        _live = None
                        for _inv in (_SETTINGS.get("invites") or []):
                            if _inv.get("h") == h and not _inv.get("used_by") \
                                    and _inv.get("expires", 0) > time.time():
                                _live = _inv
                                break
                        if _live is None:
                            self._set_json_headers(400)
                            self.wfile.write(json.dumps({"error": "invite code is invalid, used or expired"}).encode())
                            return
                        invite = _live
                        invite["used_by"] = label  # claim, locks held
                    # Wave 12 (D4): the claim save is outcome-checked
                    # like every other consequential save. A faulted
                    # used_by save used to answer ok anyway; at
                    # restart the invite read unused again, so ONE
                    # code minted TWO accounts. On failure the claim
                    # is rolled back (compare-and-restore) and the
                    # request aborts BEFORE _save_access creates the
                    # account — the claim already precedes creation.
                    _csv = _save_settings()  # persist before the hash
                    _coc = _settings_outcome(
                        _csv,
                        lambda s: any(
                            i.get("h") == h
                            and i.get("used_by") == label
                            for i in (s.get("invites") or [])),
                        lambda: _cas_rollback_invite_claim(h, label))
                    if _coc != "ok":
                        self._set_json_headers(
                            409 if _coc == "conflict" else 500)
                        self.wfile.write(json.dumps(
                            {"error": "signup could not be saved — try again"}).encode())
                        return
                try:
                    access[label] = _hash_password(password)
                    _save_access(access)
                    # The invite page itself shows the terms notice at
                    # signup, so the first-login notice (F26) is already
                    # satisfied.
                    _w10_seen = False
                    _w10_role = False
                    _prior_roles13 = None
                    _new_roles13 = None
                    with _SETTINGS_LOCK:
                        _seen = list(_SETTINGS.get("terms_seen") or [])
                        if label not in _seen:
                            _seen.append(label)
                            _SETTINGS["terms_seen"] = _seen
                            _w10_seen = True
                        if role in ("moderator", "viewer"):
                            _prior_roles13 = dict(
                                _SETTINGS.get("roles") or {})
                            roles = dict(_prior_roles13)
                            roles[label] = role
                            _SETTINGS["roles"] = roles
                            _new_roles13 = dict(roles)
                            _w10_role = True
                    # S2: saves after the lock releases (one save
                    # persists both mutations; the old code saved
                    # after each — same final state on disk).
                    if _w10_seen or _w10_role:
                        _rsv13 = _save_settings()
                        # Wave 13 (run-12 data): the ROLE save is
                        # outcome-checked like the claim save above.
                        # It used to discard its result: a fault
                        # between the (durable) claim/account and this
                        # save answered 200 while the role silently
                        # downgraded to friend at restart. The
                        # account EXISTS and the code is spent, so
                        # the honest answer names exactly that; the
                        # live role entry is CAS-rolled back so the
                        # running server does not claim it either.
                        # (terms_seen alone stays best-effort.)
                        if _w10_role:
                            # Wave 14 (run-13 settings): the rollback
                            # is passed INTO the outcome call like
                            # every other checked site — wave 13 ran
                            # it manually afterwards, with an empty
                            # _OUTCOME_PERSISTED (no identical-peer
                            # protection) and even on "conflict",
                            # where the contract is NO rollback.
                            _roc13 = _settings_outcome(
                                _rsv13,
                                lambda s: (s.get("roles") or {}).get(
                                    label) == role,
                                lambda: _cas_rollback_dict_entry(
                                    "roles", label,
                                    _prior_roles13, _new_roles13))
                            if _roc13 != "ok":
                                self._set_json_headers(
                                    409 if _roc13 == "conflict" else 500)
                                self.wfile.write(json.dumps(
                                    {"error": "signed up, but the role could not be saved — the owner can set it from the console"}).encode())
                                return
                except Exception:
                    if invite is not None:
                        with _SETTINGS_LOCK:
                            invite["used_by"] = None  # roll the claim back
                        _save_settings()
                    raise
                # Wave 11 (F11): the account was created — refund the
                # probe-budget hit this success consumed. A success is
                # observable anyway (the account now exists), so the
                # refund cannot reopen the taken/free oracle; refused
                # attempts above keep their hits.
                _rl_refund("redeemprobe", _probe_key)
                # Wave 13 (run-12 auth): the GLOBAL hit is NOT
                # refunded any more — successes accrue against the
                # global ceiling (250/900 since wave 14) exactly
                # like taken verdicts, so
                # free verdicts share the cross-source bound again.
                # The per-source refund above stays (F11 fairness).
            _audit("Users", f"Signed up via invite: {label} ({role})",
                   ip=_client_ip(self.headers, self.client_address[0]))
            _alert("signup", "signup", {"label": label, "role": role})
            # Ghost-session guard (audit run-4): a factory reset that
            # completed after this account was created must not leave
            # a live session for a non-existent account - re-check
            # existence immediately before minting.
            with _ACCESS_LOCK:
                _still_there = label in _load_access()
            if not _still_there:
                _audit("Users", f"Signup session skipped for {label}: account no longer exists")
                self._set_json_headers()
                self.wfile.write(json.dumps({"ok": True, "label": label, "role": role}).encode())
                return
            token = secrets.token_hex(32)
            sess = {"ts": time.time(), "label": label, "admin": False,
                    "chat_pw": password}
            sess.update(_session_meta(self.headers, self.client_address[0]))
            SESSIONS[token] = sess
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Set-Cookie", f"session={token}; HttpOnly; Secure; SameSite=Lax; Path=/")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True, "label": label, "role": role}).encode())
            return
        if parsed.path == "/api/login":
            if not self._ip_gate():
                return
            ip = _client_ip(self.headers, self.client_address[0])
            now = time.time()
            recent = [t for t in _login_attempts.get(ip, []) if now - t < 900]
            if _SETTINGS.get("login_lockout", True) and len(recent) >= 10:
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
                # Account-wide budget (audit run-5): pendings mint on
                # password proof alone, so without a global cap the
                # guess budget scaled with every fresh login step.
                _2FA_FAILS_GLOBAL[:] = [t for t in _2FA_FAILS_GLOBAL
                                        if now - t < 600]
                if len(_2FA_FAILS_GLOBAL) >= 10:
                    self._set_json_headers(429)
                    self.wfile.write(json.dumps({"error": "too many attempts, start login again"}).encode())
                    return
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
                    _2FA_FAILS_GLOBAL.append(now)
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
                sess.update(_session_meta(self.headers, self.client_address[0]))
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
                _audit("System", "Signed in: Rudra (admin)")
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
                # Password-only login: the password IS the identity key,
                # so collect ALL matches and fail closed on ambiguity —
                # a shared password must never silently sign the caller
                # into the first matching account.
                _matches = []
                for l, h in access.items():
                    ok, needs_up = _verify_password(password, h)
                    if ok:
                        _matches.append((l, needs_up))
                label = None
                if len(_matches) == 1:
                    label, needs_up = _matches[0]
                    if needs_up:
                        # Legacy unsalted hash — upgrade in place (the
                        # encrypted backup refreshes on the next
                        # master-password save; access.json covers the
                        # running instance). Compare-and-swap under the
                        # access lock so a concurrent reset/revoke is
                        # never overwritten by this stale snapshot.
                        with _ACCESS_LOCK:
                            _fresh = _load_access()
                            if _fresh.get(label) == access.get(label):
                                _fresh[label] = _hash_password(password)
                                _save_access(_fresh)
                if not label:
                    recent.append(now)
                    _login_attempts[ip] = recent
                    time.sleep(1)
                    _audit("System", "Failed sign-in attempt",
                           ip=_client_ip(self.headers, ip))
                    self._set_json_headers(401)
                    self.wfile.write(json.dumps({"error": "wrong password"}).encode())
                    return
                is_admin = False
                # Friends may log in even before the admin unlock: their
                # session simply can't use provider keys until then (the
                # chat/transcribe/models endpoints say so clearly).
                _blocked = _friend_blocked(label)
                if _blocked:
                    _audit("System", f"Sign-in blocked ({_blocked}): {label}")
                    self._set_json_headers(403)
                    self.wfile.write(json.dumps({"error": "maintenance mode is on" if _blocked == "maintenance" else "account suspended"}).encode())
                    return
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
            sess.update(_session_meta(self.headers, self.client_address[0]))
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
                # The integrations vault rides the session too, so
                # connected tools and AI sign-ins work in chat
                # without a separate unlock step.
                try:
                    iv = _load_intg("_owner" if master_ok else label,
                                    password)
                    if isinstance(iv, dict):
                        sess["integrations"] = iv
                except Exception:
                    pass
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
            _audit("System", f"Signed in: {label} ({'admin' if is_admin else 'friend'})",
                   ip=_client_ip(self.headers, ip))
            terms_notice = False
            if not is_admin and label not in (_SETTINGS.get("terms_seen") or []):
                # First login of an admin-added friend (F26): show the
                # terms notice once — invite signups already saw it on
                # the invite page and are marked seen at signup — and
                # record the showing in the audit trail.
                with _SETTINGS_LOCK:
                    _seen = list(_SETTINGS.get("terms_seen") or [])
                    _seen.append(label)
                    _SETTINGS["terms_seen"] = _seen
                _save_settings()  # S2: save after the lock releases
                _audit("Users", f"Terms notice shown: {label}")
                terms_notice = True
            self.wfile.write(json.dumps({"ok": True, "admin": is_admin, "label": label,
                                         "role": "owner" if is_admin else _friend_role(label),
                                         "terms_notice": terms_notice}).encode())
            return
        if parsed.path == "/api/logout":
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            token = cookie.get("session").value if cookie.get("session") else None
            if token and token in SESSIONS:
                _old = SESSIONS[token]
                if isinstance(_old, dict):
                    _audit("System", f"Signed out: {_old.get('label', '?')}")
                _drop_chat_unlock(_old.get("chat_unlock") if isinstance(_old, dict) else None)
                del SESSIONS[token]
                # Sign-out-everywhere (the admin console passes
                # {"all": true}): also end every OTHER session for the
                # same account, so copies signed in on other browsers
                # or devices do not stay alive after a sign-out.
                try:
                    _cl = int(self.headers.get("Content-Length", 0))
                    _lbody = json.loads(self.rfile.read(_cl)) if _cl else {}
                except Exception:
                    _lbody = {}
                if isinstance(_lbody, dict) and _lbody.get("all") \
                        and isinstance(_old, dict) and _old.get("label"):
                    _extra = [t for t, s in list(SESSIONS.items())
                              if isinstance(s, dict)
                              and s.get("label") == _old["label"]]
                    for _t in _extra:
                        _drop_chat_unlock(SESSIONS[_t].get("chat_unlock"))
                        del SESSIONS[_t]
                    if _extra:
                        _audit("System",
                               f"Signed out everywhere: {_old['label']} "
                               f"({len(_extra)} more session(s) ended)")
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
            # Console roles (owner design v2): the admin is the owner;
            # friends the owner promoted sign in as moderator (manage
            # users + vaults, no settings/danger zone) or viewer
            # (read-only, like a view pass). Everyone else keeps the
            # historical behaviour: admin or nothing.
            _kind, _clabel = self._console_kind()
            if _kind is None:
                if not self._require_admin():
                    return
            if not self._ip_gate():
                return
            if _kind == "viewer":
                # Viewers may only READ here: the friend list / sessions
                # and the 2FA state line the admin page renders.
                if action not in ("list", "2fa_state"):
                    self._set_json_headers(403)
                    self.wfile.write(json.dumps({"error": "read-only access"}).encode())
                    return
            if _kind == "moderator" and action in (
                    "revoke", "change_master", "viewpass_create",
                    "viewpass_list", "viewpass_revoke", "2fa_status",
                    "2fa_enable", "2fa_confirm", "2fa_disable",
                    "settings_set", "audit_clear", "custom_provider_save",
                    "custom_provider_remove", "factory_reset",
                    "webhook_test", "settings_restore_preview",
                    "settings_restore_apply"):
                self._set_json_headers(403)
                self.wfile.write(json.dumps({"error": "owner only"}).encode())
                return
            _actor = f" (by moderator {_clabel})" if _kind == "moderator" else ""

            def _stored_label2(raw):
                want = (raw or "").strip().lower()
                for k in _load_access().keys():
                    if k.lower() == want:
                        return k
                return None

            def _dual_master(data):
                """Owner-or-moderator authorisation for user-management
                actions: the owner proves the master password (as
                always); a moderator's own signed-in session is their
                credential. Returns an error string or None."""
                if _kind == "moderator":
                    return None
                if _kind == "admin":
                    return None if self._master_ok(data) \
                        else "wrong master password"
                return "not allowed"
            if action == "list":
                access = _load_access()
                sessions = []
                # Session forensics (sid, ip, ua, ts) go only to the
                # tiers holding user-management authority (audit
                # run-5): a read-only view pass gets the roster
                # shape, not everyone's connection metadata.
                _meta_ok = _kind in ("admin", "moderator")
                for tok, sess in SESSIONS.items():
                    if isinstance(sess, dict):
                        _entry = {
                            "label": sess.get("label", "?"),
                            "admin": sess.get("admin", False),
                            "viewer": bool(sess.get("viewer")),
                        }
                        if _meta_ok:
                            _entry.update({
                                "sid": sess.get("sid"),
                                "ip": sess.get("ip", ""),
                                "ua": sess.get("ua", ""),
                                "ts": sess.get("ts", 0),
                            })
                        sessions.append(_entry)
                _my_tok = self._get_session()
                _my_sid = (SESSIONS.get(_my_tok) or {}).get("sid") \
                    if _my_tok else None
                _vm = _SETTINGS.get("vault_meta") or {}
                self._set_json_headers()
                self.wfile.write(json.dumps({
                    "access": [{"label": l,
                                "vault": _userkey_path(l).exists(),
                                "suspended": _friend_blocked(l) == "suspended",
                                "role": _friend_role(l),
                                "keys": len(_vm.get(l) or []),
                                "cap": (_SETTINGS.get("user_caps") or {}).get(l)} for l in sorted(access.keys())],
                    "sessions": sessions,
                    "maintenance": bool(_SETTINGS.get("maintenance")),
                    "instance_name": _SETTINGS.get("instance_name", "Nexus"),
                    "announcement": _SETTINGS.get("announcement", ""),
                    "you": {"kind": _kind, "label": _clabel, "sid": _my_sid},
                }).encode())
                return
            if action == "viewpass_create":
                master_pw = data.get("master_pw") or ""
                if _master_proof(master_pw) is None:
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
                _audit("Users", f"View pass created: {name} ({hours}h)")
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
                if _master_proof(master_pw) is None:
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
                _audit("Users", "View pass revoked")
                self._set_json_headers()
                self.wfile.write(json.dumps({"ok": True}).encode())
                return
            if action == "settings_get":
                if _kind == "moderator":
                    # Moderators see the console's status, never the
                    # owner's full settings (no webhook, allowlist, caps
                    # policy or danger-zone configuration).
                    _lite = {k: _SETTINGS.get(k) for k in (
                        "maintenance", "instance_name", "announcement",
                        "daily_cap", "global_cap", "quota_alert_pct",
                        "latency_alert_s", "vault_meta", "roles")}
                    self._set_json_headers()
                    self.wfile.write(json.dumps({
                        "ok": True, "lite": True, "settings": _lite,
                        "system": _system_metrics(),
                        "failovers_today": _audit_count_today("Failover handled", "Providers"),
                    }).encode())
                    return
                # Invite hashes are redacted in this copy (audit
                # run-6): a full unsalted SHA-256 of a ~30-bit invite
                # code is brute-forceable offline, and this read had
                # no master gate while every sibling mutation does.
                # The invites UI uses invite_list (prefixes) instead.
                _pub = dict(_SETTINGS)
                if isinstance(_pub.get("invites"), list):
                    _pub["invites"] = [
                        {**i, "h": ""} if isinstance(i, dict) else i
                        for i in _pub["invites"]]
                self._set_json_headers()
                self.wfile.write(json.dumps({
                    "ok": True,
                    "settings": _pub,
                    "system": _system_metrics(),
                    "failovers_today": _audit_count_today("Failover handled", "Providers"),
                }).encode())
                return
            if action == "invite_list":
                # Read-only listing (hash prefixes only). The console
                # calls this on page load WITHOUT the master password,
                # so it must not sit behind the master gate: a bare 401
                # here makes the page bounce the owner to /login.
                out = []
                for i in (_SETTINGS.get("invites") or []):
                    out.append({
                        "id": i["h"][:8], "role": i.get("role", "friend"),
                        "created": i.get("created", 0),
                        "expires": i.get("expires", 0),
                        "used_by": i.get("used_by"),
                        "expired": not i.get("used_by")
                        and i.get("expires", 0) <= time.time()})
                self._set_json_headers()
                self.wfile.write(json.dumps({"ok": True, "invites": out}).encode())
                return
            # ---- User management (owner with master proof, or a
            # moderator on their own session — see _dual_master) ----
            if action in ("friend_set_cap", "friend_set_suspended",
                          "friend_role_set", "provider_health_reset",
                          "friend_vault_clear", "friend_key_add",
                          "friend_reset_pw", "invite_create",
                          "invite_revoke",
                          "simulate_failure", "session_revoke",
                          "sessions_revoke_all", "friend_usage_reset"):
                _derr = _dual_master(data)
                if _derr:
                    self._set_json_headers(
                        401 if _derr == "wrong master password" else 403)
                    self.wfile.write(json.dumps({"error": _derr}).encode())
                    return
                master_pw = data.get("master_pw") or ""
                if action == "friend_set_cap":
                    stored = _stored_label2(data.get("label"))
                    if not stored:
                        self._set_json_headers(404)
                        self.wfile.write(json.dumps({"error": "friend not found"}).encode())
                        return
                    if _kind == "moderator" and (_SETTINGS.get("roles") or {}).get(stored) == "moderator":
                        # Audit run-8: the peer guards covered
                        # suspend/role/reset/clear but missed cap —
                        # a moderator could raise their OWN owner-set
                        # cap (5 → 100000 proven) or a peer's.
                        self._set_json_headers(403)
                        self.wfile.write(json.dumps({"error": "moderators cannot change another moderator's cap"}).encode())
                        return
                    # Audit run-8: copy -> assign -> save runs
                    # under _SETTINGS_LOCK (wave 8 locked only the
                    # save, so two writers could still lose each
                    # other's update), and a failed save answers 500
                    # instead of ok:true (run-7 #14, completed here).
                    with _SETTINGS_LOCK:
                        _prior_caps = dict(_SETTINGS.get("user_caps") or {})
                        caps = dict(_prior_caps)
                        if data.get("cap") is None:
                            caps.pop(stored, None)
                        else:
                            try:
                                _c = int(data.get("cap"))
                            except Exception:
                                _c = -1
                            if not 0 <= _c <= 100000:
                                self._set_json_headers(400)
                                self.wfile.write(json.dumps({"error": "cap must be 0-100000"}).encode())
                                return
                            caps[stored] = _c
                        _SETTINGS["user_caps"] = caps
                    _sv = _save_settings()  # S2: after the lock releases
                    # Wave 11 (F1/F2): verify the outcome, not the
                    # return value — 409 on supersession, rollback +
                    # an honest 500 when genuinely unpersisted.
                    _oc = _settings_outcome(
                        _sv,
                        lambda s: (s.get("user_caps") or {}).get(stored)
                        == caps.get(stored)
                        and (stored in (s.get("user_caps") or {}))
                        == (stored in caps),
                        lambda: _cas_rollback_dict_entry(
                            "user_caps", stored, _prior_caps, caps))
                    if _oc == "conflict":
                        self._set_json_headers(409)
                        self.wfile.write(json.dumps({"error": "superseded by a concurrent change — try again"}).encode())
                        return
                    if _oc != "ok":
                        self._set_json_headers(500)
                        self.wfile.write(json.dumps({"error": "cap could not be saved to disk"}).encode())
                        return
                    _audit("Users", f"Daily cap set: {stored} → {caps.get(stored, 'default')}{_actor}")
                    self._set_json_headers()
                    self.wfile.write(json.dumps({"ok": True}).encode())
                    return
                if action == "friend_set_suspended":
                    stored = _stored_label2(data.get("label"))
                    if not stored:
                        self._set_json_headers(404)
                        self.wfile.write(json.dumps({"error": "friend not found"}).encode())
                        return
                    if _kind == "moderator" and (_SETTINGS.get("roles") or {}).get(stored) == "moderator":
                        self._set_json_headers(403)
                        self.wfile.write(json.dumps({"error": "moderators cannot suspend other moderators"}).encode())
                        return
                    with _SETTINGS_LOCK:
                        _prior_susp = list(_SETTINGS.get("suspended") or [])
                        susp = [x for x in _prior_susp if x != stored]
                        if data.get("on"):
                            susp.append(stored)
                        _SETTINGS["suspended"] = susp
                    _sv = _save_settings()  # S2: after the lock releases
                    _oc = _settings_outcome(
                        _sv,
                        lambda s: (stored in (s.get("suspended") or []))
                        == bool(data.get("on")),
                        lambda: _cas_rollback_list_entry(
                            "suspended", stored, _prior_susp, susp))
                    if _oc == "conflict":
                        self._set_json_headers(409)
                        self.wfile.write(json.dumps({"error": "superseded by a concurrent change — try again"}).encode())
                        return
                    if _oc != "ok":
                        self._set_json_headers(500)
                        self.wfile.write(json.dumps({"error": "suspension could not be saved to disk"}).encode())
                        return
                    _audit("Users", f"{stored} {'suspended' if data.get('on') else 'restored'}{_actor}")
                    self._set_json_headers()
                    self.wfile.write(json.dumps({"ok": True}).encode())
                    return
                if action == "friend_role_set":
                    stored = _stored_label2(data.get("label"))
                    role = (data.get("role") or "").strip()
                    if not stored:
                        self._set_json_headers(404)
                        self.wfile.write(json.dumps({"error": "friend not found"}).encode())
                        return
                    if role not in ("friend", "moderator", "viewer"):
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": "role must be friend, moderator or viewer"}).encode())
                        return
                    if _kind == "moderator" and (role == "moderator"
                                                 or stored == _clabel
                                                 or (_SETTINGS.get("roles") or {}).get(stored) == "moderator"):
                        # No privilege escalation, no self-demotion
                        # games, no demoting a peer moderator.
                        self._set_json_headers(403)
                        self.wfile.write(json.dumps({"error": "moderators cannot grant or change moderator roles"}).encode())
                        return
                    with _SETTINGS_LOCK:
                        _prior_roles = dict(_SETTINGS.get("roles") or {})
                        roles = dict(_prior_roles)
                        if role == "friend":
                            roles.pop(stored, None)
                        else:
                            roles[stored] = role
                        _SETTINGS["roles"] = roles
                    _sv = _save_settings()  # S2: after the lock releases
                    _oc = _settings_outcome(
                        _sv,
                        lambda s: (s.get("roles") or {}).get(stored)
                        == (None if role == "friend" else role),
                        lambda: _cas_rollback_dict_entry(
                            "roles", stored, _prior_roles, roles))
                    if _oc == "conflict":
                        self._set_json_headers(409)
                        self.wfile.write(json.dumps({"error": "superseded by a concurrent change — try again"}).encode())
                        return
                    if _oc != "ok":
                        self._set_json_headers(500)
                        self.wfile.write(json.dumps({"error": "role could not be saved to disk"}).encode())
                        return
                    _audit("Users", f"Role set: {stored} → {role}{_actor}")
                    self._set_json_headers()
                    self.wfile.write(json.dumps({"ok": True}).encode())
                    return
                if action == "provider_health_reset":
                    _PROVIDER_HEALTH.clear()
                    _audit("Providers", f"Provider statuses reset (circuit breaker cleared){_actor}")
                    self._set_json_headers()
                    self.wfile.write(json.dumps({"ok": True}).encode())
                    return
                if action == "friend_vault_clear":
                    stored = _stored_label2(data.get("label"))
                    if not stored:
                        self._set_json_headers(404)
                        self.wfile.write(json.dumps({"error": "friend not found"}).encode())
                        return
                    if _kind == "moderator" and (_SETTINGS.get("roles") or {}).get(stored) == "moderator":
                        self._set_json_headers(403)
                        self.wfile.write(json.dumps({"error": "moderators cannot clear another moderator's vault"}).encode())
                        return
                    vp = _userkey_path(stored)
                    existed = vp.exists()
                    if existed:
                        vp.unlink()
                    _vm_dirty = False
                    with _SETTINGS_LOCK:
                        vm = dict(_SETTINGS.get("vault_meta") or {})
                        if stored in vm:
                            del vm[stored]
                            _SETTINGS["vault_meta"] = vm
                            _vm_dirty = True
                    # S2: save after the lock releases.
                    if _vm_dirty and not _save_settings():
                        _audit("System", f"vault_meta cleanup could not be saved for {stored}")
                    # Live sessions hold a decrypted copy of the
                    # vault that _effective_keys consumes (audit
                    # run-5): drop it too, or the cleared keys keep
                    # working until the friend happens to re-login.
                    for sess in SESSIONS.values():
                        if isinstance(sess, dict) and sess.get("label") == stored and not sess.get("admin"):
                            sess.pop("userkeys", None)
                    _audit("Vault", f"Personal vault cleared: {stored}{_actor}")
                    self._set_json_headers()
                    self.wfile.write(json.dumps({"ok": True, "existed": existed}).encode())
                    return
                if action == "friend_key_add":
                    stored = _stored_label2(data.get("label"))
                    provider = (data.get("provider") or "").strip()
                    key = (data.get("key") or "").strip()
                    friend_pw = data.get("friend_pw") or ""
                    if not stored:
                        self._set_json_headers(404)
                        self.wfile.write(json.dumps({"error": "friend not found"}).encode())
                        return
                    if _kind == "moderator" and stored != _clabel \
                            and (_SETTINGS.get("roles") or {}).get(stored) == "moderator":
                        # Audit run-9 (S7): the peer guard the wave-9
                        # sites (cap / usage reset / session revoke)
                        # already carry — a moderator cannot add a
                        # key to a PEER moderator's vault. The owner
                        # and the target themself are unaffected.
                        self._set_json_headers(403)
                        self.wfile.write(json.dumps({"error": "moderators cannot add keys for another moderator"}).encode())
                        return
                    if not _re.match(r"^[a-z0-9_]+$", provider) or provider.startswith("_"):
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": "invalid provider name"}).encode())
                        return
                    if not key or len(key) > 400:
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": "key required (max 400 chars)"}).encode())
                        return
                    if not _SETTINGS.get("friends_byok", True):
                        self._set_json_headers(403)
                        self.wfile.write(json.dumps({"error": "personal key vaults are disabled by the admin"}).encode())
                        return
                    # Audit run-9 (S6): the failure budget is keyed
                    # by CALLER + target, not by the victim alone —
                    # keyed on the victim, a moderator's wrong
                    # guesses burned the budget the victim's own
                    # saves (and the owner's adds) rely on. A guesser
                    # now throttles only their own attempts against
                    # that target; brute force still exhausts the
                    # guesser's own bucket.
                    _fk_bucket = (_clabel, stored)
                    if _pw_throttled("friend", _fk_bucket):
                        self._set_json_headers(429)
                        self.wfile.write(json.dumps({"error": "too many wrong passwords — try again in a few minutes"}).encode())
                        return
                    access = _load_access()
                    ok_pw, needs_up = _verify_password(friend_pw, access.get(stored, ""))
                    if not ok_pw:
                        _pw_failed("friend", _fk_bucket)
                        self._set_json_headers(401)
                        self.wfile.write(json.dumps({"error": "wrong password for that friend"}).encode())
                        return
                    _PW_FAILS.pop(("friend", _fk_bucket), None)
                    if needs_up:
                        with _ACCESS_LOCK:
                            _fresh = _load_access()
                            if _fresh.get(stored) == access.get(stored):
                                _fresh[stored] = _hash_password(friend_pw)
                                _save_access(_fresh, master_pw)
                    with _USERKEYS_LOCK:
                        try:
                            vault = _load_userkeys_strict(stored, friend_pw)
                        except Exception:
                            self._set_json_headers(500)
                            self.wfile.write(json.dumps({"error": "stored keys could not be decrypted — nothing was changed"}).encode())
                            return
                        if provider not in vault and len(
                                [k for k in vault
                                 if not k.startswith("_")]) >= _USERKEY_COUNT_CAP:
                            # Audit run-7: this console path never
                            # checked the entry cap the My Keys path
                            # enforces.
                            self._set_json_headers(400)
                            self.wfile.write(json.dumps({"error": "too many keys in one vault"}).encode())
                            return
                        vault[provider] = key
                        _save_userkeys(stored, vault, friend_pw)
                    # Refresh live sessions' cached vault copies
                    # (audit run-5): without this, a key the admin
                    # adds for a signed-in friend stays invisible -
                    # and a cleared one keeps working - until the
                    # friend's next login.
                    for sess in SESSIONS.values():
                        if isinstance(sess, dict) and sess.get("label") == stored and not sess.get("admin"):
                            sess["userkeys"] = dict(vault)
                    _audit("Vault", f"Key added for {stored}: {provider}{_actor}")
                    self._set_json_headers()
                    self.wfile.write(json.dumps({"ok": True}).encode())
                    return
                if action == "friend_reset_pw":
                    stored = _stored_label2(data.get("label"))
                    new_pw = data.get("new_password") or ""
                    if not stored:
                        self._set_json_headers(404)
                        self.wfile.write(json.dumps({"error": "friend not found"}).encode())
                        return
                    if _kind == "moderator" and (_SETTINGS.get("roles") or {}).get(stored) == "moderator":
                        # Audit run-7: the run-6 peer guards covered
                        # suspend/demote/session-revoke but missed this
                        # one — a peer password reset is a takeover.
                        self._set_json_headers(403)
                        self.wfile.write(json.dumps({"error": "moderators cannot reset another moderator's password"}).encode())
                        return
                    if len(new_pw) < 6:
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": "new password must be at least 6 characters"}).encode())
                        return
                    if _kind == "moderator" and not _rl_ok("pwprobe", _clabel, 10, 900):
                        # Audit run-7: the taken-check below is a
                        # password-collision oracle (a hit hands over a
                        # working friend credential). The unproven
                        # caller is the moderator — admins prove the
                        # master password for these actions already.
                        # Run-8: the bucket is keyed on the moderator's
                        # account label ALONE — keying it per source IP
                        # as well handed a fresh 10 probes to every
                        # rotated source address.
                        self._set_json_headers(429)
                        self.wfile.write(json.dumps({"error": "too many attempts, try again later"}).encode())
                        return
                    access = _load_access()
                    if _password_taken(access, new_pw, skip_label=stored) \
                            or _is_master_password(new_pw, quiet=True):
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": "that password is already in use by another friend — pick a different one"}).encode())
                        return
                    _new_hash = _hash_password(new_pw)
                    with _ACCESS_LOCK:
                        # Reload + verify only what changed since the
                        # snapshot scan: a concurrent writer must not be
                        # overwritten by this stale dict (and a password
                        # that became taken meanwhile still refuses).
                        _fresh = _load_access()
                        if stored not in _fresh:
                            # Revoked while the pre-lock scan ran:
                            # writing the new hash into _fresh would
                            # resurrect the removed account.
                            self._set_json_headers(404)
                            self.wfile.write(json.dumps({"error": "friend not found"}).encode())
                            return
                        for _l, _h in _fresh.items():
                            if access.get(_l) != _h and _l != stored \
                                    and _verify_password(new_pw, _h)[0]:
                                self._set_json_headers(400)
                                self.wfile.write(json.dumps({"error": "that password is already in use by another friend — pick a different one"}).encode())
                                return
                        _fresh[stored] = _new_hash
                        _save_access(_fresh, master_pw)
                        access = _fresh
                    # Their vault and saved chats are encrypted under
                    # the old password — remove them, like revoke does.
                    # The integrations vault goes too: it is encrypted
                    # under the same old password, and leaving it would
                    # silently revive their OAuth tokens/API keys if
                    # the label is ever re-created with the same password.
                    # Incarnation guard (audit run-4): the cleanup runs
                    # under the lock and only fires while the account
                    # is still the incarnation this reset wrote - a
                    # revoke + re-create landing here must keep ITS
                    # files and sessions.
                    _note = " (vault + saved chats removed)"
                    with _ACCESS_LOCK:
                        if _load_access().get(stored) == _new_hash:
                            for _p in (_userkey_path(stored), _chat_path(stored), _intg_path(stored)):
                                try:
                                    if _p.exists():
                                        _p.unlink()
                                except Exception:
                                    pass
                            _vm_dirty2 = False
                            with _SETTINGS_LOCK:
                                vm = dict(_SETTINGS.get("vault_meta") or {})
                                if stored in vm:
                                    del vm[stored]
                                    _SETTINGS["vault_meta"] = vm
                                    _vm_dirty2 = True
                            # S2: save after the lock releases.
                            if _vm_dirty2 and not _save_settings():
                                _audit("System", f"vault_meta cleanup could not be saved for {stored}")
                            for tok in [t for t, s in SESSIONS.items()
                                        if isinstance(s, dict) and s.get("label") == stored]:
                                del SESSIONS[tok]
                        else:
                            _note = " (account changed during reset - files kept)"
                    _audit("Users", f"Password reset: {stored}{_note}{_actor}")
                    self._set_json_headers()
                    self.wfile.write(json.dumps({"ok": True}).encode())
                    return
                if action == "invite_create":
                    role = (data.get("role") or "friend").strip()
                    days = data.get("days")
                    if role not in ("friend", "moderator", "viewer"):
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": "role must be friend, moderator or viewer"}).encode())
                        return
                    if _kind == "moderator" and role == "moderator":
                        self._set_json_headers(403)
                        self.wfile.write(json.dumps({"error": "moderators cannot invite moderators"}).encode())
                        return
                    if days not in (1, 7, 30):
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": "expiry must be 1, 7 or 30 days"}).encode())
                        return
                    with _SETTINGS_LOCK:
                        _prior_invites = list(_SETTINGS.get("invites") or [])
                        invites = [i for i in _prior_invites
                                   if not i.get("used_by")
                                   and i.get("expires", 0) > time.time()]
                        if len(invites) >= 10:
                            self._set_json_headers(400)
                            self.wfile.write(json.dumps({"error": "too many active invites (max 10) — revoke one first"}).encode())
                            return
                        _alpha = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
                        code = "".join(secrets.choice(_alpha) for _ in range(6))
                        h = hashlib.sha256(code.encode()).hexdigest()
                        invites.append({"h": h, "role": role,
                                        "created": time.time(),
                                        "expires": time.time() + days * 86400,
                                        "used_by": None})
                        _SETTINGS["invites"] = invites
                    _sv = _save_settings()  # S2: after the lock releases
                    # Wave 11 (F1/F2): hand the code out only when THIS
                    # invite is the persisted state. A True return via
                    # the generation guard can still mean a concurrent
                    # revoke already landed without it (409, no handout);
                    # a False return whose invite a concurrent save
                    # already persisted is an honest success; a genuinely
                    # unpersisted False rolls the invite back so the
                    # 500's "no code was created" is actually true.
                    _oc = _settings_outcome(
                        _sv,
                        lambda s: any(i.get("h") == h
                                      for i in (s.get("invites") or [])),
                        lambda: _cas_rollback_invite_add(h))
                    if _oc == "conflict":
                        self._set_json_headers(409)
                        self.wfile.write(json.dumps({"error": "invite superseded by a concurrent change — no code was created, try again"}).encode())
                        return
                    if _oc != "ok":
                        # Audit run-8 (#14): never hand out a code
                        # whose save did not land — it would be dead
                        # at restart while the admin believes it works.
                        self._set_json_headers(500)
                        self.wfile.write(json.dumps({"error": "invite could not be saved — no code was created"}).encode())
                        return
                    _audit("Users", f"Invite created: {code[:2]}••• ({role}, {days}d){_actor}")
                    self._set_json_headers()
                    self.wfile.write(json.dumps({
                        "ok": True, "code": code,
                        "expires": time.time() + days * 86400}).encode())
                    return
                if action == "invite_revoke":
                    gid = (data.get("id") or "").strip()
                    # Audit run-8: this RMW ran unlocked — a revoke
                    # racing a create overwrote the create's list and
                    # the freshly issued code was dead on disk while
                    # both callers held 200/ok:true.
                    with _SETTINGS_LOCK:
                        invites = _SETTINGS.get("invites") or []
                        _prior_invites_r = list(invites)
                        keep = [i for i in invites
                                if not (len(gid) >= 6 and i["h"].startswith(gid))]
                        _removed_r = [i for i in invites
                                      if len(gid) >= 6
                                      and i["h"].startswith(gid)]
                        if len(keep) == len(invites):
                            self._set_json_headers(404)
                            self.wfile.write(json.dumps({"error": "invite not found"}).encode())
                            return
                        _SETTINGS["invites"] = keep
                    _sv = _save_settings()  # S2: after the lock releases
                    _oc = _settings_outcome(
                        _sv,
                        lambda s: not any(
                            len(gid) >= 6 and i["h"].startswith(gid)
                            for i in (s.get("invites") or [])),
                        lambda: _cas_rollback_invite_remove(
                            _removed_r))
                    if _oc == "conflict":
                        self._set_json_headers(409)
                        self.wfile.write(json.dumps({"error": "superseded by a concurrent change — try again"}).encode())
                        return
                    if _oc != "ok":
                        self._set_json_headers(500)
                        self.wfile.write(json.dumps({"error": "revocation could not be saved to disk"}).encode())
                        return
                    _audit("Users", f"Invite revoked{_actor}")
                    self._set_json_headers()
                    self.wfile.write(json.dumps({"ok": True}).encode())
                    return
                if action == "simulate_failure":
                    want = (data.get("provider") or "").strip()
                    dis = _disabled_providers()
                    cand = [p for p in _ordered_provider_names()
                            if p not in dis and not _provider_down(p)]
                    target = want if want in cand else (cand[0] if cand else None)
                    if not target:
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": "no healthy provider to simulate against"}).encode())
                        return
                    _PROVIDER_HEALTH[target] = {
                        "fails": 99, "down_until": time.time() + 60,
                        "sim": True}
                    _audit("Providers", f"Simulated failure: {target} marked down for 60s{_actor}")
                    self._set_json_headers()
                    self.wfile.write(json.dumps({"ok": True, "provider": target}).encode())
                    return
                if action == "session_revoke":
                    sid = (data.get("sid") or "").strip()
                    my_tok = self._get_session()
                    hit = None
                    for tok, s in SESSIONS.items():
                        if isinstance(s, dict) and s.get("sid") == sid:
                            hit = tok
                            break
                    if not hit:
                        self._set_json_headers(404)
                        self.wfile.write(json.dumps({"error": "session not found"}).encode())
                        return
                    if hit == my_tok:
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": "use sign out for your own session"}).encode())
                        return
                    if _kind == "moderator" and (_SETTINGS.get("roles") or {}).get(SESSIONS[hit].get("label")) == "moderator":
                        # Audit run-8: admin sessions were guarded,
                        # peer moderators were not — one moderator
                        # could sign another out at will.
                        self._set_json_headers(403)
                        self.wfile.write(json.dumps({"error": "moderators cannot revoke another moderator's session"}).encode())
                        return
                    if SESSIONS[hit].get("admin") and _kind != "admin":
                        # Audit run-6: sessions_revoke_all already
                        # spares the owner; the single revoke forgot
                        # the same guard, so a moderator could log
                        # the owner out at will.
                        self._set_json_headers(403)
                        self.wfile.write(json.dumps({"error": "only the owner can revoke an admin session"}).encode())
                        return
                    _lbl = SESSIONS[hit].get("label", "?")
                    _drop_chat_unlock(SESSIONS[hit].get("chat_unlock"))
                    del SESSIONS[hit]
                    _audit("Users", f"Session revoked: {_lbl}{_actor}")
                    self._set_json_headers()
                    self.wfile.write(json.dumps({"ok": True}).encode())
                    return
                if action == "sessions_revoke_all":
                    my_tok = self._get_session()
                    _roles8 = (_SETTINGS.get("roles") or {}) if _kind == "moderator" else {}
                    n = 0
                    for tok in [t for t, s in SESSIONS.items()
                                if isinstance(s, dict)
                                and not s.get("admin") and t != my_tok
                                and _roles8.get(s.get("label")) != "moderator"]:
                        _drop_chat_unlock(SESSIONS[tok].get("chat_unlock"))
                        del SESSIONS[tok]
                        n += 1
                    _audit("Users", f"All other sessions signed out ({n}){_actor}")
                    self._set_json_headers()
                    self.wfile.write(json.dumps({"ok": True, "revoked": n}).encode())
                    return
                if action == "friend_usage_reset":
                    stored = _stored_label2(data.get("label"))
                    if not stored:
                        self._set_json_headers(404)
                        self.wfile.write(json.dumps({"error": "friend not found"}).encode())
                        return
                    if _kind == "moderator" and (_SETTINGS.get("roles") or {}).get(stored) == "moderator":
                        # Audit run-8: same missed peer guard as
                        # friend_set_cap — a moderator could erase
                        # their own (or a peer's) usage rows and
                        # refund the daily cap.
                        self._set_json_headers(403)
                        self.wfile.write(json.dumps({"error": "moderators cannot reset another moderator's usage"}).encode())
                        return
                    today = datetime.date.today().isoformat()
                    n = 0
                    try:
                        # Read + filter + rewrite ALL under the lock
                        # (audit run-7): the snapshot used to be read
                        # outside it, so the rewrite silently erased
                        # rows appended while the scan was running.
                        with _USAGE_LOCK:
                            if os.path.exists(USAGE_PATH):
                                with open(USAGE_PATH) as f:
                                    lines2 = f.readlines()
                                keep = []
                                for line in lines2:
                                    try:
                                        e = json.loads(line)
                                    except Exception:
                                        keep.append(line)
                                        continue
                                    if isinstance(e, dict) \
                                            and e.get("user") == stored \
                                            and str(e.get("ts", ""))[:10] == today:
                                        n += 1
                                        continue
                                    keep.append(line)
                                _rewrite_lines(USAGE_PATH, keep)
                                # Wave 16 (run-15 caps): resync the
                                # provider counter from the surviving
                                # lines (the trim/purge shape) — the
                                # reset refunded the scan-based caps
                                # but provider_limits kept counting
                                # the removed rows for every user of
                                # the lane until rollover.
                                _provider_counts_resync(keep)
                    except Exception:
                        pass
                    _TODAY_CACHE["ts"] = 0.0
                    _audit("Users", f"Usage reset for {stored} ({n} rows today){_actor}")
                    self._set_json_headers()
                    self.wfile.write(json.dumps({"ok": True, "removed": n}).encode())
                    return
            if action in ("settings_set", "audit_clear",
                          "custom_provider_save", "custom_provider_remove",
                          "factory_reset", "webhook_test",
                          "settings_restore_preview",
                          "settings_restore_apply"):
                # All console mutations are master-password gated, the
                # same proof the other sensitive actions use.
                master_pw = data.get("master_pw") or ""
                if _master_proof(master_pw) is None:
                    self._set_json_headers(401)
                    self.wfile.write(json.dumps({"error": "wrong master password"}).encode())
                    return

                def _stored_label(raw):
                    want = (raw or "").strip().lower()
                    for k in _load_access().keys():
                        if k.lower() == want:
                            return k
                    return None

                if action == "settings_set":
                    patch = data.get("patch") or {}
                    if not isinstance(patch, dict) or not patch:
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": "empty settings patch"}).encode())
                        return
                    clean, err = _validate_settings_patch(patch)
                    if err:
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": err}).encode())
                        return
                    with _SETTINGS_LOCK:
                        _prior_set = {k: _SETTINGS.get(k) for k in clean}
                        _SETTINGS.update(clean)
                    _saved = _save_settings()  # S2: after the lock releases
                    _oc = _settings_outcome(
                        _saved,
                        lambda s: all(s.get(k) == v
                                      for k, v in clean.items()),
                        lambda: _cas_rollback_keys(_prior_set,
                                                   clean))
                    if _oc == "conflict":
                        self._set_json_headers(409)
                        self.wfile.write(json.dumps({"error": "superseded by a concurrent change — try again"}).encode())
                        return
                    if _oc != "ok":
                        self._set_json_headers(500)
                        self.wfile.write(json.dumps({"error": "settings could not be saved to disk"}).encode())
                        return
                    _audit("System", "Settings changed: " + ", ".join(sorted(clean.keys())))
                    if "maintenance" in clean:
                        _fire_webhook("maintenance",
                                      {"on": bool(clean["maintenance"])})
                    self._set_json_headers()
                    self.wfile.write(json.dumps({"ok": True, "settings": _SETTINGS}).encode())
                    return
                if action == "settings_restore_preview":
                    backup = data.get("backup")
                    if not isinstance(backup, dict) \
                            or not isinstance(backup.get("settings"), dict):
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": "not a Nexus backup file (no settings inside)"}).encode())
                        return
                    if len(json.dumps(backup)) > 65536:
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": "backup file too large"}).encode())
                        return
                    src = backup["settings"]
                    # Non-restorable keys are SKIPPED with a note,
                    # not fatal (audit run-6): a genuine backup
                    # contains the full settings object, so refusing
                    # the whole file made real backups unrestorable.
                    skipped = sorted(k for k in src
                                     if k not in _RESTORE_ALLOWED)
                    clean, err = _validate_settings_patch(
                        {k: src[k] for k in src if k in _RESTORE_ALLOWED})
                    if err:
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": err}).encode())
                        return
                    if not clean and skipped:
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": "backup contains only settings that are never restorable: " + ", ".join(skipped)}).encode())
                        return
                    diff = []
                    for k in sorted(clean):
                        if json.dumps(_SETTINGS.get(k), sort_keys=True) \
                                != json.dumps(clean[k], sort_keys=True):
                            diff.append({"key": k,
                                         "from": _SETTINGS.get(k),
                                         "to": clean[k]})
                    nonce = secrets.token_hex(12)
                    _RESTORE_NONCES[nonce] = (time.time() + 300, clean)
                    self._set_json_headers()
                    self.wfile.write(json.dumps({"ok": True, "nonce": nonce, "diff": diff, "skipped": skipped}).encode())
                    return
                if action == "settings_restore_apply":
                    ent = _RESTORE_NONCES.pop(data.get("nonce") or "", None)
                    if not ent or ent[0] < time.time():
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": "restore preview expired — preview again"}).encode())
                        return
                    clean = ent[1]
                    with _SETTINGS_LOCK:
                        _prior_rst = {k: _SETTINGS.get(k) for k in clean}
                        _prior_snap = _SETTINGS.get("backup_snapshot")
                        _SETTINGS["backup_snapshot"] = {
                            "ts": datetime.datetime.now().isoformat(),
                            "config": {k: _SETTINGS.get(k)
                                       for k in sorted(_RESTORE_ALLOWED)}}
                        _SETTINGS.update(clean)
                        _new_snap = _SETTINGS["backup_snapshot"]
                    _sv = _save_settings()  # S2: after the lock releases
                    def _rst_rollback():
                        _cas_rollback_keys(_prior_rst, clean,
                                           _prior_snap, _new_snap)
                    _oc = _settings_outcome(
                        _sv,
                        lambda s: all(s.get(k) == v
                                      for k, v in clean.items()),
                        _rst_rollback)
                    if _oc == "conflict":
                        self._set_json_headers(409)
                        self.wfile.write(json.dumps({"error": "superseded by a concurrent change — try again"}).encode())
                        return
                    if _oc != "ok":
                        self._set_json_headers(500)
                        self.wfile.write(json.dumps({"error": "restored settings could not be saved to disk"}).encode())
                        return
                    _audit("System", "Settings restored from backup: "
                           + ", ".join(sorted(clean.keys())))
                    _fire_webhook("settings_restored",
                                  {"keys": sorted(clean.keys())})
                    self._set_json_headers()
                    self.wfile.write(json.dumps({"ok": True, "settings": _SETTINGS, "applied": sorted(clean.keys())}).encode())
                    return
                if action == "webhook_test":
                    url = (_SETTINGS.get("webhook_url") or "").strip()
                    if not url:
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": "no webhook URL configured"}).encode())
                        return
                    if not _fire_webhook("test", {"note": "Nexus webhook test"}):
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": "webhook URL is not a public http(s) address"}).encode())
                        return
                    _audit("System", "Webhook test sent")
                    self._set_json_headers()
                    self.wfile.write(json.dumps({"ok": True}).encode())
                    return
                if action == "audit_clear":
                    try:
                        with _AUDIT_LOCK:
                            AUDIT_PATH.write_text("")
                    except Exception:
                        self._set_json_headers(500)
                        self.wfile.write(json.dumps({"error": "could not clear the audit log"}).encode())
                        return
                    _audit("System", "Audit log cleared")
                    self._set_json_headers()
                    self.wfile.write(json.dumps({"ok": True}).encode())
                    return
                if action in ("custom_provider_save", "custom_provider_remove"):
                    cname = (data.get("name") or "").strip().lower()
                    if not _re.match(r"^[a-z0-9_]+$", cname):
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": "provider name must be a-z, 0-9, _"}).encode())
                        return
                    with _KEYS_LOCK:
                        key_path = Path(__file__).parent / "keys.enc"
                        try:
                            keys = decrypt_keys(key_path, master_pw)
                        except Exception:
                            self._set_json_headers(401)
                            self.wfile.write(json.dumps({"error": "wrong master password"}).encode())
                            return
                        if action == "custom_provider_save":
                            curl_ = (data.get("url") or "").strip()
                            ckey = (data.get("key") or "").strip()
                            if not (curl_.startswith("http://") or curl_.startswith("https://")) or not ckey:
                                self._set_json_headers(400)
                                self.wfile.write(json.dumps({"error": "base URL (http/https) and API key required"}).encode())
                                return
                            if not _public_base_url_ok(curl_):
                                self._set_json_headers(400)
                                self.wfile.write(json.dumps({"error": "base URL must be a public http(s) address"}).encode())
                                return
                            keys[f"custom_relay_{cname}"] = ckey
                            keys[f"custom_relay_{cname}_url"] = curl_
                            _audit("Providers", f"Custom provider saved: {cname}")
                        else:
                            keys.pop(f"custom_relay_{cname}", None)
                            keys.pop(f"custom_relay_{cname}_url", None)
                            _audit("Providers", f"Custom provider removed: {cname}")
                        encrypt_keys(keys, master_pw, key_path)
                        os.chmod(key_path, 0o600)
                        Handler.keys = keys
                        register_custom_providers(keys)
                    self._set_json_headers()
                    self.wfile.write(json.dumps({"ok": True}).encode())
                    return
                if action == "factory_reset":
                    if (data.get("confirm") or "") != "RESET":
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": "type RESET to confirm"}).encode())
                        return
                    # The whole destructive sequence runs under
                    # _ACCESS_LOCK (audit run-4): a redeem or add whose
                    # save lands mid-sequence must not survive the reset.
                    with _ACCESS_LOCK:
                        _save_access({}, master_pw)
                        if USERKEYS_DIR.exists():
                            for f in USERKEYS_DIR.glob("*.enc"):
                                try:
                                    f.unlink()
                                except Exception:
                                    pass
                        if CHATS_DIR.exists():
                            for f in CHATS_DIR.glob("*.enc"):
                                try:
                                    f.unlink()
                                except Exception:
                                    pass
                        # Friend integrations vaults too (OAuth tokens +
                        # workspace API keys) — the owner's own stays.
                        if INTG_DIR.exists():
                            for f in INTG_DIR.glob("*.enc"):
                                if f.name == "_owner.enc":
                                    continue
                                try:
                                    f.unlink()
                                except Exception:
                                    pass
                        # The /v1 API keys are passes too (audit
                        # run-5): the reset revokes them like every
                        # other credential - file and live set go.
                        # (An env-bootstrapped key in /etc/nexus.env
                        # is operator config, outside the app's
                        # reach; the stored keys die here.)
                        try:
                            if V1KEY_PATH.exists():
                                V1KEY_PATH.unlink()
                        except Exception:
                            pass
                        with _V1KEYS_LOCK:
                            _V1KEYS["keys"] = []
                        _VIEW_GRANTS.clear()
                        # Pending 2FA completions die with the reset
                        # too (audit run-5): a token minted before it
                        # must not mint an admin session after it.
                        _PENDING_2FA.clear()
                        _2FA_ATTEMPTS.clear()
                        for tok in [t for t, s in SESSIONS.items()
                                    if isinstance(s, dict) and not s.get("admin")]:
                            del SESSIONS[tok]
                        with _SETTINGS_LOCK:
                            _SETTINGS.clear()
                            _SETTINGS.update(json.loads(json.dumps(_SETTINGS_DEFAULTS)))
                        # Wave 12 (D4): outcome-check the reset save.
                        # There is NO rollback arm here — the settings
                        # are wiped in memory and the vaults/chats are
                        # really deleted — so a failed save earns the
                        # honest 500 below instead of an ok:true while
                        # the pre-reset settings resurrect at restart.
                        _reset_oc = _settings_outcome(
                            _save_settings(),
                            # Wave 13 (run-12 data): the pred verifies
                            # the FULL intended reset state — the old
                            # 5-collection check answered ok while
                            # maintenance/daily_cap/instance_name/
                            # provider_disabled resurrected at restart
                            # whenever those collections were already
                            # empty. Judged over the persisted document
                            # merged over the defaults (exactly what
                            # the boot merge would load).
                            lambda s: all(
                                {**_SETTINGS_DEFAULTS,
                                 **{kk: s[kk] for kk in s
                                    if kk in _SETTINGS_DEFAULTS}}.get(k)
                                == v
                                for k, v in _SETTINGS_DEFAULTS.items()))
                        _PROVIDER_HEALTH.clear()
                    try:
                        # Audit run-8: truncates take _AUDIT_LOCK —
                        # an unlocked clear racing an in-flight
                        # _audit trim-replace resurrected the cleared
                        # rows (proven 5/5 pre-fix).
                        with _AUDIT_LOCK:
                            AUDIT_PATH.write_text("")
                    except Exception:
                        pass
                    # Usage history too — and the telemetry mirror:
                    # if telemetry.enc survived, boot restore would
                    # resurrect the wiped usage rows from it verbatim.
                    # Audit run-9 (S3): the truncate takes _USAGE_LOCK
                    # like every other usage writer — unlocked, an
                    # in-flight trim-rewrite (which holds the lock)
                    # could land after it and resurrect pre-reset rows.
                    try:
                        with _USAGE_LOCK:
                            USAGE_PATH.write_text("")
                            # Wave 16 (run-15 caps): the counter
                            # dies with the log it mirrors — a
                            # provider limit recreated later the
                            # same day must not inherit the erased
                            # counts.
                            _provider_counts_resync([])
                    except Exception:
                        pass
                    try:
                        with _TELEMETRY_LOCK:
                            if TELEMETRY_ENC_PATH.exists():
                                TELEMETRY_ENC_PATH.unlink()
                            _TELEMETRY["dirty"] = False
                            _TELEMETRY["saved"] = ""
                    except Exception:
                        pass
                    _audit("System", "Factory reset: friends, passes, settings and sessions cleared")
                    if _reset_oc != "ok":
                        self._set_json_headers(500)
                        self.wfile.write(json.dumps({"error": "reset applied, but the cleared settings could not be saved — they will revert at restart"}).encode())
                        return
                    self._set_json_headers()
                    self.wfile.write(json.dumps({"ok": True}).encode())
                    return
            if action == "add":
                label = (data.get("label") or "").strip().lower()
                password = data.get("password") or ""
                master_pw = data.get("master_pw") or ""
                # A moderator adds users on their own session (the
                # account still persists via the access.enc mirror; the
                # legacy users.enc refresh happens at the owner's next
                # master-password save). Their password rule is the
                # console's pw_min policy; the owner's stays min 6.
                _mod_add = _kind == "moderator"
                _min_pw = int(_SETTINGS.get("pw_min") or 8) if _mod_add else 6
                if not label or not password or len(password) < _min_pw:
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": f"label and password (min {_min_pw} chars) required"}).encode())
                    return
                if not _LABEL_RE.match(label):
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "label must be a-z, 0-9, _ (max 30 chars)"}).encode())
                    return
                if not _mod_add and not master_pw:
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "master password required to persist"}).encode())
                    return
                access = _load_access()
                if label in access or label.lower() == "rudra" \
                        or label.startswith("_"):
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "label already exists or is reserved"}).encode())
                    return
                if not _mod_add:
                    # Verify master password by decrypting keys.enc
                    if _master_proof(master_pw) is None:
                        self._set_json_headers(401)
                        self.wfile.write(json.dumps({"error": "wrong master password"}).encode())
                        return
                if _mod_add and not _rl_ok("pwprobe", _clabel, 10, 900):
                    self._set_json_headers(429)
                    self.wfile.write(json.dumps({"error": "too many attempts, try again later"}).encode())
                    return
                if _password_taken(access, password) \
                        or _is_master_password(password, quiet=True):
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "that password is already in use by another friend — pick a different one"}).encode())
                    return
                _new_hash = _hash_password(password)
                # Wave 15 (run-14 settings): the shared clean-slate
                # clear runs BEFORE the account exists (the label
                # provably has no account — the duplicate checks
                # above and the in-lock re-check below bracket it —
                # so every entry for it is stranded). Wave 14 ran
                # it after _save_access with no rollback: a faulted
                # clear left a LIVE account whose persisted settings
                # resurrected it as suspended/moderator at restart.
                # Wave 16 (run-15 settings D15-3): the clear runs
                # BEFORE _ACCESS_LOCK, so its save + outcome settle
                # no longer stalls every concurrent creation behind
                # a slow store; inside the lock the label-absence
                # invariant is re-verified against PERSISTED state
                # before _save_access. On a non-ok outcome the add
                # aborts and NO account is created; the explicit
                # role/cap application below then lands fresh.
                _clr15 = _clear_stranded_label(label)
                if _clr15 != "ok":
                    self._set_json_headers(
                        409 if _clr15 == "conflict" else 500)
                    self.wfile.write(json.dumps(
                        {"error": "friend not added — leftover settings for this name could not be cleared; try again"}).encode())
                    return
                with _ACCESS_LOCK:
                    # Reload inside the lock (see friend_reset_pw): a
                    # stale snapshot must never erase a concurrent
                    # signup, and the label/taken checks re-verify
                    # against whatever changed in the window.
                    _fresh = _load_access()
                    if label in _fresh:
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": "label already exists"}).encode())
                        return
                    for _l, _h in _fresh.items():
                        if access.get(_l) != _h \
                                and _verify_password(password, _h)[0]:
                            self._set_json_headers(400)
                            self.wfile.write(json.dumps({"error": "that password is already in use by another friend — pick a different one"}).encode())
                            return
                    # Wave 16: re-verify the clear's invariant
                    # against PERSISTED state (never live memory —
                    # that would reopen the AUTH14-2 class) before
                    # the account is saved.
                    # Wave 17 (run-16 settings D16-2): the
                    # re-decrypt is generation-guarded exactly as
                    # on the redeem path — re-paid only when the
                    # settings generation triple moved since the
                    # clear judged, or a save is in flight.
                    _judged17 = getattr(_CLEAR_JUDGED17, "triple",
                                        None)
                    if _judged17 is None or _SETTINGS_ACTIVE[0] > 0 \
                            or (_SETTINGS_GEN[0],
                                _SETTINGS_WRITTEN_GEN[0],
                                _SETTINGS_ACTIVE[0]) != _judged17:
                        _ps16 = _persisted_settings()
                        if _ps16 is not None and not \
                                _label_settings_absent(_ps16, label):
                            self._set_json_headers(500)
                            self.wfile.write(json.dumps(
                                {"error": "friend not added — leftover settings for this name could not be cleared; try again"}).encode())
                            return
                    _fresh[label] = _new_hash
                    _save_access(_fresh, None if _mod_add else master_pw)
                    access = _fresh
                # Optional role + cap straight from the add-user dialog.
                _nrole = (data.get("role") or "friend").strip()
                if _nrole in ("moderator", "viewer") \
                        and not (_mod_add and _nrole == "moderator"):
                    with _SETTINGS_LOCK:
                        _prior_roles_a = dict(
                            _SETTINGS.get("roles") or {})
                        roles = dict(_prior_roles_a)
                        roles[label] = _nrole
                        _SETTINGS["roles"] = roles
                    # Wave 12 (D4): outcome-check the role save (a
                    # per-entry pred + compare-and-restore rollback
                    # is sufficient here) — a faulted save used to
                    # log-and-continue behind an ok:true whose role
                    # silently vanished at restart while the account
                    # itself (already persisted) stayed.
                    _oc = _settings_outcome(
                        _save_settings(),
                        lambda s: (s.get("roles") or {}).get(label)
                        == _nrole,
                        lambda: _cas_rollback_dict_entry(
                            "roles", label, _prior_roles_a, roles))
                    if _oc != "ok":
                        self._set_json_headers(
                            409 if _oc == "conflict" else 500)
                        self.wfile.write(json.dumps(
                            {"error": "friend added, but the role could not be saved — set it again from the console"}).encode())
                        return
                if isinstance(data.get("cap"), (int, float)) \
                        and 0 <= int(data["cap"]) <= 100000:
                    with _SETTINGS_LOCK:
                        _prior_caps_a = dict(
                            _SETTINGS.get("user_caps") or {})
                        caps = dict(_prior_caps_a)
                        caps[label] = int(data["cap"])
                        _SETTINGS["user_caps"] = caps
                    # Wave 12 (D4): outcome-check the cap save, same
                    # shape as the role save above.
                    _oc = _settings_outcome(
                        _save_settings(),
                        lambda s: (s.get("user_caps") or {}).get(label)
                        == int(data["cap"]),
                        lambda: _cas_rollback_dict_entry(
                            "user_caps", label, _prior_caps_a, caps))
                    if _oc != "ok":
                        self._set_json_headers(
                            409 if _oc == "conflict" else 500)
                        self.wfile.write(json.dumps(
                            {"error": "friend added, but the daily cap could not be saved — set it again from the console"}).encode())
                        return
                _audit("Users", f"Friend added: {label}{_actor}")
                self._set_json_headers()
                self.wfile.write(json.dumps({"ok": True}).encode())
                return
            if action == "revoke":
                label = (data.get("label") or "").strip()
                master_pw = data.get("master_pw") or ""
                _revoke_oc13 = "ok"
                if not master_pw:
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "master password required"}).encode())
                    return
                # Verify the master password FIRST (audit run-7):
                # checked only inside the label-found branch, it let
                # a ghost label plus a WRONG password return ok:true
                # and forge a "Friend revoked" audit row.
                if _master_proof(master_pw) is None:
                    self._set_json_headers(401)
                    self.wfile.write(json.dumps({"error": "wrong master password"}).encode())
                    return
                access = _load_access()
                # Match stored label case-insensitively (labels keep original case)
                stored_label = None
                for k in access.keys():
                    if k.lower() == label.lower():
                        stored_label = k
                        break
                if stored_label is None:
                    self._set_json_headers(404)
                    self.wfile.write(json.dumps({"error": "friend not found"}).encode())
                    return
                if stored_label is not None:
                    label = stored_label
                    with _ACCESS_LOCK:
                        # Reload inside the lock: deleting from a stale
                        # snapshot would resurrect accounts created or
                        # reset since it was loaded.
                        access = _load_access()
                        if label not in access:
                            stored_label = None
                        else:
                            del access[label]
                            _save_access(access, master_pw)
                if stored_label is not None:
                    # Incarnation guard (audit run-4): the cleanup
                    # runs under the lock and only fires while the
                    # label is still absent - a re-created account
                    # with the same label must keep ITS settings,
                    # files and sessions.
                    with _ACCESS_LOCK:
                        _still_gone = label not in _load_access()
                        if _still_gone:
                            # Settings-resident per-user state goes too: a
                            # re-created label must not inherit the previous
                            # holder's cap, suspension, OAuth email link or
                            # terms-seen flag.
                            _w10_dirty = False
                            with _SETTINGS_LOCK:
                                _caps = dict(_SETTINGS.get("user_caps") or {})
                                _susp = [x for x in (_SETTINGS.get("suspended") or [])
                                         if x != label]
                                _links = [e for e in (_SETTINGS.get("oauth_links") or [])
                                          if not (isinstance(e, dict)
                                                  and e.get("label") == label)]
                                _seen = [x for x in (_SETTINGS.get("terms_seen") or [])
                                         if x != label]
                                if (_caps.pop(label, None) is not None
                                        or _susp != (_SETTINGS.get("suspended") or [])
                                        or _links != (_SETTINGS.get("oauth_links") or [])
                                        or _seen != (_SETTINGS.get("terms_seen") or [])):
                                    _SETTINGS["user_caps"] = _caps
                                    _SETTINGS["suspended"] = _susp
                                    _SETTINGS["oauth_links"] = _links
                                    _SETTINGS["terms_seen"] = _seen
                                    _w10_dirty = True
                                # Drop their console role + vault metadata too
                                _roles = dict(_SETTINGS.get("roles") or {})
                                _vm = dict(_SETTINGS.get("vault_meta") or {})
                                if label in _roles or label in _vm:
                                    _roles.pop(label, None)
                                    _vm.pop(label, None)
                                    _SETTINGS["roles"] = _roles
                                    _SETTINGS["vault_meta"] = _vm
                                    _w10_dirty = True
                            # S2: one save after the lock releases
                            # persists both cleanup mutations.
                            # Wave 13 (run-12 data): that save is
                            # outcome-checked — it used to discard its
                            # result, so a faulted revoke answered 200
                            # while the role/cap resurrected at restart
                            # and were inherited by a re-created friend.
                            if _w10_dirty:
                                _revoke_oc13 = _settings_outcome(
                                    _save_settings(),
                                    lambda s: label not in (
                                        s.get("roles") or {})
                                    and label not in (
                                        s.get("user_caps") or {})
                                    and label not in (
                                        s.get("vault_meta") or {})
                                    and label not in (
                                        s.get("suspended") or [])
                                    and label not in (
                                        s.get("terms_seen") or [])
                                    and not any(
                                        isinstance(e, dict)
                                        and e.get("label") == label
                                        for e in (
                                            s.get("oauth_links")
                                            or [])))
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
                            # And their integrations vault (Gmail/Zoom OAuth
                            # tokens + workspace API keys must not outlive the
                            # account or revive on a same-label re-creation)
                            try:
                                ip2 = _intg_path(label)
                                if ip2.exists():
                                    ip2.unlink()
                            except Exception:
                                pass
                            for tok in [t for t, s in SESSIONS.items()
                                        if isinstance(s, dict) and s.get("label") == label]:
                                del SESSIONS[tok]
                    if _still_gone:
                        # Purge their usage + audit history rows too (F28):
                        # a revoked account leaves no per-user history.
                        _purge_label_history(label)
                _audit("Users", f"Friend revoked: {label}")
                if _revoke_oc13 != "ok":
                    # The account itself IS revoked (durable via
                    # _save_access); only the settings cleanup could
                    # not be saved — say exactly that.
                    self._set_json_headers(500)
                    self.wfile.write(json.dumps({"error": "friend revoked, but their per-user settings cleanup could not be saved"}).encode())
                    return
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
                with _KEYS_LOCK:
                    key_path = Path(__file__).parent / "keys.enc"
                    kd = _master_proof(cur)
                    if kd is None:
                        self._set_json_headers(401)
                        self.wfile.write(json.dumps({"error": "wrong master password"}).encode())
                        return
                    if _password_taken(_load_access(), new):
                        # The reverse collision: password-only login
                        # tries the master branch first, so a master
                        # equal to a friend's password would shadow
                        # that friend. Checked AFTER the proof (audit
                        # run-7): before it, an admin session that did
                        # not know the current password got the verdict
                        # for free, unlimited and unaudited.
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": "that password is already in use by a friend — pick a different master password"}).encode())
                        return
                    encrypt_keys(kd, new, key_path)
                _chats_note, _intg_note = _carry_over_master_rotation(cur, new)
                Handler.keys = kd
                SESSIONS.clear()
                _CHAT_UNLOCKS.clear()
                # Pending 2FA completions were minted under the OLD
                # password's proof (audit run-5): they die with the
                # rotation like every session does.
                _PENDING_2FA.clear()
                _2FA_ATTEMPTS.clear()
                # View grants were minted under the old password's
                # authority too (audit run-6): a pre-rotation /view
                # link must not re-mint a session afterwards.
                _VIEW_GRANTS.clear()
                # Stored /v1 service keys were minted under the old
                # password's authority too (audit run-6 critic):
                # rotation revokes them, like factory reset does —
                # file and live set go. (An env-bootstrapped key is
                # operator config, outside the app's reach.)
                try:
                    if V1KEY_PATH.exists():
                        V1KEY_PATH.unlink()
                except Exception:
                    pass
                with _V1KEYS_LOCK:
                    _V1KEYS["keys"] = []
                self._set_json_headers()
                _audit("System", "Master password changed")
                self.wfile.write(json.dumps({"ok": True, "note": "password changed; all sessions signed out" + _chats_note + _intg_note}).encode())
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
                keys = _master_proof(data.get("master_pw") or "")
                if keys is None:
                    self._set_json_headers(401)
                    self.wfile.write(json.dumps({"error": "wrong master password"}).encode())
                    return
                self._set_json_headers()
                self.wfile.write(json.dumps({"enabled": bool(keys.get("_totp_secret")),
                                             "pending": bool(keys.get("_totp_pending"))}).encode())
                return
            if action == "2fa_enable":
                master_pw = data.get("master_pw") or ""
                with _KEYS_LOCK:
                    key_path = Path(__file__).parent / "keys.enc"
                    # Audit run-6 critic: this was a bare decrypt — a
                    # parallel master-password oracle OUTSIDE the shared
                    # failure budget. _master_proof is the one oracle:
                    # throttled, failure-recorded, success clears.
                    keys = _master_proof(master_pw)
                    if keys is None:
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
                with _KEYS_LOCK:
                    key_path = Path(__file__).parent / "keys.enc"
                    # Audit run-6 critic: this was a bare decrypt — a
                    # parallel master-password oracle OUTSIDE the shared
                    # failure budget. _master_proof is the one oracle:
                    # throttled, failure-recorded, success clears.
                    keys = _master_proof(master_pw)
                    if keys is None:
                        self._set_json_headers(401)
                        self.wfile.write(json.dumps({"error": "wrong master password"}).encode())
                        return
                    pending = keys.get("_totp_pending", "")
                    if not pending:
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": "no pending 2FA setup"}).encode())
                        return
                    _now7 = time.time()
                    _2FA_FAILS_CONSOLE[:] = [t for t in _2FA_FAILS_CONSOLE
                                            if _now7 - t < 600]
                    if len(_2FA_FAILS_CONSOLE) >= 10:
                        self._set_json_headers(429)
                        self.wfile.write(json.dumps({"error": "too many attempts, try again later"}).encode())
                        return
                    _step = _totp_match_step(pending, code) if code else None
                    if _step is None or _step <= _TOTP_LAST_STEP["v"]:
                        _2FA_FAILS_CONSOLE.append(_now7)
                        self._set_json_headers(401)
                        self.wfile.write(json.dumps({"error": "wrong code — check your authenticator app"}).encode())
                        return
                    _TOTP_LAST_STEP["v"] = _step  # burn the confirm code (anti-replay watermark, as at login)
                    keys["_totp_secret"] = pending
                    keys.pop("_totp_pending", None)
                    encrypt_keys(keys, master_pw, key_path)
                    os.chmod(key_path, 0o600)
                    if Handler.keys is not None:
                        Handler.keys["_totp_secret"] = pending
                        Handler.keys.pop("_totp_pending", None)
                self._set_json_headers()
                _audit("System", "2FA enabled for admin")
                self.wfile.write(json.dumps({"ok": True, "enabled": True}).encode())
                return
            if action == "2fa_disable":
                master_pw = data.get("master_pw") or ""
                code = data.get("code") or ""
                with _KEYS_LOCK:
                    key_path = Path(__file__).parent / "keys.enc"
                    # Audit run-6 critic: this was a bare decrypt — a
                    # parallel master-password oracle OUTSIDE the shared
                    # failure budget. _master_proof is the one oracle:
                    # throttled, failure-recorded, success clears.
                    keys = _master_proof(master_pw)
                    if keys is None:
                        self._set_json_headers(401)
                        self.wfile.write(json.dumps({"error": "wrong master password"}).encode())
                        return
                    secret = keys.get("_totp_secret", "")
                    _now7 = time.time()
                    _2FA_FAILS_CONSOLE[:] = [t for t in _2FA_FAILS_CONSOLE
                                            if _now7 - t < 600]
                    if len(_2FA_FAILS_CONSOLE) >= 10:
                        self._set_json_headers(429)
                        self.wfile.write(json.dumps({"error": "too many attempts, try again later"}).encode())
                        return
                    _step = _totp_match_step(secret, code) if secret else None
                    if secret and (_step is None or _step <= _TOTP_LAST_STEP["v"]):
                        _2FA_FAILS_CONSOLE.append(_now7)
                        self._set_json_headers(401)
                        self.wfile.write(json.dumps({"error": "wrong 2FA code"}).encode())
                        return
                    if _step is not None:
                        _TOTP_LAST_STEP["v"] = _step  # burn the disable code (anti-replay watermark, as at login)
                    keys.pop("_totp_secret", None)
                    keys.pop("_totp_pending", None)
                    encrypt_keys(keys, master_pw, key_path)
                    os.chmod(key_path, 0o600)
                    if Handler.keys is not None:
                        Handler.keys.pop("_totp_secret", None)
                        Handler.keys.pop("_totp_pending", None)
                _audit("System", "2FA disabled for admin")
                self._set_json_headers()
                self.wfile.write(json.dumps({"ok": True}).encode())
                return
            self._set_json_headers(400)
            self.wfile.write(json.dumps({"error": "unknown action"}).encode())
            return
        if parsed.path == "/api/chats":
            # Saved conversations, per user, encrypted with their login
            # password. Actions: list / get / save / delete / export.
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
                try:
                    store = _load_chats_strict(label, chat_pw)
                except Exception:
                    # Fail closed like the admin branch above: never
                    # rewrite a friend store that failed to decrypt.
                    self._set_json_headers(500)
                    self.wfile.write(json.dumps({"error": "saved chats could not be decrypted"}).encode())
                    return
            chats = store.get("chats", [])

            def _persist():
                if _admin_rec is not None:
                    _save_admin_chats(_admin_rec, store)
                else:
                    _save_chats(label, store, chat_pw)

            def _reload_store():
                if _admin_rec is not None:
                    return _load_admin_chats_strict(_admin_rec["dek"])
                return _load_chats_strict(label, chat_pw)
            if action == "export":
                # Data export (F29 / DPDP data portability): the
                # caller downloads their OWN decrypted chat store as a
                # JSON file. The label comes from the session only —
                # never from the request — so no one can export
                # another account's chats.
                payload = json.dumps({
                    "label": label,
                    "exported_at": datetime.datetime.now().isoformat(),
                    "chats": chats,
                }, indent=2).encode()
                _safe_label = _re.sub(r"[^a-z0-9_]", "",
                                      (label or "").lower())[:30] or "export"
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Disposition",
                                 f'attachment; filename="nexus-chats-{_safe_label}.json"')
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
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
                _media_left = [1600000]  # per-chat data-URI budget (chars)
                for m in msgs_in[:200]:
                    if not isinstance(m, dict):
                        continue
                    t = m.get("t")
                    if not isinstance(t, str) or not t:
                        continue
                    # Generated images arrive as data URIs. Keep them when
                    # they fit (a typical generated image is ~100-250k
                    # chars) so saved chats replay WITH their images; a
                    # per-chat media budget bounds total size. An image
                    # that does not fit is replaced as a WHOLE markdown
                    # image with a readable note — never leave a broken
                    # ![..]([media too large..]) behind (owner report
                    # 2026-10-10: reopened chats showed raw placeholder
                    # markdown instead of the picture).
                    def _keep_uri(uri):
                        if len(uri) <= 260000 and len(uri) <= _media_left[0]:
                            _media_left[0] -= len(uri)
                            return True
                        return False
                    def _md_img_sub(mm):
                        return mm.group(0) if _keep_uri(mm.group(2)) else "[Generated image — too large to keep in saved chats]"
                    t = _re2.sub(r"!\[([^\]]*)\]\((data:[A-Za-z0-9/;,=+_-]+)\)", _md_img_sub, t)
                    def _bare_uri_sub(mm):
                        return mm.group(0) if _keep_uri(mm.group(0)) else "[media too large to keep in saved chats]"
                    t = _re2.sub(r"data:[A-Za-z0-9/;,=+_-]{2000,}", _bare_uri_sub, t)
                    item = {"r": "user" if m.get("r") == "user" else "ai",
                            "t": t[:420000]}
                    if isinstance(m.get("m"), str) and m.get("m"):
                        item["m"] = m["m"][:200]
                    # Raw provider id that wrote this reply — shared
                    # memory uses it to detect a cross-turn provider
                    # switch and hand over cleanly.
                    if isinstance(m.get("p"), str) and m.get("p"):
                        item["p"] = _re2.sub(r"[^a-z0-9_]", "",
                                              m["p"].lower())[:60]
                    # Composer trace (per-attempt steps): keep a
                    # strictly-shaped, capped copy so reopened chats can
                    # replay what happened — never arbitrary client JSON.
                    if item["r"] == "ai" and isinstance(m.get("tr"), list):
                        _tr = []
                        for _s in m["tr"][:8]:
                            if not isinstance(_s, dict):
                                continue
                            _e = {"p": _re2.sub(r"[^a-z0-9_]", "",
                                                str(_s.get("p") or "").lower())[:60],
                                  "m": str(_s.get("m") or "")[:80],
                                  "ok": bool(_s.get("ok"))}
                            if isinstance(_s.get("ms"), (int, float)) and _s["ms"] >= 0:
                                _e["ms"] = min(int(_s["ms"]), 3600000)
                            if isinstance(_s.get("e"), str) and _s["e"]:
                                _e["e"] = _s["e"][:160]
                            _tr.append(_e)
                        if _tr:
                            item["tr"] = _tr
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
                with _CHATS_LOCK:
                    # Re-load under the lock (audit run-6): parallel
                    # saves used to mutate the snapshot loaded at the
                    # top of this handler, and the later persist
                    # silently erased the earlier tab's chat.
                    try:
                        store = _reload_store()
                    except Exception:
                        self._set_json_headers(500)
                        self.wfile.write(json.dumps({"error": "saved chats could not be decrypted"}).encode())
                        return
                    chats = store.get("chats", [])
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
                    chats = sorted(chats, key=lambda c: -c.get("updated", 0))
                    # Audit run-7: the 50-chat eviction was silent.
                    # It is now disclosed in the save response (the
                    # byte cap below refuses loudly; the count cap
                    # at least speaks).
                    _evicted = [c.get("id") for c in chats[50:]]
                    chats = chats[:50]
                    store["chats"] = chats
                    if len(json.dumps(store)) > _CHATS_STORE_CAP:
                        self._set_json_headers(413)
                        self.wfile.write(json.dumps({"error": "chat storage is full for this account — delete some chats first"}).encode())
                        return
                    try:
                        _persist()
                    except Exception:
                        self._set_json_headers(500)
                        self.wfile.write(json.dumps({"error": "could not save chat"}).encode())
                        return
                self._set_json_headers()
                self.wfile.write(json.dumps({"ok": True, "id": cid,
                    **({"evicted": _evicted} if _evicted else {})}).encode())
                return
            if action == "delete":
                cid = str(data.get("id") or "")
                with _CHATS_LOCK:
                    try:
                        store = _reload_store()
                    except Exception:
                        self._set_json_headers(500)
                        self.wfile.write(json.dumps({"error": "saved chats could not be decrypted"}).encode())
                        return
                    store["chats"] = [c for c in store.get("chats", [])
                                       if c.get("id") != cid]
                    try:
                        _persist()
                    except Exception:
                        # A delete whose persist failed must not
                        # report success (audit run-6): the chat
                        # would still be on disk.
                        self._set_json_headers(500)
                        self.wfile.write(json.dumps({"error": "could not delete chat"}).encode())
                        return
                self._set_json_headers()
                self.wfile.write(json.dumps({"ok": True}).encode())
                return
            self._set_json_headers(400)
            self.wfile.write(json.dumps({"error": "unknown action"}).encode())
            return
        if parsed.path == "/api/integrations":
            # Per-user third-party connections (see the INTG block at
            # module level). Statuses never include secret material.
            info = self._session_info()
            if not info:
                self._set_json_headers(401)
                self.wfile.write(json.dumps({"error": "not logged in"}).encode())
                return
            label = _intg_label(info)
            content_length = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(content_length) if content_length else b"{}"
            try:
                data = json.loads(raw_body)
            except Exception:
                data = {}
            action = data.get("action", "status")
            store = info.get("integrations")
            if not isinstance(store, dict):
                store = None

            def _pub():
                st_ = store or {}
                svcs = {}
                g = st_.get("google")
                for name in ("gmail", "meet"):
                    svcs[name] = ({"connected": True, "account": g.get("email", ""),
                                   "saved": bool(g.get("saved"))}
                                  if g else {"connected": False})
                z = st_.get("zoom")
                svcs["zoom"] = ({"connected": True, "account": z.get("email", ""),
                                 "saved": bool(z.get("saved"))}
                                if z else {"connected": False})
                for name in _INTG_APIKEY_SERVICES:
                    e = st_.get(name)
                    svcs[name] = ({"connected": True, "account": e.get("_account", "")}
                                  if e else {"connected": False})
                return svcs

            def _ai_state():
                own = info.get("userkeys") or {}
                if not own and not info.get("admin"):
                    meta = (_SETTINGS.get("vault_meta") or {}).get(
                        info.get("label", "")) or []
                    own = {m.get("provider"): "1" for m in meta
                           if isinstance(m, dict)}
                shared = Handler.keys or {}
                ao = (info.get("integrations") or {}).get("ai_oauth") or {}
                out = {}
                for p in _INTG_AI_PROVIDERS:
                    row = {"own": bool(own.get(p)),
                           "shared": bool(shared.get(p)),
                           "keyless": p in _INTG_AI_KEYLESS,
                           "oauth": False, "oauth_account": ""}
                    for lane, card in _AIOAUTH_CARD.items():
                        if card == p:
                            tok = ao.get(lane)
                            if isinstance(tok, dict) and tok.get("access"):
                                row["oauth"] = True
                                row["oauth_account"] = tok.get("email") or ""
                    out[p] = row
                return out

            def _status(extra=None):
                body = {"unlocked": store is not None, "services": _pub(),
                        "ai": _ai_state(),
                        "google_configured": bool(_intg_creds("google")),
                        "zoom_configured": bool(_intg_creds("zoom")),
                        "admin": bool(info.get("admin"))}
                if extra:
                    body.update(extra)
                self._set_json_headers()
                self.wfile.write(json.dumps(body).encode())

            def _err(code, msg):
                self._set_json_headers(code)
                self.wfile.write(json.dumps({"error": msg}).encode())

            if action == "status":
                _status()
                return
            if action == "unlock":
                pw = data.get("password") or ""
                if label is None or not _intg_verify(info, pw):
                    _err(401, "wrong password")
                    return
                loaded = _load_intg(label, pw)
                info["integrations"] = loaded if isinstance(loaded, dict) else {}
                store = info["integrations"]
                _status()
                return
            # AI provider connections use the userkeys vault with a
            # per-request password (the My Keys pattern) — they do
            # NOT need the integrations vault unlocked.
            if action in ("ai_save", "ai_test", "ai_disconnect"):
                prov = data.get("service")
                if prov not in _INTG_AI_PROVIDERS:
                    _err(400, "unknown provider")
                    return
                if action == "ai_test":
                    if prov in _INTG_AI_KEYLESS:
                        _status({"ok": True, "account": "",
                                 "detail": "Keyless lane — nothing to test"})
                        return
                    eff = dict(Handler.keys or {})
                    if isinstance(info.get("userkeys"), dict):
                        eff.update(info["userkeys"])
                    key = eff.get(prov) or ""
                    if not key:
                        _err(400, "no key connected for this provider")
                        return
                    ok, acct, detail = _intg_test_ai(prov, key)
                    _status({"ok": bool(ok), "account": acct, "detail": detail})
                    return
                if info.get("admin"):
                    _err(403, "the owner's provider keys live in Update Keys — this page connects personal accounts")
                    return
                flabel = info.get("label", "")
                if not _LABEL_RE.match(flabel):
                    _err(400, "invalid label")
                    return
                pw = data.get("password") or ""
                if not _intg_verify(info, pw):
                    _err(401, "wrong password")
                    return
                if action == "ai_save":
                    if prov in _INTG_AI_KEYLESS:
                        _err(400, "this lane is keyless — nothing to connect")
                        return
                    key = str(data.get("api_key") or "").strip()
                    if not key or len(key) > 512:
                        _err(400, "that key looks empty or too long")
                        return
                    with _USERKEYS_LOCK:
                        try:
                            vault = _load_userkeys_strict(flabel, pw)
                        except Exception:
                            _err(500, "stored keys could not be decrypted — nothing was changed")
                            return
                        vault[prov] = key
                        _save_userkeys(flabel, vault, pw)
                    info["userkeys"] = dict(vault)
                    ok, acct, detail = _intg_test_ai(prov, key)
                    _status({"saved": True, "verified": bool(ok),
                             "account": acct, "detail": detail})
                    return
                # ai_disconnect
                with _USERKEYS_LOCK:
                    try:
                        vault = _load_userkeys_strict(flabel, pw)
                    except Exception:
                        _err(500, "stored keys could not be decrypted — nothing was changed")
                        return
                    vault.pop(prov, None)
                    _save_userkeys(flabel, vault, pw)
                info["userkeys"] = dict(vault)
                _status()
                return
            # AI account sign-ins (Codex / Claude Code / Gemini CLI
            # OAuth). Tokens live in the integrations vault; the
            # password opens it for this one save, same as above.
            if action in ("oauth_paste", "oauth_disconnect"):
                lane = data.get("service")
                if lane not in _AIOAUTH_CLIENTS:
                    _err(400, "unknown sign-in")
                    return
                pw = data.get("password") or ""
                if label is None or not _intg_verify(info, pw):
                    _err(401, "wrong password")
                    return
                try:
                    store2 = _load_intg_strict(label, pw)
                except Exception:
                    _err(500, "stored integrations could not be decrypted — nothing was changed")
                    return
                if action == "oauth_disconnect":
                    with _INTG_LOCK:
                        try:
                            store2 = _load_intg_strict(label, pw)
                        except Exception:
                            _err(500, "stored integrations could not be decrypted — nothing was changed")
                            return
                        (store2.get("ai_oauth") or {}).pop(lane, None)
                        try:
                            _save_intg(label, store2, pw)
                        except Exception:
                            _err(500, "could not save")
                            return
                    info["integrations"] = store2
                    _status()
                    return
                text = str(data.get("text") or "").strip()
                code, st8 = "", ""
                if "://" in text:
                    q = urllib.parse.parse_qs(
                        urllib.parse.urlparse(text).query)
                    code = (q.get("code") or [""])[0]
                    st8 = (q.get("state") or [""])[0]
                elif "#" in text:
                    code, st8 = text.split("#", 1)
                else:
                    code = text
                code, st8 = code.strip(), st8.strip()
                ck = ""
                for part in (self.headers.get("Cookie") or "").split(";"):
                    part = part.strip()
                    if part.startswith("aio_state="):
                        ck = part[len("aio_state="):]
                cparts = ck.split(":")
                verifier = ""
                # The state-cookie binding is UNCONDITIONAL for every
                # lane: the code may only be exchanged against the
                # flow this browser session actually started. Lanes
                # whose artifact carries a state get it compared
                # below; bare codes are bound by PKCE instead (every
                # lane now runs PKCE — see _AIOAUTH_CLIENTS).
                if len(cparts) != 3 or cparts[0] != lane or not cparts[1]:
                    _err(400, "sign-in session expired — click Sign in "
                              "and paste the new code")
                    return
                if st8 and not secrets.compare_digest(st8, cparts[1]):
                    _err(400, "that code belongs to a different "
                              "sign-in attempt — click Sign in and "
                              "paste the fresh code")
                    return
                verifier = cparts[2]
                if not code:
                    _err(400, "paste the code (or the full address) "
                              "from the provider page first")
                    return
                if _AIOAUTH_CLIENTS[lane].get("pkce") and not verifier:
                    _err(400, "sign-in session expired — click Sign in "
                              "and paste the new code")
                    return
                try:
                    tok = _aioauth_exchange(lane, code, verifier)
                except ValueError as ve:
                    _err(400, str(ve))
                    return
                if lane == "gemini_cli":
                    st3, uj = _intg_http(
                        "https://www.googleapis.com/oauth2/v2/userinfo",
                        "GET",
                        {"Authorization": "Bearer " + tok["access"]})
                    if st3 == 200 and isinstance(uj, dict):
                        tok["email"] = uj.get("email") or ""
                    tok["project"] = _gemini_project(tok["access"])
                    if not tok["project"]:
                        _err(400, "Google signed you in, but Code "
                                  "Assist did not grant a project — "
                                  "try again in a minute")
                        return
                # Re-load under the lock before saving (audit
                # run-6): the snapshot loaded above predates the
                # token exchange's network calls, so saving it
                # verbatim erased anything saved in between.
                with _INTG_LOCK:
                    try:
                        store2 = _load_intg_strict(label, pw)
                    except Exception:
                        _err(500, "stored integrations could not be decrypted — nothing was changed")
                        return
                    store2.setdefault("ai_oauth", {})[lane] = tok
                    try:
                        _save_intg(label, store2, pw)
                    except Exception:
                        _err(500, "could not save the connection")
                        return
                info["integrations"] = store2
                _status({"connected": lane,
                         "account": tok.get("email") or ""})
                return
            if store is None:
                _err(409, "your integrations vault is locked — unlock it first")
                return
            if action == "save":
                svc = data.get("service")
                fields = data.get("fields") or {}
                if svc not in _INTG_APIKEY_SERVICES or not isinstance(fields, dict):
                    _err(400, "unknown service")
                    return
                pw = data.get("password") or ""
                if label is None or not _intg_verify(info, pw):
                    _err(401, "wrong password")
                    return
                entry = {}
                for f in _INTG_APIKEY_SERVICES[svc]:
                    v = str(fields.get(f) or "").strip()
                    if not v or len(v) > 512:
                        _err(400, f"{f} is empty or too long")
                        return
                    entry[f] = v
                if svc == "jira":
                    site = _re.sub(r"^https?://", "", entry["site"].lower()).split("/")[0]
                    if not _re.match(r"^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}$", site) or "@" in site:
                        _err(400, "site should look like yourteam.atlassian.net")
                        return
                    entry["site"] = site
                # Save, then verify live: the account label is only
                # recorded when the provider itself confirms the key.
                ok, account, detail = _INTG_TESTERS[svc](entry)
                if ok:
                    entry["_account"] = account
                with _INTG_LOCK:
                    try:
                        disk = _load_intg_strict(label, pw)
                    except Exception:
                        _err(500, "stored integrations could not be decrypted — nothing was changed")
                        return
                    disk[svc] = entry
                    _save_intg(label, disk, pw)
                info["integrations"] = disk
                store = disk
                _status({"saved": True, "verified": bool(ok),
                         "account": account if ok else "",
                         "detail": detail})
                return
            if action == "test":
                svc = data.get("service")
                if svc in _INTG_TESTERS:
                    entry = store.get(svc)
                    if not entry:
                        _err(400, "not connected")
                        return
                    ok, account, detail = _INTG_TESTERS[svc](entry)
                    if ok:
                        entry["_account"] = account
                    _status({"ok": bool(ok), "account": account, "detail": detail})
                    return
                if svc in ("gmail", "meet", "google"):
                    entry = store.get("google")
                    if not entry:
                        _err(400, "not connected")
                        return
                    try:
                        tok = _google_access_token(entry)
                        gst, gj = _intg_http(
                            "https://gmail.googleapis.com/gmail/v1/users/me/profile",
                            "GET", {"Authorization": "Bearer " + tok})
                        if gst == 200 and isinstance(gj, dict):
                            acct = f"{gj.get('emailAddress', '')} · {gj.get('messagesTotal', 0)} messages"
                            entry["email"] = gj.get("emailAddress", entry.get("email", ""))
                            _status({"ok": True, "account": acct,
                                     "detail": "Google connection is live"})
                        else:
                            _status({"ok": False, "account": "",
                                     "detail": f"Google said ({gst}): {_intg_err_text(gj)}"})
                    except ValueError as ve:
                        _status({"ok": False, "account": "", "detail": str(ve)})
                    return
                if svc == "zoom":
                    entry = store.get("zoom")
                    if not entry:
                        _err(400, "not connected")
                        return
                    try:
                        tok = _zoom_access_token(entry)
                        zst, zj = _intg_http("https://api.zoom.us/v2/users/me", "GET",
                                             {"Authorization": "Bearer " + tok})
                        if zst == 200 and isinstance(zj, dict):
                            acct = zj.get("email") or zj.get("first_name", "")
                            entry["email"] = acct
                            _status({"ok": True, "account": acct,
                                     "detail": "Zoom connection is live"})
                        else:
                            _status({"ok": False, "account": "",
                                     "detail": f"Zoom said ({zst}): {_intg_err_text(zj)}"})
                    except ValueError as ve:
                        _status({"ok": False, "account": "", "detail": str(ve)})
                    return
                _err(400, "unknown service")
                return
            if action == "disconnect":
                svc = data.get("service")
                key = "google" if svc in ("gmail", "meet", "google") else svc
                if key not in _INTG_APIKEY_SERVICES and key not in ("google", "zoom"):
                    _err(400, "unknown service")
                    return
                pw = data.get("password") or ""
                if label is None or not _intg_verify(info, pw):
                    _err(401, "wrong password")
                    return
                with _INTG_LOCK:
                    try:
                        disk = _load_intg_strict(label, pw)
                    except Exception:
                        _err(500, "stored integrations could not be decrypted — nothing was changed")
                        return
                    disk.pop(key, None)
                    _save_intg(label, disk, pw)
                info["integrations"] = disk
                store = disk
                _status()
                return
            if action == "save_oauth":
                svc = data.get("service")
                if svc not in ("google", "zoom"):
                    _err(400, "unknown service")
                    return
                entry = store.get(svc)
                if not entry:
                    _err(400, "nothing to save — connect first")
                    return
                pw = data.get("password") or ""
                if label is None or not _intg_verify(info, pw):
                    _err(401, "wrong password")
                    return
                with _INTG_LOCK:
                    try:
                        disk = _load_intg_strict(label, pw)
                    except Exception:
                        _err(500, "stored integrations could not be decrypted — nothing was changed")
                        return
                    entry = dict(entry)
                    entry["saved"] = True
                    disk[svc] = entry
                    _save_intg(label, disk, pw)
                info["integrations"] = disk
                store = disk
                _status()
                return
            if action in ("gmail_inbox", "gmail_send", "create_meet"):
                entry = store.get("google")
                if not entry:
                    _err(400, "Google is not connected")
                    return
                try:
                    tok = _google_access_token(entry)
                except ValueError as ve:
                    _err(502, str(ve))
                    return
                auth = {"Authorization": "Bearer " + tok,
                        "Content-Type": "application/json"}
                if action == "gmail_inbox":
                    lst, lj = _intg_http(
                        "https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=5",
                        "GET", auth)
                    msgs = []
                    if lst == 200 and isinstance(lj, dict):
                        for m in (lj.get("messages") or [])[:5]:
                            mst, mj = _intg_http(
                                "https://gmail.googleapis.com/gmail/v1/users/me/messages/"
                                f"{m['id']}?format=metadata&metadataHeaders=From&metadataHeaders=Subject",
                                "GET", auth)
                            if mst == 200 and isinstance(mj, dict):
                                hdrs = {h.get("name", ""): h.get("value", "")
                                        for h in (mj.get("payload") or {}).get("headers", [])}
                                msgs.append({"from": hdrs.get("From", "")[:80],
                                             "subject": hdrs.get("Subject", "(no subject)")[:120]})
                    self._set_json_headers()
                    self.wfile.write(json.dumps({"messages": msgs}).encode())
                    return
                if action == "gmail_send":
                    to = str(data.get("to") or "").strip()
                    subj = str(data.get("subject") or "").strip()[:200]
                    body_t = str(data.get("body") or "")[:5000]
                    if "@" not in to or len(to) > 200 or not subj:
                        _err(400, "a recipient and a subject are required")
                        return
                    raw = base64.urlsafe_b64encode(
                        f"To: {to}\r\nSubject: {subj}\r\n"
                        f"Content-Type: text/plain; charset=UTF-8\r\n\r\n{body_t}".encode()).decode()
                    sst, sj = _intg_http(
                        "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
                        "POST", auth, json.dumps({"raw": raw}).encode())
                    if sst == 200:
                        self._set_json_headers()
                        self.wfile.write(json.dumps({"ok": True}).encode())
                    else:
                        _err(502, f"Gmail said ({sst}): {_intg_err_text(sj)}")
                    return
                # create_meet
                title = str(data.get("title") or "Nexus meeting").strip()[:200] or "Nexus meeting"
                start = str(data.get("start") or "").strip()[:40]
                try:
                    minutes = max(5, min(480, int(data.get("minutes") or 30)))
                except Exception:
                    minutes = 30
                try:
                    dt0 = datetime.datetime.fromisoformat(start.replace("Z", "+00:00"))
                except Exception:
                    _err(400, "a valid start time is required")
                    return
                if dt0.tzinfo is None:
                    dt0 = dt0.replace(tzinfo=datetime.timezone.utc)
                dt1 = dt0 + datetime.timedelta(minutes=minutes)
                ev = {"summary": title,
                      "start": {"dateTime": dt0.isoformat()},
                      "end": {"dateTime": dt1.isoformat()},
                      "conferenceData": {"createRequest": {
                          "requestId": secrets.token_hex(8),
                          "conferenceSolutionKey": {"type": "hangoutsMeet"}}}}
                cst, cj = _intg_http(
                    "https://www.googleapis.com/calendar/v3/calendars/primary/events?conferenceDataVersion=1",
                    "POST", auth, json.dumps(ev).encode())
                if cst in (200, 201) and isinstance(cj, dict) and cj.get("hangoutLink"):
                    self._set_json_headers()
                    self.wfile.write(json.dumps({"ok": True, "link": cj["hangoutLink"]}).encode())
                else:
                    _err(502, f"Google Calendar said ({cst}): {_intg_err_text(cj)}")
                return
            if action == "create_zoom_meeting":
                entry = store.get("zoom")
                if not entry:
                    _err(400, "Zoom is not connected")
                    return
                try:
                    tok = _zoom_access_token(entry)
                except ValueError as ve:
                    _err(502, str(ve))
                    return
                topic = str(data.get("topic") or "Nexus meeting").strip()[:200] or "Nexus meeting"
                start = str(data.get("start") or "").strip()[:40]
                try:
                    minutes = max(5, min(480, int(data.get("minutes") or 40)))
                except Exception:
                    minutes = 40
                try:
                    dt0 = datetime.datetime.fromisoformat(start.replace("Z", "+00:00"))
                except Exception:
                    _err(400, "a valid start time is required")
                    return
                if dt0.tzinfo is None:
                    dt0 = dt0.replace(tzinfo=datetime.timezone.utc)
                payload = {"topic": topic, "type": 2,
                           "start_time": dt0.strftime("%Y-%m-%dT%H:%M:%SZ"),
                           "duration": minutes, "timezone": "UTC"}
                zst, zj = _intg_http("https://api.zoom.us/v2/users/me/meetings", "POST",
                                     {"Authorization": "Bearer " + tok,
                                      "Content-Type": "application/json"},
                                     json.dumps(payload).encode())
                if zst in (200, 201) and isinstance(zj, dict) and zj.get("join_url"):
                    self._set_json_headers()
                    self.wfile.write(json.dumps({"ok": True, "link": zj["join_url"]}).encode())
                else:
                    _err(502, f"Zoom said ({zst}): {_intg_err_text(zj)}")
                return
            _err(400, "unknown action")
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
                if not _SETTINGS.get("friends_byok", True):
                    self._set_json_headers(403)
                    self.wfile.write(json.dumps({"error": "personal key vaults are disabled by the admin"}).encode())
                    return
                password = data.get("password") or ""
                if not password:
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "password required to encrypt"}).encode())
                    return
                # Verify password against stored hash (audit run-6:
                # the proof feeds a per-account failure budget — it
                # was an unthrottled offline oracle).
                if _pw_throttled("friend", label):
                    self._set_json_headers(429)
                    self.wfile.write(json.dumps({"error": "too many wrong passwords — try again in a few minutes"}).encode())
                    return
                access = _load_access()
                stored = access.get(label, "")
                ok, needs_up = _verify_password(password, stored)
                if ok and needs_up and label in access:
                    with _ACCESS_LOCK:
                        _fresh = _load_access()
                        if _fresh.get(label) == stored:
                            _fresh[label] = _hash_password(password)
                            _save_access(_fresh)
                if not ok:
                    _pw_failed("friend", label)
                    self._set_json_headers(401)
                    self.wfile.write(json.dumps({"error": "wrong password"}).encode())
                    return
                _PW_FAILS.pop(("friend", label), None)
                keys_in = data.get("keys") or {}
                if not isinstance(keys_in, dict):
                    self._set_json_headers(400)
                    self.wfile.write(json.dumps({"error": "invalid keys"}).encode())
                    return
                for k, v in keys_in.items():
                    if isinstance(v, str) and len(v) > _USERKEY_VALUE_CAP:
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": "a key value is too long (512 characters max)"}).encode())
                        return
                # SSRF guard (A5): provider/gateway base URLs are
                # fetched server-side with the vault key attached, so a
                # stored URL must resolve to public addresses only.
                for k, v in keys_in.items():
                    if isinstance(v, str) and v.strip() and (
                            k == "freellmapi_url"
                            or (k.startswith("custom_relay_")
                                and k.endswith("_url"))) \
                            and not _public_base_url_ok(v):
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": "provider URL must be a public http(s) address"}).encode())
                        return
                # Load existing vault STRICTLY: an existing vault that
                # fails to decrypt must refuse the save outright — a
                # lenient empty load would let the merge overwrite it.
                with _USERKEYS_LOCK:
                    try:
                        _vault_pre = _load_userkeys_strict(label, password)
                    except Exception:
                        self._set_json_headers(500)
                        self.wfile.write(json.dumps({"error": "stored keys could not be decrypted — nothing was changed"}).encode())
                        return
                    # Load existing vault and merge: a NON-blank value sets
                    # the key; a BLANK field KEEPS the stored value (the
                    # pages submit every field on save, so blank must never
                    # silently delete). Removal is explicit only: keys named
                    # in the payload's "remove" list are deleted.
                    vault = _vault_pre
                    for k, v in keys_in.items():
                        if not isinstance(k, str) or not _re.match(r"^[a-z0-9_]+$", k):
                            continue
                        if k.startswith("_"):
                            continue
                        v = (v or "").strip() if isinstance(v, str) else ""
                        if v:
                            vault[k] = v
                    for k in (data.get("remove") or []):
                        if isinstance(k, str) and not k.startswith("_"):
                            vault.pop(k, None)
                    # Entry cap, checked once AFTER merge + removals
                    # (audit run-6 critic: inside the remove loop it
                    # never ran on a plain save — dead code).
                    if len([k for k in vault if not k.startswith("_")]) > _USERKEY_COUNT_CAP:
                        self._set_json_headers(400)
                        self.wfile.write(json.dumps({"error": "too many keys in one vault"}).encode())
                        return
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
        self._send_404_page()

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
    _boot_restore_settings()
    _boot_restore_telemetry()
    _load_v1key()
    threading.Thread(target=_housekeeper, daemon=True).start()
    threading.Thread(target=_telemetry_flusher, daemon=True).start()
    httpd = ThreadingHTTPServer(addr, Handler)
    print(f"Serving on {addr[0]}:{addr[1]} – press Ctrl-C to stop")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutdown requested")


if __name__ == "__main__":
    main()
