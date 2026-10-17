#!/usr/bin/env python3
"""Regression tests for the wave-18 fixes (security audit run-17:
4 confirmed findings; CAPS17-1 is an owner-decision item and is
NOT touched here).

Fix 1 (AUTH17-1, app/server.py): _restore_access merges under
_ACCESS_LOCK (current store wins), re-decrypts when users.enc
changed mid-decrypt, and refreshes users.enc with the merged
dict — a concurrent creation and the restore both survive, and
a label revoked during the decrypt window is not resurrected.
Fix 2 (L17-2, bin/nexuslocal.js): the launcher re-checks
(engineExited || shuttingDown) before EVERY credential POST in
claim/verify, and probes 127.0.0.1:3001 BEFORE spawning the
engine — a pre-bound port means no spawn and no credential
traffic at all. (The engine-side nonce echo is the named
remainder: the engine in this repo is dist-only, no src/.)
Fix 3 (L17-1, bin/nexuslocal.js): the three .env write-back
regexes anchor with horizontal whitespace only, so CRLF files
round-trip and LF behaviour is unchanged.
Fix 4 (D17-1, app/server.py): _clear_stranded_label records the
generation triple AT the judgement (immediately after the
in-lock existence check), so a settings save landing during the
persisted decrypt can no longer be absorbed by the recheck.

Run:  python3 -m unittest tests.test_wave18_fixes -v
   or python3 -m unittest discover -s tests
"""

import copy
import http.client
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
APP = REPO / "app"
sys.path.insert(0, str(APP))
sys.path.insert(0, str(REPO / "tests"))

os.environ.pop("NEXUS_RESTORE_KEY", None)

from key_security import decrypt_keys, encrypt_keys  # noqa: E402
import server  # noqa: E402

import test_security_audit_2026_10_16 as _a16  # noqa: E402

MASTER = _a16.MASTER
RESTORE = _a16.RESTORE
FRIEND_PW = _a16.FRIEND_PW
UNIQUE_PW = _a16.UNIQUE_PW
_FixtureServerBase = _a16._FixtureServerBase
_respawn_fixture = _a16._respawn_fixture

W18_RESTORE = "w18-restore-key"


# =====================================================================
# Fix 1 — unit: merge under the lock, bytes-changed re-decrypt
# =====================================================================
class Wave18RestoreUnitTests(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="nexus-test-w18-restore-"))
        self._saved = (server.ACCESS_PATH, server.USERS_PATH,
                       server.ACCESS_ENC_PATH, server.decrypt_keys)
        server.ACCESS_PATH = self.tmp / "access.json"
        server.USERS_PATH = self.tmp / "users.enc"
        server.ACCESS_ENC_PATH = self.tmp / "access.enc"
        self.users = {"oldone": "hash-old-1", "oldtwo": "hash-old-2"}
        encrypt_keys(self.users, MASTER, server.USERS_PATH)
        server.ACCESS_PATH.write_text("{}")

    def tearDown(self):
        (server.ACCESS_PATH, server.USERS_PATH,
         server.ACCESS_ENC_PATH, server.decrypt_keys) = self._saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _wrap_decrypt(self, side_effect):
        orig = self._saved[3]
        state = {"fired": False}

        def wrapper(path, pw):
            # decrypt_keys reads the file first and pays PBKDF2
            # afterwards, so a save landing "during the decrypt"
            # is one that lands after the read but while the
            # restore still holds the stale decrypted dict —
            # exactly: fire after orig() computed its result,
            # before the restore proceeds to write.
            result = orig(path, pw)
            if not state["fired"]:
                state["fired"] = True
                side_effect()
            return result

        server.decrypt_keys = wrapper

    def _persisted_access(self):
        return json.loads(server.ACCESS_PATH.read_text())

    def test_w18_creation_during_decrypt_survives_merge(self):
        def create():
            with server._ACCESS_LOCK:
                server._save_access({"newlabel": "hash-new"})

        self._wrap_decrypt(create)
        server._restore_access(MASTER)
        merged = self._persisted_access()
        # Pre-fix: the blind whole-store write clobbered the
        # creation (only the decrypted dict survived).
        self.assertEqual(merged.get("newlabel"), "hash-new")
        self.assertEqual(merged.get("oldone"), "hash-old-1")
        self.assertEqual(merged.get("oldtwo"), "hash-old-2")
        # The backup converges: users.enc now holds the merged
        # dict, so a second wipe cannot re-lose the creation.
        backup = decrypt_keys(server.USERS_PATH, MASTER)
        self.assertEqual(backup.get("newlabel"), "hash-new")
        self.assertEqual(backup.get("oldone"), "hash-old-1")

    def test_w18_current_store_wins_label_conflict(self):
        def create():
            with server._ACCESS_LOCK:
                server._save_access({"oldone": "hash-UPGRADED"})

        self._wrap_decrypt(create)
        server._restore_access(MASTER)
        merged = self._persisted_access()
        # A hash upgrade that landed in the window is never
        # reverted to users.enc's older hash.
        self.assertEqual(merged.get("oldone"), "hash-UPGRADED")
        self.assertEqual(merged.get("oldtwo"), "hash-old-2")

    def test_w18_revoked_during_decrypt_not_resurrected(self):
        # users.enc carries a label that a master-bearing save
        # revokes DURING the restore's decrypt: the save rewrites
        # users.enc without it (the bytes-changed guard must make
        # the restore judge the fresh bytes, not the stale dict).
        users = dict(self.users)
        users["revokeme"] = "hash-revoked"
        encrypt_keys(users, MASTER, server.USERS_PATH)

        def revoke():
            encrypt_keys(self.users, MASTER, server.USERS_PATH)

        self._wrap_decrypt(revoke)
        server._restore_access(MASTER)
        merged = self._persisted_access()
        self.assertNotIn("revokeme", merged)
        self.assertEqual(merged.get("oldone"), "hash-old-1")
        self.assertEqual(merged.get("oldtwo"), "hash-old-2")


# =====================================================================
# Fix 1 — HTTP: the verifier's staggered redeem vs admin-login race
# =====================================================================
class Wave18RestoreHttpTests(_FixtureServerBase):
    """Both compositions over HTTP: wipe the access stores, reset
    users.enc to the two fixture friends, then run a redeem and
    the owner's first admin login concurrently at staggered
    offsets. Post-fix the merge makes BOTH sides survive in every
    composition: the new account, and both restored friends, can
    all log in afterwards."""

    FIXTURE_FILES = ("keys", "access")

    @classmethod
    def setUpClass(cls):
        cls._boot()
        # Fixture-only instrumentation (the wave-17 RESTRAND17
        # pattern): widen the restore's check-to-write window on
        # demand. When RESTORE_GATE18 exists in the fixture dir,
        # _restore_access sleeps 6s right after its needs-check —
        # so a creation started during the gate is GUARANTEED to
        # be in flight across the restore's decision point, in
        # both compositions, with no reliance on stagger luck.
        sp = cls.tmp / "server.py"
        txt = sp.read_text()
        anchor = "        if needs and USERS_PATH.exists():\n"
        assert txt.count(anchor) == 1
        txt = txt.replace(
            anchor,
            anchor + "            if (Path(__file__).parent / "
                     "\"RESTORE_GATE18\").exists():\n"
                     "                time.sleep(6)\n", 1)
        sp.write_text(txt)
        _respawn_fixture(cls)
        _, _, admin = cls._login(MASTER)
        assert admin
        # Friends scale (the verifier's shape): three extra
        # PBKDF2 friends widen every creation/login window to
        # seconds, so the staggered restore reliably fires
        # INSIDE the creation window at every offset. Console
        # adds are master-bearing saves, so they also refresh
        # users.enc — the reset dict below includes them.
        for i in range(3):
            status, body, _ = cls._req(
                "POST", "/api/access",
                {"action": "add", "label": f"seed18{i}",
                 "password": f"seed18-{i}-pw", "master_pw": MASTER},
                ck=admin)
            assert status == 200, body
        # Read the fixture's real hashes back out of users.enc.
        cls._orig_access = decrypt_keys(cls.tmp / "users.enc", MASTER)

    @classmethod
    def tearDownClass(cls):
        cls._stop()

    @classmethod
    def _invite(cls, admin):
        status, body, _ = cls._req(
            "POST", "/api/access",
            {"action": "invite_create", "role": "friend", "days": 1,
             "master_pw": MASTER}, ck=admin)
        assert status == 200, body
        return body["code"]

    def _reset_stores(self):
        for name in ("access.json", "access.enc"):
            p = self.tmp / name
            if p.exists():
                p.unlink()
        encrypt_keys(self._orig_access, MASTER, self.tmp / "users.enc")

    def test_w18_restore_race_both_sides_survive(self):
        _, _, admin = self._login(MASTER)
        self.assertTrue(admin)
        gate = self.tmp / "RESTORE_GATE18"
        for k, delay in enumerate((1.0, 2.5, 4.0)):
            label = f"race18{k}"
            pw = f"Race18-New-{k}-pw"
            code = self._invite(admin)
            self._reset_stores()
            out = {}
            gate.write_text("x")

            def run_redeem():
                out["r"] = self._req(
                    "POST", "/api/invite/redeem",
                    {"label": label, "password": pw, "code": code},
                    headers={"X-Forwarded-For":
                             f"198.51.100.{20 + k}"})

            def run_login():
                out["a"] = self._login(MASTER)

            try:
                # The owner's first login goes first: its restore
                # checks (empty store), then parks in the gate.
                # The redeem starts `delay` seconds later, square
                # inside the restore's check-to-write window.
                t2 = threading.Thread(target=run_login)
                t2.start()
                time.sleep(delay)
                t = threading.Thread(target=run_redeem)
                t.start()
                t.join(180)
                t2.join(180)
            finally:
                gate.unlink(missing_ok=True)
            self.assertEqual(out["r"][0], 200, (k, out["r"]))
            self.assertEqual(out["a"][0], 200, (k, out["a"]))
            persisted = json.loads(
                (self.tmp / "access.json").read_text())
            for want in ("friendone", "solo", "seed180", label):
                self.assertIn(want, persisted, (k, persisted))
            # Every side can actually log in — no clobbered
            # account, and (therefore) no ghost session either:
            # a session the redeem minted belongs to an account
            # that still exists.
            for who, pwx in (("friendone", FRIEND_PW),
                             ("solo", UNIQUE_PW), (label, pw)):
                status, body, _ = self._login(pwx)
                self.assertEqual(status, 200, (k, who, body))
                self.assertEqual(body.get("label"), who, (k, body))
            cookie = out["r"][2]
            if cookie:
                status, _, _ = self._req("GET", "/api/quotas",
                                          ck=cookie)
                self.assertEqual(status, 200, (k, "ghost-check"))


# =====================================================================
# Fix 4 — generation triple recorded at the judgement
# =====================================================================
class Wave18GenerationTripleTests(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="nexus-test-w18-gen-"))
        self._saved_paths = (server.SETTINGS_ENC_PATH,
                             server.SETTINGS_PATH, server.ACCESS_PATH,
                             server.RESTORE_KEY,
                             server._persisted_settings)
        self._saved_settings = copy.deepcopy(server._SETTINGS)
        self._saved_counters = (server._SETTINGS_GEN[0],
                                server._SETTINGS_WRITTEN_GEN[0],
                                server._SETTINGS_ACTIVE[0])
        server.SETTINGS_ENC_PATH = self.tmp / "settings.enc"
        server.SETTINGS_PATH = self.tmp / "settings.json"
        server.ACCESS_PATH = self.tmp / "access.json"
        server.ACCESS_PATH.write_text("{}")
        server.RESTORE_KEY = W18_RESTORE
        server._SETTINGS.clear()
        server._SETTINGS.update(copy.deepcopy(self._saved_settings))
        self._write_persisted()

    def tearDown(self):
        (server.SETTINGS_ENC_PATH, server.SETTINGS_PATH,
         server.ACCESS_PATH, server.RESTORE_KEY,
         server._persisted_settings) = self._saved_paths
        server._SETTINGS.clear()
        server._SETTINGS.update(self._saved_settings)
        (server._SETTINGS_GEN[0], server._SETTINGS_WRITTEN_GEN[0],
         server._SETTINGS_ACTIVE[0]) = self._saved_counters
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write_persisted(self):
        snap = {k: server._SETTINGS.get(k)
                for k in ("roles", "user_caps", "vault_meta",
                          "suspended", "terms_seen", "oauth_links")}
        encrypt_keys(snap, W18_RESTORE, server.SETTINGS_ENC_PATH)

    def _triple(self):
        return getattr(server._CLEAR_JUDGED17, "triple", None)

    def _current(self):
        return (server._SETTINGS_GEN[0], server._SETTINGS_WRITTEN_GEN[0],
                server._SETTINGS_ACTIVE[0])

    def _writer(self, label):
        # The real settings_set writer shape: mutate under
        # _SETTINGS_LOCK, then the real _save_settings().
        with server._SETTINGS_LOCK:
            cur = list(server._SETTINGS.get("suspended") or [])
            if label not in cur:
                cur.append(label)
            server._SETTINGS["suspended"] = cur
        return server._save_settings()

    def test_w18_writer_inside_persisted_read_not_absorbed(self):
        # Deterministic form of the D17-1 window: the writer
        # lands AFTER the persisted snapshot is taken (the read
        # at the start of _persisted_settings) but BEFORE the
        # helper returns — the snapshot the judgement is earned
        # on. Injected inside the read itself, at exactly the
        # snapshot instant.
        label = "w18det"
        orig_persisted = server._persisted_settings
        state = {"fired": False}

        def fake_persisted():
            snap = orig_persisted()
            if not state["fired"]:
                state["fired"] = True
                self._writer(label)
            return snap

        server._persisted_settings = fake_persisted
        try:
            verdict = server._clear_stranded_label(label)
        finally:
            server._persisted_settings = orig_persisted
        self.assertEqual(verdict, "ok")
        # The writer DID land (it is stranded in the persisted
        # store now) — so the recheck must NOT skip: the recorded
        # triple must differ from the current one. Pre-fix the
        # triple was recorded at the return, already including
        # the writer's save, and the recheck skipped.
        persisted = orig_persisted()
        self.assertIn(label, persisted.get("suspended") or [])
        self.assertIsNotNone(self._triple())
        self.assertNotEqual(self._triple(), self._current())

    def test_w18_absorption_sweep_zero(self):
        # The verifier's sweep shape: the real writer vs the real
        # helper at staggered offsets — absorbed count must be 0.
        absorbed = 0
        for i, off in enumerate((0.0, 0.05, 0.1, 0.2, 0.35)):
            label = f"w18sw{i}"
            # Reset to a clean slate for this label.
            with server._SETTINGS_LOCK:
                cur = [x for x in (server._SETTINGS.get("suspended")
                                   or []) if x != label]
                server._SETTINGS["suspended"] = cur
            self._write_persisted()
            out = {}

            def create():
                out["v"] = server._clear_stranded_label(label)

            t = threading.Thread(target=create)
            t.start()
            time.sleep(off)
            self._writer(label)
            t.join(60)
            self.assertEqual(out.get("v"), "ok", (i, out))
            persisted = server._persisted_settings()
            stranded = label in (persisted.get("suspended") or [])
            # Absorbed = the writer is stranded in the persisted
            # store AND the recorded triple reads unmoved, so the
            # in-lock recheck would skip its decrypt and creation
            # would proceed over the stranded store.
            if stranded and self._triple() == self._current():
                absorbed += 1
            # Clean up the stranded entry for the next offset.
            with server._SETTINGS_LOCK:
                cur = [x for x in (server._SETTINGS.get("suspended")
                                   or []) if x != label]
                server._SETTINGS["suspended"] = cur
            server._save_settings()
        self.assertEqual(absorbed, 0)

    def test_w18_clean_clear_pays_one_decrypt_and_arms_guard(self):
        # D16-2 regression: a clean creation's clear pays exactly
        # ONE persisted read and the guard it records is unmoved
        # at return (so the recheck legitimately skips).
        label = "w18clean"
        orig_persisted = server._persisted_settings
        calls = [0]

        def counting():
            calls[0] += 1
            return orig_persisted()

        server._persisted_settings = counting
        try:
            verdict = server._clear_stranded_label(label)
        finally:
            server._persisted_settings = orig_persisted
        self.assertEqual(verdict, "ok")
        self.assertEqual(calls[0], 1)
        self.assertEqual(self._triple(), self._current())

    def test_w18_failed_clear_records_none(self):
        label = "w18fail"
        # Stranded in memory so the helper takes the save path,
        # then an undeletable per-label file forces "failed".
        with server._SETTINGS_LOCK:
            cur = list(server._SETTINGS.get("suspended") or [])
            cur.append(label)
            server._SETTINGS["suspended"] = cur
        blocker = self.tmp / "blocker"
        blocker.mkdir()
        saved_fns = (server._chat_path, server._userkey_path,
                     server._intg_path)
        server._chat_path = lambda _l: blocker
        server._userkey_path = lambda _l: blocker
        server._intg_path = lambda _l: blocker
        try:
            verdict = server._clear_stranded_label(label)
        finally:
            (server._chat_path, server._userkey_path,
             server._intg_path) = saved_fns
        self.assertEqual(verdict, "failed")
        self.assertIsNone(self._triple())


# =====================================================================
# Fixes 2+3 — the launcher, over real boots in a network namespace
# =====================================================================
ENGINE_CLAIM_JS = r"""
const http=require('http'),fs=require('fs');
fs.writeFileSync(process.env.ENGINE_PID,String(process.pid));
http.createServer((req,res)=>{let b='';req.on('data',c=>b+=c);
req.on('end',()=>{res.setHeader('Content-Type','application/json');
if(req.url==='/api/auth/status'){res.end(JSON.stringify({needsSetup:true}));}
else if(req.url==='/api/auth/setup'){fs.appendFileSync(process.env.SETUP_FILE,b+'\n');res.statusCode=201;res.end('{}');}
else{res.statusCode=404;res.end('{}');}});}).listen(3001,'127.0.0.1');
"""

ENGINE_DYING_JS = r"""
const http=require('http'),fs=require('fs');
fs.writeFileSync(process.env.ENGINE_PID,String(process.pid));
http.createServer((req,res)=>{let b='';req.on('data',c=>b+=c);
req.on('end',()=>{res.setHeader('Content-Type','application/json');
if(req.url==='/api/auth/status'){res.end(JSON.stringify({needsSetup:false}));}
else if(req.url==='/api/auth/login'){res.statusCode=500;res.end('{}');
fs.writeFileSync(process.env.DIED_FILE,'died');
setTimeout(()=>process.exit(42),150);}
else{res.statusCode=404;res.end('{}');}});}).listen(3001,'127.0.0.1');
"""

SQUATTER_JS = r"""
const http=require('http'),fs=require('fs');
// Poll for the genuine engine's death marker, THEN bind: the
// W2 posture (squatter arrives only after the child is dead).
const iv=setInterval(()=>{ if(fs.existsSync(process.env.DIED_FILE)){
clearInterval(iv);
http.createServer((req,res)=>{let b='';req.on('data',c=>b+=c);
req.on('end',()=>{fs.appendFileSync(process.env.SQUAT_FILE,
JSON.stringify({m:req.method,u:req.url,b})+'\n');
res.setHeader('Content-Type','application/json');
res.statusCode=200;res.end('{}');});}).listen(3001,'127.0.0.1');
fs.writeFileSync(process.env.SQUAT_PID,String(process.pid));
}},100);
"""

GATEWAY_JS = r"""
const http=require('http'),fs=require('fs');
fs.writeFileSync(process.env.SQUAT_PID,String(process.pid));
http.createServer((req,res)=>{let b='';req.on('data',c=>b+=c);
req.on('end',()=>{fs.appendFileSync(process.env.SQUAT_FILE,
JSON.stringify({m:req.method,u:req.url,b})+'\n');
res.setHeader('Content-Type','application/json');
if(req.url==='/api/auth/status'){res.end(JSON.stringify({needsSetup:process.env.GW_SETUP==='1'}));}
else if(req.url==='/api/auth/login'){res.statusCode=401;res.end('{}');}
else if(req.url==='/api/auth/setup'){res.statusCode=201;res.end('{}');}
else{res.statusCode=404;res.end('{}');}});}).listen(3001,'127.0.0.1');
"""

NODE_HARNESS_JS = r"""
const fs=require('fs');
const src=fs.readFileSync(process.argv[2],'utf8');
const a=src.indexOf('function parseEngineAdminCreds');
const b=src.indexOf('// Wave 13 (run-12 launcher): the shutdown path');
eval(src.slice(a,b));
if(process.argv[3]==='parse'){
  console.log(JSON.stringify(
    parseEngineAdminCreds(fs.readFileSync(process.argv[4],'utf8'))));
} else if(process.argv[3]==='remove'){
  removeEngineAdminCreds(process.argv[4]);
}
"""


class Wave18LauncherTests(unittest.TestCase):
    ENGINE_EMAIL = "boss18@example.com"
    ENGINE_PW = "recorded-pw-18"

    def setUp(self):
        self.node = shutil.which("node")
        if not self.node or not shutil.which("unshare"):
            self.skipTest("node/unshare not available")
        self._procs = []
        self._tmps = []

    def tearDown(self):
        for proc in self._procs:
            if proc.poll() is None:
                proc.kill()
                try:
                    proc.wait(timeout=10)
                except Exception:
                    pass
        for tmp in self._tmps:
            for name in ("engine.pid", "dash.pid", "squatter.pid"):
                f = tmp / name
                if f.exists():
                    try:
                        os.kill(int(f.read_text().strip()),
                                signal.SIGKILL)
                    except Exception:
                        pass
            shutil.rmtree(tmp, ignore_errors=True)

    # -- fixture ---------------------------------------------------
    def _fixture(self, env_bytes, engine_js):
        tmp = Path(tempfile.mkdtemp(prefix="nexus-test-w18-launcher-"))
        self._tmps.append(tmp)
        (tmp / "bin").mkdir()
        shutil.copy(REPO / "bin" / "nexuslocal.js", tmp / "bin")
        (tmp / "harness.js").write_text(NODE_HARNESS_JS)
        app = tmp / "app"
        srv = app / "engine" / "server"
        (srv / "dist").mkdir(parents=True)
        (app / "engine-data").mkdir()
        (app / "server.py").write_text(
            "import os, time\n"
            "with open(os.environ['DASH_PID'], 'w') as f:\n"
            "    f.write(str(os.getpid()))\n"
            "time.sleep(120)\n")
        (app / ".env").write_bytes(env_bytes)
        (srv / "package.json").write_text(json.dumps(
            {"name": "stub",
             "dependencies": {"dotenv": "^17.0.0", "express": "^5.0.0"}}))
        (srv / "package-lock.json").write_text("{}")
        nm = srv / "node_modules"
        nm.mkdir()
        for dep in ("dotenv", "express"):
            (nm / dep).mkdir()
            (nm / dep / "package.json").write_text("{}")
            (nm / dep / "index.js").write_text("")
        (nm / ".package-lock.json").write_text("{}")
        (srv / "dist" / "index.js").write_text(engine_js)
        return tmp

    def _boot(self, tmp, inner_prefix=""):
        env = dict(os.environ)
        env.update({
            "ENGINE_PID": str(tmp / "engine.pid"),
            "DASH_PID": str(tmp / "dash.pid"),
            "SETUP_FILE": str(tmp / "setup.jsonl"),
            "DIED_FILE": str(tmp / "died.marker"),
            "SQUAT_FILE": str(tmp / "squat.jsonl"),
            "SQUAT_PID": str(tmp / "squatter.pid"),
            "no_proxy": "127.0.0.1,localhost",
            "NO_PROXY": "127.0.0.1,localhost",
        })
        bash = (
            "ip link set lo up 2>/dev/null; "
            "curl -s -m 2 http://127.0.0.1:3001/api/auth/status "
            ">/dev/null 2>&1; "
            f"echo PRECHECK_OK curl_exit=$? >> {tmp / 'precheck.log'}; "
            + inner_prefix
            + f"exec {self.node} {tmp / 'bin' / 'nexuslocal.js'}")
        proc = subprocess.Popen(
            ["unshare", "-rn", "bash", "-c", bash],
            cwd=str(tmp), env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._procs.append(proc)
        return proc

    def _wait(self, proc, pred, timeout=30, tmp=None, what="condition"):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if pred():
                return True
            if proc.poll() is not None:
                break
            time.sleep(0.25)
        log = ""
        if tmp is not None and (tmp / "startup.log").exists():
            log = (tmp / "startup.log").read_text(errors="replace")
        self.fail(f"launcher {what} not reached; log tail:\n"
                  + log[-1200:])

    def _precheck_ok(self, tmp):
        f = tmp / "precheck.log"
        deadline = time.time() + 15
        while time.time() < deadline and not f.exists():
            time.sleep(0.2)
        self.assertTrue(f.exists(), "no pre-check was logged")
        # curl_exit=7: connection refused — 3001 was free inside
        # the namespace before anything of ours bound it.
        self.assertIn("PRECHECK_OK curl_exit=7", f.read_text())

    def _harness(self, tmp, *args):
        r = subprocess.run([self.node, str(tmp / "harness.js"),
                            str(tmp / "bin" / "nexuslocal.js"), *args],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.strip()

    # -- Fix 3: removal leg, CRLF matrix (unit, no boot) -----------
    def test_w18_remove_creds_crlf_matrix(self):
        tmp = self._fixture(b"", ENGINE_CLAIM_JS)
        cases = [
            (b"KEEP=1\r\nENGINE_ADMIN_PASSWORD=x\r\n"
             b"ENGINE_ADMIN_EMAIL=e\r\nTAIL=9\r\n",
             b"KEEP=1\r\nTAIL=9\r\n"),
            (b"KEEP=1\r\nENGINE_ADMIN_PASSWORD=x\nTAIL=9\n",
             b"KEEP=1\r\nTAIL=9\n"),
            (b"ENGINE_ADMIN_PASSWORD=x\r\nKEEP=1\r\n",
             b"KEEP=1\r\n"),
            # LF control: byte-identical to the old behaviour.
            (b"KEEP=1\nENGINE_ADMIN_PASSWORD=x\n"
             b"ENGINE_ADMIN_EMAIL=e\nTAIL=9\n",
             b"KEEP=1\nTAIL=9\n"),
        ]
        for i, (given, want) in enumerate(cases):
            f = tmp / f"case{i}.env"
            f.write_bytes(given)
            self._harness(tmp, "remove", str(f))
            self.assertEqual(f.read_bytes(), want, (i, given))

    # -- Fix 3: claim rewrite leg over real boots ------------------
    def test_w18_claim_rewrite_crlf_roundtrip(self):
        shapes = [
            b"ENCRYPTION_KEY=abc\r\nENGINE_ADMIN_PASSWORD=\r\n"
            b"ENGINE_ADMIN_EMAIL=\r\n",
            b"ENCRYPTION_KEY=abc\r\nENGINE_ADMIN_PASSWORD=\n"
            b"ENGINE_ADMIN_EMAIL=\nTAIL=1\n",
            b"ENGINE_ADMIN_PASSWORD=\r\nENGINE_ADMIN_EMAIL=\r\n"
            b"ENCRYPTION_KEY=abc\r\n",
        ]
        for i, env_bytes in enumerate(shapes):
            tmp = self._fixture(env_bytes, ENGINE_CLAIM_JS)
            proc = self._boot(tmp)
            self._precheck_ok(tmp)
            self._wait(proc, lambda: (tmp / "setup.jsonl").exists(),
                       tmp=tmp, what=f"claim setup POST (shape {i})")
            self._wait(
                proc,
                lambda: "Engine admin claimed" in
                        (tmp / "startup.log").read_text(
                            errors="replace"),
                tmp=tmp, what=f"claim log (shape {i})")
            time.sleep(0.5)
            setup = json.loads(
                (tmp / "setup.jsonl").read_text().splitlines()[0])
            out = json.loads(self._harness(
                tmp, "parse", str(tmp / "app" / ".env")))
            # Pre-fix: the rewrites glued the cred lines and the
            # launcher's own parser read both back as absent.
            self.assertEqual(out.get("email"), "owner@example.com",
                             (i, out))
            self.assertEqual(out.get("password"), setup["password"],
                             (i, out))
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)

    # -- Fix 2, W2: engine dies mid-verify, squatter gets nothing --
    def test_w18_w2_no_credential_post_after_engine_death(self):
        env = (f"ENGINE_ADMIN_EMAIL={self.ENGINE_EMAIL}\n"
               f"ENGINE_ADMIN_PASSWORD={self.ENGINE_PW}\n").encode()
        tmp = self._fixture(env, ENGINE_DYING_JS)
        (tmp / "squatter.js").write_text(SQUATTER_JS)
        proc = self._boot(
            tmp, inner_prefix=f"{self.node} {tmp / 'squatter.js'} & ")
        self._precheck_ok(tmp)

        def settled():
            log = ""
            if (tmp / "startup.log").exists():
                log = (tmp / "startup.log").read_text(errors="replace")
            return ("NOT sending" in log
                    or (tmp / "squat.jsonl").exists())

        self._wait(proc, settled, timeout=25, tmp=tmp,
                   what="post-death verdict")
        time.sleep(4)  # let any (pre-fix) retry land + be recorded
        log = (tmp / "startup.log").read_text(errors="replace")
        # Post-fix: the retry checks liveness first and sends
        # nothing; the squatter bound after the death captures
        # zero requests, and the credentials are KEPT.
        self.assertIn("NOT sending", log)
        self.assertFalse((tmp / "squat.jsonl").exists(),
                         (tmp / "squat.jsonl").read_text()
                         if (tmp / "squat.jsonl").exists() else "")
        env_after = (tmp / "app" / ".env").read_bytes()
        self.assertIn(b"ENGINE_ADMIN_PASSWORD", env_after)
        self.assertNotIn("NOT the ones from app/.env", log)

    # -- Fix 2, pre-bound port: no spawn, no POSTs, creds kept -----
    def _prebound(self, gw_setup):
        env = (f"ENGINE_ADMIN_EMAIL={self.ENGINE_EMAIL}\n"
               f"ENGINE_ADMIN_PASSWORD={self.ENGINE_PW}\n").encode()
        tmp = self._fixture(env, ENGINE_CLAIM_JS)
        (tmp / "gateway.js").write_text(GATEWAY_JS)
        prefix = (f"GW_SETUP={'1' if gw_setup else '0'} "
                  f"{self.node} {tmp / 'gateway.js'} & "
                  f"for i in $(seq 1 50); do "
                  f"[ -f {tmp / 'squatter.pid'} ] && break; "
                  f"sleep 0.1; done; ")
        proc = self._boot(tmp, inner_prefix=prefix)
        self._precheck_ok(tmp)
        self._wait(
            proc,
            lambda: (tmp / "startup.log").exists()
            and "port 3001 already in use" in
                (tmp / "startup.log").read_text(errors="replace"),
            timeout=25, tmp=tmp, what="port-in-use refusal")
        time.sleep(2)
        log = (tmp / "startup.log").read_text(errors="replace")
        self.assertIn("port 3001 already in use", log)
        # Our engine child was never spawned into the collision.
        self.assertFalse((tmp / "engine.pid").exists())
        # The foreign responder received NO requests at all from
        # the launcher (the probe is a bare TCP connect), and in
        # particular no credential POSTs and no foreign claim.
        self.assertFalse((tmp / "squat.jsonl").exists(),
                         (tmp / "squat.jsonl").read_text()
                         if (tmp / "squat.jsonl").exists() else "")
        # No credential deletion, no false foreign-claim alarm.
        env_after = (tmp / "app" / ".env").read_bytes()
        self.assertIn(b"ENGINE_ADMIN_PASSWORD", env_after)
        self.assertNotIn("NOT the ones from app/.env", log)
        self.assertNotIn("Engine admin claimed", log)

    def test_w18_prebound_verify_shaped_gateway_refused(self):
        self._prebound(gw_setup=False)

    def test_w18_prebound_claim_shaped_gateway_refused(self):
        self._prebound(gw_setup=True)


if __name__ == "__main__":
    unittest.main()
