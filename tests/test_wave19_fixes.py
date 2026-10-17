#!/usr/bin/env python3
"""Regression tests for the wave-19 fixes (security audit run-18:
5 confirmed findings, all LOW).

Fix 1 (D18-1, app/server.py): _restore_access's users.enc bytes
guard is an OUTSIDE-LOCK retry loop — no PBKDF2 decrypt runs
inside the _ACCESS_LOCK hold on the retry path (bounded 3
attempts, then a fallback that judges the freshest bytes under
the lock). The wave-18 merge semantics are unchanged: current
store wins, a label revoked mid-decrypt is not resurrected, a
creation landing mid-decrypt survives.
Fix 2 (D18-2, app/server.py): a failed users.enc backup write is
no longer swallowed — both swallow sites (the _save_access
backup write and the restore merge's convergence refresh) raise
a PERSISTENT divergence flag in a _SETTINGS key recording the
intended label set. The login restore consults it: it fires even
when the live store is non-empty, caps backup-sourced labels to
the intended set (a revoked label stays excluded after a full
wipe), recovers intended labels from the live stores, and
re-converges users.enc, clearing the flag only on a successful
users.enc write (the merge refresh or any master-bearing save).
Fix 3 (L18-L1, bin/nexuslocal.js): parseEngineAdminCreds splits
on /\\r\\n|\\r|\\n/ — CRCRLF, CR-only and trailing-CR-at-EOF
credential records parse to the recorded creds, as dotenv does.
Fix 4 (L18-L2, bin/nexuslocal.js): the four write-back regexes
use [^\\S\\r\\n] instead of [ \\t], so VT/FF/NBSP-led credential
lines (which the parser accepts) are rewritten/removed exactly
like plain lines, while LF/CRLF behaviour is byte-identical.
Fix 5 (L18-L3, bin/nexuslocal.js): an exclusive single-instance
lockfile (.nexuslocal.lock, 'wx', pid inside, held for the
process lifetime) — a second launcher exits with an
already-running message before any probe/spawn/engine traffic;
a stale lock whose pid is dead is reclaimed.

Run:  python3 -m unittest tests.test_wave19_fixes -v
   or python3 -m unittest discover -s tests
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
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
import test_wave18_fixes as _w18  # noqa: E402

MASTER = _a16.MASTER

ENGINE_CLAIM_JS = _w18.ENGINE_CLAIM_JS
NODE_HARNESS_JS = _w18.NODE_HARNESS_JS


# =====================================================================
# Fixes 1+2 — the restore merge, lock placement, divergence flag
# =====================================================================
class Wave19RestoreUnitTests(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="nexus-test-w19-restore-"))
        self._saved = (server.ACCESS_PATH, server.USERS_PATH,
                       server.ACCESS_ENC_PATH, server.SETTINGS_PATH,
                       server.SETTINGS_ENC_PATH, server.RESTORE_KEY,
                       server.decrypt_keys, server.encrypt_keys)
        server.ACCESS_PATH = self.tmp / "access.json"
        server.USERS_PATH = self.tmp / "users.enc"
        server.ACCESS_ENC_PATH = self.tmp / "access.enc"
        server.SETTINGS_PATH = self.tmp / "settings.json"
        server.SETTINGS_ENC_PATH = self.tmp / "settings.enc"
        # No restore key in these unit tests: the settings mirror
        # is skipped (plain settings.json is the persisted copy
        # the flag assertions read) and _write_access_enc no-ops.
        server.RESTORE_KEY = ""
        self._settings_saved = dict(server._SETTINGS)
        server._SETTINGS["access_backup_diverged"] = None
        # getattr guard: on the PRE-fix tree the wave-19 mem
        # backstop does not exist yet — the D18-1 test must fail
        # on its own lock assertion there, not on a setUp error.
        if hasattr(server, "_BACKUP_DIVERGED_MEM"):
            server._BACKUP_DIVERGED_MEM[0] = None
        self.users = {"oldone": "hash-old-1", "oldtwo": "hash-old-2"}
        encrypt_keys(self.users, MASTER, server.USERS_PATH)
        server.ACCESS_PATH.write_text("{}")

    def tearDown(self):
        (server.ACCESS_PATH, server.USERS_PATH,
         server.ACCESS_ENC_PATH, server.SETTINGS_PATH,
         server.SETTINGS_ENC_PATH, server.RESTORE_KEY,
         server.decrypt_keys, server.encrypt_keys) = self._saved
        server._SETTINGS.clear()
        server._SETTINGS.update(self._settings_saved)
        if hasattr(server, "_BACKUP_DIVERGED_MEM"):
            server._BACKUP_DIVERGED_MEM[0] = None
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- helpers ----------------------------------------------------
    def _persisted_access(self):
        return json.loads(server.ACCESS_PATH.read_text())

    def _persisted_settings(self):
        return json.loads(server.SETTINGS_PATH.read_text())

    def _fault_users_enc(self, on=True):
        orig = self._saved[7]

        def wrapper(d, pw, path):
            if on and Path(path) == server.USERS_PATH:
                raise OSError("injected users.enc fault (wave19)")
            return orig(d, pw, path)

        server.encrypt_keys = wrapper

    # -- Fix 1: no decrypt inside the lock on the retry path --------
    def test_w19_bytes_change_retries_outside_lock(self):
        users = dict(self.users)
        users["revokeme"] = "hash-revoked"
        encrypt_keys(users, MASTER, server.USERS_PATH)
        orig_decrypt = self._saved[6]
        calls = []

        def wrap_decrypt(path, pw):
            # Is _ACCESS_LOCK held by THIS thread right now?
            try:
                held = server._ACCESS_LOCK._is_owned()
            except Exception:
                held = not server._ACCESS_LOCK.acquire(blocking=False)
                if not held:
                    server._ACCESS_LOCK.release()
            calls.append(held)
            result = orig_decrypt(path, pw)
            if len(calls) == 1:
                # Mid-decrypt window: a creation lands in the live
                # store AND a master-bearing save rewrites
                # users.enc without the revoked label.
                with server._ACCESS_LOCK:
                    server._save_access({"newlabel": "hash-new"})
                encrypt_keys(self.users, MASTER, server.USERS_PATH)
            return result

        server.decrypt_keys = wrap_decrypt
        server._restore_access(MASTER)
        # The bytes changed, so the retry loop must have decrypted
        # at least twice — and NEVER inside the lock hold.
        # (Pre-fix: the second decrypt ran inside the lock.)
        self.assertGreaterEqual(len(calls), 2, calls)
        self.assertFalse(any(calls),
                         f"decrypt ran inside _ACCESS_LOCK: {calls}")
        merged = self._persisted_access()
        self.assertNotIn("revokeme", merged)
        self.assertEqual(merged.get("newlabel"), "hash-new")
        self.assertEqual(merged.get("oldone"), "hash-old-1")
        self.assertEqual(merged.get("oldtwo"), "hash-old-2")
        backup = decrypt_keys(server.USERS_PATH, MASTER)
        self.assertEqual(backup.get("newlabel"), "hash-new")
        self.assertNotIn("revokeme", backup)

    def test_w19_retry_exhaustion_fallback_still_merges(self):
        # users.enc changes on EVERY decrypt (fresh salt each
        # rewrite): the bounded retry loop exhausts and the
        # fallback judges the freshest bytes under the lock —
        # the restore still completes with the backup's labels.
        orig_decrypt = self._saved[6]
        state = {"n": 0}

        def wrap_decrypt(path, pw):
            result = orig_decrypt(path, pw)
            state["n"] += 1
            encrypt_keys(self.users, MASTER, server.USERS_PATH)
            return result

        server.decrypt_keys = wrap_decrypt
        server._restore_access(MASTER)
        self.assertGreaterEqual(state["n"], 3)
        merged = self._persisted_access()
        self.assertEqual(merged.get("oldone"), "hash-old-1")
        self.assertEqual(merged.get("oldtwo"), "hash-old-2")

    # -- Fix 2, I2: faulted revoke — flag, no resurrection, heal ----
    def test_w19_faulted_revoke_flagged_and_never_resurrected(self):
        both = {"friendone": "hash-f1", "solo": "hash-solo"}
        server.ACCESS_PATH.write_text(json.dumps(both))
        encrypt_keys(both, MASTER, server.USERS_PATH)
        self._fault_users_enc(True)
        with server._ACCESS_LOCK:
            d = server._load_access()
            del d["solo"]
            server._save_access(d, MASTER)
        self._fault_users_enc(False)
        server.encrypt_keys = self._saved[7]
        # The revoke took effect in the live stores…
        self.assertNotIn("solo", self._persisted_access())
        # …and the swallowed write is now RECORDED, with the
        # intended label set (revoked label excluded).
        flag = server._backup_diverged()
        self.assertIsNotNone(flag)
        self.assertEqual(flag["intended_labels"], ["friendone"])
        # The flag is PERSISTENT (settings on disk), so it
        # survives a restart: simulate one by dropping the
        # in-memory copies and re-reading the persisted settings.
        persisted = self._persisted_settings()
        self.assertEqual(
            persisted["access_backup_diverged"]["intended_labels"],
            ["friendone"])
        server._BACKUP_DIVERGED_MEM[0] = None
        server._SETTINGS["access_backup_diverged"] = \
            persisted["access_backup_diverged"]
        self.assertIsNotNone(server._backup_diverged())
        # Full wipe of both live stores, then the login restore:
        # the stale backup must NOT resurrect the revoked label.
        server.ACCESS_PATH.write_text("{}")
        server._restore_access(MASTER)
        merged = self._persisted_access()
        self.assertNotIn("solo", merged)
        self.assertEqual(merged.get("friendone"), "hash-f1")
        # The restore re-converged the backup and cleared the flag.
        backup = decrypt_keys(server.USERS_PATH, MASTER)
        self.assertNotIn("solo", backup)
        self.assertEqual(backup.get("friendone"), "hash-f1")
        self.assertIsNone(server._backup_diverged())
        self.assertIsNone(
            self._persisted_settings()["access_backup_diverged"])

    def test_w19_successful_master_save_heals_and_clears_flag(self):
        both = {"friendone": "hash-f1", "solo": "hash-solo"}
        server.ACCESS_PATH.write_text(json.dumps(both))
        encrypt_keys(both, MASTER, server.USERS_PATH)
        self._fault_users_enc(True)
        with server._ACCESS_LOCK:
            d = server._load_access()
            del d["solo"]
            server._save_access(d, MASTER)
        server.encrypt_keys = self._saved[7]
        self.assertIsNotNone(server._backup_diverged())
        # The next successful master-bearing save rewrites
        # users.enc from the live store: proven convergence,
        # so the flag clears and the backup matches the store.
        with server._ACCESS_LOCK:
            server._save_access(server._load_access(), MASTER)
        self.assertIsNone(server._backup_diverged())
        backup = decrypt_keys(server.USERS_PATH, MASTER)
        self.assertEqual(backup, {"friendone": "hash-f1"})

    # -- Fix 2, I1: faulted merge refresh — flag, second login ----
    def test_w19_faulted_merge_refresh_flagged_and_reconverged(self):
        encrypt_keys({"friendone": "hash-f1"}, MASTER,
                     server.USERS_PATH)
        orig_decrypt = self._saved[6]
        state = {"fired": False}

        def wrap_decrypt(path, pw):
            result = orig_decrypt(path, pw)
            if not state["fired"]:
                state["fired"] = True
                # A creation lands during the restore's decrypt.
                with server._ACCESS_LOCK:
                    server._save_access({"newlabel": "hash-new"})
            return result

        server.decrypt_keys = wrap_decrypt
        self._fault_users_enc(True)
        server._restore_access(MASTER)
        server.decrypt_keys = self._saved[6]
        server.encrypt_keys = self._saved[7]
        # The merge itself landed in the live store…
        merged = self._persisted_access()
        self.assertEqual(merged.get("friendone"), "hash-f1")
        self.assertEqual(merged.get("newlabel"), "hash-new")
        # …but the convergence refresh faulted, so the backup
        # still lacks the creation — and the flag records the
        # intended set that failed to reach it.
        backup = decrypt_keys(server.USERS_PATH, MASTER)
        self.assertNotIn("newlabel", backup)
        flag = server._backup_diverged()
        self.assertIsNotNone(flag)
        self.assertEqual(flag["intended_labels"],
                         ["friendone", "newlabel"])
        # Second login: the flag forces the merge even though the
        # live store is non-empty (the old needs-gate would have
        # short-circuited forever). The merged label is recovered
        # from the live store, the backup re-converges, the flag
        # clears.
        server._restore_access(MASTER)
        backup = decrypt_keys(server.USERS_PATH, MASTER)
        self.assertEqual(backup.get("newlabel"), "hash-new")
        self.assertEqual(backup.get("friendone"), "hash-f1")
        self.assertIsNone(server._backup_diverged())


# =====================================================================
# Fixes 3+4+5 — the launcher
# =====================================================================
class Wave19LauncherTests(unittest.TestCase):
    ENGINE_EMAIL = "boss19@example.com"
    ENGINE_PW = "recorded-pw-19"

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

    # -- fixture (wave-18 shape) ------------------------------------
    def _fixture(self, env_bytes, engine_js):
        tmp = Path(tempfile.mkdtemp(prefix="nexus-test-w19-launcher-"))
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
        self.assertIn("PRECHECK_OK curl_exit=7", f.read_text())

    def _harness(self, tmp, *args):
        r = subprocess.run([self.node, str(tmp / "harness.js"),
                            str(tmp / "bin" / "nexuslocal.js"), *args],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout.strip()

    # -- Fix 3: parser accepts CR line endings (unit) ---------------
    def test_w19_parser_cr_line_endings(self):
        tmp = self._fixture(b"", ENGINE_CLAIM_JS)
        em, pw = self.ENGINE_EMAIL, self.ENGINE_PW
        cases = [
            # CRCRLF (double conversion)
            f"ENGINE_ADMIN_EMAIL={em}\r\r\n"
            f"ENGINE_ADMIN_PASSWORD={pw}\r\r\n".encode(),
            # CR-only file
            f"ENGINE_ADMIN_EMAIL={em}\r"
            f"ENGINE_ADMIN_PASSWORD={pw}\r".encode(),
            # Trailing CR at EOF, password last
            f"ENGINE_ADMIN_EMAIL={em}\n"
            f"ENGINE_ADMIN_PASSWORD={pw}\r".encode(),
            # Trailing CR at EOF, email last
            f"ENGINE_ADMIN_PASSWORD={pw}\n"
            f"ENGINE_ADMIN_EMAIL={em}\r".encode(),
            # Controls: LF and CRLF parse as before.
            f"ENGINE_ADMIN_EMAIL={em}\n"
            f"ENGINE_ADMIN_PASSWORD={pw}\n".encode(),
            f"ENGINE_ADMIN_EMAIL={em}\r\n"
            f"ENGINE_ADMIN_PASSWORD={pw}\r\n".encode(),
        ]
        for i, given in enumerate(cases):
            f = tmp / f"parse{i}.env"
            f.write_bytes(given)
            out = json.loads(self._harness(tmp, "parse", str(f)))
            self.assertTrue(out.get("hasEmail"), (i, out))
            self.assertTrue(out.get("hasPassword"), (i, out))
            self.assertEqual(out.get("email"), em, (i, out))
            self.assertEqual(out.get("password"), pw, (i, out))

    # -- Fix 4: removal of exotic-led lines (unit) ------------------
    def test_w19_remove_exotic_leads(self):
        tmp = self._fixture(b"", ENGINE_CLAIM_JS)
        cases = [
            (b"\x0bENGINE_ADMIN_PASSWORD=x\nKEEP=1\n",
             b"KEEP=1\n"),
            (b"\x0cENGINE_ADMIN_PASSWORD=x\nKEEP=1\n",
             b"KEEP=1\n"),
            (("\u00a0ENGINE_ADMIN_PASSWORD=x\n"
              "KEEP=1\n").encode("utf-8"),
             b"KEEP=1\n"),
            (b"\x0bexport ENGINE_ADMIN_EMAIL=e\nKEEP=1\n",
             b"KEEP=1\n"),
            # Exotic lead + CRLF ending: neighbour byte-identical.
            (b"\x0bENGINE_ADMIN_PASSWORD=x\r\nKEEP=1\r\n",
             b"KEEP=1\r\n"),
            # Plain control (wave-18 matrix shape).
            (b"KEEP=1\r\nENGINE_ADMIN_PASSWORD=x\r\nTAIL=9\r\n",
             b"KEEP=1\r\nTAIL=9\r\n"),
        ]
        for i, (given, want) in enumerate(cases):
            f = tmp / f"rm{i}.env"
            f.write_bytes(given)
            self._harness(tmp, "remove", str(f))
            self.assertEqual(f.read_bytes(), want, (i, given))

    # -- Fix 4: claim rewrite of exotic-led lines (real boots) ------
    def test_w19_claim_rewrite_exotic_leads(self):
        shapes = [
            b"ENCRYPTION_KEY=abc\n\x0bENGINE_ADMIN_PASSWORD=\n"
            b"\x0bENGINE_ADMIN_EMAIL=\n",
            ("\u00a0ENGINE_ADMIN_PASSWORD=\n"
             "\u00a0ENGINE_ADMIN_EMAIL=\n").encode("utf-8"),
            b"ENCRYPTION_KEY=abc\n\x0cENGINE_ADMIN_PASSWORD=\n"
            b"\x0cENGINE_ADMIN_EMAIL=\n",
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
            # Pre-fix: the in-place rewrite no-oped on the exotic
            # lead, nothing was appended, and the POSTed password
            # was recorded NOWHERE while success was logged.
            self.assertEqual(out.get("password"), setup["password"],
                             (i, out))
            self.assertEqual(out.get("email"), "owner@example.com",
                             (i, out))
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=10)

    # -- Fix 5: second launcher exits, zero engine traffic ----------
    def test_w19_second_launcher_exits_already_running(self):
        env = b"ENCRYPTION_KEY=abc\n"
        tmp = self._fixture(env, ENGINE_CLAIM_JS)
        proc_a = self._boot(tmp)
        self._precheck_ok(tmp)
        self._wait(proc_a, lambda: (tmp / "setup.jsonl").exists(),
                   tmp=tmp, what="first launcher claim")
        self._wait(
            proc_a,
            lambda: "Engine admin claimed" in
                    (tmp / "startup.log").read_text(errors="replace"),
            tmp=tmp, what="first launcher claim log")
        engine_pid_before = (tmp / "engine.pid").read_text()
        # Second launcher on the SAME install (its own netns, so
        # the pre-check still proves 3001 was free inside it): the
        # lock file is on the shared filesystem, its pid is live,
        # so this launcher must exit before any engine traffic.
        proc_b = self._boot(tmp)
        self._wait(proc_b, lambda: proc_b.poll() is not None,
                   timeout=20, tmp=tmp, what="second launcher exit")
        self.assertEqual(proc_b.returncode, 0)
        log = (tmp / "startup.log").read_text(errors="replace")
        self.assertIn("nexuslocal is already running", log)
        # Zero additional engine traffic: exactly one setup POST
        # (the first launcher's), and the engine is still A's.
        time.sleep(1)
        setups = (tmp / "setup.jsonl").read_text().splitlines()
        self.assertEqual(len(setups), 1, setups)
        self.assertEqual((tmp / "engine.pid").read_text(),
                         engine_pid_before)
        self.assertIsNone(proc_a.poll())

    # -- Fix 5: a stale lock (dead pid) is reclaimed -----------------
    def test_w19_stale_lock_reclaimed(self):
        tmp = self._fixture(b"ENCRYPTION_KEY=abc\n",
                              ENGINE_CLAIM_JS)
        # A pid that is provably dead: a child that already exited.
        proc_dead = subprocess.Popen([self.node, "-e", ""])
        proc_dead.wait(timeout=10)
        dead_pid = proc_dead.pid
        with self.assertRaises(ProcessLookupError):
            os.kill(dead_pid, 0)
        (tmp / ".nexuslocal.lock").write_text(str(dead_pid))
        proc = self._boot(tmp)
        self._precheck_ok(tmp)
        self._wait(proc, lambda: (tmp / "setup.jsonl").exists(),
                   tmp=tmp, what="boot after stale lock")
        log = (tmp / "startup.log").read_text(errors="replace")
        self.assertNotIn("already running", log)
        # The lock now names the live launcher, not the dead pid.
        self.assertEqual(
            (tmp / ".nexuslocal.lock").read_text().strip(),
            str(proc.pid))


if __name__ == "__main__":
    unittest.main()
