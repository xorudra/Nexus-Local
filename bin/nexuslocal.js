#!/usr/bin/env node
/**
 * nexuslocal - Global CLI launcher for Nexus-Local
 *
 * Install: npm install -g nexuslocal
 * Run:     nexuslocal (from any directory)
 *
 * This script locates the installed package and launches the
 * dashboard + engine, reusing the same setup logic as start.bat.
 */
"use strict";

const { spawn, execSync } = require("child_process");
const path = require("path");
const fs = require("fs");
const os = require("os");

// Package root = parent of bin/
const PKG_ROOT = path.join(__dirname, "..");
const APP_DIR = path.join(PKG_ROOT, "app");
const LOG_FILE = path.join(PKG_ROOT, "startup.log");

function log(msg) {
  const line = `[${new Date().toISOString()}] ${msg}\n`;
  try { fs.appendFileSync(LOG_FILE, line); } catch (e) {}
  console.log(msg);
}

function findPython() {
  // Check system Python first
  for (const cmd of ["python", "python3", "py"]) {
    try {
      execSync(`"${cmd}" --version`, { stdio: "ignore", windowsHide: true });
      return cmd;
    } catch (e) {}
  }
  // Check portable Python in tools/
  const toolsPython = path.join(PKG_ROOT, "tools", "python", "python.exe");
  if (fs.existsSync(toolsPython)) return `"${toolsPython}"`;
  return null;
}

// Wave 12 (L1/L2/L3): ONE shared .env reader for the ENGINE_ADMIN
// credentials, used by the claim path, the verify path and the
// credential-removal path. dotenv grammar for these keys: a leading
// BOM is stripped, whitespace around `=` is tolerated, one layer of
// surrounding single/double quotes is stripped, an EMPTY value
// counts as ABSENT (a later line for the same key wins over an
// empty earlier one), and the first non-empty match wins. The old
// private regex readers disagreed with all of that: an empty first
// line shadowed valid credentials in verifyClaim, quoted/spaced
// values were read literally (a quoted password was POSTed with its
// quotes on, and the 401 that earned deleted every credential
// line), and a BOM made the first line invisible.
function parseEngineAdminCreds(envTxt) {
  let txt = envTxt || "";
  if (txt.charCodeAt(0) === 0xFEFF) txt = txt.slice(1);
  const out = { hasEmail: false, hasPassword: false };
  for (const line of txt.split(/\r?\n/)) {
    const m = line.match(/^\s*(?:export\s+)?(ENGINE_ADMIN_EMAIL|ENGINE_ADMIN_PASSWORD)\s*=\s*(.*)$/);
    if (!m) continue;
    const isEmail = m[1] === "ENGINE_ADMIN_EMAIL";
    if (isEmail) out.hasEmail = true; else out.hasPassword = true;
    let v = m[2].trim();
    // The value with NO comment handling at all (quote-strip only):
    // the alternate form verifyClaim retries with before it may
    // declare a foreign claim (wave 14, run-13 launcher L13-2).
    let raw = v;
    if (raw.length >= 2
        && ((raw[0] === '"' && raw[raw.length - 1] === '"')
            || (raw[0] === "'" && raw[raw.length - 1] === "'"))) {
      raw = raw.slice(1, -1);
    }
    // Wave 13 (run-12 launcher): dotenv's inline-comment rule —
    // an unquoted value truncates at the first '#' (even with no
    // preceding space, so `= # none yet` is EMPTY, i.e. absent);
    // a quoted value ends at its closing quote and the rest is a
    // comment. The existing quote-strip below then applies.
    // Wave 14 (run-13 launcher): (L13-1) the closing-quote scan is
    // escape-aware — a quote preceded by an ODD number of
    // backslashes is data, not the terminator, exactly as dotenv
    // treats it; the old indexOf truncated `"a\"b#c"` to `a\` and
    // verify then DELETED valid credentials. (L13-2) the unquoted
    // branch treats '#' as a comment starter only at value start
    // or when preceded by whitespace (/^#/ or /\s+#/): this
    // record's authoritative value is the engine password itself
    // (an arbitrary API-set / pre-seeded string that never passed
    // through dotenv grammar), so a '#' inside it is data — while
    // `abc123 # comment` and `= # none yet` keep their run-12
    // behaviour.
    const _quoted15 = v.startsWith('"') || v.startsWith("'");
    if (_quoted15) {
      const q = v[0];
      let end = -1;
      for (let i = 1; i < v.length; i++) {
        if (v[i] !== q) continue;
        let bs = 0;
        for (let j = i - 1; j >= 0 && v[j] === "\\"; j--) bs++;
        if (bs % 2 === 0) { end = i; break; }
      }
      if (end > 0) {
        // Truncate only when what follows the closing quote is
        // empty or a comment; otherwise the quotes are data
        // throughout (dotenv: `"abc""def"` -> `abc""def`) and the
        // whole-value quote-strip below applies instead.
        const rest = v.slice(end + 1);
        if (/^\s*(#.*)?$/.test(rest)) v = v.slice(0, end + 1);
      }
    } else {
      const hm = v.match(/\s+#|^#/);
      if (hm) v = v.slice(0, hm.index).trim();
    }
    let _dqPre16 = null;
    if (v.length >= 2
        && ((v[0] === '"' && v[v.length - 1] === '"')
            || (v[0] === "'" && v[v.length - 1] === "'"))) {
      const _dq15 = v[0] === '"';
      v = v.slice(1, -1);
      // Wave 15 (run-14 launcher L14-1): dotenv 17 expands exactly
      // \n and \r in DOUBLE-quoted values, in this order, with
      // these regexes — \t, \\ and \" stay literal, and
      // single-quoted values are never expanded.
      if (_dq15) {
        // Wave 16 (run-15 launcher L15-1): remember the
        // pre-expansion literal — when the expansion changed the
        // value it becomes the password alternate below (the
        // primary in every pre-wave-15 release, and the form a
        // legacy engine may still hold).
        _dqPre16 = v;
        v = v.replace(/\\n/g, "\n").replace(/\\r/g, "\r");
        if (v === _dqPre16) _dqPre16 = null;
      }
    }
    if (!v) continue;  // empty = absent: fall through to a later line
    if (isEmail && out.email === undefined) out.email = v;
    if (!isEmail && out.password === undefined) {
      out.password = v;
      // The alternate form for verifyClaim's one retry: the raw
      // value when comment handling shortened the primary, else
      // (symmetrically) the dotenv-truncated value when the
      // primary kept a '#' the engine may not hold.
      let alt = null;
      // Wave 15 (run-14 launcher L14-2, leg (a) only): the
      // alternate is built ONLY from unquoted lines, where the
      // raw and truncated forms are both genuine alternate
      // parses. For a quoted line the raw tail still carries the
      // quotes and the comment text — a candidate that can never
      // be the engine password — and the primary parse is
      // authoritative, so no alternate is offered.
      if (!_quoted15) {
        if (raw && raw !== v) alt = raw;
        else {
          const h = v.indexOf("#");
          if (h > 0) alt = v.slice(0, h).trim() || null;
        }
      } else if (_dqPre16) {
        // Wave 16 (run-15 launcher L15-1, backslash leg only):
        // a DOUBLE-quoted line whose expansion changed the value
        // offers the pre-expansion literal as its one alternate —
        // a genuine alternate parse, NOT the raw-tail junk alt
        // L14-2(a) killed (that still carried quotes and comment
        // text), and NOT a pre-'#' alternate (that leg was
        // rejected in run-15: no reader ever parsed a quoted
        // value truncated at '#').
        alt = _dqPre16;
      }
      if (alt && alt !== v) out.passwordAlt = alt;
    }
  }
  return out;
}

function readEngineAdminCreds(envFile) {
  try {
    return parseEngineAdminCreds(fs.readFileSync(envFile, "utf8"));
  } catch (e) {
    return { hasEmail: false, hasPassword: false };
  }
}

function removeEngineAdminCreds(envFile) {
  // The credential-removal path uses the same grammar: drop EVERY
  // ENGINE_ADMIN line, whatever its spacing, quoting or BOM.
  const envTxt = fs.readFileSync(envFile, "utf8");
  fs.writeFileSync(envFile,
    envTxt.replace(/^\uFEFF?\s*(?:export\s+)?ENGINE_ADMIN_(EMAIL|PASSWORD)\s*=.*\r?\n?/gm, ""));
  try { fs.chmodSync(envFile, 0o600); } catch (e) {}
}

// Wave 13 (run-12 launcher): the shutdown path and the child
// registry live at module scope so the signal handlers can be
// registered at the TOP of main() — before the dependency gates.
// A pid-targeted SIGTERM during the (possibly minutes-long) first
// install used to orphan the npm child, which kept rewriting
// node_modules invisibly; the handlers now exist from the start
// and shutdown() can kill the in-flight install child too.
let engine = null;
let dashboard = null;
let installChild = null;
let shuttingDown = false;
let _shutdownCode = 0;

function _killTree(child, sig) {
  if (!child) return;
  // Install children are spawned detached on POSIX so the whole
  // process GROUP (sh -> npm -> its children) gets the signal.
  if (child === installChild && process.platform !== "win32"
      && child.pid) {
    try { process.kill(-child.pid, sig); return; } catch (e) {}
  }
  try { child.kill(sig); } catch (e) {}
}

function shutdown(code) {
  if (shuttingDown) return;
  shuttingDown = true;  // F15: the engine exit this causes is ours
  _shutdownCode = code || 0;
  log("Shutting down...");
  // Wave 14 (run-13 launcher L13-3): capture the install child (and
  // its process group) NOW. The direct child's own close handler
  // nulls the global installChild as soon as the shell dies on the
  // group SIGTERM — well before the 1500ms escalation — so an
  // escalation that re-read the global had no target and a
  // TERM-ignoring install grandchild survived launcher exit.
  const _install14 = installChild;
  const _ipgid14 = _install14 && _install14.pid;
  _killTree(_install14, "SIGTERM");
  _killTree(engine, "SIGTERM");
  _killTree(dashboard, "SIGTERM");
  setTimeout(() => {
    if (_ipgid14 && process.platform !== "win32") {
      try { process.kill(-_ipgid14, "SIGKILL"); } catch (e) {}
    }
    _killTree(_install14, "SIGKILL");
    _killTree(engine, "SIGKILL");
    _killTree(dashboard, "SIGKILL");
  }, 1500);
  setTimeout(() => process.exit(_shutdownCode), 2000);
}

function runInstall(cmd, cwd) {
  // Spawn (tracked) rather than execSync: the JS thread stays free
  // so a signal during the install reaches shutdown(), which kills
  // the install child's whole group. Resolves false on a non-zero
  // exit (the caller keeps the old error path), true on success;
  // during shutdown it never resolves (shutdown exits the process).
  return new Promise((resolve) => {
    installChild = spawn(cmd, {
      cwd, stdio: "inherit", windowsHide: false, shell: true,
      detached: process.platform !== "win32",
    });
    installChild.on("error", () => { installChild = null; resolve(false); });
    installChild.on("close", (code) => {
      installChild = null;
      resolve(code === 0);
    });
  });
}

async function main() {
  // Wave 13: signal handlers FIRST, before any install phase.
  process.on("SIGINT", () => shutdown(0));
  process.on("SIGTERM", () => shutdown(0));
  process.on("SIGHUP", () => shutdown(0));
  console.log("============================================");
  console.log(" Nexus-Local - Your Personal AI Dashboard");
  console.log("============================================\n");
  log("Starting via nexuslocal CLI");

  // Verify app directory exists
  if (!fs.existsSync(path.join(APP_DIR, "server.py"))) {
    console.error("ERROR: app/server.py not found in " + PKG_ROOT);
    console.error("The installation may be corrupted. Try: npm install -g nexuslocal");
    process.exit(1);
  }

  const python = findPython();
  if (!python) {
    console.error("ERROR: Python 3.10+ not found.");
    console.error("Install from https://www.python.org/downloads/ (tick 'Add to PATH')");
    console.error("Then run 'nexuslocal' again.");
    process.exit(1);
  }
  log("Using Python: " + python);

  // Check Node.js (needed for engine)
  try {
    execSync("node --version", { stdio: "ignore", windowsHide: true });
  } catch (e) {
    console.error("ERROR: Node.js 18+ not found.");
    console.error("Install from https://nodejs.org/ then run 'nexuslocal' again.");
    process.exit(1);
  }

  // Ensure engine dependencies
  const engineServer = path.join(APP_DIR, "engine", "server");
  const nodeModules = path.join(engineServer, "node_modules");
  // Audit run-9 (L4): the gate used to be a sole dotenv sentinel —
  // a node_modules containing ONLY dotenv (an interrupted install)
  // skipped npm ci and the engine then died on a missing module in
  // total silence (stdio ignored). npm ci also writes
  // node_modules/.package-lock.json, so require both: a partial
  // tree now triggers the install.
  // Wave 11 (F14): the two sentinels alone are not enough — a
  // partial tree can keep dotenv + the hidden lockfile while losing
  // another direct dependency (express is the engine's entry point),
  // and the engine then died on every boot with the install never
  // re-attempted. Probe every direct runtime dependency named in
  // the engine's own package.json (still a cheap existence check).
  let _depsMissing = !fs.existsSync(path.join(nodeModules, "dotenv"))
      || !fs.existsSync(path.join(nodeModules, ".package-lock.json"));
  try {
    const _epkg = JSON.parse(fs.readFileSync(
      path.join(engineServer, "package.json"), "utf8"));
    // Wave 12 (L4/L5/L6): probe each direct dependency's
    // package.json (an empty directory left by an interrupted copy
    // or an antivirus quarantine is NOT an installed dependency),
    // cover `dependencies` ONLY (npm legitimately omits
    // optionalDependencies, so gating on them never converged and
    // any npm ci failure then failed the whole boot), and treat an
    // unreadable or unparseable manifest as a gate FAILURE said
    // loudly — the old silent catch{} fell back to the two
    // sentinels and hid exactly the damage this gate exists for.
    const _edeps = Object.keys(_epkg.dependencies || {});
    // Wave 13 (run-12 launcher): probe LOADABILITY, not existence —
    // require.resolve parses the dep's package.json AND resolves
    // its entry point, exactly what the engine's loader will do. A
    // manifest-only tree (or a dep whose package.json is invalid
    // JSON) used to pass the existsSync gate while the engine died
    // on every boot.
    const _unloadable = (d) => {
      try { require.resolve(d, { paths: [engineServer] }); return false; }
      catch (e) { return true; }
    };
    if (_edeps.some(_unloadable)) {
      _depsMissing = true;
    }
    // Wave 13: better-sqlite3 sits in optionalDependencies (npm may
    // omit it silently, exit 0, when its native build fails), but
    // the engine hard-requires it on every non-Android platform —
    // gate on it there. Android/Termux keeps the wave-12 exemption
    // (its node:sqlite fallback), so the gate still converges there.
    // Wave 14 (run-13 launcher L13-4): require.resolve is NOT
    // loadability for a native dep — a better-sqlite3 whose .node
    // binding is absent (npm ci --ignore-scripts tree, exit 0)
    // RESOLVES while require() fails "Could not locate the bindings
    // file", so the resolve probe certified a tree the engine dies
    // on every boot. Probe a real require in a throwaway child
    // process (a broken addon can never crash the launcher).
    // Wave 15 (run-14 launcher gate cluster — the surviving
    // run-13 gate item + L14-3 + L14-4, in verify-launcher14's
    // rank-1 shape): (i) a recursive *.node presence pre-filter —
    // a tree with NO native binding file fails the gate and is
    // reinstalled WITHOUT executing anything from it; (ii) only
    // when a binding file IS present, and only when no other
    // signal already condemns the tree, a hardened child probe
    // require()s AND instantiates the addon (better-sqlite3@12
    // loads its binding lazily, so require alone certifies
    // corrupt/wrong-arch trees), with killSignal SIGKILL so the
    // timeout is a real bound (SIGTERM can be ignored), a
    // scrubbed environment (no launcher secrets inherited) and
    // the same 15s timeout; (iii) a corrupt/wrong-arch binding
    // fails the instantiate and triggers the reinstall.
    const _bsqBindingPresent = () => {
      // Wave 16 (run-15 launcher L15-2): an unreadable SUBtree is
      // "unknown", never proof the binding is absent — skip it and
      // keep searching (only a failure at the package directory
      // itself returns false); and traverse symlinked
      // subdirectories, guarded by a visited-realpath set so a
      // symlink cycle cannot loop (the old code never traversed
      // links at all: Dirent.isDirectory() is false for them).
      const stack = [path.join(nodeModules, "better-sqlite3")];
      const seen = new Set();
      let first = true;
      while (stack.length) {
        const d = stack.pop();
        const isRoot = first;
        first = false;
        let real;
        try { real = fs.realpathSync(d); }
        catch (e) { if (isRoot) return false; continue; }
        if (seen.has(real)) continue;
        seen.add(real);
        let ents;
        try { ents = fs.readdirSync(d, { withFileTypes: true }); }
        catch (e) { if (isRoot) return false; continue; }
        for (const ent of ents) {
          const p = path.join(d, ent.name);
          if (ent.isDirectory()) { stack.push(p); continue; }
          if (ent.name.endsWith(".node")) return true;
          if (ent.isSymbolicLink()) {
            let st = null;
            try { st = fs.statSync(p); } catch (e) {}
            if (st && st.isDirectory()) stack.push(p);
          }
        }
      }
      return false;
    };
    const _bsqLoadable = () => {
      if (_unloadable("better-sqlite3")) return false;
      try {
        const { spawnSync } = require("child_process");
        const r = spawnSync(process.execPath,
          ["-e", "const DB = require('module').createRequire(process.argv[1])"
                 + "('better-sqlite3'); const db = new DB(':memory:');"
                 + " db.close();",
           path.join(engineServer, "package.json")],
          { timeout: 15000, stdio: "ignore", killSignal: "SIGKILL",
            env: { PATH: process.env.PATH || "" } });
        return !r.error && r.status === 0;
      } catch (e) { return false; }
    };
    if (process.platform !== "android"
        && (_epkg.optionalDependencies || {})["better-sqlite3"]) {
      if (!_bsqBindingPresent()) {
        log("Engine dependency better-sqlite3 has no native binding (.node) file — treating engine dependencies as missing and reinstalling.");
        _depsMissing = true;
      } else if (!_depsMissing && !_bsqLoadable()) {
        log("Engine dependency better-sqlite3 failed its load probe — treating engine dependencies as missing and reinstalling.");
        _depsMissing = true;
      }
    }
  } catch (e) {
    log(`WARNING: could not read the engine package.json (${e.message}) — treating engine dependencies as missing and reinstalling.`);
    _depsMissing = true;
  }
  if (_depsMissing) {
    log("Installing engine dependencies (first run)...");
    console.log("Installing engine (first run)...");
    // Audit run-7: install EXACTLY the pinned tree from the shipped
    // package-lock.json (npm ci verifies integrity hashes). The old
    // bare `npm install` resolved hundreds of unpinned packages on
    // first run — a supply-chain hole into processes that hold keys.
    const _lock = path.join(engineServer, "package-lock.json");
    const _npmCmd = fs.existsSync(_lock)
      ? "npm ci --no-audit --no-fund"
      : "npm install --no-audit --no-fund";
    const _npmOk = await runInstall(_npmCmd, engineServer);
    if (shuttingDown) return;
    if (!_npmOk) {
      console.error("npm install failed. Check your internet connection and try again.");
      process.exit(1);
    }
  }

  // Python dependencies
  try {
    // Audit run-9 (L5): probe EVERY module the pinned requirements
    // provide, not just cryptography — a venv with only cryptography
    // passed the old probe, the pinned install never ran, and TOTP
    // QR enrollment (qrcode/PIL) 500'd forever.
    execSync(`${python} -c "import cryptography, qrcode, PIL"`, { stdio: "ignore", windowsHide: true, cwd: APP_DIR });
  } catch (e) {
    log("Installing Python dependencies (pinned)...");
    console.log("Installing Python components...");
    // Audit run-7: install the repo's pinned requirements.txt —
    // a bare `pip install cryptography` took whatever PyPI served
    // that day (and never installed qrcode/pillow at all).
    const _pipOk = await runInstall(
      `${python} -m pip install -r "${path.join(APP_DIR, "requirements.txt")}" --quiet`,
      APP_DIR);
    if (shuttingDown) return;
    if (!_pipOk) {
      console.error("Python dependency install failed. Check your internet connection and try again.");
      process.exit(1);
    }
  }

  // Setup .env if missing
  const envFile = path.join(APP_DIR, ".env");
  if (!fs.existsSync(envFile)) {
    const example = path.join(APP_DIR, ".env.example");
    if (fs.existsSync(example)) {
      let content = fs.readFileSync(example, "utf8");
      const key = require("crypto").randomBytes(32).toString("hex");
      content = content.replace("PASTE_64_CHAR_HEX_HERE", key);
      // The .env carries the generated ENCRYPTION_KEY: owner-only
      // (audit run-7 — it used to land with default 0644).
      fs.writeFileSync(envFile, content, { mode: 0o600 });
      log("Generated .env with encryption key");
    }
  }

  // Start engine (if dist exists)
  const engineDist = path.join(engineServer, "dist", "index.js");
  engine = null;
  // Wave 11 (F15): shuttingDown is set by the shutdown path BEFORE
  // it kills the engine, so the exit handler can tell a deliberate
  // stop from a genuine crash (which must still warn). It lives at
  // module scope now (wave 13: the handlers register pre-install).
  if (fs.existsSync(engineDist)) {
    log("Starting engine on 127.0.0.1:3001");
    console.log("Starting engine...");
    const engineEnv = {
      ...process.env,
      PORT: "3001",
      HOST: "127.0.0.1",
      FREEAPI_DB_PATH: path.join(APP_DIR, "engine-data", "freeapi.db"),
      FREEAPI_CONFIG_PATH: path.join(APP_DIR, "engine", "freellmapi.config.json"),
      FREEAPI_ENV_PATH: envFile,
    };
    engine = spawn("node", [engineDist], {
      cwd: engineServer,
      env: engineEnv,
      stdio: "ignore",
      windowsHide: true,
    });
    // Audit run-7: the engine's first-run design lets any loopback
    // caller claim its admin with NO setup code, and this launcher
    // never creates a user — so the claim window never closed and a
    // claimant could export the engine's stored provider keys. Claim
    // it ourselves with a generated password (kept in the 0600 .env)
    // as soon as the engine answers.
    // Audit run-8: the run-7 claim retried only TRANSPORT errors
    // (30 x 1s), set no request timeouts, and stayed silent on
    // every other failure — a slow first boot (>~30s, e.g. AV
    // scanning on Windows) left the unauthenticated setup window
    // open for the whole session, and an active loopback claimant
    // could win the 1s poll race without leaving a trace. The
    // claim now retries ANY failure until the engine is claimed
    // or gone, verifies the claim is OURS via a login check, and
    // shouts (and drops the unregistered credentials) when a
    // foreign process won the race.
    let engineExited = false;
    engine.on("exit", (code, signal) => {
      engineExited = true;
      if (shuttingDown) {
        // Wave 11 (F15): our own SIGINT handler killed the engine —
        // an intentional stop is not a gateway failure.
        log(`Engine stopped (code ${code}, signal ${signal}) — launcher shutdown.`);
        return;
      }
      // Audit run-9 (L4): a dead engine was silent (stdio ignored,
      // exit unlogged) — the dashboard kept running with no gateway
      // behind it. Name the exit in startup.log.
      log(`WARNING: engine process exited (code ${code}, signal ${signal}) — the AI gateway is down; restart nexuslocal to bring it back.`);
    });
    const claimState = { tries: 0, lastWhy: "no attempt yet" };
    const verifyClaim = (http) => {
      // Wave 12 (L1/L2/L3): the shared dotenv-style reader — an
      // empty first line no longer shadows valid credentials, and
      // quoted/spaced/BOM values parse the way dotenv parses them.
      const _creds = readEngineAdminCreds(envFile);
      let email = _creds.email || null, pw = _creds.password || null;
      // Wave 14 (run-13 launcher L13-2): the alternate parse of the
      // recorded password (no comment truncation). A definitive
      // refusal of the primary form retries ONCE with this form
      // before anything may be deleted — a credential the engine
      // itself accepts must never be destroyed on a parse
      // technicality.
      const pwAlt = _creds.passwordAlt || null;
      let emailDefaulted = false;
      if (!pw) {
        log("WARNING: the engine admin was already claimed but app/.env holds no ENGINE_ADMIN credentials — on a fresh install, another local process claimed it first.");
        return;
      }
      // Audit run-9 (L2): a password-only .env used to leave email
      // null here — the claim had used the default owner@example.com
      // but never recorded it, so this POSTed {"email":null}, the
      // engine answered 400, and the outcome was swallowed below.
      // Fall back to the same default the claim path uses, and say
      // so loudly instead of verifying against a null identity.
      if (!email) {
        email = "owner@example.com";
        emailDefaulted = true;
        log("WARNING: app/.env holds an ENGINE_ADMIN_PASSWORD but no ENGINE_ADMIN_EMAIL — verifying the claim against the default owner@example.com.");
      }
      // Audit run-9 (L1): the old verify made ONE login POST and
      // silently swallowed every outcome other than 200/401/403 —
      // including the REAL 429 case (the engine locks the email for
      // 15 minutes after 5 failed logins, so a correct password can
      // legitimately answer 429). Inconclusive outcomes now retry a
      // bounded number of times and end in a WARNING naming the
      // outcome — never silence, and credentials are only removed
      // on a DEFINITIVE 401/403.
      let attempts = 0, triedAlt = false;
      const tryLogin = () => {
        attempts += 1;
        const payload = JSON.stringify({ email, password: pw });
        const post = http.request({
          host: "127.0.0.1", port: 3001, path: "/api/auth/login",
          method: "POST",
          headers: { "Content-Type": "application/json",
                     "Content-Length": Buffer.byteLength(payload) },
        }, (r2) => {
          r2.resume();
          r2.on("end", () => {
            if (r2.statusCode === 200) return; // ours — done
            if (r2.statusCode === 401 || r2.statusCode === 403) {
              if (pwAlt && !triedAlt) {
                // Wave 14: retry ONCE with the alternate form —
                // only a refusal of BOTH forms is a foreign claim.
                triedAlt = true;
                pw = pwAlt;
                attempts = 0;
                setTimeout(tryLogin, 300);
                return;
              }
              if (emailDefaulted) {
                // Wave 12 (L1): a login attempted with the DEFAULT
                // email (the .env recorded none) is not a
                // definitive verdict on the recorded password —
                // credentials are never deleted on it.
                log("WARNING: the engine admin login with the recorded password and the default email was refused — credentials KEPT, because app/.env records no email to verify against. Check the engine and app/.env.");
                return;
              }
              try { removeEngineAdminCreds(envFile); } catch (e) {}
              log("WARNING: the engine admin is claimed by credentials that are NOT the ones from app/.env (now removed) — another local process won the first-run claim, and the engine's stored provider keys may be exposed to it.");
              return;
            }
            if (attempts < 5) { setTimeout(tryLogin, 3000); return; }
            log(`WARNING: could not verify the engine admin claim — login answered ${r2.statusCode} on all ${attempts} attempts; whether the claim is ours is UNKNOWN (credentials kept). Check the engine and app/.env.`);
          });
        });
        post.setTimeout(3000, () => post.destroy(new Error("timeout")));
        post.on("error", () => {
          if (attempts < 5) { setTimeout(tryLogin, 3000); return; }
          log(`WARNING: could not verify the engine admin claim — the login request failed on all ${attempts} attempts; whether the claim is ours is UNKNOWN (credentials kept). Check the engine and app/.env.`);
        });
        post.write(payload);
        post.end();
      };
      tryLogin();
    };
    const claimStep = () => {
      if (engineExited) return;
      claimState.tries += 1;
      if (claimState.tries === 301) {
        // Audit run-9 (L3): the old cap stopped the loop FOREVER
        // with one cause-less WARNING while the unauthenticated
        // setup window stayed open. The warning now names the
        // last failure cause, and the claim keeps retrying at a
        // slow cadence (see retry) for the life of the process.
        log(`WARNING: engine admin still unclaimed after 300 attempts (last failure: ${claimState.lastWhy}) — its setup window may be open; the claim keeps retrying every 5 minutes. Check the engine.`);
      }
      const http = require("http");
      const retry = (why) => {
        claimState.lastWhy = why;
        if (claimState.tries === 1 || claimState.tries % 30 === 0) {
          log(`Engine claim pending (${why}), retrying...`);
        }
        setTimeout(claimStep, claimState.tries > 300 ? 5 * 60 * 1000 : 1000);
      };
      const req = http.get("http://127.0.0.1:3001/api/auth/status", (res) => {
        let body = "";
        res.on("data", (c) => { body += c; });
        res.on("end", () => {
          let st = null;
          try { st = JSON.parse(body); } catch (e) {}
          if (!st || typeof st.needsSetup !== "boolean") {
            return retry("bad status reply");
          }
          if (!st.needsSetup) return verifyClaim(http);
          let email = "owner@example.com", pw = null;
          try {
            // Credentials land in .env: tighten a pre-existing
            // loose file (the .env.example copy path used to stay
            // 0644 with the admin password inside — run-8) BEFORE
            // appending, and never duplicate the email line.
            try { fs.chmodSync(envFile, 0o600); } catch (e) {}
            const envTxt = fs.readFileSync(envFile, "utf8");
            // Wave 12 (L1/L2/L3): the shared dotenv-style reader
            // (claimStep keeps no private reader any more). Wave 11
            // (F12/F13) semantics ride on top of it: an EMPTY-valued
            // line counts as ABSENT — readers used to be
            // first-match, so an empty line left in place shadowed
            // any appended credential forever. Empty lines are
            // therefore REWRITTEN IN PLACE with the value being
            // recorded, never duplicated by an append.
            const _creds = parseEngineAdminCreds(envTxt);
            if (_creds.email) email = _creds.email;
            if (_creds.password) pw = _creds.password;
            const emEmpty = _creds.hasEmail && !_creds.email;
            const pmEmpty = _creds.hasPassword && !_creds.password;
            if (!pw) {
              pw = require("crypto").randomBytes(24).toString("hex");
              let txt = envTxt, add = "";
              if (pmEmpty) {
                txt = txt.replace(/^\uFEFF?\s*(?:export\s+)?ENGINE_ADMIN_PASSWORD\s*=.*$/m,
                                  `ENGINE_ADMIN_PASSWORD=${pw}`);
              } else {
                add += `\nENGINE_ADMIN_PASSWORD=${pw}\n`;
              }
              if (emEmpty) {
                txt = txt.replace(/^\uFEFF?\s*(?:export\s+)?ENGINE_ADMIN_EMAIL\s*=.*$/m,
                                  `ENGINE_ADMIN_EMAIL=${email}`);
              } else if (!_creds.hasEmail) {
                add += `\nENGINE_ADMIN_EMAIL=${email}`;
              }
              if (txt !== envTxt) fs.writeFileSync(envFile, txt);
              if (add) fs.appendFileSync(envFile, add);
            } else if (!_creds.hasEmail || emEmpty) {
              // Audit run-9 (L2): a pre-existing password with NO
              // email line — record the email actually being used
              // (the default above) so verifyClaim never has to
              // guess it (it used to POST {"email":null}). Wave 11:
              // an EMPTY email line gets the same recording, by
              // rewriting it in place instead of appending a
              // shadowed duplicate.
              if (emEmpty) {
                fs.writeFileSync(envFile, envTxt.replace(
                  /^\uFEFF?\s*(?:export\s+)?ENGINE_ADMIN_EMAIL\s*=.*$/m,
                  `ENGINE_ADMIN_EMAIL=${email}`));
              } else {
                fs.appendFileSync(envFile, `\nENGINE_ADMIN_EMAIL=${email}\n`);
              }
            }
          } catch (e) { return retry("env write failed"); }
          const payload = JSON.stringify({ email, password: pw });
          const post = http.request({
            host: "127.0.0.1", port: 3001, path: "/api/auth/setup",
            method: "POST",
            headers: { "Content-Type": "application/json",
                       "Content-Length": Buffer.byteLength(payload) },
          }, (r2) => {
            r2.resume();
            r2.on("end", () => {
              if (r2.statusCode === 201) {
                log("Engine admin claimed (credentials in app/.env)");
              } else {
                retry("setup answered " + r2.statusCode);
              }
            });
          });
          post.setTimeout(3000, () => post.destroy(new Error("timeout")));
          post.on("error", () => retry("setup post failed"));
          post.write(payload);
          post.end();
        });
      });
      req.setTimeout(3000, () => req.destroy(new Error("timeout")));
      req.on("error", () => retry("engine not answering yet"));
    };
    setTimeout(claimStep, 500);
    // Don't detach — we need to kill it on shutdown
  } else {
    log("Engine dist not found, skipping engine");
  }

  // Start dashboard (foreground - keeps the terminal alive)
  log("Starting dashboard on 127.0.0.1:8080");
  console.log("\nOpen http://127.0.0.1:8080 in your browser\n");
  console.log("Press Ctrl+C to stop.\n");

  // Auto-open browser on Windows
  if (os.platform() === "win32") {
    setTimeout(() => {
      try {
        execSync('start http://127.0.0.1:8080', { windowsHide: true });
      } catch (e) {}
    }, 2000);
  }

  dashboard = spawn(python.replace(/"/g, ""), ["server.py"], {
    cwd: APP_DIR,
    stdio: "inherit",
    windowsHide: false,
    shell: python.startsWith('"'),
  });

  // Wave 12 (L7/L8): ONE shutdown path for every exit route —
  // SIGINT, SIGTERM, SIGHUP, and the dashboard dying on its own.
  // The shared path (module scope since wave 13, so it can be
  // registered before the install phase and can kill the install
  // child) sets the flag, stops ALL children (SIGTERM, a short
  // grace, then SIGKILL), then exits.
  dashboard.on("close", (code) => {
    log(`Dashboard exited with code ${code}`);
    if (!shuttingDown) {
      // L8: the dashboard died on its own — stop the engine via
      // the same shutdown path instead of orphaning it.
      shutdown(code || 0);
    }
  });
}

main();
