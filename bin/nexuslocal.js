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

function main() {
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
  if (!fs.existsSync(path.join(nodeModules, "dotenv"))
      || !fs.existsSync(path.join(nodeModules, ".package-lock.json"))) {
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
    try {
      execSync(_npmCmd, {
        cwd: engineServer,
        stdio: "inherit",
        windowsHide: false,
      });
    } catch (e) {
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
    execSync(`${python} -m pip install -r "${path.join(APP_DIR, "requirements.txt")}" --quiet`, { stdio: "inherit", cwd: APP_DIR });
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
  let engine = null;
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
      // Audit run-9 (L4): a dead engine was silent (stdio ignored,
      // exit unlogged) — the dashboard kept running with no gateway
      // behind it. Name the exit in startup.log.
      log(`WARNING: engine process exited (code ${code}, signal ${signal}) — the AI gateway is down; restart nexuslocal to bring it back.`);
    });
    const claimState = { tries: 0, lastWhy: "no attempt yet" };
    const verifyClaim = (http) => {
      let email = null, pw = null;
      try {
        const envTxt = fs.readFileSync(envFile, "utf8");
        const em = envTxt.match(/^ENGINE_ADMIN_EMAIL=(.*)$/m);
        const pm = envTxt.match(/^ENGINE_ADMIN_PASSWORD=(.*)$/m);
        if (em) email = em[1].trim();
        if (pm) pw = pm[1].trim();
      } catch (e) {}
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
      let attempts = 0;
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
              try {
                const envTxt = fs.readFileSync(envFile, "utf8");
                fs.writeFileSync(envFile,
                  envTxt.replace(/^ENGINE_ADMIN_(EMAIL|PASSWORD)=.*\n?/gm, ""));
                try { fs.chmodSync(envFile, 0o600); } catch (e) {}
              } catch (e) {}
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
            const em = envTxt.match(/^ENGINE_ADMIN_EMAIL=(.*)$/m);
            const pm = envTxt.match(/^ENGINE_ADMIN_PASSWORD=(.*)$/m);
            if (em) email = em[1].trim();
            if (pm) pw = pm[1].trim();
            if (!pw) {
              pw = require("crypto").randomBytes(24).toString("hex");
              let add = "";
              if (!em) add += `\nENGINE_ADMIN_EMAIL=${email}`;
              add += `\nENGINE_ADMIN_PASSWORD=${pw}\n`;
              fs.appendFileSync(envFile, add);
            } else if (!em) {
              // Audit run-9 (L2): a pre-existing password with NO
              // email line — record the email actually being used
              // (the default above) so verifyClaim never has to
              // guess it (it used to POST {"email":null}).
              fs.appendFileSync(envFile, `\nENGINE_ADMIN_EMAIL=${email}\n`);
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

  const dashboard = spawn(python.replace(/"/g, ""), ["server.py"], {
    cwd: APP_DIR,
    stdio: "inherit",
    windowsHide: false,
    shell: python.startsWith('"'),
  });

  dashboard.on("close", (code) => {
    log(`Dashboard exited with code ${code}`);
    process.exit(code || 0);
  });

  // Graceful shutdown — kill engine AND dashboard
  process.on("SIGINT", () => {
    log("Shutting down...");
    if (engine) {
      try { engine.kill(); } catch (e) {}
    }
    dashboard.kill("SIGINT");
  });
}

main();
