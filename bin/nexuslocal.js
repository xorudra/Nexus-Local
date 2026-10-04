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
  if (!fs.existsSync(path.join(nodeModules, "dotenv"))) {
    log("Installing engine dependencies (first run)...");
    console.log("Installing engine (first run)...");
    try {
      execSync("npm install --no-audit --no-fund", {
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
    execSync(`${python} -c "import cryptography"`, { stdio: "ignore", windowsHide: true, cwd: APP_DIR });
  } catch (e) {
    log("Installing Python cryptography...");
    console.log("Installing Python components...");
    execSync(`${python} -m pip install cryptography --quiet`, { stdio: "inherit", cwd: APP_DIR });
  }

  // Setup .env if missing
  const envFile = path.join(APP_DIR, ".env");
  if (!fs.existsSync(envFile)) {
    const example = path.join(APP_DIR, ".env.example");
    if (fs.existsSync(example)) {
      let content = fs.readFileSync(example, "utf8");
      const key = require("crypto").randomBytes(32).toString("hex");
      content = content.replace("PASTE_64_CHAR_HEX_HERE", key);
      fs.writeFileSync(envFile, content);
      log("Generated .env with encryption key");
    }
  }

  // Start engine (if dist exists)
  const engineDist = path.join(engineServer, "dist", "index.js");
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
    const engine = spawn("node", [engineDist], {
      cwd: engineServer,
      env: engineEnv,
      stdio: "ignore",
      detached: true,
      windowsHide: true,
    });
    engine.unref();
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

  // Graceful shutdown
  process.on("SIGINT", () => {
    log("Shutting down...");
    dashboard.kill("SIGINT");
  });
}

main();
