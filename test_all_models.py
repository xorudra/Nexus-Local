#!/usr/bin/env python3
"""Test chat completion for every model across all providers."""
import urllib.request, json, concurrent.futures, sys, os, time

BASE = "https://nexus-local.onrender.com"
PASSWORD = os.environ.get("NEXUS_TEST_PASSWORD", "")
if not PASSWORD:
    raise SystemExit("Set NEXUS_TEST_PASSWORD to the site master password to run this test.")

# Login
req = urllib.request.Request(f"{BASE}/api/login", 
    data=json.dumps({"password": PASSWORD}).encode(),
    headers={"Content-Type": "application/json"}, method="POST")
with urllib.request.urlopen(req, timeout=15) as r:
    cookies = r.headers.get("Set-Cookie", "").split(";")[0]

def api(path, data=None, timeout=30):
    headers = {"Cookie": cookies, "Content-Type": "application/json"}
    req = urllib.request.Request(f"{BASE}{path}", 
        data=json.dumps(data).encode() if data else None,
        headers=headers, method="POST" if data else "GET")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())

# Get all providers and their models
providers = ["google", "groq", "openrouter", "nvidia", "cohere", "mistral", 
             "siliconflow", "zhipu", "ovh", "pollinations",
             "relay_openrouter", "relay_groq", "relay_nvidia", 
             "relay_pollinations", "relay_gemini"]

print("Fetching model lists...", flush=True)
all_models = {}
for p in providers:
    try:
        d = api(f"/api/models?provider={p}", timeout=30)
        all_models[p] = d.get("models", [])
        print(f"  {p}: {len(all_models[p])} models", flush=True)
    except Exception as e:
        print(f"  {p}: FAILED to list - {str(e)[:80]}", flush=True)
        all_models[p] = []

total = sum(len(v) for v in all_models.values())
print(f"\nTotal models to test: {total}", flush=True)

# Test each model
results = {"ok": [], "fail": [], "timeout": []}

def test_one(provider, model):
    try:
        d = api("/api/chat", {
            "provider": provider,
            "model": model,
            "message": "Say OK"
        }, timeout=25)
        if d.get("reply") or d.get("response") or "error" not in d:
            return (provider, model, "ok", "")
        else:
            return (provider, model, "fail", str(d.get("error", "unknown"))[:80])
    except Exception as e:
        msg = str(e)[:80]
        if "timed out" in msg.lower() or "timeout" in msg.lower():
            return (provider, model, "timeout", msg)
        return (provider, model, "fail", msg)

print("\nTesting (this will take a while)...", flush=True)
tested = 0
with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
    futures = {}
    for p, models in all_models.items():
        for m in models:
            f = ex.submit(test_one, p, m)
            futures[f] = (p, m)
    
    for f in concurrent.futures.as_completed(futures):
        p, m = futures[f]
        try:
            prov, mod, status, err = f.result()
            results[status].append((prov, mod, err))
        except Exception as e:
            results["fail"].append((p, m, str(e)[:80]))
        tested += 1
        if tested % 20 == 0:
            print(f"  Tested {tested}/{total}...", flush=True)

# Report
print(f"\n{'='*60}")
print(f"RESULTS: {len(results['ok'])} OK, {len(results['fail'])} FAIL, {len(results['timeout'])} TIMEOUT")
print(f"{'='*60}")

if results["fail"]:
    print(f"\nFAILED ({len(results['fail'])}):")
    for p, m, e in sorted(results["fail"])[:30]:
        print(f"  [{p}] {m}: {e}")

if results["timeout"]:
    print(f"\nTIMEOUT ({len(results['timeout'])}):")
    for p, m, e in sorted(results["timeout"])[:30]:
        print(f"  [{p}] {m}")

# Save full results
with open("/tmp/model_test_results.json", "w") as f:
    json.dump({
        "ok": [(p, m) for p, m, _ in results["ok"]],
        "fail": [(p, m, e) for p, m, e in results["fail"]],
        "timeout": [(p, m) for p, m, _ in results["timeout"]],
    }, f, indent=1)
print(f"\nFull results saved to /tmp/model_test_results.json")
