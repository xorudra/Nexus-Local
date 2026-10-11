// Nexus Local — k6 smoke/load script (Launch Safety Standard G34).
//
// Run ONLY against a locally booted instance or staging — NEVER
// production. Boot a local copy first, e.g.:
//   HOST=127.0.0.1 PORT=18080 python3 app/server.py
// Then:
//   k6 run -e BASE_URL=http://127.0.0.1:18080 tests/load/k6-smoke.js
//
// Profile is deliberately tiny (<=50 VUs, ~2.5 min): this proves the
// server stays healthy under light concurrency and records a p95 /
// breaking-point baseline. It is not a capacity certification.

import http from "k6/http";
import { check, sleep } from "k6";

// 200 = served, 302 = bounced to /login (signed-out page routes),
// 401 = auth-gated API answering correctly. Anything else is a failure.
http.setResponseCallback(http.expectedStatuses(200, 302, 401));

export const options = {
  stages: [
    { duration: "30s", target: 10 },
    { duration: "60s", target: 25 },
    { duration: "30s", target: 50 },
    { duration: "30s", target: 0 },
  ],
  thresholds: {
    http_req_failed: ["rate<0.01"], // <1% failed requests
    http_req_duration: ["p(95)<2000"], // stated p95 budget: 2s local
  },
};

const BASE = __ENV.BASE_URL || "http://127.0.0.1:18080";

export default function () {
  const health = http.get(`${BASE}/health`);
  check(health, { "health 200": (r) => r.status === 200 });

  const login = http.get(`${BASE}/login`);
  check(login, { "login page 200": (r) => r.status === 200 });

  const root = http.get(`${BASE}/`, { redirects: 0 });
  check(root, { "root bounces to login": (r) => r.status === 302 });

  const icon = http.get(`${BASE}/favicon.ico`);
  check(icon, { "favicon 200 (cached static)": (r) => r.status === 200 });

  const quotas = http.get(`${BASE}/api/quotas`);
  check(quotas, { "quotas API is auth-gated": (r) => r.status === 401 || r.status === 302 });

  const missing = http.get(`${BASE}/definitely-not-a-page`);
  check(missing, { "unknown path is a clean 404": (r) => r.status === 404 });

  sleep(1);
}
