import { AsyncLocalStorage } from 'async_hooks';
import { classifyClientAgent } from './client-classifier.js';
// Request-scoped caller identity, readable from anywhere below the middleware
// without threading parameters through every logRequest() call site (the chat
// proxy, responses, anthropic, fusion, embeddings and media paths all log).
const storage = new AsyncLocalStorage();
// Resolve the client IP. With Express's `trust proxy` disabled (the default),
// this is the socket peer address and a spoofed X-Forwarded-For from a LAN
// client is ignored. When TRUST_PROXY (#1024) opts into trusting a reverse
// proxy, `req.ip` walks the configured trusted-proxy chain and returns the
// first untrusted address — instead of trusting the leftmost caller-supplied
// X-Forwarded-For value, which would let any direct caller spoof it.
function resolveClientIp(req) {
    const raw = req.ip ?? req.socket.remoteAddress ?? null;
    // Normalize IPv4-mapped IPv6 ("::ffff:192.168.0.5" -> "192.168.0.5").
    return raw?.replace(/^::ffff:/i, '') ?? null;
}
// Privacy opt-out: REQUEST_ANALYTICS_LOG_CLIENT=false stores nulls instead of
// the caller's IP/UA. Read per request (not at module load) so tests and
// embedders can toggle it without re-importing.
function clientLoggingEnabled() {
    return process.env.REQUEST_ANALYTICS_LOG_CLIENT !== 'false';
}
export function clientContextMiddleware(req, _res, next) {
    if (!clientLoggingEnabled()) {
        storage.run({ ip: null, userAgent: null, agent: null }, next);
        return;
    }
    const ua = req.headers['user-agent'];
    storage.run({
        ip: resolveClientIp(req),
        userAgent: typeof ua === 'string' ? ua.slice(0, 256) : null,
        agent: classifyClientAgent(req),
    }, next);
}
export function getClientContext() {
    return storage.getStore() ?? { ip: null, userAgent: null, agent: null };
}
//# sourceMappingURL=client-context.js.map