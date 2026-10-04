import { validateSession } from '../services/auth.js';
// Gate the /api/* admin surface behind a dashboard session (#35, item #2).
// The token is the opaque session token issued by /api/auth/login|setup, sent
// as `Authorization: Bearer <token>`. The /v1 proxy is NOT gated by this — it
// keeps its own unified-API-key auth for app clients.
export function requireAuth(req, res, next) {
    const token = req.headers.authorization?.replace(/^Bearer\s+/i, '')
        ?? req.headers['x-dashboard-token'];
    const session = validateSession(token);
    if (!session) {
        res.status(401).json({ error: { message: 'Authentication required', type: 'authentication_error' } });
        return;
    }
    req.user = session;
    next();
}
//# sourceMappingURL=requireAuth.js.map