import { getDb } from '../db/index.js';
import { isUnifyEnabled, getModelGroups } from './model-groups.js';
import { hasUsableKeyForModel } from './router.js';
// `ready` — at least one key could actually serve a request for this model
// right now: enabled, healthy or never probed (probing is lazy, so an unprobed
// key counts as usable), not scoped away from the model (#657), not on
// cooldown, and inside its rate and token windows. `exhausted` — keys match
// the model but every one of them is currently blocked, so a request would
// fail straight away. `needsKey` — nothing matches it at all, or the model is
// disabled.
//
// The gates are the router's own (hasOtherUsableKey), deliberately rather than
// a second reading of api_keys.status: a live 429 never writes that column, it
// writes a cooldown row (see services/ratelimit.ts, lib/fallback-loop.ts), so
// status alone reports a cooling-down model as ready.
function executionStatusFor(modelDbIds, available) {
    if (available !== 1)
        return 'needsKey';
    return modelDbIds.some(id => hasUsableKeyForModel(id)) ? 'ready' : 'exhausted';
}
export function buildModelListing() {
    const availableExpr = `
    (CASE WHEN m.enabled = 1 AND EXISTS (
        SELECT 1 FROM api_keys k
        WHERE k.platform = m.platform
          AND k.enabled = 1
          AND (m.key_id IS NULL OR k.id = m.key_id)
      ) THEN 1 ELSE 0 END)`;
    const db = getDb();
    let allListed;
    if (isUnifyEnabled()) {
        const rows = db.prepare(`
      SELECT m.id, m.platform, m.intelligence_rank, m.context_window, m.supports_tools,
             m.enabled AS enabled, ${availableExpr} AS available
      FROM models m
    `).all();
        const byId = new Map(rows.map(r => [r.id, r]));
        allListed = getModelGroups().map(g => {
            const infos = g.members.map(m => byId.get(m.model_db_id)).filter(Boolean);
            const ctxs = infos.map(i => i.context_window).filter((c) => c != null);
            const available = infos.some(i => i.available === 1) ? 1 : 0;
            return {
                id: g.canonicalId,
                name: g.groupLabel,
                ownedBy: 'freellmapi',
                available,
                enabled: infos.some(i => i.enabled === 1) ? 1 : 0,
                contextWindow: ctxs.length ? Math.max(...ctxs) : null,
                intel: infos.length ? Math.min(...infos.map(i => i.intelligence_rank)) : Number.MAX_SAFE_INTEGER,
                platforms: [...new Set(infos.map(i => i.platform))],
                supportsTools: infos.some(i => i.supports_tools === 1),
                // A group is ready when ANY member can serve it — that is exactly the
                // choice the router has when it dispatches the group.
                executionStatus: executionStatusFor(g.members.map(m => m.model_db_id), available),
            };
        });
    }
    else {
        // Unify OFF: one entry per model_id (dedup picks the available, smartest
        // representative row).
        const models = db.prepare(`
      SELECT platform, model_id, display_name, context_window, enabled, available, intelligence_rank, id, supports_tools
      FROM (
        SELECT m.platform, m.model_id, m.display_name, m.context_window, m.intelligence_rank, m.id, m.supports_tools,
               m.enabled AS enabled,
               ${availableExpr} AS available,
               ROW_NUMBER() OVER (
                 PARTITION BY m.model_id
                 ORDER BY ${availableExpr} DESC, m.intelligence_rank ASC, m.id ASC
               ) AS rn
        FROM models m
      )
      WHERE rn = 1
    `).all();
        allListed = models.map(m => ({
            id: m.model_id, name: m.display_name, ownedBy: m.platform,
            available: m.available, enabled: m.enabled, contextWindow: m.context_window,
            intel: m.intelligence_rank,
            platforms: [m.platform],
            supportsTools: m.supports_tools === 1,
            executionStatus: executionStatusFor([m.id], m.available),
        }));
    }
    // Stable order: usable first, then enabled, then smartest, then name.
    allListed.sort((a, b) => (b.available - a.available) || (b.enabled - a.enabled) || (a.intel - b.intel) || a.name.localeCompare(b.name));
    const availableContextWindows = allListed
        .filter(m => m.available === 1 && m.contextWindow != null)
        .map(m => m.contextWindow);
    const autoContextWindow = availableContextWindows.length > 0
        ? Math.max(...availableContextWindows)
        : null;
    return { models: allListed, autoContextWindow };
}
//# sourceMappingURL=model-listing.js.map