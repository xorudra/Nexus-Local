import { resolveCustomEndpointKey, customEndpointKeyIds } from './custom-endpoint.js';
import { customModelSeed } from './custom-model-seed.js';
import { ensureModelInProfiles } from './profile-models.js';
import { clearCustomModelTombstone } from './custom-model-tombstone.js';
import { endpointScopeForBaseUrl } from '../lib/endpoint-scope.js';
/**
 * Register (or re-register) models against a custom endpoint inside one
 * transaction.
 *
 * Key rows are matched on (base_url, secret): a new secret for a known
 * endpoint is a SECOND credential for it, not a replacement (#619), and a
 * new base_url is a separate provider (#212). Identity is per endpoint
 * (#651): the same model id on a DIFFERENT relay is a separate row with its
 * own enabled flag, ranks and stats, instead of silently rebinding the other
 * endpoint's row. A model already on THIS endpoint keeps the key it has, so
 * adding a second credential doesn't re-bind it (#619).
 *
 * Capability flags: an unset flag binds NULL so COALESCE picks the insert
 * default (tools 1, vision 0) on a new row and preserves the existing value
 * on re-registration (#470). An omitted display name binds NULL the same way
 * — it falls back to the model id on a new row and leaves a name already on
 * the row alone, so the bulk re-registration behind "Fetch models" (which
 * posts bare ids) can't wipe names the operator set.
 */
export function registerCustomModels(db, baseUrl, providedKey, label, pinnedKeyId, entries) {
    return db.transaction(() => {
        const { keyId, storedKey } = resolveCustomEndpointKey(db, baseUrl, providedKey, label, pinnedKeyId);
        const registered = registerCustomChatModels(db, baseUrl, keyId, entries);
        return { keyId, storedKey, registered };
    })();
}
/**
 * The registration loop itself, against an ALREADY-resolved endpoint key and
 * inside the caller's transaction. Split out from registerCustomModels so the
 * bulk key importer (#382) — which resolves its own key and owns a wider
 * transaction — shares this exact write path instead of keeping a second copy.
 */
export function registerCustomChatModels(db, baseUrl, keyId, entries) {
    const endpointKeyIds = customEndpointKeyIds(db, keyId);
    // The identity discriminator for every row registered in this call (#651).
    const endpointScope = endpointScopeForBaseUrl(baseUrl);
    // Unknown ≠ worst: seed the routing ranks at the catalog median so a new
    // custom model is explored instead of buried at intelligence 0 (#488).
    const seed = customModelSeed(db);
    const registered = [];
    for (const { modelId, displayName, supportsTools, supportsVision } of entries) {
        // #926: this is an EXPLICIT registration (POST /custom, bulk importer or
        // the dashboard's "Fetch models" submit), so it overrides a previous
        // deletion. The scheduled sync never reaches this loop for a tombstoned
        // model — it filters them out in custom-model-sync.ts — so the tombstone
        // can only be lifted here by a human choosing to re-add the model.
        clearCustomModelTombstone(db, endpointScope, modelId);
        const bound = db.prepare("SELECT key_id FROM models WHERE platform = 'custom' AND model_id = ? AND endpoint_scope = ?").get(modelId, endpointScope);
        const created = bound === undefined;
        const bindKeyId = bound?.key_id != null && endpointKeyIds.has(bound.key_id) ? bound.key_id : keyId;
        const toolsParam = supportsTools === undefined ? null : (supportsTools ? 1 : 0);
        const visionParam = supportsVision === undefined ? null : (supportsVision ? 1 : 0);
        // The seed applies on INSERT only: DO UPDATE deliberately leaves the rank
        // columns alone so re-registering a model (or bulk-adding alongside it)
        // never rewrites ranks the operator has since tuned by hand.
        db.prepare(`
      INSERT INTO models
        (platform, model_id, display_name, intelligence_rank, speed_rank, size_label,
         rpm_limit, rpd_limit, tpm_limit, tpd_limit, monthly_token_budget, context_window, enabled, key_id,
         supports_tools, supports_vision, source, endpoint_scope)
      VALUES ('custom', @modelId, COALESCE(@displayName, @modelId), @intelligenceRank, @speedRank, @sizeLabel,
         NULL, NULL, NULL, NULL, '', NULL, 1, @keyId,
         COALESCE(@tools, 1), COALESCE(@vision, 0), 'user', @endpointScope)
      ON CONFLICT(platform, model_id, endpoint_scope)
      DO UPDATE SET
        display_name = COALESCE(@displayName, display_name),
        key_id = excluded.key_id,
        enabled = 1,
        supports_tools = COALESCE(@tools, supports_tools),
        supports_vision = COALESCE(@vision, supports_vision)
    `).run({
            modelId, displayName, keyId: bindKeyId, tools: toolsParam, vision: visionParam,
            intelligenceRank: seed.intelligenceRank, speedRank: seed.speedRank, sizeLabel: seed.sizeLabel,
            endpointScope,
        });
        // Read back rather than echo the submitted values: an omitted display name
        // or capability flag resolves in SQL, so the row is the only place that
        // knows what this model is actually called now.
        const modelRow = db.prepare("SELECT id, display_name, supports_tools, supports_vision FROM models WHERE platform = 'custom' AND model_id = ? AND endpoint_scope = ?").get(modelId, endpointScope);
        // Append to the fallback chain if not already present.
        const inChain = db.prepare('SELECT 1 FROM fallback_config WHERE model_db_id = ?').get(modelRow.id);
        if (!inChain) {
            const max = db.prepare('SELECT COALESCE(MAX(priority), 0) AS m FROM fallback_config').get();
            db.prepare('INSERT INTO fallback_config (model_db_id, priority, enabled) VALUES (?, ?, 1)').run(modelRow.id, max.m + 1);
        }
        ensureModelInProfiles(db, modelRow.id);
        registered.push({
            modelDbId: modelRow.id,
            model: modelId,
            displayName: modelRow.display_name,
            supportsTools: modelRow.supports_tools === 1,
            supportsVision: modelRow.supports_vision === 1,
            created,
        });
    }
    return registered;
}
//# sourceMappingURL=custom-model-register.js.map