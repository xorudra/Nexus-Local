// Keep catalog values separately from effective local edits. Legacy blobs
// recover their defaults from the verified catalog cache; catalog sync refreshes
// recorded baselines before reapplying overrides. Unknown defaults stay unknown.
const CATALOG_BASELINE_KEY = 'catalogDefaults';
const OVERRIDE_COLUMNS = {
    displayName: 'display_name',
    intelligenceRank: 'intelligence_rank',
    speedRank: 'speed_rank',
    sizeLabel: 'size_label',
    rpmLimit: 'rpm_limit',
    rpdLimit: 'rpd_limit',
    tpmLimit: 'tpm_limit',
    tpdLimit: 'tpd_limit',
    monthlyTokenBudget: 'monthly_token_budget',
    contextWindow: 'context_window',
    supportsVision: 'supports_vision',
    supportsTools: 'supports_tools',
    enabled: 'enabled',
};
function parseOverrides(raw) {
    if (!raw)
        return {};
    try {
        const parsed = JSON.parse(raw);
        return parsed && typeof parsed === 'object' ? parsed : {};
    }
    catch {
        return {};
    }
}
function toDbValue(key, value) {
    if (key === 'supportsVision' || key === 'supportsTools' || key === 'enabled')
        return value ? 1 : 0;
    return value;
}
function cleanPatch(patch) {
    const cleaned = {};
    for (const key of Object.keys(OVERRIDE_COLUMNS)) {
        if (Object.prototype.hasOwnProperty.call(patch, key)) {
            cleaned[key] = patch[key];
        }
    }
    return cleaned;
}
// The blob split into its two parts: the fields actually overridden, and the
// pre-override values they are measured against.
function parseOverridesBlob(raw) {
    const overrides = { ...parseOverrides(raw) };
    const rawBaselines = overrides[CATALOG_BASELINE_KEY];
    delete overrides[CATALOG_BASELINE_KEY];
    const baselines = {};
    if (rawBaselines && typeof rawBaselines === 'object') {
        for (const key of Object.keys(rawBaselines)) {
            if (key in OVERRIDE_COLUMNS)
                baselines[key] = rawBaselines[key];
        }
    }
    return { overrides, baselines };
}
// Convert a catalog-applied database value into the PATCH representation.
function modelRowValue(row, key) {
    if (!row)
        return undefined;
    const value = row[OVERRIDE_COLUMNS[key]];
    if (key === 'supportsVision' || key === 'supportsTools' || key === 'enabled')
        return value === 1;
    return value ?? null;
}
export function routableContextWindow(platform, modelId, contextWindow) {
    if (platform === 'github' && modelId === 'openai/gpt-4.1')
        return 8000;
    return contextWindow;
}
function cachedCatalogDefaults(db, platform, modelId) {
    const row = db.prepare("SELECT value FROM settings WHERE key = 'catalog_applied_json'").get();
    if (!row)
        return {};
    try {
        const catalog = JSON.parse(row.value);
        const model = catalog.models?.find(m => m.platform === platform && m.modelId === modelId && (!m.modality || m.modality === 'text'));
        if (!model?.limits)
            return {};
        return {
            displayName: model.displayName, intelligenceRank: model.intelligenceRank,
            speedRank: model.speedRank, sizeLabel: model.sizeLabel,
            rpmLimit: model.limits.rpm, rpdLimit: model.limits.rpd,
            tpmLimit: model.limits.tpm, tpdLimit: model.limits.tpd,
            monthlyTokenBudget: model.monthlyTokenBudget ?? '',
            contextWindow: routableContextWindow(platform, modelId, model.contextWindow),
            supportsVision: model.supportsVision, supportsTools: model.supportsTools,
            enabled: model.enabled,
        };
    }
    catch {
        return {};
    }
}
/** Called after catalog metadata is written, before local overrides are applied. */
export function refreshModelOverrideBaselines(db, platform, modelId) {
    const existing = db.prepare('SELECT overrides_json FROM model_overrides WHERE platform = ? AND model_id = ?')
        .get(platform, modelId);
    if (!existing)
        return;
    const { overrides } = parseOverridesBlob(existing.overrides_json);
    const row = db.prepare('SELECT * FROM models WHERE platform = ? AND model_id = ?').get(platform, modelId);
    const baselines = {};
    for (const key of Object.keys(cleanPatch(overrides))) {
        const value = modelRowValue(row, key);
        if (value !== undefined)
            baselines[key] = value;
    }
    db.prepare('UPDATE model_overrides SET overrides_json = ? WHERE platform = ? AND model_id = ?')
        .run(JSON.stringify({ ...overrides, [CATALOG_BASELINE_KEY]: baselines }), platform, modelId);
}
/**
 * The fields a stored overrides blob actually overrides, for callers that
 * already selected `model_overrides.overrides_json` alongside the model row.
 * The dashboard uses this to mark individual inputs as locally overridden
 * instead of flagging the whole model (#551).
 */
export function overriddenFieldNames(overridesJson) {
    const stored = parseOverrides(overridesJson ?? undefined);
    return Object.keys(stored).filter(key => key in OVERRIDE_COLUMNS);
}
export function isCatalogManagedModel(row) {
    // `source` is the authoritative provenance (models.source: 'catalog', 'user'
    // or 'discovered'). Discovered rows on built-in platforms (#1348) count as
    // catalog-managed: deleting one records a catalog tombstone, which both
    // discovery and a later catalog honor;
    // callers that select it get an exact answer. The platform/key_id fallback
    // covers callers that don't have the column in hand.
    if (row.source === 'user')
        return false;
    return row.platform !== 'custom' && row.key_id == null;
}
export function getCatalogModelTombstone(db, kind, platform, modelId) {
    const row = db
        .prepare('SELECT source, reason, created_at FROM catalog_model_tombstones WHERE kind = ? AND platform = ? AND model_id = ?')
        .get(kind, platform, modelId);
    if (!row)
        return undefined;
    return {
        source: row.source === 'upstream_eol' ? 'upstream_eol' : 'user',
        reason: row.reason ?? null,
        createdAt: row.created_at,
    };
}
/**
 * True only for models the USER deleted — the "keep it deleted" contract every
 * caller here means. An upstream-retirement tombstone deliberately does NOT
 * count: those models stay in the catalog's write path so a refreshed catalog
 * can reinstate them (see reinstateUpstreamRetiredCatalogModel).
 */
export function isCatalogModelTombstoned(db, kind, platform, modelId) {
    return getCatalogModelTombstone(db, kind, platform, modelId)?.source === 'user';
}
export function recordCatalogModelTombstone(db, kind, platform, modelId, options = {}) {
    const source = options.source ?? 'user';
    db.prepare(`
    INSERT INTO catalog_model_tombstones (kind, platform, model_id, source, reason)
    VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(kind, platform, model_id)
    DO UPDATE SET created_at = datetime('now'), source = excluded.source, reason = excluded.reason
  `).run(kind, platform, modelId, source, options.reason ?? null);
    // A user deletion drops their local metadata edits with the row. An upstream
    // retirement keeps the row, so it keeps the overrides too — they must survive
    // if the model is reinstated.
    if (kind === 'chat' && source === 'user') {
        db.prepare('DELETE FROM model_overrides WHERE platform = ? AND model_id = ?').run(platform, modelId);
    }
}
/**
 * Auto-disable a catalog model the provider reports as permanently retired
 * (issue #634). Deliberately NOT a delete: the row stays visible in the
 * dashboard, tagged with the upstream wording, and the user can flip it back on
 * if they disagree. Turning off the chain entries (and the active profile's
 * copy) is exactly what the dashboard's own switch does, so the router stops
 * picking it while an explicitly-requested model id still resolves.
 *
 * Returns true when this call performed the retirement (false when it was
 * already retired, or the user had deleted the model outright).
 */
export function retireCatalogModelUpstream(db, modelDbId, platform, modelId, reason) {
    const existing = getCatalogModelTombstone(db, 'chat', platform, modelId);
    if (existing)
        return false;
    recordCatalogModelTombstone(db, 'chat', platform, modelId, { source: 'upstream_eol', reason });
    db.prepare('UPDATE fallback_config SET enabled = 0 WHERE model_db_id = ?').run(modelDbId);
    db.prepare('UPDATE profile_models SET enabled = 0 WHERE model_db_id = ?').run(modelDbId);
    return true;
}
/**
 * Lift an upstream retirement: a catalog that still lists the model — and lists
 * it enabled — is newer and better evidence than one provider's 404. Returns
 * true when a retirement was actually lifted.
 */
export function reinstateUpstreamRetiredCatalogModel(db, platform, modelId) {
    if (getCatalogModelTombstone(db, 'chat', platform, modelId)?.source !== 'upstream_eol')
        return false;
    clearCatalogModelTombstone(db, 'chat', platform, modelId);
    const row = db
        .prepare('SELECT id FROM models WHERE platform = ? AND model_id = ?')
        .get(platform, modelId);
    if (row) {
        db.prepare('UPDATE fallback_config SET enabled = 1 WHERE model_db_id = ?').run(row.id);
        db.prepare('UPDATE profile_models SET enabled = 1 WHERE model_db_id = ?').run(row.id);
    }
    return true;
}
export function clearCatalogModelTombstone(db, kind, platform, modelId) {
    db.prepare('DELETE FROM catalog_model_tombstones WHERE kind = ? AND platform = ? AND model_id = ?')
        .run(kind, platform, modelId);
}
export function upsertModelOverrides(db, platform, modelId, patch, options = {}) {
    const cleaned = cleanPatch(patch);
    if (Object.keys(cleaned).length === 0)
        return {};
    const existing = db
        .prepare('SELECT overrides_json FROM model_overrides WHERE platform = ? AND model_id = ?')
        .get(platform, modelId);
    const { overrides: stored, baselines } = parseOverridesBlob(existing?.overrides_json);
    const catalogDefaults = options.baselineRow ? cachedCatalogDefaults(db, platform, modelId) : {};
    const merged = { ...stored };
    const mergedBaselines = { ...baselines };
    for (const key of Object.keys(cleaned)) {
        const next = cleaned[key];
        if (mergedBaselines[key] === undefined && options.baselineRow) {
            // An old override is already applied to the row. Never mistake that
            // effective value for the catalog value during an upgrade.
            const captured = catalogDefaults[key] !== undefined ? catalogDefaults[key]
                : stored[key] === undefined ? modelRowValue(options.baselineRow, key) : undefined;
            if (captured !== undefined)
                mergedBaselines[key] = captured;
        }
        const baseline = mergedBaselines[key];
        if (options.baselineRow && baseline !== undefined && next === baseline) {
            // Back at the pre-override value: the override (and its baseline) drop
            // out, so the field tracks the catalog again.
            delete merged[key];
            delete mergedBaselines[key];
        }
        else {
            merged[key] = next;
        }
    }
    if (Object.keys(merged).length === 0) {
        // Nothing left to pin: drop the row so has_overrides goes false and the
        // dashboard's badge clears.
        db.prepare('DELETE FROM model_overrides WHERE platform = ? AND model_id = ?').run(platform, modelId);
        return {};
    }
    const blob = { ...merged, [CATALOG_BASELINE_KEY]: mergedBaselines };
    db.prepare(`
    INSERT INTO model_overrides (platform, model_id, overrides_json, updated_at)
    VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(platform, model_id)
    DO UPDATE SET overrides_json = excluded.overrides_json, updated_at = excluded.updated_at
  `).run(platform, modelId, JSON.stringify(blob));
    return merged;
}
export function getModelOverrides(db, platform, modelId) {
    const row = db
        .prepare('SELECT overrides_json FROM model_overrides WHERE platform = ? AND model_id = ?')
        .get(platform, modelId);
    return parseOverrides(row?.overrides_json);
}
/**
 * Every model whose stored overrides pin ONE given field, as a set of
 * "platform:model_id" keys. One query over a table that only ever holds the
 * models a user has actually touched, so callers that need "is this field
 * user-owned?" for a whole catalog don't do it per model.
 *
 * Note it keys off the field, not the row: a user who renamed a model has an
 * override row but has said nothing about its speed_rank, so a derived value
 * may still fill that column (#619).
 */
export function modelsWithOverriddenField(db, field) {
    const rows = db.prepare('SELECT platform, model_id, overrides_json FROM model_overrides')
        .all();
    const pinned = new Set();
    for (const row of rows) {
        const overrides = parseOverrides(row.overrides_json);
        if (overrides[field] !== undefined)
            pinned.add(`${row.platform}:${row.model_id}`);
    }
    return pinned;
}
export function applyModelOverrides(db, platform, modelId) {
    const overrides = getModelOverrides(db, platform, modelId);
    const keys = Object.keys(overrides).filter(k => k in OVERRIDE_COLUMNS);
    if (keys.length === 0)
        return false;
    const assignments = [];
    const values = [];
    for (const key of keys) {
        assignments.push(`${OVERRIDE_COLUMNS[key]} = ?`);
        values.push(toDbValue(key, overrides[key]));
    }
    values.push(platform, modelId);
    db.prepare(`UPDATE models SET ${assignments.join(', ')} WHERE platform = ? AND model_id = ?`).run(...values);
    return true;
}
export function applyAllModelOverrides(db) {
    const rows = db.prepare('SELECT platform, model_id FROM model_overrides').all();
    let applied = 0;
    for (const row of rows) {
        if (applyModelOverrides(db, row.platform, row.model_id))
            applied++;
    }
    return applied;
}
// Only USER tombstones delete rows. An upstream-retirement tombstone disables
// its model and keeps it (see retireCatalogModelUpstream), so deleting here
// would throw away both the row and the reason the dashboard shows for it.
export function deleteTombstonedCatalogModels(db) {
    const chatRows = db.prepare(`
    SELECT m.id, m.platform, m.model_id
      FROM models m
      JOIN catalog_model_tombstones t
        ON t.kind = 'chat' AND t.platform = m.platform AND t.model_id = m.model_id
     WHERE t.source = 'user' AND m.platform != 'custom' AND m.key_id IS NULL AND m.source != 'user'
  `).all();
    const mediaRows = db.prepare(`
    SELECT mm.id
      FROM media_models mm
      JOIN catalog_model_tombstones t
        ON t.kind = 'media' AND t.platform = mm.platform AND t.model_id = mm.model_id
     WHERE t.source = 'user'
  `).all();
    const deleteChatFallback = db.prepare('DELETE FROM fallback_config WHERE model_db_id = ?');
    const deleteChat = db.prepare('DELETE FROM models WHERE id = ?');
    const deleteMedia = db.prepare('DELETE FROM media_models WHERE id = ?');
    for (const row of chatRows) {
        deleteChatFallback.run(row.id);
        deleteChat.run(row.id);
    }
    for (const row of mediaRows) {
        deleteMedia.run(row.id);
    }
    return chatRows.length + mediaRows.length;
}
//# sourceMappingURL=model-state.js.map