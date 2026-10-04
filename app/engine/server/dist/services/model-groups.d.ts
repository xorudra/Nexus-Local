/**
 * Model grouping — "unify" the same logical model that several providers serve
 * into ONE item. The `models` table keeps one row per (platform, model_id); a
 * model offered by N providers is N rows. This module computes a logical group
 * for those rows at runtime (NO schema change) from the curated `display_name`,
 * plus operator overrides stored as JSON in the existing `settings` table.
 *
 * Pure by design: the core functions (normalizeGroupKey / groupRows /
 * resolveRequestedIdToMembers) take rows as arguments and touch no globals, so
 * they're trivially unit-testable. Only the settings getters/setters and the
 * getModelGroups() convenience touch the DB.
 *
 * Gated by the `unify_models_enabled` setting (default ON). When OFF, callers
 * keep their pre-unification behavior.
 */
import { z } from 'zod';
export declare const UNIFY_ENABLED_KEY = "unify_models_enabled";
export declare const UNIFY_OVERRIDES_KEY = "model_unify_overrides";
export declare const unifyOverridesSchema: z.ZodDefault<z.ZodObject<{
    merges: z.ZodDefault<z.ZodArray<z.ZodObject<{
        into: z.ZodString;
        keys: z.ZodArray<z.ZodString, "many">;
    }, "strip", z.ZodTypeAny, {
        keys: string[];
        into: string;
    }, {
        keys: string[];
        into: string;
    }>, "many">>;
    splits: z.ZodDefault<z.ZodArray<z.ZodObject<{
        member: z.ZodString;
        groupKey: z.ZodOptional<z.ZodString>;
    }, "strip", z.ZodTypeAny, {
        member: string;
        groupKey?: string | undefined;
    }, {
        member: string;
        groupKey?: string | undefined;
    }>, "many">>;
}, "strip", z.ZodTypeAny, {
    merges: {
        keys: string[];
        into: string;
    }[];
    splits: {
        member: string;
        groupKey?: string | undefined;
    }[];
}, {
    merges?: {
        keys: string[];
        into: string;
    }[] | undefined;
    splits?: {
        member: string;
        groupKey?: string | undefined;
    }[] | undefined;
}>>;
export type UnifyOverrides = z.infer<typeof unifyOverridesSchema>;
export interface GroupableRow {
    model_db_id: number;
    platform: string;
    model_id: string;
    display_name: string;
    intelligence_rank?: number;
    endpoint_scope?: string;
}
/**
 * How a resolved member was reached: by its own model_id (or a group the
 * operator built), versus only through a group's auto-derived slug.
 */
export type MatchTier = 'literal' | 'slug';
export interface TieredMember {
    modelDbId: number;
    tier: MatchTier;
}
export interface ModelGroup {
    groupKey: string;
    canonicalId: string;
    groupLabel: string;
    members: GroupableRow[];
    userDefined: boolean;
}
export declare function isUnifyEnabled(): boolean;
export declare function setUnifyEnabled(on: boolean): void;
export declare function getUnifyOverrides(): UnifyOverrides;
export declare function setUnifyOverrides(input: unknown): UnifyOverrides;
export declare function stripProviderSuffix(displayName: string): string;
export declare function normalizeGroupKey(displayName: string): string;
export declare function slugifyGroupLabel(label: string): string;
/**
 * The endpoint-qualified member id, or null when the row needs no qualifier.
 * Only custom rows that actually carry an endpoint scope have one, which is why
 * an install with a single relay never sees a qualified id anywhere (#651).
 */
export declare function qualifiedMemberId(row: GroupableRow): string | null;
/**
 * Group catalog rows into logical models. Pure — pass overrides explicitly in
 * tests; defaults to the persisted overrides.
 */
export declare function groupRows(rows: GroupableRow[], ov: UnifyOverrides): ModelGroup[];
/**
 * Resolve a requested model id to the db ids of its group members, or null.
 *
 * The ladder, most specific first:
 *   1. "custom:model_id#endpoint" → exactly that relay's copy (#651) — the only
 *      form that can separate two endpoints offering the same model id. The
 *      endpoint part accepts the short handle or the endpoint URL itself;
 *   2. "platform:model_id" → that platform's copies. Normally exactly one row,
 *      so this is unchanged (#580: naming the platform means "this provider's
 *      copy", no failover to the rest of the group). Two relays sharing a model
 *      id are both 'custom', so this names both and the router picks the better
 *      one — nothing an existing setup can notice, and no error to hit;
 *   3. a canonical group slug OR a bare `model_id` → the union of every group
 *      that answers to it. Display name is presentation, not identity: it may
 *      EXPAND what a bare id reaches (that is the unify feature — one name,
 *      several providers) but it must never SHRINK it. Renaming one relay's
 *      copy, or splitting it out for display, moves it to its own group;
 *      stopping at the first match would strand the other relay, unreachable by
 *      the id every client already has (#651).
 *
 * Member order here is incidental — the router re-orders by the active strategy.
 */
export declare function resolveRequestedIdToTieredMembers(requested: string, groups: ModelGroup[]): TieredMember[] | null;
/**
 * The same resolution, flattened to db ids in tier order. Callers that dispatch
 * a request should prefer the tiered form and pass `demotedMemberIds()` to the
 * router, so a fallback match cannot outrank a literal one on score alone.
 */
export declare function resolveRequestedIdToMembers(requested: string, groups: ModelGroup[]): number[] | null;
/** The subset of a tiered resolution that was reached only through a slug. */
export declare function demotedMemberIds(members: readonly TieredMember[]): Set<number>;
export interface DispatchMembers {
    /** Every member, in tier order. */
    memberDbIds: number[];
    /** Those of them that are fallbacks — hand this to resolveModelGroupCandidates. */
    demotedDbIds: Set<number>;
}
/**
 * One-call resolution for the request path: the member ids to route over plus
 * the ones that must not outrank a literal match on score (#651).
 */
export declare function resolveRequestedIdForDispatch(requested: string, groups: ModelGroup[]): DispatchMembers | null;
/**
 * Group the whole catalog (enabled + disabled rows so availability can be shown
 * and resolution is complete), applying the persisted overrides.
 */
export declare function getModelGroups(): ModelGroup[];
//# sourceMappingURL=model-groups.d.ts.map