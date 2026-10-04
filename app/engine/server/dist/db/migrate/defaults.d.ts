import type { Db } from '../types.js';
export interface MigrationModule {
    up(db: Db): void;
    down(db: Db): void;
}
export interface DefaultMigration {
    filename: string;
    module: MigrationModule;
}
export declare const LEGACY_BASELINE_FILENAME = "20260101_000000_legacy_baseline.ts";
export declare const CUSTOM_PROVIDER_MODALITIES_FILENAME = "20260627_000001_custom_provider_modalities.ts";
export declare const CATALOG_MODEL_STATE_FILENAME = "20260627_000002_catalog_model_state.ts";
export declare const REQUEST_AGGREGATES_FILENAME = "20260628_120000_request_aggregates.ts";
export declare const GITHUB_GPT41_CONTEXT_FILENAME = "20260630_000001_github_gpt41_context.ts";
export declare const REQUEST_CLIENT_INFO_FILENAME = "20260706_000001_request_client_info.ts";
export declare const CUSTOM_MODEL_TOOL_SUPPORT_FILENAME = "20260706_000002_custom_model_tool_support.ts";
export declare const PROFILE_CHAIN_BACKFILL_FILENAME = "20260714_000001_profile_chain_backfill.ts";
export declare const KEY_HEALTH_ERROR_FILENAME = "20260720_000001_key_health_error.ts";
export declare const COOLDOWN_PROBE_PROVENANCE_FILENAME = "20260726_000001_cooldown_probe_provenance.ts";
export declare const REQUEST_ATTEMPTS_FILENAME = "20260726_000002_request_attempts.ts";
export declare const MODEL_SOURCE_PROVENANCE_FILENAME = "20260726_000003_model_source_provenance.ts";
export declare const MEDIA_MODEL_META_FILENAME = "20260726_000004_media_model_meta.ts";
export declare const REQUEST_SERVED_MODEL_FILENAME = "20260726_000005_request_served_model.ts";
export declare const ATTEMPT_ERROR_SUMMARY_FILENAME = "20260726_000006_attempt_error_summary.ts";
export declare const AGENT_COMPATIBILITY_FILENAME = "20260727_000001_agent_compatibility.ts";
export declare const TOMBSTONE_PROVENANCE_FILENAME = "20260728_000001_tombstone_provenance.ts";
export declare const CUSTOM_MODEL_ENDPOINT_IDENTITY_FILENAME = "20260729_000001_custom_model_endpoint_identity.ts";
export declare const CUSTOM_ENDPOINT_HOST_LABELS_FILENAME = "20260802_000001_custom_endpoint_host_labels.ts";
export declare const KEY_MODEL_SCOPE_FILENAME = "20260805_000001_key_model_scope.ts";
export declare const CLIENT_PROFILES_FILENAME = "20260805_000002_client_profiles.ts";
export declare const API_KEY_PROXY_FILENAME = "20260810_000001_api_key_proxy.ts";
export declare const PLAYGROUND_CONVERSATIONS_FILENAME = "20260820_000001_playground_conversations.ts";
export declare const CUSTOM_MODEL_TOMBSTONES_FILENAME = "20260819_000001_custom_model_tombstones.ts";
export declare const SERVER_LOGS_FILENAME = "20260823_000001_server_logs.ts";
export declare const BACKUPS_TABLE_FILENAME = "20260823_000002_backups_table.ts";
export declare const ATTEMPT_KEY_LABEL_FILENAME = "20260823_000003_attempt_key_label.ts";
export declare const PROFILE_AUTO_INCLUDE_FILENAME = "20260823_000004_profile_auto_include.ts";
export declare const IDEMPOTENCY_CLAIMS_FILENAME = "20260901_000001_idempotency_claims.ts";
export declare const QUOTA_OBSERVATION_LOOKUP_FILENAME = "20260901_000002_quota_observation_lookup.ts";
export declare const REQUEST_CALLER_FILENAME = "20260901_000003_request_caller.ts";
export declare const ANALYTICS_LATENCY_PERCENTILE_INDEX_FILENAME = "20260902_000001_analytics_latency_percentile_index.ts";
export declare const MCP_ENABLED_DEFAULT_FILENAME = "20260903_000001_mcp_enabled_default.ts";
export declare const RESPONSE_CACHE_FILENAME = "20260903_000002_response_cache.ts";
export declare const KEY_MONTHLY_BUDGET_FILENAME = "20260904_000001_key_monthly_budget.ts";
export declare const REQUEST_MODEL_ATTRIBUTION_FILENAME = "20260913_000001_request_model_attribution.ts";
export declare const KEY_MONTHLY_USAGE_FILENAME = "20260914_000001_key_monthly_usage.ts";
export declare const QUOTA_SNAPSHOT_FRESHNESS_FILENAME = "20260915_000001_quota_snapshot_freshness.ts";
export declare const DEFAULT_MIGRATIONS: readonly DefaultMigration[];
//# sourceMappingURL=defaults.d.ts.map