export declare const keysRouter: import("express-serve-static-core").Router;
/**
 * Whether a stored row belongs in an export file. Kept in one place because the
 * export dialog shows a count before downloading, and computing that count from
 * a different rule than the export itself made it lie: it promised 40 keys and
 * wrote 39 whenever a no-auth custom endpoint was in the list (#687).
 *
 * A custom endpoint is worth exporting even when it holds only the `no-key`
 * placeholder — the endpoint IS the thing being backed up, and its base_url
 * restores it. Anything else needs a real secret to be worth a line.
 */
export declare function isExportableKey(row: {
    platform: string;
    baseUrl: string | null;
    key: string;
}): boolean;
//# sourceMappingURL=keys.d.ts.map