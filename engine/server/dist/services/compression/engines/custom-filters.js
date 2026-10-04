import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { filterRuleSchema } from './filter-definitions.js';
let cacheKey = '';
let cached = [];
function readFilterFile(file) {
    try {
        const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
        const values = Array.isArray(parsed)
            ? parsed
            : (parsed && typeof parsed === 'object' && Array.isArray(parsed.filters)
                ? parsed.filters
                : [parsed]);
        return values.flatMap(value => {
            const result = filterRuleSchema.safeParse(value);
            return result.success ? [result.data] : [];
        });
    }
    catch {
        return [];
    }
}
export function loadCustomFilters(trustProjectFilters) {
    const key = `${process.cwd()}:${trustProjectFilters}`;
    if (key === cacheKey)
        return cached;
    const filters = [];
    const userDir = path.join(os.homedir(), '.freellmapi', 'filters');
    try {
        for (const name of fs.readdirSync(userDir).filter(name => name.endsWith('.json')).sort()) {
            filters.push(...readFilterFile(path.join(userDir, name)));
        }
    }
    catch {
        // Optional directory.
    }
    if (trustProjectFilters) {
        filters.push(...readFilterFile(path.resolve(process.cwd(), '.freellmapi', 'filters.json')));
    }
    cacheKey = key;
    cached = filters.slice(0, 100);
    return cached;
}
export function _clearCustomFilterCacheForTesting() {
    cacheKey = '';
    cached = [];
}
//# sourceMappingURL=custom-filters.js.map