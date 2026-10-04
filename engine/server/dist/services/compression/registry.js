const engines = new Map();
export function registerEngine(engine) {
    if (engines.has(engine.id))
        throw new Error(`Compression engine already registered: ${engine.id}`);
    engines.set(engine.id, engine);
}
export function getEngine(id) {
    return engines.get(id);
}
export function getRegisteredEngines() {
    return [...engines.values()].sort((a, b) => a.priority - b.priority || a.id.localeCompare(b.id));
}
export function _clearRegistryForTesting() {
    engines.clear();
}
//# sourceMappingURL=registry.js.map