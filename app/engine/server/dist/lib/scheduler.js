export class NodeScheduler {
    every(ms, fn, _opts) {
        const id = setInterval(() => { void fn(); }, ms);
        return () => clearInterval(id);
    }
    after(ms, fn) {
        const id = setTimeout(() => { void fn(); }, ms);
        return () => clearTimeout(id);
    }
}
//# sourceMappingURL=scheduler.js.map