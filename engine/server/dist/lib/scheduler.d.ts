export interface Scheduler {
    every(ms: number, fn: () => void | Promise<void>, opts?: {
        name?: string;
    }): () => void;
    after(ms: number, fn: () => void | Promise<void>): () => void;
}
export declare class NodeScheduler implements Scheduler {
    every(ms: number, fn: () => void | Promise<void>, _opts?: {
        name?: string;
    }): () => void;
    after(ms: number, fn: () => void | Promise<void>): () => void;
}
//# sourceMappingURL=scheduler.d.ts.map