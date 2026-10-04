export interface WakeHooks {
    onWake: (event: WakeEvent) => void | Promise<void>;
}
export interface WakeEvent {
    reason: 'drift' | 'signal';
    idleMs: number;
    signal?: string;
}
export declare function startWakeDetect(h: WakeHooks): void;
export declare function stopWakeDetect(): void;
export declare function _resetForTests(): void;
//# sourceMappingURL=wake-detect.d.ts.map