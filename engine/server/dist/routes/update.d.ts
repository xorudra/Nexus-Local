import { Router } from 'express';
/**
 * Settings-table key for the dashboard's automatic release check (#782).
 * Absent or anything other than '1' means off, so an install that has never
 * been told otherwise never phones GitHub on its own. The manual checker above
 * is a separate surface and stays available regardless.
 */
export declare const UPDATE_CHECK_SETTING = "update_check_enabled";
export declare function isAutoUpdateCheckEnabled(): boolean;
type ExecFile = (file: string, args: string[], options: {
    cwd: string;
    encoding: 'utf8';
    timeout: number;
}) => Promise<{
    stdout: string | Buffer;
}>;
export interface UpdateRouterOptions {
    fetch?: typeof globalThis.fetch;
    execFile?: ExecFile;
    env?: NodeJS.ProcessEnv;
    cwd?: string;
    now?: () => number;
    logger?: Pick<Console, 'error'>;
    version?: () => string | null;
    /** Reads the opt-in flag; injectable so the endpoint is testable without a DB. */
    autoCheckEnabled?: () => boolean;
}
export declare function createUpdateRouter(options?: UpdateRouterOptions): Router;
export declare const updateRouter: Router;
export {};
//# sourceMappingURL=update.d.ts.map