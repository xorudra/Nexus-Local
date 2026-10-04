import type { NextFunction, Request, Response } from 'express';
import { type ClientAgent } from './client-classifier.js';
export interface ClientContext {
    ip: string | null;
    userAgent: string | null;
    agent: ClientAgent | null;
}
export declare function clientContextMiddleware(req: Request, _res: Response, next: NextFunction): void;
export declare function getClientContext(): ClientContext;
//# sourceMappingURL=client-context.d.ts.map