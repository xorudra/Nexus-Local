import type { Request, Response, NextFunction } from 'express';
export declare function createProxyRateLimiter(rpmLimit?: number): (req: Request, res: Response, next: NextFunction) => void;
export declare function createAdminRateLimiter(rpm?: number): (req: Request, res: Response, next: NextFunction) => void;
//# sourceMappingURL=rateLimit.d.ts.map