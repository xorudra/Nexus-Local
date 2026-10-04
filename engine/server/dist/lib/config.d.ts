export interface Config {
    port: number | string;
    host: string;
    dbPath: string | null;
    dashboardOrigins: string[];
    clientDist: string | null;
    proxyRateLimitRpm: number;
    /** JSON body limit (bytes) for the LLM wire surfaces — see
     *  parseRequestBodyLimitBytes. REQUEST_BODY_LIMIT_MB overrides. */
    requestBodyLimitBytes: number;
    nodeEnv: string;
    serveStaticAssets: boolean;
    /**
     * Express `trust proxy` setting, parsed from TRUST_PROXY (#1024).
     * - false:        do not trust forwarded headers (default; direct callers
     *                 cannot spoof X-Forwarded-For).
     * - true:         trust all proxies (with a security warning).
     * - number:       trust that many hops counted from the socket peer
     *                 (Express's `trust proxy: 1` idiom for one proxy in front).
     * - string[]:     trust only these proxy addresses/CIDRs.
     */
    trustProxy: boolean | number | string[];
    /**
     * Tri-state override for the CSP `upgrade-insecure-requests` directive (#682).
     * - undefined: auto — emit the directive only when the request arrived over
     *   TLS (or behind an HTTPS reverse proxy that forwarded X-Forwarded-Proto).
     * - true:      always emit (force HTTPS upgrade even on plain HTTP).
     * - false:     never emit (let HTTP LAN installs render the dashboard).
     */
    cspUpgradeInsecureRequests: boolean | undefined;
}
export declare function loadConfig(): Config;
//# sourceMappingURL=config.d.ts.map