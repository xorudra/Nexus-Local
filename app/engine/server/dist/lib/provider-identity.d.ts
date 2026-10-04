/**
 * The host (and port) of a custom endpoint's base_url — the short identifier
 * that actually tells two endpoints apart. Mirrors the default label
 * convention in services/custom-endpoint.ts (`new URL(baseUrl).host`) but
 * returns null instead of a literal when the URL is unparseable, so callers
 * can fall back to the generic 'custom' id rather than a fake host.
 */
export declare function endpointHost(baseUrl: string | null | undefined): string | null;
/**
 * The stable provider id for an analytics row. Non-custom platforms keep their
 * bare slug ('groq', 'openai', …) so existing filters and the platform dot
 * coloring are untouched. Custom endpoints get 'custom:<base_url>' so two
 * relays never collide; a custom request whose key is gone (or never had a
 * base_url) falls back to the plain 'custom' id, preserving the pre-fix shape.
 */
export declare function providerIdFor(platform: string, baseUrl: string | null | undefined): string;
/**
 * The display name for an analytics row: the platform slug for catalog
 * providers, and for a custom row the endpoint host plus any non-trivial path.
 *
 * Host alone is not an identity: a single gateway commonly fronts several
 * endpoints ('https://gw.example.com/tenant-a/v1' and '…/tenant-b/v1'), and
 * naming both of them 'gw.example.com' re-creates the #889 collision one level
 * down — two rows the operator cannot tell apart. Appending the path makes the
 * name injective on (host, path), while a bare '…/v1' endpoint still reads as
 * the plain host it is.
 *
 * Derived purely from this row's base_url, like endpoint-scope's handles: the
 * name never changes because some OTHER endpoint appeared or was deleted, so
 * every view (by-platform, by-model, errors) agrees on what to call an
 * endpoint even when they see different subsets of them.
 *
 * A null/unparseable base_url falls back to the platform, so there is always
 * something to render.
 */
export declare function providerDisplayName(platform: string, baseUrl: string | null | undefined): string;
//# sourceMappingURL=provider-identity.d.ts.map