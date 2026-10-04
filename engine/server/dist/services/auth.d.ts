export interface SessionUser {
    userId: number;
    email: string;
}
/** The one spelling of an address the DB is keyed on. Exported so callers that
 *  bucket by email (the login throttle in routes/auth.ts) key on exactly what
 *  verifyCredentials will look up — keying on anything else lets a padded
 *  address authenticate against the real row while landing in its own bucket. */
export declare function normalizeEmail(email: string): string;
export declare function userCount(): number;
/** Create a user. Throws { code: 'email_taken' } if the email already exists. */
export declare function createUser(email: string, password: string): SessionUser;
/** Verify credentials. Returns the user on success, null on failure. */
export declare function verifyCredentials(email: string, password: string): SessionUser | null;
/** Mint a session and return the raw token (only the hash is persisted). */
export declare function createSession(userId: number): string;
/** Resolve a session token to its user, or null if missing/expired. */
export declare function validateSession(token: string | undefined | null): SessionUser | null;
export declare function deleteSession(token: string | undefined | null): void;
/** Update the email of the authenticated user after verifying the current password. Throws { code: 'email_taken' } on conflict. */
export declare function updateEmail(userId: number, currentPassword: string, newEmail: string): boolean;
/** Update the password of the authenticated user after verifying the current one. Invalidates all sessions on success. */
export declare function updatePassword(userId: number, currentPassword: string, newPassword: string): boolean;
/**
 * Reset the password for the single existing user and invalidate all
 * sessions.
 * Returns false if no user exists.
 */
export declare function resetUserPassword(newPassword: string): boolean;
//# sourceMappingURL=auth.d.ts.map