import crypto from 'crypto';
// Shared primitive for generating and verifying one-time alphanumeric codes.
//
// Uppercase letters + digits, minus visually ambiguous characters (I, O, 0, 1),
// so codes are easy to read from a terminal log and type by hand.
//
// Usage: call createOneTimeCode() to get an independent code instance; each
// instance keeps its own state and can be generated / cleared / compared
// without affecting any other instance.
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const CODE_LENGTH = 10;
export function createOneTimeCode() {
    let current = null;
    return {
        generate() {
            const bytes = crypto.randomBytes(CODE_LENGTH);
            let out = '';
            for (let i = 0; i < CODE_LENGTH; i++) {
                out += ALPHABET[bytes[i] % ALPHABET.length];
            }
            current = out;
            return current;
        },
        get() {
            return current;
        },
        clear() {
            current = null;
        },
        matches(provided) {
            if (!current || typeof provided !== 'string')
                return false;
            const a = Buffer.from(current);
            const b = Buffer.from(provided);
            if (a.length !== b.length)
                return false;
            return crypto.timingSafeEqual(a, b);
        },
    };
}
//# sourceMappingURL=one-time-code.js.map