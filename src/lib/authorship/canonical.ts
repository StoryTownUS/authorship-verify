/* RFC 8785 (JCS) canonical JSON. v1 also forbids non-integer numbers anywhere, so number formatting can
   never differ between platforms. */

import canonicalizeLib from 'canonicalize';
import { sha256Tagged, utf8 } from './encoding.ts';

export function canonicalize(value: unknown): string {
    assertIntegersOnly(value, '$');
    const out = canonicalizeLib(value);
    if (typeof out !== 'string') throw new Error('authorship: value cannot be canonicalized');
    return out;
}

/** "sha256:<hex>" of the JCS bytes. */
export function hashCanonical(value: unknown): string {
    return sha256Tagged(utf8(canonicalize(value)));
}

/** Throws on any number that isn't a safe integer (also NaN/Infinity), or on undefined/function values. */
export function assertIntegersOnly(value: unknown, path: string): void {
    if (typeof value === 'number') {
        if (!Number.isSafeInteger(value)) throw new Error(`authorship: non-integer number at ${path}`);
        return;
    }
    if (value === null || typeof value === 'string' || typeof value === 'boolean') return;
    if (Array.isArray(value)) {
        value.forEach((v, i) => assertIntegersOnly(v, `${path}[${i}]`));
        return;
    }
    if (typeof value === 'object') {
        for (const [k, v] of Object.entries(value as Record<string, unknown>)) assertIntegersOnly(v, `${path}.${k}`);
        return;
    }
    throw new Error(`authorship: unsupported value (${typeof value}) at ${path}`);
}

/** Integers-only check that returns instead of throwing (for the verifier). */
export function hasOnlyIntegers(value: unknown): boolean {
    try {
        assertIntegersOnly(value, '$');
        return true;
    } catch {
        return false;
    }
}
