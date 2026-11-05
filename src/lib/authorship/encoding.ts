/* Strict encodings. Strict on purpose: a decoder that ignores spare bits would let a changed character
   decode to the same bytes, and tampering would pass. */

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';

const B64U = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

export function utf8(text: string): Uint8Array {
    return new TextEncoder().encode(text);
}

export function b64uEncode(bytes: Uint8Array): string {
    let out = '';
    let i = 0;
    for (; i + 2 < bytes.length; i += 3) {
        const n = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
        out += B64U[(n >> 18) & 63] + B64U[(n >> 12) & 63] + B64U[(n >> 6) & 63] + B64U[n & 63];
    }
    const rest = bytes.length - i;
    if (rest === 1) {
        const n = bytes[i] << 16;
        out += B64U[(n >> 18) & 63] + B64U[(n >> 12) & 63];
    } else if (rest === 2) {
        const n = (bytes[i] << 16) | (bytes[i + 1] << 8);
        out += B64U[(n >> 18) & 63] + B64U[(n >> 12) & 63] + B64U[(n >> 6) & 63];
    }
    return out;
}

/** Decodes base64url (no padding). Returns null unless the input is the ONE canonical encoding of its bytes. */
export function b64uDecode(text: string): Uint8Array | null {
    if (typeof text !== 'string' || !/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) return null;
    const out: number[] = [];
    let buf = 0;
    let bits = 0;
    for (const ch of text) {
        buf = (buf << 6) | B64U.indexOf(ch);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push((buf >> bits) & 0xff);
        }
    }
    const bytes = new Uint8Array(out);
    return b64uEncode(bytes) === text ? bytes : null;
}

export const HASH_RE = /^sha256:[0-9a-f]{64}$/;

export function sha256Tagged(bytes: Uint8Array): string {
    return 'sha256:' + bytesToHex(sha256(bytes));
}

export function randomBytes(n: number): Uint8Array {
    const b = new Uint8Array(n);
    globalThis.crypto.getRandomValues(b);
    return b;
}
