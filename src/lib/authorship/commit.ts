/* Salted fingerprints of content (spec §4). The salt never goes in the entry; it lives in salts.jsonl
   (private). Revealing one piece of work = handing over that salt + the content. */

import { concatBytes } from '@noble/hashes/utils.js';
import { b64uDecode, b64uEncode, randomBytes, sha256Tagged, utf8 } from './encoding.ts';

export type CommitKind = 'text' | 'hash';

export interface SaltRecord {
    c: string;
    salt: string;
    kind: CommitKind;
}

export const SALT_BYTES = 16;

function valueFor(kind: CommitKind, value: string): string {
    return kind === 'text' ? value.normalize('NFC') : value;
}

/** c = sha256( salt || utf8(value) ). Text is NFC-normalised first; a hash string is used as-is. */
export function commit(kind: CommitKind, value: string, salt: Uint8Array): string {
    if (salt.length !== SALT_BYTES) throw new Error('authorship: salt must be 16 bytes');
    return sha256Tagged(concatBytes(salt, utf8(valueFor(kind, value))));
}

/** New random salt + commitment, with the private salt record to store in salts.jsonl. */
export function commitNew(kind: CommitKind, value: string): SaltRecord {
    const salt = randomBytes(SALT_BYTES);
    return { c: commit(kind, value, salt), salt: b64uEncode(salt), kind };
}

/** Checks a disclosed piece of work against its fingerprint. */
export function checkDisclosure(c: string, saltB64u: string, kind: CommitKind, value: string): boolean {
    const salt = b64uDecode(saltB64u);
    if (!salt || salt.length !== SALT_BYTES) return false;
    return commit(kind, value, salt) === c;
}
