/* Story Town witness (spec §6b, Phase 2 step 4): our server co-signs a seal with ITS clock — JCS({statement, received})
   with ES256. It proves the seal existed by `received` without trusting the creator's device clock. Bonus, never
   required: a record with no witness still checks out.

   The PUBLISHED keys below are the only ones a checker trusts as "Story Town". A record also carries
   witness-keys.json so it can be read offline, but a key in a file is never trusted on its own — otherwise anyone
   could ship their own "storytown-witness-1". Keys are only ever ADDED here (an old key stays to check old seals).
   Key kind is 'device' to stay inside the frozen v1 key-file shape. The private half lives only in the server env
   AUTHORSHIP_WITNESS_KEY (never in the repo, never logged). */

import { canonicalize } from './canonical.ts';
import { verifyES256 } from './keys.ts';
import { witnessBytes } from './seal.ts';
import { V1 } from './types.ts';
import type { KeyFile, PublicKeyRecord, SealStatement, Witness } from './types.ts';

export const STORYTOWN_WITNESS_KEYS: Readonly<Record<string, PublicKeyRecord>> = Object.freeze({
    // Made Nov 5 2026.
    'storytown-witness-1': {
        kind: 'device', alg: 'ES256',
        jwk: { kty: 'EC', crv: 'P-256', x: 'NeaqiIFSM48UV1__KKR3JFACpT-eeT8229o-Gn3Mo1w', y: 'sqXMttZpP8KxjysR3HcXEFwjJoSl0bMrlZZezIvSBf0' },
    },
});

/** The key the server signs with today. */
export const CURRENT_WITNESS_KEY = 'storytown-witness-1';

const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

/** Null if `w` is a valid Story Town witness of `statement`; otherwise a plain reason. */
export function witnessProblem(statement: SealStatement, w: Witness, keys: Readonly<Record<string, PublicKeyRecord>> = STORYTOWN_WITNESS_KEYS): string | null {
    if (!w || typeof w !== 'object' || Object.keys(w).sort().join(',') !== 'key,received,sig') return 'the witness is malformed';
    if (typeof w.received !== 'string' || !ISO.test(w.received)) return 'the witness time is malformed';
    const k = Object.prototype.hasOwnProperty.call(keys, w.key) ? keys[w.key] : undefined;
    if (!k) return `the witness key ${String(w.key)} is not a published Story Town key`;
    if (!verifyES256(k.jwk, witnessBytes(statement, w.received), w.sig)) return "the Story Town witness signature doesn't verify";
    return null;
}

/** witness-keys.json for a record: the published keys its seals use (one JCS line + \n), or undefined if none. */
export function witnessKeysFile(used: Iterable<string>): string | undefined {
    const kf: KeyFile = { v: V1, keys: {} };
    for (const id of [...new Set(used)].sort()) {
        if (Object.prototype.hasOwnProperty.call(STORYTOWN_WITNESS_KEYS, id)) kf.keys[id] = STORYTOWN_WITNESS_KEYS[id];
    }
    return Object.keys(kf.keys).length ? canonicalize(kf) + '\n' : undefined;
}
