/* Seals (spec §6): the creator's key signs the head of a chain. Witness (Phase 2) and Bitcoin receipts
   (Phase 3) attach to the same seal record later. */

import { sha256 } from '@noble/hashes/sha2.js';
import { canonicalize } from './canonical.ts';
import { entryHash } from './chain.ts';
import { b64uEncode, utf8 } from './encoding.ts';
import { V1 } from './types.ts';
import type { Entry, Seal, SealReason, SealStatement, Signer } from './types.ts';

/** Exact bytes the creator's key signs. */
export function statementBytes(statement: SealStatement): Uint8Array {
    return utf8(canonicalize(statement));
}

/** Exact bytes the witness signs: JCS({statement, received}). */
export function witnessBytes(statement: SealStatement, received: string): Uint8Array {
    return utf8(canonicalize({ statement, received }));
}

/** 32-byte digest sent to OpenTimestamps calendars (Phase 3). */
export function otsDigest(statement: SealStatement): Uint8Array {
    return sha256(statementBytes(statement));
}

export function makeStatement(params: {
    head: Entry;
    seal: number;
    reason: SealReason;
    at: string;
    keyId: string;
}): SealStatement {
    return {
        v: V1,
        chain: params.head.chain,
        seal: params.seal,
        seq: params.head.seq,
        head: entryHash(params.head),
        reason: params.reason,
        at: params.at,
        key: params.keyId,
    };
}

/** Signs a chain's head. A failure throws: the caller sends it to the Bell (never a silent green). */
export async function sealHead(params: {
    head: Entry;
    seal: number;
    reason: SealReason;
    at: string;
    signer: Signer;
}): Promise<Seal> {
    const statement = makeStatement({ ...params, keyId: params.signer.keyId });
    const sig = await params.signer.sign(statementBytes(statement));
    if (!(sig instanceof Uint8Array) || sig.length !== 64) throw new Error('authorship: signer returned a bad signature');
    return { statement, sig: b64uEncode(sig), witness: null, ots: [] };
}

export function sealLine(seal: Seal): string {
    return canonicalize(seal);
}
