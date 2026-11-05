/* A seal's Bitcoin receipts (spec §6c) are always DERIVED from its `.ots` proof, never written by hand: one receipt
   per calendar in the proof, `anchored` + block when that calendar's branch reached Bitcoin. So the seal line and
   the proof can't disagree, and upgrading the proof (which only adds) can only move receipts forward.

   In RecordFiles, `.ots` files are binary strings (one char per byte, "latin1"), the same as the open checker reads
   them from a folder or a zip. */

import { otsDigest } from '../seal.ts';
import type { OtsReceipt, Seal } from '../types.ts';
import { checkOts } from './check.ts';

export const otsFileName = (chain: string, seal: number) => `ots/${chain}-${seal}.ots`;

export function bytesToBinary(b: Uint8Array): string {
    let s = '';
    for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
    return s;
}
export function binaryToBytes(s: string): Uint8Array {
    const b = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) {
        const c = s.charCodeAt(i);
        if (c > 0xff) throw new Error('authorship: a Bitcoin receipt file is not binary');
        b[i] = c;
    }
    return b;
}

/** Receipts for this seal read off its proof. Throws (plainly) if the proof doesn't belong to the seal. */
export function receiptsFromProof(seal: Seal, proof: Uint8Array): OtsReceipt[] {
    const c = checkOts(proof, otsDigest(seal.statement));
    if (c.problem) throw new Error(`authorship: seal ${seal.statement.seal}: ${c.problem}`);
    const file = otsFileName(seal.statement.chain, seal.statement.seal);
    return c.calendars.map(x => ({
        calendar: x.calendar, file,
        state: x.block === null ? 'pending' as const : 'anchored' as const,
        block: x.block,
    }));
}

/** Null if the seal's receipts are exactly what its proof says; otherwise a plain reason. */
export function receiptsProblem(seal: Seal, proof: Uint8Array | undefined): string | null {
    if (!seal.ots.length) return null;
    if (!proof) return `its Bitcoin receipt ${seal.ots[0].file} is missing`;
    let derived: OtsReceipt[];
    try { derived = receiptsFromProof(seal, proof); } catch (e) { return (e as Error).message.replace(/^authorship: seal \d+: /, ''); }
    const key = (r: OtsReceipt) => `${r.calendar}|${r.file}|${r.state}|${r.block}`;
    const want = new Set(derived.map(key));
    for (const r of seal.ots) if (!want.has(key(r))) return `its Bitcoin receipt from ${r.calendar} doesn't match the proof`;
    return null;
}
