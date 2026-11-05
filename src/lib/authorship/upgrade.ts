/* Seal upgrades (Phase 2, spec §6b/§6c). A seal is made once and never changed: the creator's signed part
   (statement + sig) is fixed forever. Receipts arrive later and may only be ADDED:
   - witness: null → our server's co-signature (once set it never changes);
   - ots: a Bitcoin receipt may go pending → anchored (and get its block), never back; new receipts may be added;
     none may disappear.
   The device store, the cloud copy (migration 014, same rule in SQL) and merges all use this one rule. */

import { canonicalize } from './canonical.ts';
import type { OtsReceipt, Seal } from './types.ts';

/** Why `next` is NOT an allowed upgrade of `old` (null = same seal, or the same seal with receipts added). */
export function sealUpgradeProblem(old: Seal, next: Seal): string | null {
    if (canonicalize(old.statement) !== canonicalize(next.statement)) return 'the signed statement changed';
    if (old.sig !== next.sig) return "the creator's signature changed";
    if (old.witness !== null && canonicalize(old.witness) !== canonicalize(next.witness)) return 'the witness changed';
    for (const o of old.ots) {
        const n = next.ots.find(x => x.calendar === o.calendar && x.file === o.file);
        if (!n) return `the Bitcoin receipt ${o.file} was removed`;
        const p = otsStepProblem(o, n);
        if (p) return p;
    }
    return null;
}

function otsStepProblem(o: OtsReceipt, n: OtsReceipt): string | null {
    if (o.state === 'anchored') {
        return n.state === 'anchored' && n.block === o.block ? null : `the Bitcoin receipt ${o.file} changed after it was anchored`;
    }
    if (o.block !== null) return `the Bitcoin receipt ${o.file} has a block while pending`;
    return null; // pending → pending or anchored (with any block)
}

/** Which of two copies of the same seal to keep: 'same' | 'next' (next has more) | 'old' (old has more) | 'conflict'. */
export function newerSeal(old: Seal, next: Seal): 'same' | 'next' | 'old' | 'conflict' {
    const fwd = sealUpgradeProblem(old, next) === null;
    const back = sealUpgradeProblem(next, old) === null;
    if (fwd && back) return 'same'; // same receipts (maybe listed in another order): keep the copy we have
    if (fwd) return 'next';
    if (back) return 'old';
    return 'conflict';
}
