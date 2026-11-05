/* Building entries (spec §3, §5). Pure: no store, no React. The app's writer (Phase 1) calls these. */

import { canonicalize, hashCanonical } from './canonical.ts';
import { b64uEncode, randomBytes } from './encoding.ts';
import { checkEntryShape } from './shape.ts';
import { TYPE_CHAIN_START, TYPE_KEY_ADDED, V1 } from './types.ts';
import type { Actor, Entry, ProviderReceipt, Ref, Timing, Weight } from './types.ts';

export function newChainId(): string {
    return b64uEncode(randomBytes(16));
}

export function entryHash(entry: Entry): string {
    return hashCanonical(entry);
}

/** The exact stored line for an entry (JCS, no newline). */
export function entryLine(entry: Entry): string {
    return canonicalize(entry);
}

export interface EntryInput {
    type: string;
    w: Weight;
    by: Actor;
    at: string;
    account: string | null;
    refs?: Ref[];
    provider?: ProviderReceipt | null;
    cause?: number | null;
    t?: Timing | null;
}

/** Next entry after `prev` (or the first, when prev is null). Throws loudly on a malformed entry. */
export function nextEntry(chain: string, prev: Entry | null, input: EntryInput): Entry {
    if (prev && prev.chain !== chain) throw new Error('authorship: previous entry belongs to another chain');
    const entry: Entry = {
        v: V1,
        chain,
        seq: prev ? prev.seq + 1 : 0,
        prev: prev ? entryHash(prev) : null,
        type: input.type,
        w: input.w,
        by: input.by,
        at: input.at,
        account: input.account,
        refs: input.refs ?? [],
        provider: input.provider ?? null,
        cause: input.cause ?? null,
        t: input.t ?? null,
    };
    const problem = checkEntryShape(entry);
    if (problem) throw new Error(`authorship: bad entry: ${problem}`);
    return entry;
}

/** First two entries of a new chain: chain.start (+ heads of other chains seen) then key.added. */
export function startChain(params: {
    chain: string;
    at: string;
    account: string | null;
    keyId: string;
    projectRef?: Ref;
    continues?: string[];
}): [Entry, Entry] {
    const refs: Ref[] = [];
    if (params.projectRef) refs.push(params.projectRef);
    for (const head of params.continues ?? []) refs.push({ role: 'continues', c: head });
    const start = nextEntry(params.chain, null, {
        type: TYPE_CHAIN_START, w: 'big', by: 'you', at: params.at, account: params.account, refs,
    });
    const added = nextEntry(params.chain, start, {
        type: TYPE_KEY_ADDED, w: 'big', by: 'you', at: params.at, account: params.account,
        refs: [{ role: 'key', id: params.keyId }],
    });
    return [start, added];
}
