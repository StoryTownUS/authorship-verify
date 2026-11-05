/* Talking to OpenTimestamps calendars (free public servers, no account). Only a 32-byte fingerprint ever leaves the
   device: the seal digest with 16 private random bytes appended, hashed again (same as the official client), so
   the calendar can't even link the stamp to the seal.

   stamp()   → submit to ≥2 calendars, return a proof whose every branch is "pending".
   upgrade() → ask each calendar whether its branch is in Bitcoin yet; merge the answer in (only ever adds).

   Browser notes (checked Nov 4 2026): POST /digest is a CORS "simple" request (no content-type, safelisted Accept)
   and answers with `Access-Control-Allow-Origin: *`; GET /timestamp answers 200 with the same header once the
   stamp is complete, but a still-pending 404 has no CORS header, so the browser sees a network error. Both are
   reported as `waiting`, never as a failure. */

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { allAttestations, mergeTimestamp, OtsFormatError, parseTimestamp, type Timestamp } from './format.ts';

export const DEFAULT_CALENDARS = [
    'https://a.pool.opentimestamps.org',
    'https://b.pool.opentimestamps.org',
    'https://a.pool.eternitywall.com',
] as const;

/** Spec §6c: a seal's Bitcoin stamp is kept only if at least this many calendars took it. */
export const MIN_CALENDARS = 2;

const ACCEPT = 'application/vnd.opentimestamps.v1';
const MAX_REPLY = 10_000;

export type Fetch = (url: string, init: { method: 'GET' | 'POST'; headers: Record<string, string>; body?: Uint8Array; signal?: AbortSignal }) =>
    Promise<{ status: number; arrayBuffer(): Promise<ArrayBuffer> }>;

export interface StampResult {
    /** Proof tree rooted at the seal digest (null if fewer than MIN_CALENDARS answered). */
    timestamp: Timestamp | null;
    /** Calendars holding the stamp, as written in the proof (a pool like a.pool.opentimestamps.org hands it to a
     *  calendar like alice.btc.calendar.opentimestamps.org). These are the receipts' `calendar` values (§6c). */
    accepted: string[];
    /** Calendars that didn't, with a plain reason. */
    failed: { calendar: string; reason: string }[];
}

async function readReply(res: { status: number; arrayBuffer(): Promise<ArrayBuffer> }): Promise<Uint8Array> {
    const b = new Uint8Array(await res.arrayBuffer());
    if (b.length > MAX_REPLY) throw new OtsFormatError('calendar reply too large');
    return b;
}

/** Submit a 32-byte digest to calendars. `random16` is injectable for tests; defaults to crypto.getRandomValues. */
export async function stamp(digest: Uint8Array, opts: {
    fetch: Fetch;
    calendars?: readonly string[];
    random16?: () => Uint8Array;
    timeoutMs?: number;
}): Promise<StampResult> {
    if (digest.length !== 32) throw new Error('authorship: stamp needs a 32-byte digest');
    const calendars = opts.calendars ?? DEFAULT_CALENDARS;
    const nonce = opts.random16 ? opts.random16() : crypto.getRandomValues(new Uint8Array(16));
    if (nonce.length !== 16) throw new Error('authorship: nonce must be 16 bytes');
    const appended = new Uint8Array([...digest, ...nonce]);
    const root = sha256(appended);
    // digest --append(nonce)--> appended --sha256--> root --(calendar branches)-->
    const rootStamp: Timestamp = { msg: root, attestations: [], ops: [] };
    const tree: Timestamp = {
        msg: digest, attestations: [],
        ops: [{ op: { op: 'append', arg: nonce }, stamp: { msg: appended, attestations: [], ops: [{ op: { op: 'sha256' }, stamp: rootStamp }] } }],
    };
    const res: StampResult = { timestamp: null, accepted: [], failed: [] };
    await Promise.all(calendars.map(async cal => {
        try {
            const r = await opts.fetch(`${cal}/digest`, {
                method: 'POST', headers: { Accept: ACCEPT }, body: root,
                signal: AbortSignal.timeout(opts.timeoutMs ?? 15_000),
            });
            if (r.status !== 200) throw new Error(`answered ${r.status}`);
            const t = parseTimestamp(await readReply(r), root);
            const uris = allAttestations(t).flatMap(a => a.att.kind === 'pending' ? [a.att.uri] : []);
            if (!uris.length) throw new Error('reply had no pending receipt');
            for (const u of uris) if (!res.accepted.includes(u)) res.accepted.push(u);
            mergeTimestamp(rootStamp, t);
        } catch (e) {
            res.failed.push({ calendar: cal, reason: (e as Error).message || 'no answer' });
        }
    }));
    res.accepted.sort();
    if (res.accepted.length >= MIN_CALENDARS) res.timestamp = tree; // distinct calendars, not pools
    return res;
}

export interface UpgradeResult {
    /** True if anything new was merged into the proof. */
    changed: boolean;
    /** Calendar addresses (as written in the proof) now confirmed in Bitcoin. */
    anchored: string[];
    /** Calendar addresses still waiting (or unreachable right now). */
    waiting: string[];
}

/** Ask every calendar named in a pending attestation for the finished branch; merge it in place. */
export async function upgrade(t: Timestamp, opts: { fetch: Fetch; timeoutMs?: number }): Promise<UpgradeResult> {
    const out: UpgradeResult = { changed: false, anchored: [], waiting: [] };
    const nodes: Timestamp[] = [];
    const walk = (n: Timestamp) => { nodes.push(n); n.ops.forEach(o => walk(o.stamp)); };
    walk(t);
    for (const node of nodes) {
        for (const a of node.attestations) {
            if (a.kind !== 'pending') continue;
            // A branch that already reached Bitcoin needs no more asking.
            if (node.ops.length && allAttestations(node).some(x => x.att.kind === 'bitcoin')) { out.anchored.push(a.uri); continue; }
            try {
                const r = await opts.fetch(`${a.uri}/timestamp/${bytesToHex(node.msg)}`, {
                    method: 'GET', headers: { Accept: ACCEPT }, signal: AbortSignal.timeout(opts.timeoutMs ?? 15_000),
                });
                if (r.status !== 200) { out.waiting.push(a.uri); continue; }
                const got = parseTimestamp(await readReply(r), node.msg);
                out.changed = mergeTimestamp(node, got) || out.changed;
                (allAttestations(got).some(x => x.att.kind === 'bitcoin') ? out.anchored : out.waiting).push(a.uri);
            } catch (e) {
                if (e instanceof OtsFormatError) throw e; // a broken reply is loud, never "waiting"
                out.waiting.push(a.uri);
            }
        }
    }
    return out;
}
