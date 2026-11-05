/* Checking a Bitcoin receipt (`.ots`) against a seal — pure, no network. Used by the open checker, the app and
   later storytown.us/verify.

   Two separate questions:
   1. Does this proof belong to THIS seal? (its digest = sha256(JCS(statement)), and every operation is valid) —
      answered here, offline.
   2. Is the claimed Bitcoin block real? Each Bitcoin attestation says "message M is the merkle root of block N".
      That needs block N's header from a source the checker picks (a node, an explorer). `bitcoinClaims` lists what
      to look up; `matchesBlockMerkleRoot` compares. We never ship a default source of truth for this. */

import { bytesToHex } from '@noble/hashes/utils.js';
import { allAttestations, OtsFormatError, parseOts, type Timestamp } from './format.ts';

export interface OtsCalendarState {
    /** Calendar address as written in the proof. */
    calendar: string;
    /** Bitcoin block height if this calendar's branch reached Bitcoin, else null (still pending). */
    block: number | null;
}

export interface BitcoinClaim {
    height: number;
    /** The block's merkle root in the usual explorer order (byte-reversed hex). */
    merkleRoot: string;
}

export interface OtsCheck {
    /** Plain reason the proof does NOT belong to the seal, or null. */
    problem: string | null;
    calendars: OtsCalendarState[];
    bitcoin: BitcoinClaim[];
}

/** Per pending attestation: did its branch reach a Bitcoin attestation? (lowest block wins) */
export function calendarStates(t: Timestamp): OtsCalendarState[] {
    const out = new Map<string, number | null>();
    const walk = (n: Timestamp) => {
        for (const a of n.attestations) {
            if (a.kind !== 'pending') continue;
            const heights = allAttestations(n).flatMap(x => x.att.kind === 'bitcoin' ? [x.att.height] : []);
            const h = heights.length ? Math.min(...heights) : null;
            const prev = out.get(a.uri);
            out.set(a.uri, prev == null ? h : h == null ? prev : Math.min(prev, h));
        }
        n.ops.forEach(o => walk(o.stamp));
    };
    walk(t);
    return [...out].map(([calendar, block]) => ({ calendar, block })).sort((a, b) => a.calendar.localeCompare(b.calendar));
}

export function bitcoinClaims(t: Timestamp): BitcoinClaim[] {
    const seen = new Set<string>();
    return allAttestations(t).flatMap(({ msg, att }) => {
        if (att.kind !== 'bitcoin') return [];
        if (msg.length !== 32) return [];
        const merkleRoot = bytesToHex(msg.slice().reverse());
        const k = `${att.height}:${merkleRoot}`;
        if (seen.has(k)) return [];
        seen.add(k);
        return [{ height: att.height, merkleRoot }];
    }).sort((a, b) => a.height - b.height);
}

/** The block header's merkle root (explorer hex order) must equal the claim. */
export function matchesBlockMerkleRoot(claim: BitcoinClaim, headerMerkleRoot: string): boolean {
    return claim.merkleRoot === headerMerkleRoot.toLowerCase();
}

/** Does this `.ots` file prove the seal digest? Never throws on bad input: a broken file is a `problem`. */
export function checkOts(bytes: Uint8Array, sealDigest: Uint8Array): OtsCheck {
    let parsed: ReturnType<typeof parseOts>;
    try {
        parsed = parseOts(bytes);
    } catch (e) {
        const why = e instanceof OtsFormatError ? e.message : 'unreadable';
        return { problem: `the Bitcoin receipt can't be read (${why})`, calendars: [], bitcoin: [] };
    }
    if (bytesToHex(parsed.digest) !== bytesToHex(sealDigest)) {
        return { problem: 'the Bitcoin receipt is for a different seal', calendars: [], bitcoin: [] };
    }
    const bad = allAttestations(parsed.timestamp).some(a => a.att.kind === 'bitcoin' && a.msg.length !== 32);
    if (bad) return { problem: 'the Bitcoin receipt points at something that is not a block', calendars: [], bitcoin: [] };
    return { problem: null, calendars: calendarStates(parsed.timestamp), bitcoin: bitcoinClaims(parsed.timestamp) };
}
