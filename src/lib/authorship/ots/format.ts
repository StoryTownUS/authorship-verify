/* OpenTimestamps proof format (`.ots`), read + write. Our own small client (spec §6c, plan Phase 2 step 2): the
   official JS client is unmaintained since 2022. Byte-compatible with the reference Python implementation
   (python-opentimestamps core/{op,notary,timestamp,serialize}.py): a file we write verifies with the standard
   `ots verify` tool, and real files from the official client round-trip byte for byte.

   A timestamp is a tree. Each node holds a message; each edge is an operation (append/prepend bytes, or a hash)
   that turns the parent's message into the child's; leaves are attestations: "pending at calendar X" or
   "this message is the merkle root of Bitcoin block N". */

import { sha256 } from '@noble/hashes/sha2.js';
import { ripemd160, sha1 } from '@noble/hashes/legacy.js';
import { keccak_256 } from '@noble/hashes/sha3.js';
import { bytesToHex, concatBytes, hexToBytes } from '@noble/hashes/utils.js';

export const HEADER_MAGIC = hexToBytes('004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294');
const MAJOR_VERSION = 1;
const MAX_MSG = 4096;
const MAX_PAYLOAD = 8192;
const MAX_URI = 1000;
const MAX_DEPTH = 256;
const MAX_HEIGHT = 2 ** 32 - 1;
const URI_CHARS = /^[A-Za-z0-9\-._/:]*$/;

export const TAG_PENDING = '83dfe30d2ef90c8e';
export const TAG_BITCOIN = '0588960d73d71901';

export type Op =
    | { op: 'append' | 'prepend'; arg: Uint8Array }
    | { op: 'sha256' | 'sha1' | 'ripemd160' | 'keccak256' | 'reverse' | 'hexlify' };

export type Attestation =
    | { kind: 'pending'; uri: string }
    | { kind: 'bitcoin'; height: number }
    | { kind: 'unknown'; tag: string; payload: Uint8Array };

export interface Timestamp {
    msg: Uint8Array;
    attestations: Attestation[];
    ops: { op: Op; stamp: Timestamp }[];
}

export class OtsFormatError extends Error {}

const OP_TAGS: Record<string, number> = {
    append: 0xf0, prepend: 0xf1, reverse: 0xf2, hexlify: 0xf3, sha1: 0x02, ripemd160: 0x03, sha256: 0x08, keccak256: 0x67,
};
const OP_BY_TAG = new Map(Object.entries(OP_TAGS).map(([k, v]) => [v, k as Op['op']]));

export function applyOp(op: Op, msg: Uint8Array): Uint8Array {
    if (msg.length > MAX_MSG) throw new OtsFormatError(`message too long for ${op.op}`);
    let r: Uint8Array;
    switch (op.op) {
        case 'append': r = concatBytes(msg, op.arg); break;
        case 'prepend': r = concatBytes(op.arg, msg); break;
        case 'sha256': r = sha256(msg); break;
        case 'sha1': r = sha1(msg); break;
        case 'ripemd160': r = ripemd160(msg); break;
        case 'keccak256': r = keccak_256(msg); break;
        case 'reverse':
            if (!msg.length) throw new OtsFormatError("can't reverse an empty message");
            r = msg.slice().reverse(); break;
        case 'hexlify':
            if (!msg.length || msg.length > MAX_MSG / 2) throw new OtsFormatError('bad hexlify length');
            r = new TextEncoder().encode(bytesToHex(msg)); break;
    }
    if (r.length > MAX_MSG) throw new OtsFormatError(`result too long for ${op.op}`);
    return r;
}

// ── reading ────────────────────────────────────────────────────────────────────────────────────────────────────

class Reader {
    i = 0;
    private b: Uint8Array;
    // (no parameter properties: plain Node runs this file for the open checker, strip-only)
    constructor(b: Uint8Array) { this.b = b; }
    byte(): number {
        if (this.i >= this.b.length) throw new OtsFormatError('file ends too early');
        return this.b[this.i++];
    }
    bytes(n: number): Uint8Array {
        if (this.i + n > this.b.length) throw new OtsFormatError('file ends too early');
        const r = this.b.slice(this.i, this.i + n);
        this.i += n;
        return r;
    }
    varuint(): number {
        let v = 0, shift = 0;
        for (let k = 0; k < 9; k++) {
            const b = this.byte();
            v += (b & 0x7f) * 2 ** shift;
            if (!(b & 0x80)) {
                if (!Number.isSafeInteger(v)) throw new OtsFormatError('number too big');
                return v;
            }
            shift += 7;
        }
        throw new OtsFormatError('number too long');
    }
    varbytes(max: number, min = 0): Uint8Array {
        const n = this.varuint();
        if (n > max || n < min) throw new OtsFormatError(`length ${n} out of range`);
        return this.bytes(n);
    }
    eof(): boolean { return this.i === this.b.length; }
}

function readAttestation(r: Reader): Attestation {
    const tag = bytesToHex(r.bytes(8));
    const payload = r.varbytes(MAX_PAYLOAD);
    const p = new Reader(payload);
    if (tag === TAG_PENDING) {
        const raw = p.varbytes(MAX_URI);
        const uri = new TextDecoder().decode(raw);
        if (!URI_CHARS.test(uri)) throw new OtsFormatError('calendar address has characters that are not allowed');
        if (!p.eof()) throw new OtsFormatError('extra bytes after a pending attestation');
        return { kind: 'pending', uri };
    }
    if (tag === TAG_BITCOIN) {
        const height = p.varuint();
        if (height > MAX_HEIGHT) throw new OtsFormatError('block height too large');
        if (!p.eof()) throw new OtsFormatError('extra bytes after a Bitcoin attestation');
        return { kind: 'bitcoin', height };
    }
    return { kind: 'unknown', tag, payload };
}

function readOp(r: Reader, tag: number): Op {
    const name = OP_BY_TAG.get(tag);
    if (!name) throw new OtsFormatError(`unknown operation 0x${tag.toString(16)}`);
    if (name === 'append' || name === 'prepend') return { op: name, arg: r.varbytes(MAX_MSG, 1) };
    return { op: name } as Op;
}

function readTimestamp(r: Reader, msg: Uint8Array, depth: number): Timestamp {
    if (depth <= 0) throw new OtsFormatError('proof is nested too deep');
    const t: Timestamp = { msg, attestations: [], ops: [] };
    const one = (tag: number) => {
        if (tag === 0x00) { t.attestations.push(readAttestation(r)); return; }
        const op = readOp(r, tag);
        if (t.ops.some(x => opKey(x.op) === opKey(op))) throw new OtsFormatError('an operation is repeated');
        let next: Uint8Array;
        try { next = applyOp(op, msg); } catch (e) { throw new OtsFormatError(`bad operation: ${(e as Error).message}`); }
        t.ops.push({ op, stamp: readTimestamp(r, next, depth - 1) });
    };
    let tag = r.byte();
    while (tag === 0xff) { one(r.byte()); tag = r.byte(); }
    one(tag);
    return t;
}

/** Parse a detached `.ots` file. `digest` is the 32-byte sha256 the proof is for. */
export function parseOts(bytes: Uint8Array): { digest: Uint8Array; timestamp: Timestamp } {
    const r = new Reader(bytes);
    const magic = r.bytes(HEADER_MAGIC.length);
    if (bytesToHex(magic) !== bytesToHex(HEADER_MAGIC)) throw new OtsFormatError('not an OpenTimestamps file');
    if (r.varuint() !== MAJOR_VERSION) throw new OtsFormatError('unsupported OpenTimestamps version');
    if (r.byte() !== OP_TAGS.sha256) throw new OtsFormatError('only sha256 proofs are used by Story Town');
    const digest = r.bytes(32);
    const timestamp = readTimestamp(r, digest, MAX_DEPTH);
    if (!r.eof()) throw new OtsFormatError('extra bytes at the end of the file');
    return { digest, timestamp };
}

/** Parse a bare timestamp as returned by a calendar, for `msg`. */
export function parseTimestamp(bytes: Uint8Array, msg: Uint8Array): Timestamp {
    const r = new Reader(bytes);
    const t = readTimestamp(r, msg, MAX_DEPTH);
    if (!r.eof()) throw new OtsFormatError('extra bytes after the calendar reply');
    return t;
}

// ── writing (same order as the reference client, so its files round-trip exactly) ──────────────────────────────

function varuint(n: number): number[] {
    const out: number[] = [];
    do {
        let b = n % 128;
        n = Math.floor(n / 128);
        if (n > 0) b |= 0x80;
        out.push(b);
    } while (n > 0);
    return out;
}
const varbytes = (b: Uint8Array) => concatBytes(new Uint8Array(varuint(b.length)), b);

function attestationBytes(a: Attestation): Uint8Array {
    let tag: string, payload: Uint8Array;
    if (a.kind === 'pending') { tag = TAG_PENDING; payload = varbytes(new TextEncoder().encode(a.uri)); }
    else if (a.kind === 'bitcoin') { tag = TAG_BITCOIN; payload = new Uint8Array(varuint(a.height)); }
    else { tag = a.tag; payload = a.payload; }
    return concatBytes(hexToBytes(tag), varbytes(payload));
}

const cmpBytes = (a: Uint8Array, b: Uint8Array) => {
    for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
    return a.length - b.length;
};
function cmpAttestation(a: Attestation, b: Attestation): number {
    const ta = a.kind === 'pending' ? TAG_PENDING : a.kind === 'bitcoin' ? TAG_BITCOIN : a.tag;
    const tb = b.kind === 'pending' ? TAG_PENDING : b.kind === 'bitcoin' ? TAG_BITCOIN : b.tag;
    if (ta !== tb) return cmpBytes(hexToBytes(ta), hexToBytes(tb));
    if (a.kind === 'pending' && b.kind === 'pending') return a.uri < b.uri ? -1 : a.uri > b.uri ? 1 : 0;
    if (a.kind === 'bitcoin' && b.kind === 'bitcoin') return a.height - b.height;
    if (a.kind === 'unknown' && b.kind === 'unknown') return cmpBytes(a.payload, b.payload);
    return 0;
}
function cmpOp(a: Op, b: Op): number {
    if (a.op !== b.op) return OP_TAGS[a.op] - OP_TAGS[b.op];
    return 'arg' in a && 'arg' in b ? cmpBytes(a.arg, b.arg) : 0;
}
const opBytes = (op: Op) => 'arg' in op ? concatBytes(new Uint8Array([OP_TAGS[op.op]]), varbytes(op.arg)) : new Uint8Array([OP_TAGS[op.op]]);
export const opKey = (op: Op) => 'arg' in op ? `${op.op}:${bytesToHex(op.arg)}` : op.op;
const attKey = (a: Attestation) => a.kind === 'pending' ? `p:${a.uri}` : a.kind === 'bitcoin' ? `b:${a.height}` : `u:${a.tag}:${bytesToHex(a.payload)}`;

function writeTimestamp(t: Timestamp, out: Uint8Array[]): void {
    if (!t.attestations.length && !t.ops.length) throw new OtsFormatError("an empty timestamp can't be written");
    const atts = [...t.attestations].sort(cmpAttestation);
    const ops = [...t.ops].sort((x, y) => cmpOp(x.op, y.op));
    for (const a of atts.slice(0, -1)) out.push(new Uint8Array([0xff, 0x00]), attestationBytes(a));
    if (!ops.length) { out.push(new Uint8Array([0x00]), attestationBytes(atts[atts.length - 1])); return; }
    if (atts.length) out.push(new Uint8Array([0xff, 0x00]), attestationBytes(atts[atts.length - 1]));
    ops.forEach(({ op, stamp }, i) => {
        if (i < ops.length - 1) out.push(new Uint8Array([0xff]));
        out.push(opBytes(op));
        writeTimestamp(stamp, out);
    });
}

export function serializeTimestamp(t: Timestamp): Uint8Array {
    const out: Uint8Array[] = [];
    writeTimestamp(t, out);
    return concatBytes(...out);
}

export function serializeOts(digest: Uint8Array, t: Timestamp): Uint8Array {
    if (digest.length !== 32) throw new OtsFormatError('digest must be 32 bytes');
    return concatBytes(HEADER_MAGIC, new Uint8Array([MAJOR_VERSION, OP_TAGS.sha256]), digest, serializeTimestamp(t));
}

// ── tree helpers ───────────────────────────────────────────────────────────────────────────────────────────────

/** Add everything from `other` (same message) into `t`. Only ever adds; returns true if anything was new. */
export function mergeTimestamp(t: Timestamp, other: Timestamp): boolean {
    if (bytesToHex(t.msg) !== bytesToHex(other.msg)) throw new OtsFormatError("can't merge proofs for different messages");
    let changed = false;
    for (const a of other.attestations) {
        if (!t.attestations.some(x => attKey(x) === attKey(a))) { t.attestations.push(a); changed = true; }
    }
    for (const o of other.ops) {
        const mine = t.ops.find(x => opKey(x.op) === opKey(o.op));
        if (mine) changed = mergeTimestamp(mine.stamp, o.stamp) || changed;
        else { t.ops.push(o); changed = true; }
    }
    return changed;
}

/** Every attestation in the tree with the message it attests to. */
export function allAttestations(t: Timestamp): { msg: Uint8Array; att: Attestation }[] {
    const out: { msg: Uint8Array; att: Attestation }[] = [];
    const walk = (n: Timestamp) => {
        for (const a of n.attestations) out.push({ msg: n.msg, att: a });
        for (const o of n.ops) walk(o.stamp);
    };
    walk(t);
    return out;
}
