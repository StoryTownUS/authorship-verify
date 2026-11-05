/* Exact field checks for v1 (spec §3, §6). Returns a problem string, or null when the shape is right.
   Strict on purpose: an extra or missing field is never silently ignored. */

import { hasOnlyIntegers } from './canonical.ts';
import { b64uDecode, HASH_RE } from './encoding.ts';
import { V1 } from './types.ts';

const ISO_MS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const TYPE_RE = /^[a-z][a-z0-9]*(\.[a-z][a-z0-9_]*)+$/;

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
    return !!v && typeof v === 'object' && !Array.isArray(v);
}
function exactKeys(o: Obj, keys: string[]): string | null {
    const have = Object.keys(o).sort();
    const want = [...keys].sort();
    const extra = have.filter(k => !want.includes(k));
    const missing = want.filter(k => !have.includes(k));
    if (extra.length) return `extra field ${extra.join(', ')}`;
    if (missing.length) return `missing field ${missing.join(', ')}`;
    return null;
}
function str(v: unknown, max = 256): v is string {
    return typeof v === 'string' && v.length > 0 && v.length <= max;
}
function uint(v: unknown): v is number {
    return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
}
export function isChainId(v: unknown): v is string {
    const b = typeof v === 'string' ? b64uDecode(v) : null;
    return !!b && b.length === 16;
}
export function isIsoMs(v: unknown): v is string {
    return typeof v === 'string' && ISO_MS.test(v) && !Number.isNaN(Date.parse(v));
}

export const ENTRY_FIELDS = ['v', 'chain', 'seq', 'prev', 'type', 'w', 'by', 'at', 'account', 'refs', 'provider', 'cause', 't'];

export function checkEntryShape(e: unknown): string | null {
    if (!isObj(e)) return 'entry is not an object';
    if (!hasOnlyIntegers(e)) return 'non-integer number';
    const k = exactKeys(e, ENTRY_FIELDS);
    if (k) return k;
    if (e.v !== V1) return 'v';
    if (!isChainId(e.chain)) return 'chain';
    if (!uint(e.seq)) return 'seq';
    if (e.seq === 0 ? e.prev !== null : !(typeof e.prev === 'string' && HASH_RE.test(e.prev))) return 'prev';
    if (!(typeof e.type === 'string' && e.type.length <= 64 && TYPE_RE.test(e.type))) return 'type';
    if (e.w !== 'big' && e.w !== 'choice' && e.w !== 'edit') return 'w';
    if (e.by !== 'you' && e.by !== 'ad') return 'by';
    if (!isIsoMs(e.at)) return 'at';
    if (!(e.account === null || str(e.account, 128))) return 'account';
    if (!Array.isArray(e.refs) || e.refs.length > 64) return 'refs';
    for (const r of e.refs) {
        if (!isObj(r)) return 'refs item';
        const extra = Object.keys(r).filter(x => x !== 'role' && x !== 'id' && x !== 'c');
        if (extra.length) return `refs extra field ${extra.join(', ')}`;
        if (!str(r.role, 32)) return 'refs.role';
        if ('id' in r && !str(r.id, 128)) return 'refs.id';
        if ('c' in r && !(typeof r.c === 'string' && HASH_RE.test(r.c))) return 'refs.c';
    }
    if (e.provider !== null) {
        if (!isObj(e.provider)) return 'provider';
        const pk = exactKeys(e.provider, ['name', 'model', 'gen', 'bridge']);
        if (pk) return `provider ${pk}`;
        const p = e.provider;
        if (!str(p.name, 64) || !str(p.model, 128)) return 'provider name/model';
        if (!(p.gen === null || (typeof p.gen === 'string' && HASH_RE.test(p.gen)))) return 'provider.gen';
        if (!(p.bridge === null || str(p.bridge, 128))) return 'provider.bridge';
    }
    if (!(e.cause === null || (uint(e.cause) && e.cause < (e.seq as number)))) return 'cause';
    if (e.t !== null) {
        if (!isObj(e.t)) return 't';
        const tk = exactKeys(e.t, ['ms', 'rev']);
        if (tk) return `t ${tk}`;
        if (!uint(e.t.ms) || !uint(e.t.rev)) return 't values';
    }
    return null;
}

export function checkStatementShape(s: unknown): string | null {
    if (!isObj(s)) return 'statement is not an object';
    const k = exactKeys(s, ['v', 'chain', 'seal', 'seq', 'head', 'reason', 'at', 'key']);
    if (k) return `statement ${k}`;
    if (s.v !== V1) return 'statement.v';
    if (!isChainId(s.chain)) return 'statement.chain';
    if (!uint(s.seal) || !uint(s.seq)) return 'statement seal/seq';
    if (!(typeof s.head === 'string' && HASH_RE.test(s.head))) return 'statement.head';
    if (s.reason !== 'session_end' && s.reason !== 'export') return 'statement.reason';
    if (!isIsoMs(s.at)) return 'statement.at';
    if (!(typeof s.key === 'string' && HASH_RE.test(s.key))) return 'statement.key';
    return null;
}

export function checkSealShape(seal: unknown): string | null {
    if (!isObj(seal)) return 'seal is not an object';
    if (!hasOnlyIntegers(seal)) return 'non-integer number';
    const k = exactKeys(seal, ['statement', 'sig', 'witness', 'ots']);
    if (k) return k;
    const st = checkStatementShape(seal.statement);
    if (st) return st;
    if (typeof seal.sig !== 'string') return 'sig';
    if (seal.witness !== null) {
        if (!isObj(seal.witness)) return 'witness';
        const wk = exactKeys(seal.witness, ['key', 'received', 'sig']);
        if (wk) return `witness ${wk}`;
        if (!str(seal.witness.key, 64) || !isIsoMs(seal.witness.received) || typeof seal.witness.sig !== 'string') return 'witness values';
    }
    if (!Array.isArray(seal.ots)) return 'ots';
    for (const o of seal.ots) {
        if (!isObj(o)) return 'ots item';
        const ok = exactKeys(o, ['calendar', 'file', 'state', 'block']);
        if (ok) return `ots ${ok}`;
        if (!str(o.calendar, 256) || !str(o.file, 128)) return 'ots calendar/file';
        if (o.state !== 'pending' && o.state !== 'anchored') return 'ots.state';
        if (!(o.block === null || uint(o.block))) return 'ots.block';
    }
    return null;
}
