/* The verifier (spec §8). Pure, zero network calls. The CLI (tools/authorship-verify) and the app run this
   same code. Any changed byte must fail loudly with a code, a file and a line. */

import { canonicalize } from './canonical.ts';
import { entryHash } from './chain.ts';
import { checkEntryShape, checkSealShape, isChainId } from './shape.ts';
import { isPublicJwk, keyId, verifyES256 } from './keys.ts';
import { statementBytes, witnessBytes } from './seal.ts';
import { STORYTOWN_WITNESS_KEYS } from './witness.ts';
import { otsDigest } from './seal.ts';
import { checkOts } from './ots/check.ts';
import { binaryToBytes, otsFileName, receiptsProblem } from './ots/receipts.ts';
import { TYPE_CHAIN_START, TYPE_KEY_ADDED, TYPE_KEY_RETIRED, V1 } from './types.ts';
import { REVEALED_FILE, checkReveals } from './reveal.ts';
import type { Claim, Revealed } from './reveal.ts';
import type { Entry, KeyFile, PublicKeyRecord, Seal } from './types.ts';

export type IssueCode =
    | 'E_VERSION' | 'E_JSON' | 'E_NOT_CANONICAL' | 'E_FIELD' | 'E_SEQ' | 'E_PREV' | 'E_START'
    | 'E_SEAL_HEAD' | 'E_KEY' | 'E_SIG' | 'E_OTS' | 'E_FILES' | 'E_REVEAL' | 'W_REVEAL_UNSEALED'
    | 'W_TIME_BACKWARDS' | 'W_UNSEALED' | 'W_NO_WITNESS_KEYS' | 'W_UNKNOWN_WITNESS' | 'W_OTS_NOT_CHECKED' | 'W_BLOCK_NOT_CHECKED' | 'W_NO_SEALS';

export interface Issue {
    code: IssueCode;
    file: string;
    line?: number;
    message: string;
}

/** The record's files as text, keyed by their path inside `authorship/` (e.g. "chains/<id>.jsonl"). */
export interface RecordFiles {
    [path: string]: string;
}

export interface ChainReport {
    chain: string;
    entries: number;
    decisions: number;
    byYou: number;
    byAd: number;
    generations: number;
    rejected: number;
    imported: number;
    seals: number;
    sealsWitnessed: number;
    sealsAnchored: number;
    unsealed: number;
    keys: string[];
    first: string | null;
    last: string | null;
}

/** A Bitcoin block a seal's proof points at. The proof is checked offline; whether Bitcoin's block really has this
 *  merkle root needs a block source the checker picks (ots/headers.ts `checkBlocks`, CLI `--headers`). */
export interface BitcoinRef { chain: string; seal: number; height: number; merkleRoot: string }

export interface Report {
    ok: boolean;
    errors: Issue[];
    warnings: Issue[];
    chains: ChainReport[];
    bitcoin: BitcoinRef[];
    /** Decisions the creator chose to show (revealed.jsonl), each matched to its fingerprint. */
    revealed: Revealed[];
    /** The creator's claim (name + title), CLAIMED and signed — not proven identity. null = no sealed claim. */
    claim: Claim | null;
    totals: Omit<ChainReport, 'chain' | 'keys' | 'first' | 'last'> & { chains: number; first: string | null; last: string | null };
}

const RECORD_TYPES = new Set([TYPE_CHAIN_START, TYPE_KEY_ADDED, TYPE_KEY_RETIRED]);

interface ParsedLine<T> { value: T; line: number }

/** Splits a JSONL file into canonical JSON lines. Every line, the last included, ends with exactly one "\n";
    any other ending is a changed file. */
function parseJsonl(file: string, text: string, errors: Issue[]): ParsedLine<unknown>[] | null {
    if (text === '') return [];
    if (!text.endsWith('\n')) {
        errors.push({ code: 'E_NOT_CANONICAL', file, message: 'file must end with one line break' });
        return null;
    }
    const body = text.slice(0, -1);
    const out: ParsedLine<unknown>[] = [];
    const lines = body.split('\n');
    for (let i = 0; i < lines.length; i++) {
        const line = i + 1;
        let value: unknown;
        try {
            value = JSON.parse(lines[i]);
        } catch {
            errors.push({ code: 'E_JSON', file, line, message: 'not valid JSON' });
            return null;
        }
        let canon: string;
        try {
            canon = canonicalize(value);
        } catch {
            errors.push({ code: 'E_FIELD', file, line, message: 'contains a non-integer number or unsupported value' });
            return null;
        }
        if (canon !== lines[i]) {
            errors.push({ code: 'E_NOT_CANONICAL', file, line, message: 'line is not in canonical (RFC 8785) form' });
            return null;
        }
        out.push({ value, line });
    }
    return out;
}

function parseKeyFile(file: string, text: string | undefined, errors: Issue[]): Map<string, PublicKeyRecord> | null {
    const map = new Map<string, PublicKeyRecord>();
    if (text === undefined) return map;
    const lines = parseJsonl(file, text, errors);
    if (!lines) return null;
    if (lines.length !== 1) {
        errors.push({ code: 'E_FIELD', file, message: 'must hold exactly one line' });
        return null;
    }
    const kf = lines[0].value as KeyFile;
    if (!kf || typeof kf !== 'object' || Array.isArray(kf) || Object.keys(kf).sort().join(',') !== 'keys,v') {
        errors.push({ code: 'E_FIELD', file, line: 1, message: 'must be {"keys":{…},"v":"authorship/v1"}' });
        return null;
    }
    if (kf.v !== V1) {
        errors.push({ code: 'E_VERSION', file, line: 1, message: versionMessage(kf.v) });
        return null;
    }
    if (!kf.keys || typeof kf.keys !== 'object' || Array.isArray(kf.keys)) {
        errors.push({ code: 'E_FIELD', file, line: 1, message: 'keys must be an object' });
        return null;
    }
    for (const [id, rec] of Object.entries(kf.keys)) {
        const r = rec as unknown as Record<string, unknown>;
        if (!r || typeof r !== 'object' || Object.keys(r).sort().join(',') !== 'alg,jwk,kind'
            || r.alg !== 'ES256' || (r.kind !== 'device' && r.kind !== 'passkey') || !isPublicJwk(r.jwk)) {
            errors.push({ code: 'E_FIELD', file, line: 1, message: `key ${id} is malformed` });
            return null;
        }
        map.set(id, rec);
    }
    return map;
}

function versionMessage(v: unknown): string {
    return typeof v === 'string' && v.startsWith('authorship/')
        ? `format ${v} is newer than this verifier understands: update the verifier`
        : 'not an authorship record';
}

function emptyCounts(chain: string): ChainReport {
    return {
        chain, entries: 0, decisions: 0, byYou: 0, byAd: 0, generations: 0, rejected: 0, imported: 0,
        seals: 0, sealsWitnessed: 0, sealsAnchored: 0, unsealed: 0, keys: [], first: null, last: null,
    };
}

export function verifyRecord(files: RecordFiles): Report {
    const errors: Issue[] = [];
    const warnings: Issue[] = [];
    const reports: ChainReport[] = [];
    const bitcoin: BitcoinRef[] = [];

    const chainFiles = Object.keys(files).filter(p => p.startsWith('chains/')).sort();
    if (chainFiles.length === 0) errors.push({ code: 'E_FILES', file: 'chains/', message: 'no chains in this record' });

    // Device keys: every listed key must match its id (thumbprint).
    const keys = parseKeyFile('keys.json', files['keys.json'], errors);
    if (keys) {
        for (const [id, rec] of keys) {
            if (keyId(rec.jwk) !== id) errors.push({ code: 'E_KEY', file: 'keys.json', line: 1, message: `key ${id} doesn't match its public key` });
        }
    }
    const witnessKeys = parseKeyFile('witness-keys.json', files['witness-keys.json'], errors);

    // Seals, grouped by chain.
    const sealsByChain = new Map<string, ParsedLine<Seal>[]>();
    if (files['seals.jsonl'] !== undefined) {
        const lines = parseJsonl('seals.jsonl', files['seals.jsonl'], errors);
        for (const pl of lines ?? []) {
            const problem = checkSealShape(pl.value);
            if (problem) {
                const s = pl.value as { statement?: { v?: unknown } };
                const isVersion = problem === 'statement.v' && s?.statement?.v !== undefined;
                errors.push({ code: isVersion ? 'E_VERSION' : 'E_FIELD', file: 'seals.jsonl', line: pl.line, message: isVersion ? versionMessage(s.statement!.v) : problem });
                continue;
            }
            const seal = pl.value as Seal;
            const list = sealsByChain.get(seal.statement.chain) ?? [];
            list.push({ value: seal, line: pl.line });
            sealsByChain.set(seal.statement.chain, list);
        }
    }

    const knownChains = new Set<string>();
    const entriesByChain = new Map<string, Entry[]>();
    const sealedSeqs = new Map<string, { seal: number; seq: number }[]>();
    for (const path of chainFiles) {
        const chainId = path.slice('chains/'.length).replace(/\.jsonl$/, '');
        knownChains.add(chainId);
        const rep = emptyCounts(chainId);
        reports.push(rep);
        if (!path.endsWith('.jsonl') || !isChainId(chainId)) {
            errors.push({ code: 'E_FILES', file: path, message: 'chain file name must be <chain id>.jsonl' });
            continue;
        }
        const entries = verifyChain(path, chainId, files[path], rep, errors, warnings);
        if (!entries) continue;
        entriesByChain.set(chainId, entries);
        const good: { seal: number; seq: number }[] = [];
        sealedSeqs.set(chainId, good);
        verifySeals(chainId, entries, sealsByChain.get(chainId) ?? [], keys, witnessKeys, rep, errors, warnings, files, bitcoin, good);
    }
    for (const [chainId, list] of sealsByChain) {
        if (!knownChains.has(chainId)) {
            errors.push({ code: 'E_SEAL_HEAD', file: 'seals.jsonl', line: list[0].line, message: `seal for chain ${chainId}, which isn't in this record` });
        }
    }

    const totals = {
        chains: reports.length, entries: 0, decisions: 0, byYou: 0, byAd: 0, generations: 0, rejected: 0, imported: 0,
        seals: 0, sealsWitnessed: 0, sealsAnchored: 0, unsealed: 0,
        first: null as string | null, last: null as string | null,
    };
    for (const r of reports) {
        for (const k of ['entries', 'decisions', 'byYou', 'byAd', 'generations', 'rejected', 'imported', 'seals', 'sealsWitnessed', 'sealsAnchored', 'unsealed'] as const) {
            totals[k] += r[k];
        }
        if (r.first && (!totals.first || r.first < totals.first)) totals.first = r.first;
        if (r.last && (!totals.last || r.last > totals.last)) totals.last = r.last;
    }
    if (bitcoin.length) {
        const heights = [...new Set(bitcoin.map(b => b.height))].sort((a, b) => a - b);
        warnings.push({ code: 'W_BLOCK_NOT_CHECKED', file: 'ots/', message: `the proofs point at Bitcoin block${heights.length > 1 ? 's' : ''} ${heights.join(', ')}; that Bitcoin really holds ${heights.length > 1 ? 'them' : 'it'} needs a block source you pick (CLI: --headers https://mempool.space/api)` });
    }
    let revealed: Revealed[] = [];
    let claim: Claim | null = null;
    if (files[REVEALED_FILE] !== undefined) {
        const r = checkReveals(files[REVEALED_FILE], entriesByChain, sealedSeqs);
        for (const i of r.issues) (i.code === 'E_REVEAL' ? errors : warnings).push({ code: i.code, file: REVEALED_FILE, line: i.line, message: i.message });
        revealed = r.revealed;
        claim = r.claim;
    }
    return { ok: errors.length === 0, errors, warnings, chains: reports, bitcoin, revealed, claim, totals };
}

/** Checks one chain's links. Returns its entries, or null after the first error (later links would cascade). */
function verifyChain(file: string, chainId: string, text: string, rep: ChainReport, errors: Issue[], warnings: Issue[]): Entry[] | null {
    const lines = parseJsonl(file, text, errors);
    if (!lines) return null;
    if (lines.length === 0) {
        errors.push({ code: 'E_START', file, message: 'empty chain' });
        return null;
    }
    const entries: Entry[] = [];
    let prevHash: string | null = null;
    let lastAt = '';
    for (const { value, line } of lines) {
        const v = (value as { v?: unknown })?.v;
        if (v !== V1) {
            errors.push({ code: 'E_VERSION', file, line, message: versionMessage(v) });
            return null;
        }
        const problem = checkEntryShape(value);
        if (problem) {
            errors.push({ code: 'E_FIELD', file, line, message: problem });
            return null;
        }
        const e = value as Entry;
        if (e.chain !== chainId || e.seq !== entries.length) {
            errors.push({ code: 'E_SEQ', file, line, message: e.chain !== chainId ? 'entry belongs to another chain' : `expected seq ${entries.length}, found ${e.seq}` });
            return null;
        }
        if (e.prev !== prevHash) {
            errors.push({ code: 'E_PREV', file, line, message: `decision ${e.seq} doesn't match the one before it` });
            return null;
        }
        if ((e.seq === 0 && e.type !== TYPE_CHAIN_START) || (e.seq === 1 && e.type !== TYPE_KEY_ADDED) || (e.seq > 0 && e.type === TYPE_CHAIN_START)) {
            errors.push({ code: 'E_START', file, line, message: 'a chain starts with chain.start then key.added, once' });
            return null;
        }
        if (lastAt && e.at < lastAt) warnings.push({ code: 'W_TIME_BACKWARDS', file, line, message: 'device clock went backwards (device time is not trusted)' });
        lastAt = e.at;
        prevHash = entryHash(e);
        entries.push(e);

        rep.entries++;
        if (!RECORD_TYPES.has(e.type)) {
            rep.decisions++;
            if (e.by === 'you') rep.byYou++;
            else rep.byAd++;
        }
        if (e.type === 'ai.received') rep.generations++;
        if (e.type === 'direct.rejected') rep.rejected++;
        if (e.type === 'media.imported') rep.imported++;
        if (!rep.first) rep.first = e.at;
        rep.last = e.at;
    }
    if (entries.length < 2) {
        errors.push({ code: 'E_START', file, message: 'a chain starts with chain.start then key.added' });
        return null;
    }
    return entries;
}

function keyEventsOk(entries: Entry[], id: string, sealSeq: number): string | null {
    let added = -1;
    let retired = -1;
    for (const e of entries) {
        if (e.seq > sealSeq) break;
        const names = e.refs.some(r => r.role === 'key' && r.id === id);
        if (!names) continue;
        if (e.type === TYPE_KEY_ADDED && added < 0) added = e.seq;
        if (e.type === TYPE_KEY_RETIRED && retired < 0) retired = e.seq;
    }
    if (added < 0) return 'its key was never added to this chain before the seal';
    if (retired >= 0) return 'its key was retired before the seal';
    return null;
}

function verifySeals(
    chainId: string, entries: Entry[], seals: ParsedLine<Seal>[],
    keys: Map<string, PublicKeyRecord> | null, witnessKeys: Map<string, PublicKeyRecord> | null,
    rep: ChainReport, errors: Issue[], warnings: Issue[], files: RecordFiles, bitcoin: BitcoinRef[],
    good: { seal: number; seq: number }[] = [],
): void {
    const file = 'seals.jsonl';
    let lastSeq = -1;
    seals.forEach(({ value: seal, line }, i) => {
        const st = seal.statement;
        if (st.seal !== i || st.seq < lastSeq) {
            errors.push({ code: 'E_SEQ', file, line, message: `seal numbers for chain ${chainId} must run 0,1,2… in order` });
            return;
        }
        lastSeq = st.seq;
        const head = entries[st.seq];
        if (!head || entryHash(head) !== st.head) {
            errors.push({ code: 'E_SEAL_HEAD', file, line, message: `seal ${st.seal} doesn't match decision ${st.seq}` });
            return;
        }
        const key = keys?.get(st.key);
        const keyProblem = !key ? 'its key is missing from keys.json' : keyEventsOk(entries, st.key, st.seq);
        if (keyProblem) {
            errors.push({ code: 'E_KEY', file, line, message: `seal ${st.seal}: ${keyProblem}` });
            return;
        }
        if (!verifyES256(key!.jwk, statementBytes(st), seal.sig)) {
            errors.push({ code: 'E_SIG', file, line, message: `seal ${st.seal}: the creator's signature doesn't verify` });
            return;
        }
        if (!rep.keys.includes(st.key)) rep.keys.push(st.key);
        rep.seals++;
        good.push({ seal: st.seal, seq: st.seq });
        if (seal.witness) {
            // Only Story Town's PUBLISHED witness keys count (./witness.ts); a key shipped inside the file is never
            // trusted on its own — anyone could write their own "storytown-witness-1".
            const id = seal.witness.key;
            const published = Object.prototype.hasOwnProperty.call(STORYTOWN_WITNESS_KEYS, id) ? STORYTOWN_WITNESS_KEYS[id] : undefined;
            const inFile = witnessKeys?.get(id);
            if (published && inFile && canonicalize(inFile) !== canonicalize(published)) {
                errors.push({ code: 'E_SIG', file: 'witness-keys.json', message: `witness key ${id} is not Story Town's published key` });
                return;
            }
            if (!published) {
                warnings.push(inFile
                    ? { code: 'W_UNKNOWN_WITNESS', file, line, message: `seal ${st.seal}: witness key ${id} is not a published Story Town key (or this checker is too old), so it isn't counted` }
                    : { code: 'W_NO_WITNESS_KEYS', file, line, message: `seal ${st.seal}: witness key ${id} is unknown, witness not checked` });
            } else if (!verifyES256(published.jwk, witnessBytes(st, seal.witness.received), seal.witness.sig)) {
                errors.push({ code: 'E_SIG', file, line, message: `seal ${st.seal}: the Story Town witness signature doesn't verify` });
                return;
            } else {
                rep.sealsWitnessed++;
            }
        }
        if (seal.ots.length) {
            // The proof must belong to THIS seal and the receipts must say exactly what the proof says (spec §6c).
            const want = otsFileName(st.chain, st.seal);
            if (seal.ots.some(o => o.file !== want)) {
                errors.push({ code: 'E_OTS', file, line, message: `seal ${st.seal}: a Bitcoin receipt points at the wrong file` });
                return;
            }
            const text = files[want];
            let proof: Uint8Array | undefined;
            try { proof = text === undefined ? undefined : binaryToBytes(text); } catch { proof = undefined; }
            const problem = text !== undefined && !proof ? 'its Bitcoin receipt file is damaged' : receiptsProblem(seal, proof);
            if (problem) {
                errors.push({ code: 'E_OTS', file: text === undefined ? file : want, line: text === undefined ? line : undefined, message: `seal ${st.seal}: ${problem}` });
                return;
            }
            const claims = checkOts(proof!, otsDigest(st)).bitcoin;
            if (claims.length) {
                rep.sealsAnchored++;
                for (const c of claims) bitcoin.push({ chain: chainId, seal: st.seal, height: c.height, merkleRoot: c.merkleRoot });
            }
        }
    });
    const lastSealed = seals.length ? Math.max(...seals.map(s => s.value.statement.seq)) : -1;
    rep.unsealed = entries.length - 1 - lastSealed;
    if (seals.length === 0) warnings.push({ code: 'W_NO_SEALS', file: `chains/${chainId}.jsonl`, message: 'this chain has no seals yet' });
    else if (rep.unsealed > 0) warnings.push({ code: 'W_UNSEALED', file: `chains/${chainId}.jsonl`, message: `${rep.unsealed} decision(s) after the last seal are not sealed yet` });
}
