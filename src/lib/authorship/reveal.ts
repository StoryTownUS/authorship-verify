/* Revealed decisions + the creator's claim (ledger spec note "Nov 5 2026, Phase 3 step 1"). Pure, no network.
   A shared proof package may carry `revealed.jsonl`: the content + salt of the few fingerprints the creator chose to
   show. Each one must match its fingerprint in the chain exactly. The claim ("Directed by <name>", title) is one such
   revealed decision of type `finish.claimed`. Reported as CLAIMED AND SIGNED by the creator — never as proven identity. */

import { canonicalize } from './canonical.ts';
import { checkDisclosure } from './commit.ts';
import type { CommitKind } from './commit.ts';
import type { Entry } from './types.ts';

export const TYPE_CLAIMED = 'finish.claimed';
export const REVEALED_FILE = 'revealed.jsonl';

export interface RevealLine { chain: string; seq: number; ref: number; kind: CommitKind; value: string; salt: string }
export interface Revealed { chain: string; seq: number; type: string; at: string; value: string; sealedBy: number | null }
export interface Claim { name: string; title: string; chain: string; seq: number; at: string; sealedBy: number | null }

export interface RevealIssue { code: 'E_REVEAL' | 'W_REVEAL_UNSEALED'; line: number; message: string }

/** The exact text the claim fingerprint covers. */
export function claimValue(name: string, title: string): string {
    return canonicalize({ name: name.normalize('NFC').trim(), title: title.normalize('NFC').trim() });
}


export function revealLine(r: RevealLine): string {
    return canonicalize({ chain: r.chain, kind: r.kind, ref: r.ref, salt: r.salt, seq: r.seq, value: r.value });
}

function parseClaim(value: string): { name: string; title: string } | null {
    try {
        const v = JSON.parse(value) as Record<string, unknown>;
        if (typeof v?.name !== 'string' || typeof v?.title !== 'string' || Object.keys(v).length !== 2) return null;
        if (canonicalize(v) !== value || !v.name) return null;
        return { name: v.name, title: v.title };
    } catch { return null; }
}

/** Checks `revealed.jsonl` against the chains. `sealedSeqs` = per chain, each valid seal's {seal, seq} in order. */
export function checkReveals(
    text: string,
    entriesByChain: Map<string, Entry[]>,
    sealedSeqs: Map<string, { seal: number; seq: number }[]>,
): { revealed: Revealed[]; claim: Claim | null; issues: RevealIssue[] } {
    const issues: RevealIssue[] = [];
    const revealed: Revealed[] = [];
    const claims: Claim[] = [];
    if (!text.endsWith('\n')) return { revealed, claim: null, issues: [{ code: 'E_REVEAL', line: 1, message: 'file must end with one line break' }] };
    text.slice(0, -1).split('\n').forEach((raw, i) => {
        const line = i + 1;
        let r: RevealLine;
        try { r = JSON.parse(raw) as RevealLine; } catch { issues.push({ code: 'E_REVEAL', line, message: 'not JSON' }); return; }
        if (typeof r !== 'object' || r === null || typeof r.chain !== 'string' || !Number.isInteger(r.seq) || !Number.isInteger(r.ref)
            || (r.kind !== 'text' && r.kind !== 'hash') || typeof r.value !== 'string' || typeof r.salt !== 'string' || revealLine(r) !== raw) {
            issues.push({ code: 'E_REVEAL', line, message: 'must be canonical {chain, kind, ref, salt, seq, value}' });
            return;
        }
        const e = entriesByChain.get(r.chain)?.[r.seq];
        const c = e?.refs[r.ref]?.c;
        if (!e || !c) { issues.push({ code: 'E_REVEAL', line, message: `decision ${r.seq} has no fingerprint #${r.ref} in this record` }); return; }
        if (!checkDisclosure(c, r.salt, r.kind, r.value)) { issues.push({ code: 'E_REVEAL', line, message: `the revealed content doesn't match decision ${r.seq}'s fingerprint` }); return; }
        const cover = (sealedSeqs.get(r.chain) ?? []).find(s => s.seq >= r.seq);
        const sealedBy = cover ? cover.seal : null;
        if (sealedBy === null) issues.push({ code: 'W_REVEAL_UNSEALED', line, message: `decision ${r.seq} is revealed but not sealed yet: nothing vouches for its date` });
        revealed.push({ chain: r.chain, seq: r.seq, type: e.type, at: e.at, value: r.value, sealedBy });
        if (e.type === TYPE_CLAIMED && e.refs[r.ref].role === 'claim') {
            const p = parseClaim(r.value);
            if (!p) { issues.push({ code: 'E_REVEAL', line, message: 'a claim must be {"name","title"} with a name' }); return; }
            claims.push({ ...p, chain: r.chain, seq: r.seq, at: e.at, sealedBy });
        }
    });
    // Current claim = the latest SEALED one (device time orders them only within a chain; across chains, the later at).
    const sealedClaims = claims.filter(c => c.sealedBy !== null).sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : a.seq - b.seq));
    return { revealed, claim: sealedClaims.at(-1) ?? null, issues };
}
