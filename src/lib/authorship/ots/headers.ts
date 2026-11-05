/* Bitcoin block check (Phase 2 step 5). A proof says "block N has merkle root R"; this asks block sources the
   CHECKER picks (Esplora API: mempool.space/api, blockstream.info/api, or their own node's Esplora) whether Bitcoin
   agrees. Never a Story Town server by default. Every source must agree; a source that can't answer is reported,
   never treated as a pass. */

import { matchesBlockMerkleRoot, type BitcoinClaim } from './check.ts';

export interface HeaderFetch { (url: string): Promise<{ ok: boolean; status: number; text(): Promise<string> }> }

export interface BlockCheck {
    height: number;
    /** true = every source agrees with the proof; false = a source says otherwise; null = a source couldn't answer. */
    ok: boolean | null;
    /** Block time from the first source that answered (UTC ISO), for display. */
    time: string | null;
    sources: { source: string; merkleRoot: string | null; problem: string | null }[];
}

const HEX64 = /^[0-9a-f]{64}$/;

async function blockAt(base: string, height: number, f: HeaderFetch): Promise<{ merkleRoot: string; time: string }> {
    const b = base.replace(/\/+$/, '');
    const h = await f(`${b}/block-height/${height}`);
    if (!h.ok) throw new Error(`block-height ${height}: HTTP ${h.status}`);
    const hash = (await h.text()).trim();
    if (!HEX64.test(hash)) throw new Error(`block-height ${height}: not a block hash`);
    const r = await f(`${b}/block/${hash}`);
    if (!r.ok) throw new Error(`block ${hash.slice(0, 12)}…: HTTP ${r.status}`);
    const j = JSON.parse(await r.text()) as { height?: number; merkle_root?: string; timestamp?: number };
    if (j.height !== height || typeof j.merkle_root !== 'string' || !HEX64.test(j.merkle_root)) throw new Error(`block ${height}: unexpected answer`);
    return { merkleRoot: j.merkle_root, time: typeof j.timestamp === 'number' ? new Date(j.timestamp * 1000).toISOString() : '' };
}

export async function checkBlocks(claims: readonly BitcoinClaim[], sources: readonly string[], f: HeaderFetch): Promise<BlockCheck[]> {
    if (!sources.length) throw new Error('no block source chosen');
    const byHeight = new Map<number, Set<string>>();
    for (const c of claims) (byHeight.get(c.height) ?? byHeight.set(c.height, new Set()).get(c.height)!).add(c.merkleRoot);
    const out: BlockCheck[] = [];
    for (const [height, roots] of [...byHeight].sort((a, b) => a[0] - b[0])) {
        const res: BlockCheck = { height, ok: true, time: null, sources: [] };
        for (const s of sources) {
            try {
                const b = await blockAt(s, height, f);
                res.time ??= b.time || null;
                const agrees = [...roots].every(r => matchesBlockMerkleRoot({ height, merkleRoot: r }, b.merkleRoot));
                res.sources.push({ source: s, merkleRoot: b.merkleRoot, problem: agrees ? null : "Bitcoin's record for this block is different" });
                if (!agrees) res.ok = false;
            } catch (e) {
                res.sources.push({ source: s, merkleRoot: null, problem: (e as Error).message });
                if (res.ok === true) res.ok = null;
            }
        }
        out.push(res);
    }
    return out;
}
