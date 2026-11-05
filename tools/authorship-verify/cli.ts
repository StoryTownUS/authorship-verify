#!/usr/bin/env node
/* Story Town authorship verifier (authorship/v1). Open tool: checks a record with zero calls to storytown.us.
   Usage: node tools/authorship-verify/cli.ts <project.storytown | folder> [--json] [--headers <block source>]...
   --headers: ask a Bitcoin block source YOU pick (any Esplora API, e.g. https://mempool.space/api,
   https://blockstream.info/api, or your own node's) whether the blocks the Bitcoin proofs point at are real.
   Give it twice to cross-check two sources. Without it, nothing goes on the network.
   Exit: 0 = record checks out, 1 = record failed, 2 = couldn't read it / a block source couldn't answer. */

// Node prints a "module type not specified" note for the shared .ts core; it's noise for the person checking a proof.
export {};
process.removeAllListeners('warning');
const { verifyRecord } = await import('../../src/lib/authorship/index.ts');
const { readRecord } = await import('./files.ts');
const { checkBlocks } = await import('../../src/lib/authorship/ots/headers.ts');

async function main(): Promise<number> {
    const args = process.argv.slice(2);
    const json = args.includes('--json');
    const sources: string[] = [];
    const rest: string[] = [];
    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--headers') {
            const s = args[++i];
            if (!s || !/^https?:\/\//.test(s)) { console.error('--headers needs a block source URL, e.g. https://mempool.space/api'); return 2; }
            sources.push(s);
        } else rest.push(args[i]);
    }
    const path = rest.find(a => !a.startsWith('--'));
    if (!path) {
        console.error('Usage: node tools/authorship-verify/cli.ts <project.storytown | folder> [--json]');
        return 2;
    }
    let files;
    try {
        files = await readRecord(path);
    } catch (err) {
        console.error(`Couldn't read ${path}: ${(err as Error).message}`);
        return 2;
    }
    const report = verifyRecord(files);
    let blocks: Awaited<ReturnType<typeof checkBlocks>> | null = null;
    if (sources.length && report.bitcoin.length) {
        blocks = await checkBlocks(report.bitcoin, sources, (u) => fetch(u));
        for (const b of blocks) for (const s of b.sources) {
            if (s.problem && s.merkleRoot) report.errors.push({ code: 'E_OTS', file: 'ots/', message: `Bitcoin block ${b.height}: ${s.problem} (${s.source}), so a proof pointing at it is false` });
        }
        report.ok = report.errors.length === 0;
        report.warnings = report.warnings.filter(w => w.code !== 'W_BLOCK_NOT_CHECKED');
    }
    const unanswered = blocks?.some(b => b.ok === null) ?? false;
    const exit = !report.ok ? 1 : unanswered ? 2 : 0;
    if (json) {
        console.log(JSON.stringify({ ...report, blocks }, null, 2));
        return exit;
    }
    const t = report.totals;
    console.log(!report.ok ? 'RECORD FAILED' : unanswered ? "RECORD CHECKS OUT, BUT BITCOIN COULDN'T BE CHECKED (a block source didn't answer)" : 'RECORD CHECKS OUT');
    if (report.claim) console.log(`  Claimed by           ${report.claim.name}${report.claim.title ? ` · "${report.claim.title}"` : ''}  (signed by the creator; a claim, not proof of identity)`);
    if (report.revealed.length > (report.claim ? 1 : 0)) console.log(`  Revealed decisions   ${report.revealed.length}`);
    console.log(`  Decisions            ${t.decisions}  (by the creator ${t.byYou}, carried out by the AD ${t.byAd})`);
    console.log(`  AI generations       ${t.generations}`);
    console.log(`  Takes rejected       ${t.rejected}`);
    console.log(`  Imported files       ${t.imported}`);
    console.log(`  Devices (chains)     ${t.chains}`);
    console.log(`  Seals signed         ${t.seals}`);
    console.log(`  Witnessed            ${t.sealsWitnessed} of ${t.seals}`);
    console.log(`  Anchored in Bitcoin  ${t.sealsAnchored} of ${t.seals}`);
    const heights = [...new Set(report.bitcoin.map(b => b.height))].sort((a, b) => a - b);
    for (const h of heights) {
        const b = blocks?.find(x => x.height === h);
        const when = b?.time ? ` (${b.time.slice(0, 16).replace('T', ' ')} UTC)` : '';
        const verdict = !b ? 'proof only: add --headers <block source> to check Bitcoin itself'
            : b.ok === true ? `Bitcoin agrees: ${b.sources.map(s => new URL(s.source).host).join(' + ')}`
            : b.ok === false ? 'Bitcoin DISAGREES'
            : `couldn't check: ${b.sources.filter(s => s.problem).map(s => `${new URL(s.source).host} ${s.problem}`).join('; ')}`;
        console.log(`    block ${h}${when}  ${verdict}`);
    }
    if (t.first) console.log(`  Device dates         ${t.first.slice(0, 10)} to ${t.last?.slice(0, 10)} (device clock, not trusted)`);
    for (const e of report.errors) console.log(`  FAIL ${e.code}  ${e.file}${e.line ? `:${e.line}` : ''}  ${e.message}`);
    for (const w of report.warnings) console.log(`  note ${w.code}  ${w.file}${w.line ? `:${w.line}` : ''}  ${w.message}`);
    return exit;
}

main().then(code => process.exit(code), err => { console.error(err); process.exit(2); });
