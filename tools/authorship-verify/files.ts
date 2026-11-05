/* Reads an authorship record from a .storytown file (ZIP), a project folder or an authorship/ folder. */

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { join, relative } from 'node:path';
import JSZip from 'jszip';
import type { RecordFiles } from '../../src/lib/authorship/index.ts';

function walk(dir: string, base: string, out: RecordFiles): void {
    for (const name of readdirSync(dir)) {
        const full = join(dir, name);
        if (statSync(full).isDirectory()) walk(full, base, out);
        else out[relative(base, full).split('\\').join('/')] = readFileSync(full, name.endsWith('.ots') ? 'latin1' : 'utf8');
    }
}

export async function readRecord(path: string): Promise<RecordFiles> {
    if (!existsSync(path)) throw new Error(`not found: ${path}`);
    const out: RecordFiles = {};
    if (statSync(path).isDirectory()) {
        const inner = join(path, 'authorship');
        walk(existsSync(inner) && statSync(inner).isDirectory() ? inner : path, existsSync(inner) ? inner : path, out);
        return out;
    }
    const zip = await JSZip.loadAsync(readFileSync(path));
    for (const [name, file] of Object.entries(zip.files)) {
        if (file.dir || !name.startsWith('authorship/')) continue;
        out[name.slice('authorship/'.length)] = await file.async(name.endsWith('.ots') ? 'binarystring' : 'string');
    }
    return out;
}
