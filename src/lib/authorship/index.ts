/* Authorship record core (authorship/v1). Pure TS: no React, no stores, no network.
   Spec: docs/design/authorship-ledger-v1.md. Same code runs in the app and in tools/authorship-verify. */
export * from './types.ts';
export { canonicalize, hashCanonical } from './canonical.ts';
export { b64uDecode, b64uEncode, sha256Tagged } from './encoding.ts';
export { commit, commitNew, checkDisclosure, SALT_BYTES } from './commit.ts';
export type { CommitKind, SaltRecord } from './commit.ts';
export { keyId, verifyES256, createDeviceKey, deviceKeyFrom } from './keys.ts';
export type { DeviceKey } from './keys.ts';
export { newChainId, entryHash, entryLine, nextEntry, startChain } from './chain.ts';
export type { EntryInput } from './chain.ts';
export { makeStatement, sealHead, sealLine, statementBytes, witnessBytes, otsDigest } from './seal.ts';
export { sealUpgradeProblem, newerSeal } from './upgrade.ts';
export { verifyRecord } from './verify.ts';
export type { Issue, IssueCode, RecordFiles, Report, ChainReport, BitcoinRef } from './verify.ts';
export { STORYTOWN_WITNESS_KEYS, CURRENT_WITNESS_KEY, witnessProblem, witnessKeysFile } from './witness.ts';
export { TYPE_CLAIMED, REVEALED_FILE, claimValue, revealLine, checkReveals } from './reveal.ts';
export type { Claim, Revealed, RevealLine } from './reveal.ts';
