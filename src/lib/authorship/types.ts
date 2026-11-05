/* Authorship record — format types (authorship/v1). Spec: docs/design/authorship-ledger-v1.md.
   FROZEN CONTRACT: a v1 record must verify forever. Any new field = a new version, never an edit here. */

export const V1 = 'authorship/v1' as const;
export type FormatVersion = typeof V1;

export type Weight = 'big' | 'choice' | 'edit';
export type Actor = 'you' | 'ad';
export type SealReason = 'session_end' | 'export';

/** A thing the decision touched: the app's own id + a salted fingerprint of its content. Never the content. */
export interface Ref {
    role: string;
    id?: string;
    c?: string;
}

export interface ProviderReceipt {
    /** Maker, plain (e.g. "fal"). */
    name: string;
    /** Maker's official model name, plain. */
    model: string;
    /** Salted fingerprint of the maker's generation id, or null. */
    gen: string | null;
    /** Studio Bridge receipt id from our server, or null. */
    bridge: string | null;
}

export interface Timing {
    /** ms from shown to decided. */
    ms: number;
    /** Revision count. */
    rev: number;
}

export interface Entry {
    v: FormatVersion;
    chain: string;
    seq: number;
    prev: string | null;
    type: string;
    w: Weight;
    by: Actor;
    /** Device clock, ISO-8601 UTC with ms. NOT trusted. */
    at: string;
    account: string | null;
    refs: Ref[];
    provider: ProviderReceipt | null;
    cause: number | null;
    t: Timing | null;
}

/** What the creator's key (and the witness) sign. */
export interface SealStatement {
    v: FormatVersion;
    chain: string;
    seal: number;
    seq: number;
    head: string;
    reason: SealReason;
    at: string;
    key: string;
}

export interface Witness {
    key: string;
    received: string;
    sig: string;
}

export interface OtsReceipt {
    calendar: string;
    file: string;
    state: 'pending' | 'anchored';
    block: number | null;
}

export interface Seal {
    statement: SealStatement;
    sig: string;
    witness: Witness | null;
    ots: OtsReceipt[];
}

export interface PublicJwk {
    kty: 'EC';
    crv: 'P-256';
    x: string;
    y: string;
}

export interface PublicKeyRecord {
    kind: 'device' | 'passkey';
    alg: 'ES256';
    jwk: PublicJwk;
}

/** keys.json and witness-keys.json share this shape (one JCS line). */
export interface KeyFile {
    v: FormatVersion;
    keys: Record<string, PublicKeyRecord>;
}

/** Signs bytes with ES256 (P-256 + SHA-256), returns raw 64-byte r||s. */
export interface Signer {
    keyId: string;
    alg: 'ES256';
    sign(message: Uint8Array): Promise<Uint8Array>;
}

/** Types the record itself writes. App decision types are listed in the spec §10; unknown types stay valid. */
export const TYPE_CHAIN_START = 'chain.start';
export const TYPE_KEY_ADDED = 'key.added';
export const TYPE_KEY_RETIRED = 'key.retired';
