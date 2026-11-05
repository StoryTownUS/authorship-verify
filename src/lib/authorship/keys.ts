/* Keys: thumbprint ids, ES256 verification (same code in the CLI and the browser), and the browser's
   device key (WebCrypto, private part can't be exported). Spec §2, §7. */

import { p256 } from '@noble/curves/nist.js';
import { concatBytes } from '@noble/hashes/utils.js';
import { hashCanonical } from './canonical.ts';
import { b64uDecode, b64uEncode } from './encoding.ts';
import type { PublicJwk, Signer } from './types.ts';

/** Key id = sha256 of the JCS of {crv,kty,x,y} (RFC 7638 style). */
export function keyId(jwk: PublicJwk): string {
    return hashCanonical({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y });
}

export function isPublicJwk(v: unknown): v is PublicJwk {
    if (!v || typeof v !== 'object' || Array.isArray(v)) return false;
    const o = v as Record<string, unknown>;
    const keys = Object.keys(o).sort().join(',');
    if (keys !== 'crv,kty,x,y') return false;
    if (o.kty !== 'EC' || o.crv !== 'P-256') return false;
    const x = b64uDecode(o.x as string);
    const y = b64uDecode(o.y as string);
    return !!x && !!y && x.length === 32 && y.length === 32;
}

function pointBytes(jwk: PublicJwk): Uint8Array | null {
    const x = b64uDecode(jwk.x);
    const y = b64uDecode(jwk.y);
    if (!x || !y || x.length !== 32 || y.length !== 32) return null;
    return concatBytes(new Uint8Array([4]), x, y);
}

/** ES256 check. Accepts high-S (WebCrypto doesn't normalise S); the signature is never used as an id. */
export function verifyES256(jwk: PublicJwk, message: Uint8Array, sigB64u: string): boolean {
    const sig = b64uDecode(sigB64u);
    const pub = pointBytes(jwk);
    if (!sig || sig.length !== 64 || !pub) return false;
    try {
        return p256.verify(sig, message, pub, { lowS: false });
    } catch {
        return false;
    }
}

/** Public JWK from a raw 32-byte private key (tests / vectors only). */
export function jwkFromSecret(secret: Uint8Array): PublicJwk {
    const pub = p256.getPublicKey(secret, false);
    return { kty: 'EC', crv: 'P-256', x: b64uEncode(pub.slice(1, 33)), y: b64uEncode(pub.slice(33, 65)) };
}

/** Deterministic signer from a raw private key (RFC 6979). For test vectors ONLY; the app uses the device key. */
export function secretKeySigner(secret: Uint8Array): Signer {
    const jwk = jwkFromSecret(secret);
    return {
        keyId: keyId(jwk),
        alg: 'ES256',
        async sign(message: Uint8Array) {
            return p256.sign(message, secret);
        },
    };
}

export interface DeviceKey {
    keyPair: CryptoKeyPair;
    jwk: PublicJwk;
    signer: Signer;
}

/** Makes a new device key. The private half is created non-extractable: no script can copy it out. */
export async function createDeviceKey(subtle: SubtleCrypto = globalThis.crypto.subtle): Promise<DeviceKey> {
    const keyPair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    return deviceKeyFrom(keyPair, subtle);
}

/** Rebuilds the signer from a stored key pair (IndexedDB keeps CryptoKey objects as-is). */
export async function deviceKeyFrom(keyPair: CryptoKeyPair, subtle: SubtleCrypto = globalThis.crypto.subtle): Promise<DeviceKey> {
    const raw = (await subtle.exportKey('jwk', keyPair.publicKey)) as JsonWebKey;
    if (!raw.x || !raw.y) throw new Error('authorship: device public key has no x/y');
    const jwk: PublicJwk = { kty: 'EC', crv: 'P-256', x: raw.x, y: raw.y };
    const signer: Signer = {
        keyId: keyId(jwk),
        alg: 'ES256',
        async sign(message: Uint8Array) {
            const sig = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, keyPair.privateKey, message as BufferSource);
            return new Uint8Array(sig);
        },
    };
    return { keyPair, jwk, signer };
}
