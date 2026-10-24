/**
 * Verify a QWED attestation (#319).
 *
 * A VERIFIED answer from a QWED server carries `attestation`: an ES256 JWT
 * the server signed after checking the verdict. Verifying it shows the
 * answer came from that server and was not changed:
 *
 * - the signature, with the key the token header's `kid` names in the
 *   server's JWKS (`GET /.well-known/jwks.json`);
 * - the issuer, and that the token has not expired;
 * - that it attests a VERIFIED result;
 * - that its `proof_hash` is the answer's `proof_ref`, so it is this
 *   answer's token;
 * - optionally, that its `query_hash` is the SHA-256 of the statement the
 *   verdict covers.
 *
 * A token says the server reached the verdict; whether to act on it is
 * still the answer's admission (`isAdmitted`). Uses WebCrypto (browsers,
 * Node 18+), with no dependency.
 */

import type { AttestationClaims } from './types';

/** The issuer a QWED server signs as. */
export const DEFAULT_ISSUER = 'did:qwed:node:local';
export const JWKS_PATH = '/.well-known/jwks.json';
const TOKEN_TYPE = 'qwed-attestation+jwt';

/** The attestation does not verify, or does not attest this answer. */
export class AttestationError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'AttestationError';
    }
}

/** No key in the JWKS has the token's kid: it may have rotated since the JWKS was fetched. */
export class UnknownKeyError extends AttestationError {
    constructor(message: string) {
        super(message);
        this.name = 'UnknownKeyError';
    }
}

export interface Jwk {
    kty?: string;
    crv?: string;
    x?: string;
    y?: string;
    kid?: string;
    alg?: string;
    use?: string;
    [member: string]: unknown;
}

export interface Jwks {
    keys: Jwk[];
}

export interface VerifyAttestationOptions {
    /** The answer's `proof_ref`: the token must be this answer's. */
    proofRef: string;
    /** When given, the statement the verdict covers must hash to the token's `query_hash`. */
    query?: string;
    issuer?: string;
    /** Clock skew allowed on expiry, in seconds. */
    leewaySeconds?: number;
    /** The current time in seconds (tests). */
    now?: number;
}

type Subtle = typeof globalThis.crypto.subtle;

async function subtleCrypto(): Promise<Subtle> {
    // Global in browsers and Node 19+; Node 18 has it on node:crypto. Looked
    // up on use, so importing the SDK needs neither.
    const global = (globalThis as { crypto?: { subtle?: Subtle } }).crypto;
    if (global?.subtle) {
        return global.subtle;
    }
    const nodeCrypto = await import('node:crypto');
    return nodeCrypto.webcrypto.subtle as unknown as Subtle;
}

function base64UrlBytes(segment: string): Uint8Array {
    if (!/^[A-Za-z0-9_-]*$/.test(segment)) {
        throw new AttestationError('attestation is not a JWT');
    }
    const padded = segment.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (segment.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

function jsonSegment(segment: string): Record<string, unknown> {
    let value: unknown;
    try {
        value = JSON.parse(new TextDecoder().decode(base64UrlBytes(segment)));
    } catch (error) {
        if (error instanceof AttestationError) throw error;
        throw new AttestationError('attestation is not a JWT');
    }
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new AttestationError('attestation is not a JWT');
    }
    return value as Record<string, unknown>;
}

function keyFor(kid: unknown, jwks: Jwks): Jwk {
    if (typeof kid !== 'string' || kid.length === 0) {
        throw new AttestationError('token header names no key (kid)');
    }
    if (!jwks || !Array.isArray(jwks.keys)) {
        throw new AttestationError('JWKS has no keys');
    }
    const jwk = jwks.keys.find(key => key && key.kid === kid);
    if (!jwk) {
        throw new UnknownKeyError("no JWKS key matches the token's kid");
    }
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || (jwk.alg ?? 'ES256') !== 'ES256'
        || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') {
        throw new AttestationError('JWKS key is not an ES256 P-256 key');
    }
    return jwk;
}

/** The `query_hash` a token carries for `statement`. */
export async function statementHash(statement: string): Promise<string> {
    const subtle = await subtleCrypto();
    const digest = new Uint8Array(await subtle.digest('SHA-256', new TextEncoder().encode(statement)));
    return 'sha256:' + Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Verify `token` as the attestation of the answer whose `proof_ref` is
 * `options.proofRef`, and return its claims; throw AttestationError otherwise.
 */
export async function verifyAttestation(
    token: string,
    jwks: Jwks,
    options: VerifyAttestationOptions,
): Promise<AttestationClaims> {
    if (typeof token !== 'string' || token.length === 0) {
        throw new AttestationError('no attestation');
    }
    if (typeof options?.proofRef !== 'string' || options.proofRef.length === 0) {
        throw new AttestationError('no proof_ref to bind the attestation to');
    }
    const parts = token.split('.');
    if (parts.length !== 3 || parts.some(part => part.length === 0)) {
        throw new AttestationError('attestation is not a JWT');
    }
    const [headerSegment, payloadSegment, signatureSegment] = parts;
    const header = jsonSegment(headerSegment);
    // Only ES256: a token that names another algorithm, including "none" or
    // an HMAC one, is refused before any key is used.
    if (header.alg !== 'ES256') {
        throw new AttestationError('attestation is not signed with ES256');
    }
    if (header.typ !== TOKEN_TYPE) {
        throw new AttestationError('token is not a QWED attestation');
    }
    const jwk = keyFor(header.kid, jwks);

    const subtle = await subtleCrypto();
    let valid: boolean;
    try {
        const key = await subtle.importKey(
            'jwk',
            { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, ext: true },
            { name: 'ECDSA', namedCurve: 'P-256' },
            false,
            ['verify'],
        );
        const signature = base64UrlBytes(signatureSegment);
        // JWS ES256 is the raw r || s pair, 64 bytes, as WebCrypto expects.
        valid = signature.length === 64 && await subtle.verify(
            { name: 'ECDSA', hash: 'SHA-256' },
            key,
            signature,
            new TextEncoder().encode(`${headerSegment}.${payloadSegment}`),
        );
    } catch {
        throw new AttestationError('JWKS key is unusable');
    }
    if (!valid) {
        throw new AttestationError('attestation signature or claims do not verify');
    }

    const claims = jsonSegment(payloadSegment);
    for (const name of ['iss', 'sub', 'iat', 'exp', 'jti']) {
        if (claims[name] === undefined) {
            throw new AttestationError('attestation signature or claims do not verify');
        }
    }
    if (claims.iss !== (options.issuer ?? DEFAULT_ISSUER)) {
        throw new AttestationError('attestation signature or claims do not verify');
    }
    const now = options.now ?? Math.floor(Date.now() / 1000);
    if (typeof claims.exp !== 'number' || now > claims.exp + (options.leewaySeconds ?? 0)) {
        throw new AttestationError('attestation has expired');
    }

    const qwed = claims.qwed as { result?: { status?: unknown }; proof_hash?: unknown; query_hash?: unknown } | undefined;
    if (!qwed || typeof qwed !== 'object' || qwed.result?.status !== 'VERIFIED') {
        throw new AttestationError('attestation does not attest a VERIFIED result');
    }
    if (qwed.proof_hash !== options.proofRef) {
        throw new AttestationError('attestation is for another answer (proof_ref differs)');
    }
    if (options.query !== undefined && qwed.query_hash !== await statementHash(options.query)) {
        throw new AttestationError('attestation is for another statement (query differs)');
    }
    return claims as unknown as AttestationClaims;
}
