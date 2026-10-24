/**
 * #319: the TypeScript SDK reads and verifies attestations.
 *
 * Tokens are signed at test time with a key generated here, shaped as the
 * server issues them (ES256, typ qwed-attestation+jwt, kid naming the key);
 * none is stored in the repository.
 */

import { afterEach, describe, expect, it, vi } from 'vitest';

import {
    AttestationError,
    QWEDClient,
    UnknownKeyError,
    parseVerificationResponse,
    statementHash,
    verifyAttestation,
} from '../src';
import type { Jwks } from '../src';

const PROOF = 'sha256:' + 'e'.repeat(64);
const QUERY = '2+2=4';
const KID = 'did:qwed:node:local#test-key';
const subtle = globalThis.crypto.subtle;

function b64url(bytes: Uint8Array | string): string {
    const raw = typeof bytes === 'string' ? new TextEncoder().encode(bytes) : bytes;
    return btoa(String.fromCharCode(...raw)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function keyPair() {
    const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const jwk = await subtle.exportKey('jwk', pair.publicKey);
    const jwks: Jwks = { keys: [{ kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, kid: KID, alg: 'ES256', use: 'sig' }] };
    return { privateKey: pair.privateKey, jwks };
}

type PrivateKey = Awaited<ReturnType<typeof keyPair>>['privateKey'];

async function sign(
    privateKey: PrivateKey,
    claims: Record<string, unknown>,
    header: Record<string, unknown> = { alg: 'ES256', typ: 'qwed-attestation+jwt', kid: KID },
): Promise<string> {
    const signingInput = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
    const signature = new Uint8Array(await subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' }, privateKey, new TextEncoder().encode(signingInput),
    ));
    return `${signingInput}.${b64url(signature)}`;
}

async function claims(overrides: Record<string, unknown> = {}) {
    const now = Math.floor(Date.now() / 1000);
    return {
        iss: 'did:qwed:node:local',
        sub: await statementHash(QUERY),
        iat: now,
        exp: now + 3600,
        jti: 'att_test',
        qwed: {
            version: '1.0',
            result: { status: 'VERIFIED', verified: true, engine: 'math', confidence: 1 },
            query_hash: await statementHash(QUERY),
            proof_hash: PROOF,
        },
        ...overrides,
    };
}

describe('verifyAttestation', () => {
    it('verifies a genuine attestation', async () => {
        const { privateKey, jwks } = await keyPair();
        const token = await sign(privateKey, await claims());

        const verified = await verifyAttestation(token, jwks, { proofRef: PROOF, query: QUERY });

        expect(verified.qwed.proof_hash).toBe(PROOF);
    });

    it("refuses another answer's token", async () => {
        const { privateKey, jwks } = await keyPair();
        const token = await sign(privateKey, await claims());

        await expect(verifyAttestation(token, jwks, { proofRef: 'sha256:' + 'f'.repeat(64) }))
            .rejects.toThrow(/another answer/);
    });

    it('refuses a token for another statement', async () => {
        const { privateKey, jwks } = await keyPair();
        const token = await sign(privateKey, await claims());

        await expect(verifyAttestation(token, jwks, { proofRef: PROOF, query: '2+2=5' }))
            .rejects.toThrow(/another statement/);
    });

    it('refuses a token that does not attest VERIFIED', async () => {
        const { privateKey, jwks } = await keyPair();
        const base = await claims();
        const token = await sign(privateKey, { ...base, qwed: { ...base.qwed, result: { status: 'BLOCKED' } } });

        await expect(verifyAttestation(token, jwks, { proofRef: PROOF })).rejects.toThrow(/VERIFIED/);
    });

    it('refuses an expired token, within the leeway it is still accepted', async () => {
        const { privateKey, jwks } = await keyPair();
        const now = Math.floor(Date.now() / 1000);
        const token = await sign(privateKey, await claims({ exp: now - 30 }));

        await expect(verifyAttestation(token, jwks, { proofRef: PROOF })).rejects.toThrow(/expired/);
        await expect(verifyAttestation(token, jwks, { proofRef: PROOF, leewaySeconds: 60 })).resolves.toBeTruthy();
    });

    it('refuses another issuer', async () => {
        const { privateKey, jwks } = await keyPair();
        const token = await sign(privateKey, await claims({ iss: 'did:example:other' }));

        await expect(verifyAttestation(token, jwks, { proofRef: PROOF })).rejects.toThrow(AttestationError);
    });

    it('refuses a token signed by another key under the right kid', async () => {
        const { jwks } = await keyPair();
        const forger = await keyPair();
        const token = await sign(forger.privateKey, await claims());

        await expect(verifyAttestation(token, jwks, { proofRef: PROOF })).rejects.toThrow(/signature/);
    });

    it('refuses a token whose payload was changed after signing', async () => {
        const { privateKey, jwks } = await keyPair();
        const [header, , signature] = (await sign(privateKey, await claims())).split('.');
        const tampered = `${header}.${b64url(JSON.stringify(await claims({ jti: 'att_other' })))}.${signature}`;

        await expect(verifyAttestation(tampered, jwks, { proofRef: PROOF })).rejects.toThrow(/signature/);
    });

    it.each(['none', 'HS256'])('refuses a token naming %s before any key is used', async alg => {
        const { privateKey, jwks } = await keyPair();
        const token = await sign(privateKey, await claims(), { alg, typ: 'qwed-attestation+jwt', kid: KID });

        await expect(verifyAttestation(token, jwks, { proofRef: PROOF })).rejects.toThrow(/ES256/);
    });

    it('refuses a token whose kid the JWKS does not hold, as UnknownKeyError', async () => {
        const { privateKey } = await keyPair();
        const token = await sign(privateKey, await claims());

        await expect(verifyAttestation(token, { keys: [] }, { proofRef: PROOF })).rejects.toBeInstanceOf(UnknownKeyError);
    });

    it('refuses a JWKS key that is not ES256 P-256', async () => {
        const { privateKey, jwks } = await keyPair();
        const token = await sign(privateKey, await claims());
        const bad: Jwks = { keys: [{ ...jwks.keys[0], crv: 'P-384' }] };

        await expect(verifyAttestation(token, bad, { proofRef: PROOF })).rejects.toThrow(/ES256 P-256/);
    });

    it.each(['', 'not.a.jwt', 'a.b', '%%.%%.%%'])('refuses a malformed token %j', async token => {
        const { jwks } = await keyPair();

        await expect(verifyAttestation(token, jwks, { proofRef: PROOF })).rejects.toBeInstanceOf(AttestationError);
    });
});

describe('the response and the client', () => {
    afterEach(() => vi.unstubAllGlobals());

    it('keeps a string attestation and drops any other', () => {
        expect(parseVerificationResponse({ status: 'VERIFIED', attestation: 't' }).attestation).toBe('t');
        expect(parseVerificationResponse({ status: 'VERIFIED', attestation: 1 })).not.toHaveProperty('attestation');
        expect(parseVerificationResponse({ status: 'VERIFIED', attestation: '' })).not.toHaveProperty('attestation');
    });

    it('verifies against the JWKS it fetches, and fetches again when the kid is unknown', async () => {
        const { privateKey, jwks } = await keyPair();
        const token = await sign(privateKey, await claims());
        const fetched: string[] = [];
        vi.stubGlobal('fetch', async (url: string) => {
            fetched.push(url);
            // The first fetch is stale (an old key); the second has the new one.
            const body = fetched.length === 1 ? { keys: [] } : jwks;
            return new Response(JSON.stringify(body), { status: 200 });
        });
        const client = new QWEDClient({ apiKey: 'k', baseUrl: 'http://qwed.test' });

        const verified = await client.verifyAttestation({ attestation: token, proof_ref: PROOF }, QUERY);

        expect(verified.qwed.proof_hash).toBe(PROOF);
        expect(fetched).toEqual(['http://qwed.test/.well-known/jwks.json', 'http://qwed.test/.well-known/jwks.json']);
    });

    it('reuses the JWKS within its lifetime', async () => {
        const { privateKey, jwks } = await keyPair();
        const token = await sign(privateKey, await claims());
        let fetches = 0;
        vi.stubGlobal('fetch', async () => {
            fetches += 1;
            return new Response(JSON.stringify(jwks), { status: 200 });
        });
        const client = new QWEDClient({ apiKey: 'k', baseUrl: 'http://qwed.test' });

        await client.verifyAttestation({ attestation: token, proof_ref: PROOF });
        await client.verifyAttestation({ attestation: token, proof_ref: PROOF });

        expect(fetches).toBe(1);
    });
});
