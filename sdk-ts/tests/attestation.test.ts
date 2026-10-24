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
    KeyMismatchError,
    QWEDClient,
    QWEDError,
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

    it('treats a token as expired from the second its exp names, as PyJWT does', async () => {
        const { privateKey, jwks } = await keyPair();
        const exp = Math.floor(Date.now() / 1000) + 100;
        const token = await sign(privateKey, await claims({ exp }));

        await expect(verifyAttestation(token, jwks, { proofRef: PROOF, now: exp - 1 })).resolves.toBeTruthy();
        await expect(verifyAttestation(token, jwks, { proofRef: PROOF, now: exp })).rejects.toThrow(/expired/);
    });

    it('refuses a token before its nbf, within the leeway it is accepted', async () => {
        const { privateKey, jwks } = await keyPair();
        const now = Math.floor(Date.now() / 1000);
        const token = await sign(privateKey, await claims({ nbf: now + 30 }));

        await expect(verifyAttestation(token, jwks, { proofRef: PROOF, now })).rejects.toThrow(/not yet valid/);
        await expect(verifyAttestation(token, jwks, { proofRef: PROOF, now, leewaySeconds: 60 })).resolves.toBeTruthy();
    });

    it('refuses a token whose nbf is not a number', async () => {
        const { privateKey, jwks } = await keyPair();
        const token = await sign(privateKey, await claims({ nbf: 'soon' }));

        await expect(verifyAttestation(token, jwks, { proofRef: PROOF })).rejects.toThrow(/not yet valid/);
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

        const refused = verifyAttestation(token, jwks, { proofRef: PROOF });
        await expect(refused).rejects.toThrow(/signature/);
        await expect(refused).rejects.toBeInstanceOf(KeyMismatchError);
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

    it.each(['%%%', 'A', 'AAAAA'])('reports a malformed signature %j as such, not as an unusable key', async bad => {
        // 'A' and 'AAAAA' pass the alphabet check but are no base64: atob
        // throws, and that is an AttestationError too (#512 review).
        const { privateKey, jwks } = await keyPair();
        const [header, payload] = (await sign(privateKey, await claims())).split('.');

        const refused = verifyAttestation(`${header}.${payload}.${bad}`, jwks, { proofRef: PROOF });
        await expect(refused).rejects.toBeInstanceOf(AttestationError);
        await expect(refused).rejects.toThrow(/not a JWT/);
    });

    it('verifies through node:crypto where there is no global crypto (Node 18)', async () => {
        const { privateKey, jwks } = await keyPair();
        const token = await sign(privateKey, await claims());
        vi.stubGlobal('crypto', undefined);
        try {
            expect(globalThis.crypto).toBeUndefined();

            const verified = await verifyAttestation(token, jwks, { proofRef: PROOF, query: QUERY });

            expect(verified.qwed.proof_hash).toBe(PROOF);
        } finally {
            vi.unstubAllGlobals();
        }
    });
});

describe('the response and the client', () => {
    afterEach(() => {
        vi.unstubAllGlobals();
        vi.restoreAllMocks();
    });

    it('keeps a string attestation and drops any other', () => {
        expect(parseVerificationResponse({ status: 'VERIFIED', attestation: 't' }).attestation).toBe('t');
        expect(parseVerificationResponse({ status: 'VERIFIED', attestation: 1 })).not.toHaveProperty('attestation');
        expect(parseVerificationResponse({ status: 'VERIFIED', attestation: '' })).not.toHaveProperty('attestation');
    });

    it('fetches the JWKS again for an unknown kid, but not within 30 s of the last fetch', async () => {
        const { privateKey, jwks } = await keyPair();
        const token = await sign(privateKey, await claims());
        const fetched: string[] = [];
        vi.stubGlobal('fetch', async (url: string) => {
            fetched.push(url);
            // The first fetch is stale (an old key); the next has the new one.
            const body = fetched.length === 1 ? { keys: [] } : jwks;
            return new Response(JSON.stringify(body), { status: 200 });
        });
        let now = Date.now();
        vi.spyOn(Date, 'now').mockImplementation(() => now);
        const client = new QWEDClient({ apiKey: 'k', baseUrl: 'http://qwed.test' });
        const answer = { attestation: token, proof_ref: PROOF };

        // Just fetched: an unknown kid is refused without another request, so
        // a stream of made-up kids cannot bypass the cache (#512 review).
        await expect(client.verifyAttestation(answer, QUERY)).rejects.toBeInstanceOf(UnknownKeyError);
        await expect(client.verifyAttestation(answer, QUERY)).rejects.toBeInstanceOf(UnknownKeyError);
        expect(fetched).toHaveLength(1);

        // A minute later (still within the five-minute cache): one more fetch.
        now += 60_000;
        const verified = await client.verifyAttestation(answer, QUERY);

        expect(verified.qwed.proof_hash).toBe(PROOF);
        expect(fetched).toEqual(['http://qwed.test/.well-known/jwks.json', 'http://qwed.test/.well-known/jwks.json']);
    });

    it('fetches the JWKS again when the kid now names another key, but not within 30 s', async () => {
        // A server restarted with a new ephemeral key under the same kid
        // (#512 review): the cached key no longer verifies its tokens.
        const { privateKey, jwks } = await keyPair();
        const before = await keyPair();
        const token = await sign(privateKey, await claims());
        let fetches = 0;
        vi.stubGlobal('fetch', async () => {
            fetches += 1;
            return new Response(JSON.stringify(fetches === 1 ? before.jwks : jwks), { status: 200 });
        });
        let now = Date.now();
        vi.spyOn(Date, 'now').mockImplementation(() => now);
        const client = new QWEDClient({ apiKey: 'k', baseUrl: 'http://qwed.test' });
        const answer = { attestation: token, proof_ref: PROOF };

        await expect(client.verifyAttestation(answer)).rejects.toBeInstanceOf(KeyMismatchError);
        expect(fetches).toBe(1);

        now += 60_000;
        const verified = await client.verifyAttestation(answer);

        expect(verified.qwed.proof_hash).toBe(PROOF);
        expect(fetches).toBe(2);
    });

    it('tries keys another caller fetched meanwhile, without fetching', async () => {
        // One call checks the old keys while another refreshes them (#512
        // review): it retries with the new keys although they were just fetched.
        const { privateKey, jwks } = await keyPair();
        const before = await keyPair();
        const token = await sign(privateKey, await claims());
        let fetches = 0;
        vi.stubGlobal('fetch', async () => {
            fetches += 1;
            return new Response(JSON.stringify(jwks), { status: 200 });
        });
        const client = new QWEDClient({ apiKey: 'k', baseUrl: 'http://qwed.test' });
        await client.getJwks();
        vi.spyOn(client, 'getJwks').mockResolvedValueOnce(before.jwks);

        const verified = await client.verifyAttestation({ attestation: token, proof_ref: PROOF });

        expect(verified.qwed.proof_hash).toBe(PROOF);
        expect(fetches).toBe(1);
    });

    it('waits 30 s after a failed refresh too', async () => {
        // An unreachable key endpoint is not asked again for every token the
        // cached keys do not verify (#512 review).
        const { privateKey } = await keyPair();
        const before = await keyPair();
        const token = await sign(privateKey, await claims());
        let fetches = 0;
        vi.stubGlobal('fetch', async () => {
            fetches += 1;
            return fetches === 1
                ? new Response(JSON.stringify(before.jwks), { status: 200 })
                : new Response('', { status: 503 });
        });
        let now = Date.now();
        vi.spyOn(Date, 'now').mockImplementation(() => now);
        const client = new QWEDClient({ apiKey: 'k', baseUrl: 'http://qwed.test' });
        await client.getJwks();
        now += 60_000;
        const answer = { attestation: token, proof_ref: PROOF };

        await expect(client.verifyAttestation(answer)).rejects.toThrow(/keys unavailable/);
        // Within the next 30 s, the refresh's failure, not a missing key
        // (#513 review), and no request.
        await expect(client.verifyAttestation(answer)).rejects.toThrow(/keys unavailable/);
        expect(fetches).toBe(2);
    });

    it('shares a slow failure for the full 30 s', async () => {
        // #513 review: the 30 s counted from the start of a fetch, so one that
        // took 30 s to fail was already past them. Now they count from its end.
        const { privateKey } = await keyPair();
        const token = await sign(privateKey, await claims());
        let now = Date.now();
        let fetches = 0;
        vi.stubGlobal('fetch', async () => {
            fetches += 1;
            now += 40_000; // the fetch takes 40 s to fail
            return new Response('', { status: 503 });
        });
        vi.spyOn(Date, 'now').mockImplementation(() => now);
        const client = new QWEDClient({ apiKey: 'k', baseUrl: 'http://qwed.test' });
        const answer = { attestation: token, proof_ref: PROOF };

        await expect(client.verifyAttestation(answer)).rejects.toThrow(/keys unavailable/);
        await expect(client.verifyAttestation(answer)).rejects.toThrow(/keys unavailable/);
        expect(fetches).toBe(1);
    });

    it.each([
        [{ proof_ref: PROOF }, /no attestation/],
        [{ attestation: 't' }, /no proof_ref/],
    ])('checks the answer before fetching keys (%j)', async (answer, message) => {
        let fetches = 0;
        vi.stubGlobal('fetch', async () => {
            fetches += 1;
            return new Response('', { status: 503 });
        });
        const client = new QWEDClient({ apiKey: 'k', baseUrl: 'http://qwed.test' });

        await expect(client.verifyAttestation(answer)).rejects.toThrow(message);
        expect(fetches).toBe(0);
    });

    it('shares one JWKS fetch among concurrent callers', async () => {
        const { privateKey, jwks } = await keyPair();
        const token = await sign(privateKey, await claims());
        let fetches = 0;
        vi.stubGlobal('fetch', async () => {
            fetches += 1;
            await new Promise(resolve => setTimeout(resolve, 10));
            return new Response(JSON.stringify(jwks), { status: 200 });
        });
        const client = new QWEDClient({ apiKey: 'k', baseUrl: 'http://qwed.test' });
        const answer = { attestation: token, proof_ref: PROOF };

        const verified = await Promise.all([1, 2, 3].map(() => client.verifyAttestation(answer)));

        expect(verified).toHaveLength(3);
        expect(fetches).toBe(1);
    });

    it.each([
        ['a network failure', async () => { throw new TypeError('fetch failed'); }, 'QWED-ATTEST-001', /fetch failed/],
        ['a body that is not JSON', async () => new Response('not json', { status: 200 }), 'QWED-ATTEST-001', /unavailable/],
        ['an HTTP error', async () => new Response('', { status: 503 }), 'QWED-ATTEST-001', /unavailable/],
    ])('reports %s fetching the keys as a QWEDError, and again for 30 s', async (_case, respond, code, message) => {
        // As request() does, and as Python's KeysUnavailableError (#512 review).
        const { privateKey } = await keyPair();
        const token = await sign(privateKey, await claims());
        let fetches = 0;
        vi.stubGlobal('fetch', async () => {
            fetches += 1;
            return respond();
        });
        const client = new QWEDClient({ apiKey: 'k', baseUrl: 'http://qwed.test' });
        const answer = { attestation: token, proof_ref: PROOF };

        for (let call = 0; call < 2; call++) {
            const failed = client.verifyAttestation(answer);
            await expect(failed).rejects.toBeInstanceOf(QWEDError);
            await expect(failed).rejects.toMatchObject({ code });
            await expect(failed).rejects.toThrow(message);
        }
        expect(fetches).toBe(1);
    });

    it('reports a key fetch that times out as QWED-SYS-TIMEOUT', async () => {
        const { privateKey } = await keyPair();
        const token = await sign(privateKey, await claims());
        vi.stubGlobal('fetch', (_url: string, init: { signal: AbortSignal }) => new Promise((_resolve, reject) => {
            init.signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
        }));
        const client = new QWEDClient({ apiKey: 'k', baseUrl: 'http://qwed.test', timeout: 10 });

        const failed = client.verifyAttestation({ attestation: token, proof_ref: PROOF });

        await expect(failed).rejects.toBeInstanceOf(QWEDError);
        await expect(failed).rejects.toMatchObject({ code: 'QWED-SYS-TIMEOUT', statusCode: 504 });
    });

    it('gives a failed fetch to every caller for 30 s, then fetches again', async () => {
        // An unreachable key endpoint is not asked for every token (#512
        // review); concurrent callers share the failing fetch.
        const { privateKey, jwks } = await keyPair();
        const token = await sign(privateKey, await claims());
        let fetches = 0;
        vi.stubGlobal('fetch', async () => {
            fetches += 1;
            return fetches === 1
                ? new Response('', { status: 503 })
                : new Response(JSON.stringify(jwks), { status: 200 });
        });
        let now = Date.now();
        vi.spyOn(Date, 'now').mockImplementation(() => now);
        const client = new QWEDClient({ apiKey: 'k', baseUrl: 'http://qwed.test' });
        const answer = { attestation: token, proof_ref: PROOF };

        const first = await Promise.allSettled([1, 2, 3].map(() => client.verifyAttestation(answer)));
        await expect(client.verifyAttestation(answer)).rejects.toThrow(/keys unavailable/);
        expect(first.every(outcome => outcome.status === 'rejected')).toBe(true);
        expect(fetches).toBe(1);

        now += 31_000;
        await expect(client.verifyAttestation(answer)).resolves.toBeTruthy();
        expect(fetches).toBe(2);
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
