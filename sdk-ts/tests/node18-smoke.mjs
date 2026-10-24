/**
 * #319: verify an attestation with the built SDK on the oldest supported
 * runtime (CI runs it on Node 18, which has no global crypto, so the SDK
 * takes its node:crypto fallback). The token is signed here at run time.
 *
 *   node tests/node18-smoke.mjs   (after npm run build)
 */

import { Buffer } from 'node:buffer';
import { createHash, webcrypto } from 'node:crypto';
import process from 'node:process';
import { URL } from 'node:url';

const sdk = await import(new URL('../dist/index.mjs', import.meta.url));
const { subtle } = webcrypto;
const QUERY = '2+2=4';
const PROOF = 'sha256:' + 'e'.repeat(64);
const KID = 'did:qwed:node:local#smoke';

const b64url = bytes => Buffer.from(bytes).toString('base64url');
const hash = 'sha256:' + createHash('sha256').update(QUERY).digest('hex');

const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const { x, y } = await subtle.exportKey('jwk', pair.publicKey);
const now = Math.floor(Date.now() / 1000);
const header = { alg: 'ES256', typ: 'qwed-attestation+jwt', kid: KID };
const claims = {
    iss: sdk.DEFAULT_ISSUER, sub: hash, iat: now, exp: now + 60, jti: 'att_smoke',
    qwed: { result: { status: 'VERIFIED' }, query_hash: hash, proof_hash: PROOF },
};
const input = `${b64url(JSON.stringify(header))}.${b64url(JSON.stringify(claims))}`;
const signature = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, Buffer.from(input));
const token = `${input}.${b64url(new Uint8Array(signature))}`;
const jwks = { keys: [{ kty: 'EC', crv: 'P-256', x, y, kid: KID, alg: 'ES256' }] };

if (await sdk.statementHash(QUERY) !== hash) {
    throw new Error('statementHash disagrees with node:crypto');
}
const verified = await sdk.verifyAttestation(token, jwks, { proofRef: PROOF, query: QUERY });
if (verified.qwed.proof_hash !== PROOF) {
    throw new Error('verifyAttestation returned the wrong claims');
}
process.stdout.write(`attestation smoke OK on Node ${process.version} (global crypto: ${typeof globalThis.crypto !== 'undefined'})\n`);
