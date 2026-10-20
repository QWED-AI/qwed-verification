/**
 * Contract tests (#480): the SDK must parse what the QWED server sends.
 *
 * Every file in sdk-fixtures/ at the repository root is a response captured
 * from the server. The Rust and Go SDKs parse the same files, and
 * tests/test_issue_468_rust_sdk_contract.py checks that the deterministic
 * ones still match what the server returns today.
 */

import { readFileSync } from 'node:fs';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
    Admission,
    AgentVerificationStatus,
    QWEDClient,
    QWEDError,
    VerificationStatus,
    VerificationType,
    getErrorMessage,
    isAdmitted,
    isVerified,
    parseBatchResponse,
    parseVerificationResponse,
} from '../src';

function fixture(name: string): unknown {
    const url = new URL(`../../sdk-fixtures/${name}.json`, import.meta.url);
    return JSON.parse(readFileSync(url, 'utf-8'));
}

const response = (name: string) => parseVerificationResponse(fixture(name));

describe('captured server responses', () => {
    it.each([
        ['math_verified', VerificationStatus.Verified, Admission.Admit, true, true],
        // The engine proved 2 + 2 = 5 false: VERIFIED, with a proof, yet BLOCKED.
        ['math_false', VerificationStatus.Verified, Admission.Blocked, true, false],
        ['math_ambiguous', VerificationStatus.Blocked, Admission.Blocked, false, false],
        ['code_safe', VerificationStatus.Verified, Admission.Admit, true, true],
        ['code_unsafe', VerificationStatus.Verified, Admission.Blocked, true, false],
        ['sql', VerificationStatus.Verified, Admission.Admit, true, true],
        ['natural_language', VerificationStatus.Unverifiable, Admission.Blocked, false, false],
        // /verify/logic and /verify/fact make no admission decision.
        ['logic', VerificationStatus.Blocked, undefined, false, false],
        ['fact', VerificationStatus.Unverifiable, undefined, false, false],
    ] as const)('%s is %s / %s', (name, status, admission, proof, admitted) => {
        const r = response(name);
        expect(r.status).toBe(status);
        expect(r.admission).toBe(admission);
        expect('admission' in r).toBe(admission !== undefined);
        expect(typeof r.proof_ref === 'string' && r.proof_ref.length > 0).toBe(proof);
        expect(isAdmitted(r)).toBe(admitted);
        expect(r.verified).toBe(admitted);
        expect(isVerified(r)).toBe(admitted);
        expect(typeof r.agent_message).toBe('string');
        expect(typeof r.is_authoritative).toBe('boolean');
    });

    it('keeps the envelope details and the endpoint fields', () => {
        const verified = response('math_verified');
        expect(verified.proof_ref).toMatch(/^sha256:[0-9a-f]{64}$/);
        expect(verified.is_authoritative).toBe(true);

        // /verify/math sends result as a boolean.
        const falseIdentity = response('math_false');
        expect(falseIdentity.is_valid).toBe(false);
        expect(falseIdentity.result).toBe(false);

        const unsafeCode = response('code_unsafe');
        expect(unsafeCode.constraint_id).toBe('code_verifier.code_unsafe');
        expect(unsafeCode.developer_fields?.is_safe).toBe(false);
        expect(Array.isArray(unsafeCode.issues)).toBe(true);
    });

    it.each(['math_false', 'code_unsafe', 'logic', 'fact'])(
        '%s keeps its endpoint fields through a JSON round trip',
        name => {
            const first = response(name);
            const second = parseVerificationResponse(JSON.parse(JSON.stringify(first)));
            expect(second).toEqual(first);
            for (const key of Object.keys(fixture(name) as object)) {
                expect(second).toHaveProperty([key]);
            }
        }
    );

    it('reads a string error, as /verify/logic sends it', () => {
        expect(getErrorMessage(response('logic'))).toBe('LLM translation failed');
        expect(getErrorMessage(response('math_verified'))).toBeNull();
    });

    it('parses a batch job and its items', () => {
        const batch = parseBatchResponse(fixture('batch'));
        expect(batch.status).toBe('completed');
        expect(batch.job_id).toBeTypeOf('string');
        expect([batch.total_items, batch.completed_items, batch.failed_items]).toEqual([2, 2, 0]);
        expect(batch.progress_percent).toBe(100);
        expect(batch).not.toHaveProperty('summary');

        expect(batch.items.map(item => item.status)).toEqual(['completed', 'completed']);
        expect(batch.items.map(item => item.type)).toEqual(['math', 'math']);
        expect(batch.items.map(item => item.result?.status)).toEqual([
            VerificationStatus.Verified,
            VerificationStatus.Unverifiable,
        ]);
        expect(batch.items[0].result?.proof_ref).toMatch(/^sha256:/);

        // Batch math items carry no admission decision today, so none is admitted.
        for (const item of batch.items) {
            expect(item.result?.admission).toBeUndefined();
            expect(isAdmitted(item.result)).toBe(false);
            expect(item.verified).toBe(false);
        }
    });
});

describe('status and admission parsing', () => {
    it.each([
        [{ status: 'VERIFIED', admission: 'ADMIT' }, VerificationStatus.Verified, Admission.Admit],
        [{ status: 'UNVERIFIABLE', admission: 'BLOCKED' }, VerificationStatus.Unverifiable, Admission.Blocked],
        [{ status: 'BLOCKED' }, VerificationStatus.Blocked, undefined],
        [{ status: 'BLOCKED', admission: null }, VerificationStatus.Blocked, undefined],
        // Unrecognised values, wrong case, old statuses and wrong types are Unknown.
        [{ status: 'PASSED', admission: 'DENY' }, VerificationStatus.Unknown, Admission.Unknown],
        [{ status: 'verified', admission: 'admit' }, VerificationStatus.Unknown, Admission.Unknown],
        [{ status: 'FAILED' }, VerificationStatus.Unknown, undefined],
        [{ status: 1, admission: true }, VerificationStatus.Unknown, Admission.Unknown],
        [{ status: null }, VerificationStatus.Unknown, undefined],
        [{}, VerificationStatus.Unknown, undefined],
    ])('%j', (body, status, admission) => {
        const r = parseVerificationResponse(body);
        expect(r.status).toBe(status);
        expect(r.admission).toBe(admission);
    });

    it('keeps the server status text in rawStatus', () => {
        // A batch logic item can answer with a solver status, not an envelope one.
        const sat = parseVerificationResponse({
            status: 'SAT',
            admission: 'ADMIT',
            proof_ref: 'sha256:ab',
            model: { x: 6 },
        });
        expect(sat.status).toBe(VerificationStatus.Unknown);
        expect(sat.rawStatus).toBe('SAT');
        expect(isAdmitted(sat)).toBe(false);

        expect(response('math_verified').rawStatus).toBe('VERIFIED');
        expect(parseVerificationResponse({ status: 'verified' }).rawStatus).toBe('verified');
        expect(parseVerificationResponse({ status: null })).not.toHaveProperty('rawStatus');
        expect(parseVerificationResponse({})).not.toHaveProperty('rawStatus');
        // A rawStatus key in the body is not trusted.
        expect(parseVerificationResponse({ rawStatus: 'VERIFIED' })).not.toHaveProperty('rawStatus');
        expect(parseVerificationResponse({ status: 'BLOCKED', rawStatus: 'VERIFIED' }).rawStatus).toBe('BLOCKED');
    });

    it('types the agent verification statuses the maths engine returns', () => {
        const statuses: AgentVerificationStatus[] = [
            VerificationStatus.Verified,
            VerificationStatus.Blocked,
            'DISPROVEN',
            'INCONCLUSIVE',
            'SYNTAX_ERROR',
        ];
        expect(statuses).toHaveLength(5);
    });

    it.each([null, 'VERIFIED', [], 42])('rejects a body that is not an object: %j', body => {
        expect(() => parseVerificationResponse(body)).toThrow(QWEDError);
    });

    it('rejects a batch body without items', () => {
        expect(() => parseBatchResponse({ job_id: 'x', status: 'completed' })).toThrow(QWEDError);
        expect(() => parseBatchResponse({ items: ['x'] })).toThrow(QWEDError);
    });
});

describe('isAdmitted fails closed', () => {
    const proof = { proof_ref: 'sha256:ab' };
    it.each([
        ['admit, verified, proof', { status: 'VERIFIED', admission: 'ADMIT', ...proof }, true],
        ['blocked admission', { status: 'VERIFIED', admission: 'BLOCKED', ...proof }, false],
        ['no admission', { status: 'VERIFIED', ...proof }, false],
        ['unknown admission', { status: 'VERIFIED', admission: 'DENY', ...proof }, false],
        ['admit without proof', { status: 'VERIFIED', admission: 'ADMIT' }, false],
        ['admit with empty proof', { status: 'VERIFIED', admission: 'ADMIT', proof_ref: '' }, false],
        ['admit with null proof', { status: 'VERIFIED', admission: 'ADMIT', proof_ref: null }, false],
        ['admit with object proof', { status: 'VERIFIED', admission: 'ADMIT', proof_ref: { sha256: 'ab' } }, false],
        ['admit, unverifiable', { status: 'UNVERIFIABLE', admission: 'ADMIT', ...proof }, false],
        ['admit, unknown status', { status: 'PASSED', admission: 'ADMIT', ...proof }, false],
        ['admit, no status', { admission: 'ADMIT', ...proof }, false],
        // A top-level verified field is not trusted.
        ['verified true only', { status: 'VERIFIED', verified: true }, false],
    ])('%s', (_name, body, want) => {
        const r = parseVerificationResponse(body);
        expect(isAdmitted(r)).toBe(want);
        expect(r.verified).toBe(want);
    });

    it('is false for a missing response', () => {
        expect(isAdmitted(null)).toBe(false);
        expect(isAdmitted(undefined)).toBe(false);
    });
});

describe('client', () => {
    afterEach(() => {
        vi.unstubAllGlobals();
    });

    function serve(name: string) {
        const fetchMock = vi.fn(async () =>
            new Response(JSON.stringify(fixture(name)), {
                status: 200,
                headers: { 'Content-Type': 'application/json' },
            })
        );
        vi.stubGlobal('fetch', fetchMock);
        return fetchMock;
    }

    const client = new QWEDClient({ apiKey: 'test-key', baseUrl: 'http://qwed.test' });

    it('verifyMath returns an admitted result for a true identity', async () => {
        const fetchMock = serve('math_verified');
        const r = await client.verifyMath('2 + 2 = 4');
        expect(fetchMock).toHaveBeenCalledWith('http://qwed.test/verify/math', expect.anything());
        expect(r.status).toBe(VerificationStatus.Verified);
        expect(isAdmitted(r)).toBe(true);
    });

    it('verifyMath does not admit a claim proven false', async () => {
        serve('math_false');
        const r = await client.verifyMath('2 + 2 = 5');
        expect(r.status).toBe(VerificationStatus.Verified);
        expect(r.admission).toBe(Admission.Blocked);
        expect(isAdmitted(r)).toBe(false);
        expect(r.verified).toBe(false);
    });

    it('verifyCode does not admit unsafe code', async () => {
        serve('code_unsafe');
        // fetch is stubbed, so the code sent does not matter.
        expect(isAdmitted(await client.verifyCode('unsafe code placeholder'))).toBe(false);
    });

    it('verifyLogic parses a response without an admission', async () => {
        serve('logic');
        const r = await client.verifyLogic('(A AND B) implies B');
        expect(r.status).toBe(VerificationStatus.Blocked);
        expect(r.admission).toBeUndefined();
        expect(isAdmitted(r)).toBe(false);
    });

    it('verifyBatch parses the batch job', async () => {
        serve('batch');
        const batch = await client.verifyBatch([
            { query: '2 + 2 = 4', type: VerificationType.Math },
            { query: '2 + 2 = 5', type: VerificationType.Math },
        ]);
        expect(batch.items).toHaveLength(2);
        expect(batch.items[0].result?.status).toBe(VerificationStatus.Verified);
        expect(batch.items.some(item => isAdmitted(item.result))).toBe(false);
    });
});
