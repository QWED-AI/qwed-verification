/**
 * QWED TypeScript SDK Client
 * Version: 1.0.0
 */

import {
    Admission,
    QWEDClientOptions,
    VerificationRequest,
    VerificationResponse,
    VerificationStatus,
    VerificationType,
    BatchItemResult,
    BatchRequest,
    BatchResponse,
    AgentRegistration,
    AgentVerificationRequest,
    AgentVerificationResponse,
    AttestationClaims,
} from './types';
import {
    DEFAULT_ISSUER,
    JWKS_PATH,
    Jwks,
    KeyMismatchError,
    requireAnswer,
    verifyAttestation,
} from './attestation';

// How long a fetched JWKS is reused, as the server's Cache-Control says.
const JWKS_MAX_AGE_MS = 300_000;
// The least time since the last fetch ended before another (counted from the
// end, so a fetch that is slow to fail is still shared for all of it, #513):
// after a token whose key it lacks (an unknown kid, or a signature that does
// not verify with the kid's key; a key rotation or a restart with a new
// ephemeral key is picked up within this, but a stream of made-up or forged
// tokens cannot turn each one into a request), and after a failed fetch,
// whose failure every caller gets meanwhile instead of a request each (#512).
const JWKS_MIN_REFRESH_MS = 30_000;

// ============================================================================
// Errors
// ============================================================================

export class QWEDError extends Error {
    constructor(
        message: string,
        public code: string,
        public statusCode?: number,
        public details?: Record<string, unknown>
    ) {
        super(message);
        this.name = 'QWEDError';
    }
}

export class QWEDAuthError extends QWEDError {
    constructor(message: string) {
        super(message, 'QWED-AUTH-001', 401);
        this.name = 'QWEDAuthError';
    }
}

export class QWEDRateLimitError extends QWEDError {
    constructor(message: string, public retryAfter?: number) {
        super(message, 'QWED-AUTH-004', 429);
        this.name = 'QWEDRateLimitError';
    }
}

// ============================================================================
// Client Implementation
// ============================================================================

export class QWEDClient {
    private baseUrl: string;
    private apiKey: string;
    private timeout: number;
    private headers: Record<string, string>;
    private jwks?: Jwks;
    private jwksFetchedAt = 0;
    private jwksAttemptedAt = 0;
    private jwksError?: unknown;
    private jwksFetch?: Promise<Jwks>;

    constructor(options: QWEDClientOptions) {
        this.apiKey = options.apiKey;
        this.baseUrl = (options.baseUrl || 'http://localhost:8000').replace(/\/$/, '');
        this.timeout = options.timeout || 30000;
        this.headers = {
            'Content-Type': 'application/json',
            'X-API-Key': this.apiKey,
            ...options.headers,
        };
    }

    // --------------------------------------------------------------------------
    // Attestations (#319)
    // --------------------------------------------------------------------------

    /**
     * The server's attestation keys (`GET /.well-known/jwks.json`, public),
     * reused for five minutes as the server's Cache-Control says. If they
     * cannot be fetched, that failure is thrown again for 30 seconds,
     * without a request, unless `refresh`.
     */
    async getJwks(refresh = false): Promise<Jwks> {
        const stale = Date.now() - this.jwksFetchedAt > JWKS_MAX_AGE_MS;
        if (this.jwks && !refresh && !stale) {
            return this.jwks;
        }
        // Callers that need keys while a fetch is in flight share it, a
        // refresh included: it began after the keys they found wanting.
        if (this.jwksFetch) {
            return this.jwksFetch;
        }
        // After a failed fetch its failure, for JWKS_MIN_REFRESH_MS. Keys
        // past their age are not used instead: a key the server has since
        // withdrawn would still verify.
        if (!refresh && this.jwksError !== undefined && Date.now() - this.jwksAttemptedAt < JWKS_MIN_REFRESH_MS) {
            throw this.jwksError;
        }
        const fetching = this.fetchJwks();
        const done = () => {
            if (this.jwksFetch === fetching) this.jwksFetch = undefined;
        };
        this.jwksFetch = fetching;
        fetching.then(done, done);
        return fetching;
    }

    private async fetchJwks(): Promise<Jwks> {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);
        try {
            const response = await fetch(`${this.baseUrl}${JWKS_PATH}`, { signal: controller.signal });
            if (!response.ok) {
                throw new QWEDError('Attestation keys unavailable', 'QWED-ATTEST-001', response.status);
            }
            const jwks = await response.json() as Jwks;
            this.jwks = jwks;
            this.jwksError = undefined;
            this.jwksFetchedAt = this.jwksAttemptedAt = Date.now();
            return jwks;
        } catch (error) {
            // As request() does: a QWEDError whatever failed (a network
            // error, a timeout, a body that is not JSON), as Python's
            // KeysUnavailableError is.
            const wrapped = error instanceof QWEDError
                ? error
                : error instanceof Error && error.name === 'AbortError'
                    ? new QWEDError('Attestation keys unavailable: request timeout', 'QWED-SYS-TIMEOUT', 504)
                    : new QWEDError(
                        `Attestation keys unavailable: ${error instanceof Error ? error.message : 'unknown error'}`,
                        'QWED-ATTEST-001',
                    );
            this.jwksError = wrapped;
            this.jwksAttemptedAt = Date.now();
            throw wrapped;
        } finally {
            clearTimeout(timeoutId);
        }
    }

    /**
     * Verify an answer's attestation against this server's keys and return
     * its claims; throws AttestationError if it does not verify or is not
     * this answer's. `query`, when given, must be the statement the verdict
     * covers. To verify against keys you pinned, call `verifyAttestation`
     * with your JWKS.
     */
    async verifyAttestation(
        result: Pick<VerificationResponse, 'attestation' | 'proof_ref'>,
        query?: string,
        options: { issuer?: string; leewaySeconds?: number } = {},
    ): Promise<AttestationClaims> {
        // A missing token or proof_ref is an AttestationError, not a network
        // error from the key fetch.
        requireAnswer(result?.attestation, result?.proof_ref);
        const verify = async (jwks: Jwks) => verifyAttestation(result.attestation as string, jwks, {
            proofRef: result.proof_ref as string,
            query,
            issuer: options.issuer ?? DEFAULT_ISSUER,
            leewaySeconds: options.leewaySeconds,
        });
        const jwks = await this.getJwks();
        try {
            return await verify(jwks);
        } catch (error) {
            if (!(error instanceof KeyMismatchError)) throw error;
            // The key may have rotated, or the server restarted with a new
            // key under the same kid, since the JWKS was cached: try the
            // keys once more (see jwksAfterMismatch).
            const newer = await this.jwksAfterMismatch(jwks);
            if (!newer) throw error;
            return verify(newer);
        }
    }

    /**
     * Keys to try once more after none in `used` verified a token: those
     * another caller fetched, or is fetching, meanwhile; else a fresh fetch
     * if the last one ended at least JWKS_MIN_REFRESH_MS ago. Within that,
     * the last fetch's failure if it failed (not a missing key, #513), else
     * none.
     */
    private async jwksAfterMismatch(used: Jwks): Promise<Jwks | undefined> {
        if (this.jwksFetch) return this.jwksFetch;
        if (this.jwks && this.jwks !== used) return this.jwks;
        if (Date.now() - this.jwksAttemptedAt < JWKS_MIN_REFRESH_MS) {
            if (this.jwksError !== undefined) throw this.jwksError;
            return undefined;
        }
        return this.getJwks(true);
    }

    // --------------------------------------------------------------------------
    // HTTP Methods
    // --------------------------------------------------------------------------

    private formatAgentId(agentId: number): string {
        if (!Number.isInteger(agentId)) {
            throw new QWEDError(
                'Agent ID must be an integer',
                'QWED-AGENT-ID-001',
                400
            );
        }

        return encodeURIComponent(String(agentId));
    }

    private async request<T>(
        method: string,
        endpoint: string,
        body?: unknown,
        extraHeaders?: Record<string, string>
    ): Promise<T> {
        const url = `${this.baseUrl}${endpoint}`;

        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), this.timeout);

        try {
            const response = await fetch(url, {
                method,
                headers: {
                    ...this.headers,
                    ...extraHeaders,
                },
                body: body ? JSON.stringify(body) : undefined,
                signal: controller.signal,
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                const errorData = await response.json().catch(() => ({})) as {
                    message?: string;
                    error?: {
                        message?: string;
                        code?: string;
                        details?: Record<string, unknown>;
                    };
                };

                if (response.status === 401) {
                    throw new QWEDAuthError(errorData.message || 'Invalid API key');
                }

                if (response.status === 429) {
                    const retryAfter = response.headers.get('Retry-After');
                    throw new QWEDRateLimitError(
                        errorData.message || 'Rate limit exceeded',
                        retryAfter ? parseInt(retryAfter) : undefined
                    );
                }

                throw new QWEDError(
                    errorData.error?.message || `HTTP ${response.status}`,
                    errorData.error?.code || `HTTP-${response.status}`,
                    response.status,
                    errorData.error?.details
                );
            }

            return response.json() as Promise<T>;
        } catch (error) {
            clearTimeout(timeoutId);

            if (error instanceof QWEDError) throw error;

            if (error instanceof Error && error.name === 'AbortError') {
                throw new QWEDError('Request timeout', 'QWED-SYS-TIMEOUT', 504);
            }

            throw new QWEDError(
                error instanceof Error ? error.message : 'Unknown error',
                'QWED-SYS-001'
            );
        }
    }

    // --------------------------------------------------------------------------
    // Health Check
    // --------------------------------------------------------------------------

    async health(): Promise<{ status: string; version?: string }> {
        return this.request('GET', '/health');
    }

    // --------------------------------------------------------------------------
    // Verification Methods
    // --------------------------------------------------------------------------

    async verify(
        query: string,
        options?: {
            type?: VerificationType;
            includeAttestation?: boolean;
            timeout?: number;
        }
    ): Promise<VerificationResponse> {
        const request: VerificationRequest = {
            query,
            type: options?.type || VerificationType.NaturalLanguage,
            options: {
                include_attestation: options?.includeAttestation,
                timeout_ms: options?.timeout,
            },
        };

        return parseVerificationResponse(
            await this.request<unknown>('POST', '/verify/natural_language', request)
        );
    }

    async verifyMath(
        expression: string,
        options?: { precision?: number }
    ): Promise<VerificationResponse> {
        return parseVerificationResponse(await this.request<unknown>('POST', '/verify/math', {
            expression,
            params: { precision: options?.precision },
        }));
    }

    async verifyLogic(
        query: string,
        options?: { format?: 'natural' | 'dsl' }
    ): Promise<VerificationResponse> {
        return parseVerificationResponse(await this.request<unknown>('POST', '/verify/logic', {
            query,
            params: { format: options?.format || 'dsl' },
        }));
    }

    async verifyCode(
        code: string,
        options?: { language?: string }
    ): Promise<VerificationResponse> {
        return parseVerificationResponse(await this.request<unknown>('POST', '/verify/code', {
            code,
            language: options?.language || 'python',
        }));
    }

    async verifyFact(
        claim: string,
        context: string
    ): Promise<VerificationResponse> {
        return parseVerificationResponse(
            await this.request<unknown>('POST', '/verify/fact', { claim, context })
        );
    }

    async verifySQL(
        query: string,
        schema: string,
        options?: { dialect?: string }
    ): Promise<VerificationResponse> {
        return parseVerificationResponse(await this.request<unknown>('POST', '/verify/sql', {
            query,
            schema_ddl: schema,
            dialect: options?.dialect || 'postgresql',
        }));
    }

    async verifyProcess(
        reasoningTrace: string,
        options?: { mode?: 'irac' | 'milestones'; keyMilestones?: string[] }
    ): Promise<VerificationResponse> {
        return parseVerificationResponse(await this.request<unknown>('POST', '/verify/process', {
            trace: reasoningTrace,
            mode: options?.mode || 'irac',
            milestones: options?.keyMilestones,
        }));
    }

    async verifyRAG(
        targetDocumentId: string,
        retrievedChunks: Record<string, unknown>[],
        options?: { maxDrmRate?: string }
    ): Promise<VerificationResponse> {
        return parseVerificationResponse(await this.request<unknown>('POST', '/verify/rag', {
            target_document_id: targetDocumentId,
            chunks: retrievedChunks,
            max_drm_rate: options?.maxDrmRate,
        }));
    }

    async verifyAgent(
        agentId: number,
        agentToken: string,
        query: string,
        options?: {
            provider?: string;
            toolSchema?: Record<string, unknown>;
        }
    ): Promise<AgentVerificationResponse> {
        // Security checks are enforced server-side and cannot be disabled by clients.
        const payload: Record<string, unknown> = {
            query: query,
        };
        if (options?.provider) payload.provider = options.provider;
        if (options?.toolSchema) {
            payload.tool_schema = options.toolSchema;
        }

        return this.request(
            'POST',
            `/agents/${this.formatAgentId(agentId)}/verify`,
            payload,
            { 'X-Agent-Token': agentToken }
        );
    }

    // --------------------------------------------------------------------------
    // Batch Operations
    // --------------------------------------------------------------------------

    async verifyBatch(
        items: Array<{
            query: string;
            type?: VerificationType;
        }>,
        options?: { maxParallel?: number; failFast?: boolean }
    ): Promise<BatchResponse> {
        const request: BatchRequest = {
            batch: true,
            items: items.map(item => ({
                query: item.query,
                type: item.type || VerificationType.NaturalLanguage,
            })),
            options: {
                max_parallel: options?.maxParallel,
                fail_fast: options?.failFast,
            },
        };

        return parseBatchResponse(await this.request<unknown>('POST', '/verify/batch', request));
    }

    // --------------------------------------------------------------------------
    // Agent Methods
    // --------------------------------------------------------------------------

    async registerAgent(
        registration: AgentRegistration
    ): Promise<{ agent_id: number; agent_token: string; status: string }> {
        return this.request('POST', '/agents/register', registration);
    }

    async verifyAgentAction(
        request: AgentVerificationRequest
    ): Promise<AgentVerificationResponse> {
        const query = request.query ?? request.action?.query;
        if (!query) {
            throw new QWEDError(
                'Agent verification requires a query payload',
                'QWED-AGENT-VERIFY-001',
                400
            );
        }

        const payload: Record<string, unknown> = { query };
        if (request.provider) {
            payload.provider = request.provider;
        }
        if (request.tool_schema) {
            payload.tool_schema = request.tool_schema;
        }

        return this.request(
            'POST',
            `/agents/${this.formatAgentId(request.agent_id)}/verify`,
            payload,
            { 'X-Agent-Token': request.agent_token }
        );
    }

    async getAgentBudget(
        agentId: number,
        agentToken: string
    ): Promise<{
        cost: { current_daily_usd: number; max_daily_usd: number };
        requests: { current_hour: number; max_per_hour: number };
    }> {
        const originalKey = this.headers['X-API-Key'];
        this.headers['X-API-Key'] = agentToken;

        try {
            return await this.request('GET', `/agents/${this.formatAgentId(agentId)}/budget`);
        } finally {
            this.headers['X-API-Key'] = originalKey;
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

const KNOWN_STATUSES: ReadonlySet<unknown> = new Set([
    VerificationStatus.Verified,
    VerificationStatus.Unverifiable,
    VerificationStatus.Blocked,
]);

const KNOWN_ADMISSIONS: ReadonlySet<unknown> = new Set([Admission.Admit, Admission.Blocked]);

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * True only when the server admitted the result: `admission` is ADMIT,
 * `status` is VERIFIED and `proof_ref` is a non-empty string. Anything else,
 * including a missing or unknown admission, is not admitted.
 *
 * VERIFIED alone is not a pass: a claim proven false (`2 + 2 = 5`) or code
 * proven unsafe is VERIFIED with admission BLOCKED.
 */
export function isAdmitted(response: VerificationResponse | null | undefined): boolean {
    return (
        response?.admission === Admission.Admit &&
        response.status === VerificationStatus.Verified &&
        typeof response.proof_ref === 'string' &&
        response.proof_ref.length > 0
    );
}

/**
 * Reads a verification answer from a parsed JSON body. `status` and
 * `admission` keep only the values the server sends; any other status,
 * including a missing one, becomes `Unknown`, any other admission becomes
 * `Unknown`, and a null admission is left out. Neither is ever admitted.
 * The server's status text is kept in `rawStatus`. Every other field is
 * kept as sent; numbers are JavaScript numbers, so an integer above 2^53 or
 * a long decimal is rounded by `JSON.parse` before it gets here.
 *
 * The result has a non-enumerable `toJSON`, so `JSON.stringify` writes no
 * `rawStatus` key and, where `status` is `Unknown`, writes the server's text
 * as `status`. Parsing that JSON again gives the same `status` and
 * `rawStatus`, so a cached or logged response keeps the server's status. A
 * known status is written as it is, including one changed locally.
 *
 * The client calls this for `verify`, `verifyMath`, `verifyLogic`,
 * `verifyCode`, `verifyFact`, `verifySQL`, `verifyProcess` and `verifyRAG`;
 * `verifyAgent` and `verifyAgentAction` return the agent endpoint's own
 * shape and are not parsed.
 */
export function parseVerificationResponse(body: unknown): VerificationResponse {
    if (!isRecord(body)) {
        throw new QWEDError('Response is not a verification result', 'QWED-SDK-PARSE-001');
    }

    const response: VerificationResponse = {
        ...body,
        status: KNOWN_STATUSES.has(body.status)
            ? (body.status as VerificationStatus)
            : VerificationStatus.Unknown,
    };
    // The server's own text, even where status is Unknown; never trusted
    // from a rawStatus key in the body.
    if (typeof body.status === 'string') {
        response.rawStatus = body.status;
    } else {
        delete response.rawStatus;
    }
    if (body.admission === undefined || body.admission === null) {
        delete response.admission;
    } else {
        response.admission = KNOWN_ADMISSIONS.has(body.admission)
            ? (body.admission as Admission)
            : Admission.Unknown;
    }
    // A token is a non-empty string or nothing (#319).
    if (typeof body.attestation !== 'string' || body.attestation.length === 0) {
        delete response.attestation;
    }
    response.verified = isAdmitted(response);
    Object.defineProperty(response, 'toJSON', {
        value: serialiseAsSent,
        enumerable: false,
        configurable: true,
        writable: true,
    });
    return response;
}

/**
 * `toJSON` for a parsed response: every enumerable field and no `rawStatus`
 * key. `status` is the response's own status, except that an `Unknown`
 * status is written as the server's text (`rawStatus`) when that text is one
 * this SDK does not know, such as `SAT`, so it survives a round trip.
 *
 * Invariant: the status written is either the current `status`, or server
 * text the SDK does not know, which always parses back to `Unknown`. So
 * serialising never raises a status: a response changed locally (VERIFIED
 * to BLOCKED, or to `Unknown` to quarantine it) is written as changed. Go's
 * `MarshalJSON` follows the same rule.
 */
function serialiseAsSent(this: VerificationResponse): Record<string, unknown> {
    const { rawStatus, ...fields } = this;
    const keepRawStatus =
        fields.status === VerificationStatus.Unknown &&
        typeof rawStatus === 'string' &&
        rawStatus.length > 0 &&
        !KNOWN_STATUSES.has(rawStatus) &&
        rawStatus !== VerificationStatus.Unknown;
    return { ...fields, status: keepRawStatus ? rawStatus : fields.status };
}

/**
 * Reads a batch job from a parsed JSON body; each item's `result` goes
 * through {@link parseVerificationResponse}.
 */
export function parseBatchResponse(body: unknown): BatchResponse {
    if (!isRecord(body) || !Array.isArray(body.items)) {
        throw new QWEDError('Response is not a batch job', 'QWED-SDK-PARSE-002');
    }

    const items = body.items.map((item: unknown): BatchItemResult => {
        if (!isRecord(item)) {
            throw new QWEDError('Batch item is not an object', 'QWED-SDK-PARSE-002');
        }
        const result = item.result === undefined || item.result === null
            ? item.result
            : parseVerificationResponse(item.result);
        return {
            ...(item as unknown as BatchItemResult),
            result,
            verified: isAdmitted(result),
        };
    });

    return { ...(body as unknown as BatchResponse), items };
}

/**
 * Returns `isAdmitted(response)`.
 * @deprecated Use {@link isAdmitted}. VERIFIED alone is not a pass, and a
 * `verified` field in a response is not an admission decision.
 */
export function isVerified(response: VerificationResponse): boolean {
    return isAdmitted(response);
}

/**
 * The response's `error` field: a string on endpoints such as
 * `/verify/logic`, or the `message` of an error object.
 */
export function getErrorMessage(response: VerificationResponse): string | null {
    const error = response.error;
    if (typeof error === 'string') {
        return error || null;
    }
    if (isRecord(error) && typeof error.message === 'string') {
        return error.message || null;
    }
    return null;
}

export function parseAttestation(jwt: string): {
    header: Record<string, unknown>;
    payload: Record<string, unknown>;
    signature: string;
} | null {
    try {
        const [headerB64, payloadB64, signature] = jwt.split('.');
        return {
            header: JSON.parse(atob(headerB64)),
            payload: JSON.parse(atob(payloadB64)),
            signature,
        };
    } catch {
        return null;
    }
}

