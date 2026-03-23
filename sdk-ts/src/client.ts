/**
 * QWED TypeScript SDK Client
 * Version: 1.0.0
 */

import {
    QWEDClientOptions,
    VerificationRequest,
    VerificationResponse,
    VerificationType,
    BatchRequest,
    BatchResponse,
    AgentRegistration,
    AgentVerificationRequest,
    AgentVerificationResponse,
} from './types';

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
    // HTTP Methods
    // --------------------------------------------------------------------------

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

        return this.request('POST', '/verify/natural_language', request);
    }

    async verifyMath(
        expression: string,
        options?: { precision?: number }
    ): Promise<VerificationResponse> {
        return this.request('POST', '/verify/math', {
            expression,
            params: { precision: options?.precision },
        });
    }

    async verifyLogic(
        query: string,
        options?: { format?: 'natural' | 'dsl' }
    ): Promise<VerificationResponse> {
        return this.request('POST', '/verify/logic', {
            query,
            params: { format: options?.format || 'dsl' },
        });
    }

    async verifyCode(
        code: string,
        options?: { language?: string }
    ): Promise<VerificationResponse> {
        return this.request('POST', '/verify/code', {
            code,
            language: options?.language || 'python',
        });
    }

    async verifyFact(
        claim: string,
        context: string
    ): Promise<VerificationResponse> {
        return this.request('POST', '/verify/fact', { claim, context });
    }

    async verifySQL(
        query: string,
        schema: string,
        options?: { dialect?: string }
    ): Promise<VerificationResponse> {
        return this.request('POST', '/verify/sql', {
            query,
            schema_ddl: schema,
            dialect: options?.dialect || 'postgresql',
        });
    }

    async verifyProcess(
        reasoningTrace: string,
        options?: { mode?: 'irac' | 'milestones'; keyMilestones?: string[] }
    ): Promise<VerificationResponse> {
        return this.request('POST', '/verify/process', {
            trace: reasoningTrace,
            mode: options?.mode || 'irac',
            milestones: options?.keyMilestones,
        });
    }

    async verifyRAG(
        targetDocumentId: string,
        retrievedChunks: Record<string, unknown>[],
        options?: { maxDrmRate?: string }
    ): Promise<VerificationResponse> {
        return this.request('POST', '/verify/rag', {
            target_document_id: targetDocumentId,
            chunks: retrievedChunks,
            max_drm_rate: options?.maxDrmRate,
        });
    }

    async verifyAgent(
        agentId: string,
        agentToken: string,
        query: string,
        options?: {
            provider?: string;
            checkExfiltration?: boolean;
            checkMcpPoison?: boolean;
            toolSchema?: Record<string, unknown>;
        }
    ): Promise<AgentVerificationResponse> {
        // Build the correct payload matching backend AgentVerifyRequest + optional security checks
        const payload: Record<string, unknown> = {
            query: query,
        };
        if (options?.provider) payload.provider = options.provider;
        if (options?.checkExfiltration !== undefined || options?.checkMcpPoison !== undefined) {
            payload.security_checks = {
                exfiltration: options?.checkExfiltration,
                mcp_poison: options?.checkMcpPoison,
            };
        }
        if (options?.toolSchema) {
            payload.tool_schema = options.toolSchema;
        }

        return this.request(
            'POST',
            `/agents/${encodeURIComponent(agentId)}/verify`,
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

        return this.request('POST', '/verify/batch', request);
    }

    // --------------------------------------------------------------------------
    // Agent Methods
    // --------------------------------------------------------------------------

    async registerAgent(
        registration: AgentRegistration
    ): Promise<{ agent_id: string; agent_token: string; status: string }> {
        return this.request('POST', '/agents/register', registration);
    }

    async verifyAgentAction(
        request: AgentVerificationRequest
    ): Promise<AgentVerificationResponse> {
        return this.request(
            'POST',
            `/agents/${encodeURIComponent(request.agent_id)}/verify`,
            request
        );
    }

    async getAgentBudget(
        agentId: string,
        agentToken: string
    ): Promise<{
        cost: { current_daily_usd: number; max_daily_usd: number };
        requests: { current_hour: number; max_per_hour: number };
    }> {
        const originalKey = this.headers['X-API-Key'];
        this.headers['X-API-Key'] = agentToken;

        try {
            return await this.request('GET', `/agents/${encodeURIComponent(agentId)}/budget`);
        } finally {
            this.headers['X-API-Key'] = originalKey;
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

export function isVerified(response: VerificationResponse): boolean {
    return response.verified === true;
}

export function getErrorMessage(response: VerificationResponse): string | null {
    return response.error?.message || null;
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

