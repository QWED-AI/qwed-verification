/**
 * QWED Protocol TypeScript Types
 * Version: 1.0.0
 */

// ============================================================================
// Enums
// ============================================================================

export enum VerificationType {
    NaturalLanguage = 'natural_language',
    Math = 'math',
    Logic = 'logic',
    Stats = 'stats',
    Fact = 'fact',
    Code = 'code',
    SQL = 'sql',
    Image = 'image',
    Reasoning = 'reasoning',
    Process = 'process',
    RAG = 'rag',
    Security = 'security',
}

/**
 * Diagnostic status of a verification (`DiagnosticResult.status`).
 *
 * `Verified` says the engine reached a deterministic answer, not that the
 * claim holds: a false identity such as `2 + 2 = 5` is VERIFIED too, and its
 * admission is BLOCKED. Gate on {@link isAdmitted}, never on the status alone.
 */
export enum VerificationStatus {
    /** The claim was evaluated deterministically and `proof_ref` is set. */
    Verified = 'VERIFIED',
    /** The claim could not be proven. */
    Unverifiable = 'UNVERIFIABLE',
    /** Verification could not be attempted (parse error, policy, missing dependency). */
    Blocked = 'BLOCKED',
    /** A missing status, or one this SDK version does not know. Never admitted. */
    Unknown = 'UNKNOWN',
}

/**
 * The server's decision at its enforcement boundary. Absent (`undefined`)
 * where the endpoint makes no decision, as `/verify/logic`, `/verify/fact`
 * and batch items do today; absent is never admitted.
 */
export enum Admission {
    /** The boundary may proceed with the verdict. */
    Admit = 'ADMIT',
    /** The boundary must not admit. */
    Blocked = 'BLOCKED',
    /** A decision this SDK version does not know. Never admitted. */
    Unknown = 'UNKNOWN',
}

export enum Satisfiability {
    SAT = 'SAT',
    UNSAT = 'UNSAT',
    Unknown = 'UNKNOWN',
}

export enum FactVerdict {
    Supported = 'SUPPORTED',
    Refuted = 'REFUTED',
    NotEnoughInfo = 'NOT_ENOUGH_INFO',
}

// ============================================================================
// Request Types
// ============================================================================

export interface VerificationRequestParams {
    language?: string;
    dialect?: string;
    schema_ddl?: string;
    context?: string;
    format?: 'natural' | 'dsl';
    domain?: 'real' | 'integer' | 'complex';
    precision?: number;
}

export interface VerificationRequestOptions {
    timeout_ms?: number;
    include_proof?: boolean;
    include_attestation?: boolean;
    attestation_validity_days?: number;
}

export interface VerificationRequestMetadata {
    request_id?: string;
    correlation_id?: string;
    trace_id?: string;
}

export interface VerificationRequest {
    query: string;
    type?: VerificationType;
    params?: VerificationRequestParams;
    options?: VerificationRequestOptions;
    metadata?: VerificationRequestMetadata;
}

export interface BatchRequest {
    batch: true;
    items: Array<{
        query: string;
        type?: VerificationType;
        params?: VerificationRequestParams;
    }>;
    options?: {
        max_parallel?: number;
        fail_fast?: boolean;
    };
}

// ============================================================================
// Response Types
// ============================================================================

export interface VerificationError {
    code: string;
    message: string;
    details?: Record<string, unknown>;
    documentation_url?: string;
}

/**
 * A verification answer: the server's DiagnosticResult envelope.
 *
 * Gate on {@link isAdmitted}: true only for admission ADMIT with status
 * VERIFIED and a `proof_ref`. Every other key is the endpoint's own field,
 * such as `is_valid`, `issues` or `error`.
 */
export interface VerificationResponse {
    status: VerificationStatus;
    /** Absent where the endpoint makes no decision. Absent is not admitted. */
    admission?: Admission;
    /** Set only when `status` is VERIFIED. */
    proof_ref?: string | null;
    agent_message?: string | null;
    is_authoritative?: boolean | null;
    constraint_id?: string | null;
    developer_fields?: Record<string, unknown> | null;
    /**
     * Set by the client to `isAdmitted(response)`. The server sends no
     * `verified` field.
     * @deprecated Use {@link isAdmitted}.
     */
    verified?: boolean;
    /** The endpoint's own fields. */
    [field: string]: unknown;
}

/** One item of a batch job. */
export interface BatchItemResult {
    id: string;
    /**
     * Item state, such as `pending`, `completed` or `failed`. The
     * verification status is `result.status`.
     */
    status: string;
    query?: string;
    type?: string;
    /** The item's verification answer, once it has one. */
    result?: VerificationResponse | null;
    error?: string | null;
    latency_ms?: number;
    /**
     * Set by the client to `isAdmitted(item.result)`. The server sends no
     * `verified` field.
     * @deprecated Use `isAdmitted(item.result)`.
     */
    verified?: boolean;
}

/** A batch job and its items. */
export interface BatchResponse {
    job_id: string;
    /** Job state: `pending`, `processing`, `completed`, `partial` or `failed`. */
    status: string;
    progress_percent?: number;
    total_items?: number;
    completed_items?: number;
    failed_items?: number;
    created_at?: string;
    completed_at?: string | null;
    items: BatchItemResult[];
}

// ============================================================================
// Attestation Types
// ============================================================================

export interface AttestationResult {
    status: VerificationStatus;
    verified: boolean;
    engine?: string;
    confidence?: number;
}

export interface AttestationClaims {
    iss: string;
    sub: string;
    iat: number;
    exp?: number;
    nbf?: number;
    jti: string;
    qwed: {
        version: string;
        result: AttestationResult;
        query_hash?: string;
        proof_hash?: string;
        chain_id?: string;
        chain_index?: number;
    };
}

// ============================================================================
// Agent Types
// ============================================================================

export interface AgentPermissions {
    allowed_engines?: VerificationType[];
    allowed_tools?: string[];
    blocked_tools?: string[];
}

export interface AgentBudget {
    max_daily_cost_usd?: number;
    max_per_request_cost_usd?: number;
    max_requests_per_hour?: number;
    max_requests_per_day?: number;
    max_tokens_per_request?: number;
}

export interface AgentRegistration {
    agent: {
        name: string;
        type: 'supervised' | 'autonomous' | 'trusted';
        description?: string;
        principal_id: string;
        framework?: 'langchain' | 'crewai' | 'autogen' | 'custom';
        model?: string;
    };
    permissions: AgentPermissions;
    budget: AgentBudget;
    trust_level?: 0 | 1 | 2 | 3;
}

export interface AgentAction {
    type: string;
    query?: string;
    code?: string;
    target?: string;
    parameters?: Record<string, unknown>;
}

export interface AgentVerificationRequest {
    agent_id: number;
    agent_token: string;
    query?: string;
    provider?: string;
    tool_schema?: Record<string, unknown>;
    action?: AgentAction;
    context?: {
        conversation_id?: string;
        step_number?: number;
        user_intent?: string;
    };
    options?: {
        require_attestation?: boolean;
        risk_threshold?: 'low' | 'medium' | 'high' | 'critical';
    };
}

export type AgentDecision = 'APPROVED' | 'DENIED' | 'CORRECTED' | 'PENDING' | 'BUDGET_EXCEEDED';

export interface AgentVerificationResponse {
    decision: AgentDecision;
    verification?: {
        status: VerificationStatus;
        engine?: string;
        risk_level?: 'low' | 'medium' | 'high' | 'critical';
        checks_passed?: string[];
        checks_failed?: string[];
    };
    corrected_action?: AgentAction;
    attestation?: string;
    budget_remaining?: {
        daily_cost_usd?: number;
        hourly_requests?: number;
        daily_requests?: number;
    };
    error?: VerificationError;
}

// ============================================================================
// Client Options
// ============================================================================

export interface QWEDClientOptions {
    apiKey: string;
    baseUrl?: string;
    timeout?: number;
    headers?: Record<string, string>;
}

