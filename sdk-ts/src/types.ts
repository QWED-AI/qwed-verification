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

export enum VerificationStatus {
    Verified = 'VERIFIED',
    Failed = 'FAILED',
    Corrected = 'CORRECTED',
    Blocked = 'BLOCKED',
    Error = 'ERROR',
    Timeout = 'TIMEOUT',
    Unsupported = 'UNSUPPORTED',
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

export interface Vulnerability {
    type: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    line?: number;
    message: string;
}

export interface Citation {
    text: string;
    source: string;
}

export interface VerificationResultData {
    is_valid?: boolean;
    message?: string;
    expected?: unknown;
    actual?: unknown;
    simplified?: string;
    model?: Record<string, unknown>;
    satisfiability?: Satisfiability;
    vulnerabilities?: Vulnerability[];
    verdict?: FactVerdict;
    citations?: Citation[];
    
    // ProcessVerifier Metrics
    score?: number;
    process_rate?: number;
    missing_steps?: string[];
    missed_milestones?: string[];
    
    // RAGGuard DRM Metrics
    drm_rate?: number;
    chunks_checked?: number;
    mismatched_count?: number;
    
    // IRAC Compliance Audits
    'irac.issue'?: string;
    'irac.rule'?: string;
    'irac.application'?: string;
    'irac.conclusion'?: string;

    // Agentic Standalone Metrics
    risk?: 'DOCUMENT_RETRIEVAL_MISMATCH' | 'EXFILTRATION_ATTEMPT' | 'MCP_POISONING' | 'TOXIC_CHAIN' | 'SOVEREIGNTY_VIOLATION' | 'FABRICATED_REASONING';
    risk_level?: 'low' | 'medium' | 'high' | 'critical';
}

export interface VerificationProof {
    type: string;
    steps?: unknown[];
    hash: string;
}

export interface VerificationError {
    code: string;
    message: string;
    details?: Record<string, unknown>;
    documentation_url?: string;
}

export interface VerificationResponseMetadata {
    request_id?: string;
    latency_ms?: number;
    engine_version?: string;
    protocol_version?: string;
    cached?: boolean;
}

export interface VerificationResponse {
    status: VerificationStatus;
    verified: boolean;
    engine?: string;
    result?: VerificationResultData;
    proof?: VerificationProof;
    attestation?: string;
    error?: VerificationError;
    metadata?: VerificationResponseMetadata;
}

export interface BatchItemResult {
    id: string;
    status: VerificationStatus;
    verified: boolean;
    result?: VerificationResultData;
    error?: VerificationError;
}

export interface BatchResponse {
    batch: true;
    job_id: string;
    status: 'completed' | 'partial' | 'failed';
    summary: {
        total: number;
        verified: number;
        failed: number;
        success_rate: number;
    };
    items: BatchItemResult[];
    metadata?: {
        total_latency_ms?: number;
    };
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

