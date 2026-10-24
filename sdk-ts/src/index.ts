/**
 * @qwed-ai/sdk
 * TypeScript SDK for QWED Verification Protocol
 * 
 * @example
 * ```typescript
 * import { QWEDClient, isAdmitted } from '@qwed-ai/sdk';
 * 
 * const client = new QWEDClient({ apiKey: 'qwed_...' });
 * const result = await client.verifyMath('2 + 2 = 4');
 * console.log(result.status, result.admission, isAdmitted(result)); // VERIFIED ADMIT true
 * ```
 *
 * Gate on `isAdmitted()`, never on `status` alone: `2 + 2 = 5` is also
 * VERIFIED (proven false), with admission BLOCKED.
 */

// Re-export types
export * from './types';

// Re-export client and helpers
export {
    QWEDClient,
    QWEDError,
    QWEDAuthError,
    QWEDRateLimitError,
    isAdmitted,
    isVerified,
    parseVerificationResponse,
    parseBatchResponse,
    getErrorMessage,
    parseAttestation,
} from './client';

// Verify attestations (#319)
export {
    AttestationError,
    KeyMismatchError,
    UnknownKeyError,
    verifyAttestation,
    statementHash,
    DEFAULT_ISSUER,
    JWKS_PATH,
} from './attestation';
export type { Jwk, Jwks, VerifyAttestationOptions } from './attestation';

