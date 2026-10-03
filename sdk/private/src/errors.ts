/**
 * Every error the SDK raises on purpose. Messages and details never carry a seed, a key, a
 * signature, a viewing key, note plaintext or a private balance.
 */
export type ErrorCode =
  | "invalid_argument"
  | "invalid_address"
  | "invalid_viewing_key"
  | "invalid_mnemonic"
  | "deployment_not_pinned"
  | "deployment_mismatch"
  | "artifact_mismatch"
  | "prover_failed"
  | "proof_invalid"
  | "signature_invalid"
  | "signature_not_deterministic"
  | "signature_seed_changed"
  | "storage_unreadable"
  | "state_conflict"
  | "account_busy"
  | "service_unavailable"
  | "service_rejected"
  | "indexer_fault"
  | "rpc_error"
  | "tree_unverified"
  | "vault_unavailable"
  | "limit_exceeded"
  | "insufficient_funds"
  | "needs_consolidation"
  | "fee_above_cap"
  | "quote_invalid"
  | "not_confirmed"
  | "destination_invalid"
  | "signer_mismatch"
  | "transaction_failed"
  | "view_only"
  | "not_found"
  | "history_unavailable";

export type ErrorDetails = Readonly<Record<string, string | number | boolean>>;

/**
 * The error type for every failure the SDK detects. `details` holds only public values, such as
 * a rule name, a service error code or an artifact hash.
 */
export class CyphrasError extends Error {
  readonly code: ErrorCode;
  readonly details: ErrorDetails;

  constructor(code: ErrorCode, message: string, details: ErrorDetails = {}) {
    super(message);
    this.name = "CyphrasError";
    this.code = code;
    this.details = details;
  }
}

export function fail(code: ErrorCode, message: string, details?: ErrorDetails): never {
  throw new CyphrasError(code, message, details);
}
