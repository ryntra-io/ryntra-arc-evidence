/**
 * Public and serialized Guard state vocabulary.
 *
 * These tuples are deliberately dependency-free so API schemas, public pages,
 * presentations, and tests can consume one exact set of values.
 */
export const GUARD_EVIDENCE_STATUSES = [
  "COMPLETE",
  "PARTIAL",
  "INSUFFICIENT",
  "CONFLICTING",
  "UNAVAILABLE",
] as const;

export const GUARD_POLICY_DECISIONS = [
  "ALLOWED_BY_POLICY",
  "REVIEW_REQUIRED",
  "BLOCKED_BY_RULE",
  "INSUFFICIENT_EVIDENCE",
  "UNSUPPORTED",
  "EXPIRED",
] as const;

export const GUARD_AUTHORIZATION_STATUSES = [
  "NOT_REQUIRED",
  "PENDING",
  "APPROVED",
  "REJECTED",
  "EXPIRED",
  "REVOKED",
] as const;

export const GUARD_EXECUTION_STATUSES = [
  "NOT_STARTED",
  "SUBMITTED",
  "SOURCE_CONFIRMED",
  "IN_TRANSIT",
  "DESTINATION_PENDING",
  "CONFIRMED",
  "FAILED",
  "RECOVERY_REQUIRED",
  "RECONCILIATION_REQUIRED",
  "CANCELLED",
] as const;

export const GUARD_RECONCILIATION_STATUSES = [
  "NOT_RECONCILED",
  "RECONCILIATION_REQUIRED",
  "MATCHED",
  "DEVIATION_RECORDED",
] as const;

export type GuardEvidenceStatus = (typeof GUARD_EVIDENCE_STATUSES)[number];
export type GuardPolicyDecision = (typeof GUARD_POLICY_DECISIONS)[number];
export type GuardAuthorizationStatus = (typeof GUARD_AUTHORIZATION_STATUSES)[number];
export type GuardExecutionStatus = (typeof GUARD_EXECUTION_STATUSES)[number];
export type GuardReconciliationStatus = (typeof GUARD_RECONCILIATION_STATUSES)[number];

export type GuardStatusAxes = {
  evidenceStatus: GuardEvidenceStatus;
  policyDecision: GuardPolicyDecision;
  authorizationStatus: GuardAuthorizationStatus;
  executionStatus: GuardExecutionStatus;
  reconciliationStatus: GuardReconciliationStatus;
};

export type ResolvedGuardStatusAxes = {
  [Axis in keyof GuardStatusAxes]: GuardStatusAxes[Axis] | null;
};

export const GUARD_STATUS_AXIS_DEFINITIONS = [
  { key: "evidenceStatus", label: "EVIDENCE" },
  { key: "policyDecision", label: "POLICY" },
  { key: "authorizationStatus", label: "AUTHORIZATION" },
  { key: "executionStatus", label: "EXECUTION" },
  { key: "reconciliationStatus", label: "RECONCILIATION" },
] as const satisfies ReadonlyArray<{ key: keyof GuardStatusAxes; label: string }>;

type GuardStatusSource = Partial<GuardStatusAxes> | null | undefined;

/**
 * Resolve the five independent public axes without synthesizing display-only
 * states. A finalized receipt is authoritative when present; otherwise the
 * preflight evaluation remains the canonical source.
 */
export function resolveGuardStatusAxes(
  evaluation: GuardStatusSource,
  receipt?: GuardStatusSource,
): ResolvedGuardStatusAxes {
  return {
    evidenceStatus: receipt?.evidenceStatus ?? evaluation?.evidenceStatus ?? null,
    policyDecision: receipt?.policyDecision ?? evaluation?.policyDecision ?? null,
    authorizationStatus:
      receipt?.authorizationStatus ?? evaluation?.authorizationStatus ?? null,
    executionStatus: receipt?.executionStatus ?? evaluation?.executionStatus ?? null,
    reconciliationStatus:
      receipt?.reconciliationStatus ?? evaluation?.reconciliationStatus ?? null,
  };
}
