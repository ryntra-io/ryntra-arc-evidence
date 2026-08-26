import { z } from "zod";

import { hashCanonical } from "./canonical.ts";
import { hashDecisionSettlementReceiptCore } from "./payout-canonical.ts";
import {
  GUARD_AUTHORIZATION_STATUSES,
  GUARD_EVIDENCE_STATUSES,
  GUARD_EXECUTION_STATUSES,
  GUARD_POLICY_DECISIONS,
  GUARD_RECONCILIATION_STATUSES,
} from "./status-values.ts";

const DECIMAL_STRING = /^(?:0|[1-9]\d*)(?:\.\d+)?$/;
const HEX_HASH = /^0x[0-9a-fA-F]{64}$/;
const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const CAIP2 = /^[a-z0-9-]+:[A-Za-z0-9-]+$/;
const ASSET_REF = /^[a-z0-9-]+:[A-Za-z0-9-]+\/[a-z0-9-]+:[A-Za-z0-9._%-]+$/;
const ARC_EXPLORER_TRANSACTION = /^https:\/\/testnet\.arcscan\.app\/tx\/0x[0-9a-f]{64}$/;

const decimalString = z.string().min(1).max(128).regex(DECIMAL_STRING);
const timestamp = z.string().datetime({ offset: true });

function exactSixDecimalBaseUnits(value: string): bigint | null {
  const match = /^(0|[1-9]\d*)(?:\.(\d{1,6}))?$/.exec(value);
  if (!match) return null;
  return BigInt(match[1]) * 1_000_000n + BigInt((match[2] ?? "").padEnd(6, "0") || "0");
}
const evidenceFactScalar = z.union([
  z.string().max(4_096),
  z.number().finite(),
  z.boolean(),
  z.null(),
]);
const evidenceFactObject = z.record(z.string().min(1).max(128), evidenceFactScalar);
const evidenceFactValue = z.union([evidenceFactScalar, evidenceFactObject, z.array(z.union([evidenceFactScalar, evidenceFactObject])).max(128)]);

export const ExecutionIntentSchema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    id: z.string().min(3).max(128),
    tenantId: z.string().min(3).max(128),
    applicationId: z.string().min(3).max(128),
    externalPartnerId: z.string().min(1).max(256),
    subjectRef: z.string().min(1).max(256),
    walletAddress: z.string().regex(EVM_ADDRESS),
    walletType: z.enum(["EOA", "SMART_ACCOUNT", "SAFE", "ERC4337", "OTHER"]),
    chainRef: z.string().regex(CAIP2),
    environment: z.enum(["ARC_TESTNET", "TESTNET", "SANDBOX", "PRODUCTION"]),
    actionType: z.enum(["SWAP", "SEND", "SPEND", "BRIDGE"]),
    instrumentRef: z.string().min(3).max(256),
    sellAssetRef: z.string().regex(ASSET_REF),
    buyAssetRef: z.string().regex(ASSET_REF),
    amount: decimalString,
    leverage: decimalString.nullable().default(null),
    amountType: z.enum(["EXACT_INPUT", "EXACT_OUTPUT"]),
    recipient: z.string().regex(EVM_ADDRESS),
    venueRef: z.string().min(1).max(128),
    routeRef: z.string().min(1).max(256),
    quoteRef: z.string().min(1).max(256).nullable(),
    executionBindingKind: z.enum(["EVM_TRANSACTION", "APP_KIT_REQUEST"]).default("EVM_TRANSACTION"),
    target: z.string().regex(EVM_ADDRESS).nullable(),
    calldataHash: z.string().regex(HEX_HASH).nullable(),
    nativeValue: decimalString,
    adapterRequestHash: z.string().regex(HEX_HASH).nullable().default(null),
    productionCalldataBound: z.boolean().default(true),
    portfolioSnapshotRef: z.string().min(1).max(256).nullable(),
    policyRef: z
      .object({
        id: z.string().min(1).max(128),
        version: z.number().int().positive(),
      })
      .strict(),
    createdAt: timestamp,
    expiresAt: timestamp,
    revision: z.number().int().positive(),
    idempotencyKey: z.string().min(8).max(256),
  })
  .strict()
  .superRefine((value, context) => {
    if (Date.parse(value.expiresAt) <= Date.parse(value.createdAt)) {
      context.addIssue({
        code: "custom",
        path: ["expiresAt"],
        message: "Intent expiry must be after creation.",
      });
    }
    if (
      value.executionBindingKind === "EVM_TRANSACTION" &&
      (!value.target || !value.calldataHash || !value.productionCalldataBound)
    ) {
      context.addIssue({
        code: "custom",
        path: ["executionBindingKind"],
        message: "EVM transaction binding requires target, calldata hash, and production binding.",
      });
    }
    if (
      value.executionBindingKind === "APP_KIT_REQUEST" &&
      (value.target !== null ||
        value.calldataHash !== null ||
        !value.adapterRequestHash ||
        value.productionCalldataBound)
    ) {
      context.addIssue({
        code: "custom",
        path: ["executionBindingKind"],
        message: "App Kit request binding must expose that target and calldata are not prebound.",
      });
    }
  });

export const ArcMemoSchema = z
  .object({
    intentHash: z.string().regex(HEX_HASH),
    evidenceRoot: z.string().regex(HEX_HASH),
    policyHash: z.string().regex(HEX_HASH),
    receiptSchemaVersion: z.literal("1.0.0"),
  })
  .strict();

class ContractBoundaryError extends Error {
  readonly code: "CAPABILITY_UNAVAILABLE" | "VALIDATION_ERROR";

  constructor(code: "CAPABILITY_UNAVAILABLE" | "VALIDATION_ERROR", message: string) {
    super(message);
    this.name = "ContractBoundaryError";
    this.code = code;
  }
}

export function assertCapabilityEnvironment({
  state,
  runtimeEnvironment,
}: {
  state: "LIVE" | "LIMITED" | "TESTNET_ONLY" | "PLANNED" | "PAUSED" | "BLOCKED" | "UNVERIFIED" | "DEPRECATED";
  runtimeEnvironment: "SANDBOX" | "TESTNET" | "ARC_TESTNET" | "PRODUCTION";
}): void {
  if (
    runtimeEnvironment === "PRODUCTION" &&
    (state === "PLANNED" ||
      state === "TESTNET_ONLY" ||
      state === "PAUSED" ||
      state === "BLOCKED" ||
      state === "UNVERIFIED" ||
      state === "DEPRECATED")
  ) {
    throw new ContractBoundaryError(
      "CAPABILITY_UNAVAILABLE",
      "Capability state cannot be used in production.",
    );
  }
}

export function assertCredentialEnvironment({
  credentialEnvironment,
  runtimeEnvironment,
}: {
  credentialEnvironment: "SANDBOX" | "TESTNET" | "ARC_TESTNET" | "PRODUCTION";
  runtimeEnvironment: "SANDBOX" | "TESTNET" | "ARC_TESTNET" | "PRODUCTION";
}): void {
  if (credentialEnvironment !== runtimeEnvironment) {
    throw new ContractBoundaryError(
      "VALIDATION_ERROR",
      "Credential environment does not match runtime environment.",
    );
  }
}

type Integrity = {
  algorithm: "SHA-256";
  hash: string;
};

export function createIntegrityEnvelope<T extends Record<string, unknown>>(
  payload: T,
): T & { integrity: Integrity } {
  return {
    ...structuredClone(payload),
    integrity: {
      algorithm: "SHA-256",
      hash: hashCanonical(payload),
    },
  };
}

export function verifyIntegrityEnvelope(value: unknown): boolean {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const { integrity, ...payload } = value as Record<string, unknown>;
  if (
    !integrity ||
    typeof integrity !== "object" ||
    Array.isArray(integrity) ||
    (integrity as Record<string, unknown>).algorithm !== "SHA-256" ||
    typeof (integrity as Record<string, unknown>).hash !== "string"
  ) {
    return false;
  }
  return (integrity as Record<string, unknown>).hash === hashCanonical(payload);
}

const SENSITIVE_LOG_KEYS = new Set([
  "apikey",
  "api_key",
  "authorization",
  "clientsecret",
  "client_secret",
  "entitysecret",
  "entity_secret",
  "privatekey",
  "private_key",
  "seedphrase",
  "seed_phrase",
  "accesstoken",
  "access_token",
  "refreshtoken",
  "refresh_token",
]);

export function redactGuardLog(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(redactGuardLog);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).map(([key, entry]) => [
      key,
      SENSITIVE_LOG_KEYS.has(key.toLowerCase()) ? "[REDACTED]" : redactGuardLog(entry),
    ]),
  );
}

export const EvidenceItemSchema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    id: z.string().min(3).max(128),
    provider: z.string().min(1).max(128),
    sourceRef: z.string().min(1).max(512),
    adapter: z.string().min(1).max(128),
    adapterVersion: z.string().min(1).max(128),
    sourceType: z.string().min(1).max(128),
    observedAt: timestamp,
    receivedAt: timestamp,
    validUntil: timestamp,
    confidence: z.string().min(1).max(128),
    coverage: z
      .object({
        subjectRefs: z.array(z.string().min(1).max(256)).min(1).max(64),
        fields: z.array(z.string().min(1).max(128)).min(1).max(128),
        limitations: z.array(z.string().min(1).max(256)).max(64),
      })
      .strict(),
    availability: z.enum(["AVAILABLE", "PARTIAL", "UNAVAILABLE", "UNSUPPORTED"]),
    verificationStatus: z.enum([
      "PROVIDER_REPORTED",
      "DETERMINISTICALLY_DERIVED",
      "ONCHAIN_VERIFIED",
      "NOT_VERIFIED",
      "CONFLICTING",
    ]),
    chainRef: z.string().regex(CAIP2).nullable(),
    blockRef: z.string().min(1).max(256).nullable(),
    transactionRef: z.string().min(1).max(256).nullable(),
    status: z.enum(["VALID", "STALE", "MISSING", "CONFLICTING", "UNAVAILABLE", "UNSUPPORTED"]),
    requestHash: z.string().regex(HEX_HASH),
    responseHash: z.string().regex(HEX_HASH),
    responseDigest: z.string().regex(HEX_HASH),
    reason: z.string().min(1).max(512).nullable(),
    transformationVersion: z.string().min(1).max(128),
    fallbackUsed: z.boolean(),
    facts: z.record(z.string().min(1).max(128), evidenceFactValue),
  })
  .strict()
  .superRefine((value, context) => {
    if (Date.parse(value.receivedAt) < Date.parse(value.observedAt)) {
      context.addIssue({
        code: "custom",
        path: ["receivedAt"],
        message: "Evidence cannot be received before it is observed.",
      });
    }
    if (Date.parse(value.validUntil) < Date.parse(value.observedAt)) {
      context.addIssue({
        code: "custom",
        path: ["validUntil"],
        message: "Evidence validity cannot precede observation.",
      });
    }
    if (value.responseDigest !== value.responseHash) {
      context.addIssue({
        code: "custom",
        path: ["responseDigest"],
        message: "Evidence response digest must match the compatibility response hash.",
      });
    }
    if (value.availability !== "AVAILABLE" && !value.reason) {
      context.addIssue({
        code: "custom",
        path: ["reason"],
        message: "Non-available evidence requires an explicit reason.",
      });
    }
    const expectedAvailability = {
      VALID: "AVAILABLE",
      STALE: "PARTIAL",
      MISSING: "PARTIAL",
      CONFLICTING: "PARTIAL",
      UNAVAILABLE: "UNAVAILABLE",
      UNSUPPORTED: "UNSUPPORTED",
    }[value.status];
    if (value.availability !== expectedAvailability) {
      context.addIssue({
        code: "custom",
        path: ["availability"],
        message: "Evidence availability must agree with its status.",
      });
    }
    if (value.fallbackUsed && !value.reason) {
      context.addIssue({
        code: "custom",
        path: ["reason"],
        message: "Fallback evidence must disclose why the fallback was used.",
      });
    }
  });

export const RiskSignalSchema = z
  .object({
    id: z.string().min(3).max(128),
    schemaVersion: z.literal("1.0.0"),
    category: z.enum([
      "MARKET_SESSION",
      "PRICE_FRESHNESS",
      "ORACLE_CONFIDENCE",
      "PRICE_DEVIATION",
      "SPREAD",
      "DEPTH",
      "SLIPPAGE",
      "FEES",
      "ROUTE",
      "ISSUER",
      "TOKEN_CONTRACT",
      "TRANSFER_RESTRICTION",
      "CORPORATE_ACTION",
      "REDEMPTION",
      "LIQUIDITY",
      "VENUE",
      "PORTFOLIO_EXPOSURE",
      "CONCENTRATION",
      "LEVERAGE",
      "LIQUIDATION",
      "SETTLEMENT",
      "RECOVERY",
      "COMPLIANCE",
      "CONTRACT_SIMULATION",
      "CAPABILITY",
      "AGENT_MANDATE",
    ]),
    subjectRef: z.string().min(1).max(256),
    status: z.enum(["VALID", "STALE", "MISSING", "CONFLICTING", "UNSUPPORTED"]),
    severity: z.enum(["INFO", "WARNING", "CRITICAL"]),
    observedValue: z.string().max(256).optional(),
    unit: z.string().max(64).optional(),
    threshold: z.string().max(256).optional(),
    evidenceRefs: z.array(z.string().min(3).max(128)).max(64),
    sourceTimestamp: timestamp.optional(),
    validUntil: timestamp.optional(),
    confidence: z.string().max(128).optional(),
    explanationCode: z.string().min(1).max(128),
    remediation: z.string().max(512).optional(),
  })
  .strict();

const PolicyRuleSchema = z.discriminatedUnion("type", [
  z
    .object({
      id: z.string().min(1).max(128),
      type: z.literal("ALLOWED_CHAIN"),
      value: z.string().regex(CAIP2),
      onViolation: z.literal("BLOCK"),
    })
    .strict(),
  z
    .object({
      id: z.string().min(1).max(128),
      type: z.literal("ALLOWED_PAIR"),
      value: z.tuple([z.string().regex(ASSET_REF), z.string().regex(ASSET_REF)]),
      onViolation: z.literal("BLOCK"),
    })
    .strict(),
  z
    .object({
      id: z.string().min(1).max(128),
      type: z.literal("MAX_TOTAL_DEBIT"),
      value: decimalString,
      currencyAssetRef: z.string().regex(ASSET_REF),
      onViolation: z.literal("BLOCK"),
    })
    .strict(),
  z
    .object({
      id: z.string().min(1).max(128),
      type: z.literal("MAX_QUOTE_AGE_SECONDS"),
      value: z.number().int().positive().max(3_600),
      onViolation: z.literal("INSUFFICIENT_EVIDENCE"),
    })
    .strict(),
  z
    .object({
      id: z.string().min(1).max(128),
      type: z.literal("MAX_SLIPPAGE_BPS"),
      value: decimalString,
      onViolation: z.literal("REVIEW"),
    })
    .strict(),
  z
    .object({
      id: z.string().min(1).max(128),
      type: z.literal("HUMAN_AUTHORIZATION_REQUIRED"),
      value: z.boolean(),
      onViolation: z.literal("REQUIRE_AUTHORIZATION"),
    })
    .strict(),
]);

export const GuardPolicySchema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    id: z.string().min(1).max(128),
    version: z.number().int().positive(),
    publishedAt: timestamp,
    immutable: z.literal(true),
    rules: z.array(PolicyRuleSchema).min(1).max(128),
  })
  .strict();

/**
 * Immutable, versioned output of deterministic policy evaluation.
 *
 * This is deliberately separate from evidence, authorization, execution and
 * reconciliation. A consumer can therefore persist or validate the policy
 * decision without treating it as permission to sign or proof of settlement.
 */
export const PolicyResultSchema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    id: z.string().min(3).max(128),
    intentId: z.string().min(3).max(128),
    intentRevision: z.number().int().positive(),
    policyRef: z
      .object({
        id: z.string().min(1).max(128),
        version: z.number().int().positive(),
      })
      .strict(),
    policyVersion: z.number().int().positive(),
    policyDigest: z.string().regex(HEX_HASH),
    evidenceRoot: z.string().regex(HEX_HASH),
    evidenceRefs: z.array(z.string().min(3).max(128)).max(256),
    decision: z.enum([
      "ALLOWED_BY_POLICY",
      "REVIEW_REQUIRED",
      "BLOCKED_BY_RULE",
      "INSUFFICIENT_EVIDENCE",
      "UNSUPPORTED",
      "EXPIRED",
    ]),
    status: z.enum(["PASS", "WARN", "BLOCK", "NOT_EVALUATED"]),
    blockers: z.array(z.string().min(1).max(256)).max(128),
    warnings: z.array(z.string().min(1).max(256)).max(128),
    evaluatedAt: timestamp,
  })
  .strict()
  .superRefine((value, context) => {
    if (value.policyRef.version !== value.policyVersion) {
      context.addIssue({
        code: "custom",
        path: ["policyVersion"],
        message: "Policy result version must match its bound policy reference.",
      });
    }
  });

export const ExecutionFingerprintSchema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    intentId: z.string().min(3).max(128),
    intentRevision: z.number().int().positive(),
    chainRef: z.string().regex(CAIP2),
    walletAddress: z.string().regex(EVM_ADDRESS),
    bindingKind: z.enum(["EVM_TRANSACTION", "APP_KIT_REQUEST"]).default("EVM_TRANSACTION"),
    target: z.string().regex(EVM_ADDRESS).nullable(),
    calldataHash: z.string().regex(HEX_HASH).nullable(),
    nativeValue: decimalString,
    adapterRequestHash: z.string().regex(HEX_HASH).nullable().default(null),
    productionCalldataBound: z.boolean().default(true),
    sellAssetRef: z.string().regex(ASSET_REF),
    buyAssetRef: z.string().regex(ASSET_REF),
    amount: decimalString,
    leverage: decimalString.nullable().default(null),
    recipient: z.string().regex(EVM_ADDRESS),
    venueRef: z.string().min(1).max(128),
    routeRef: z.string().min(1).max(256),
    quoteHash: z.string().regex(HEX_HASH),
    maxFee: decimalString,
    minimumOutput: decimalString,
    expiresAt: timestamp,
  })
  .strict()
  .superRefine((value, context) => {
    if (
      value.bindingKind === "EVM_TRANSACTION" &&
      (!value.target || !value.calldataHash || !value.productionCalldataBound)
    ) {
      context.addIssue({
        code: "custom",
        path: ["bindingKind"],
        message: "EVM fingerprint requires target, calldata hash, and production binding.",
      });
    }
    if (
      value.bindingKind === "APP_KIT_REQUEST" &&
      (value.target !== null || value.calldataHash !== null || !value.adapterRequestHash || value.productionCalldataBound)
    ) {
      context.addIssue({
        code: "custom",
        path: ["bindingKind"],
        message: "App Kit request fingerprint must disclose that target and calldata are not prebound.",
      });
    }
  });

export const HumanAuthorizationSchema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    id: z.string().min(3).max(128),
    tenantId: z.string().min(3).max(128),
    intentId: z.string().min(3).max(128),
    intentRevision: z.number().int().positive(),
    evaluationId: z.string().min(3).max(128),
    intentHash: z.string().regex(HEX_HASH),
    evidenceRoot: z.string().regex(HEX_HASH),
    policyHash: z.string().regex(HEX_HASH),
    policyVersion: z.number().int().positive(),
    policyDigest: z.string().regex(HEX_HASH),
    preflightHash: z.string().regex(HEX_HASH),
    executionFingerprintHash: z.string().regex(HEX_HASH),
    materialWarningsShown: z.array(z.string().min(1).max(128)).max(64),
    subjectRef: z.string().min(1).max(256),
    method: z.enum(["PARTNER_AUTHENTICATED", "EIP712"]),
    decision: z.enum(["APPROVED", "REJECTED"]),
    createdAt: timestamp,
    expiresAt: timestamp,
    signatureRef: z.string().min(1).max(512).nullable(),
  })
  .strict()
  .superRefine((value, context) => {
    if (value.policyDigest !== value.policyHash) {
      context.addIssue({
        code: "custom",
        path: ["policyDigest"],
        message: "Authorization policy digest must match the bound policy hash.",
      });
    }
    if (Date.parse(value.expiresAt) <= Date.parse(value.createdAt)) {
      context.addIssue({
        code: "custom",
        path: ["expiresAt"],
        message: "Authorization expiry must follow creation.",
      });
    }
    if (value.method === "EIP712" && value.signatureRef === null) {
      context.addIssue({
        code: "custom",
        path: ["signatureRef"],
        message: "EIP-712 authorization requires a verified signature reference.",
      });
    }
  });

const FinancialOutcomeSchema = z
  .object({
    amountIn: decimalString,
    amountOut: decimalString,
    feeAmount: decimalString,
  })
  .strict();

const ExpectedEffectsSchema = z
  .object({
    amountIn: decimalString,
    amountOut: decimalString,
    minimumAmountOut: decimalString,
    feeAmount: decimalString,
    totalDebit: decimalString,
  })
  .strict();

const ReconciliationStatusSchema = z.enum(GUARD_RECONCILIATION_STATUSES);

const ExecutionReferenceSchema = z
  .object({
    transactionHash: z.string().regex(HEX_HASH),
    explorerUrl: z.string().url(),
  })
  .strict();

export const ReadinessEnvelopeSchema = z
  .object({
    schemaVersion: z.literal("1.0.0"),
    id: z.string().min(3).max(128),
    tenantId: z.string().min(3).max(128),
    intentId: z.string().min(3).max(128),
    intentRevision: z.number().int().positive(),
    version: z.number().int().positive(),
    amends: z.string().min(3).max(128).nullable(),
    intentHash: z.string().regex(HEX_HASH),
    instrumentRef: z.string().min(3).max(256),
    evidenceRoot: z.string().regex(HEX_HASH),
    evidenceRefs: z.array(z.string().min(3).max(128)).max(256),
    policyRef: z
      .object({
        id: z.string().min(1).max(128),
        version: z.number().int().positive(),
      })
      .strict(),
    policyHash: z.string().regex(HEX_HASH),
    policyVersion: z.number().int().positive(),
    policyDigest: z.string().regex(HEX_HASH),
    preflightHash: z.string().regex(HEX_HASH),
    dataStatus: z.enum(["COMPLETE", "PARTIAL", "INSUFFICIENT", "CONFLICTING", "UNAVAILABLE"]),
    evidenceStatus: z.enum(GUARD_EVIDENCE_STATUSES),
    outcome: z.enum([
      "ALLOWED_BY_POLICY",
      "REVIEW_REQUIRED",
      "BLOCKED_BY_RULE",
      "INSUFFICIENT_EVIDENCE",
      "UNSUPPORTED",
      "EXPIRED",
    ]),
    policyDecision: z.enum(GUARD_POLICY_DECISIONS),
    policyStatus: z.enum(["PASS", "WARN", "BLOCK", "NOT_EVALUATED"]),
    authorizationStatus: z.enum(GUARD_AUTHORIZATION_STATUSES),
    executionStatus: z.enum(GUARD_EXECUTION_STATUSES),
    riskSignals: z.array(RiskSignalSchema).max(512),
    warnings: z.array(z.string().min(1).max(256)).max(128),
    blockers: z.array(z.string().min(1).max(256)).max(128),
    missingEvidence: z.array(z.string().min(1).max(256)).max(128),
    humanAuthorizationId: z.string().min(3).max(128).nullable(),
    expectedOutcome: FinancialOutcomeSchema.nullable(),
    expectedEffects: ExpectedEffectsSchema.nullable(),
    executionReference: ExecutionReferenceSchema.nullable(),
    actualOutcome: FinancialOutcomeSchema.nullable(),
    actualEffects: FinancialOutcomeSchema.nullable(),
    reconciliationStatus: ReconciliationStatusSchema,
    settlementState: z.enum([
      "NOT_STARTED",
      "PENDING",
      "FUNDS_IN_MOTION",
      "DESTINATION_PENDING",
      "CONFIRMED",
      "FAILED",
    ]),
    recoveryState: z.enum(["NOT_REQUIRED", "AVAILABLE", "REQUIRED", "IN_PROGRESS", "RECOVERED", "FAILED"]),
    receiptHash: z.string().regex(HEX_HASH).nullable(),
    createdAt: timestamp,
    finalizedAt: timestamp.nullable(),
    limitations: z.array(z.string().min(1).max(128)).min(1).max(64),
  })
  .strict();

export const EvidenceReceiptSchema = ReadinessEnvelopeSchema.superRefine((value, context) => {
  if (
    value.executionStatus !== "CONFIRMED" ||
    value.settlementState !== "CONFIRMED" ||
    !value.executionReference ||
    !value.actualOutcome ||
    !value.actualEffects ||
    !value.receiptHash ||
    !["MATCHED", "DEVIATION_RECORDED"].includes(value.reconciliationStatus) ||
    !value.finalizedAt
  ) {
    context.addIssue({
      code: "custom",
      message: "A finalized evidence receipt requires confirmed execution and settlement.",
    });
  }
});

const DecisionSettlementReconciliationEvidenceSchema = z
  .object({
    provider: z.string().min(1).max(128),
    sourceRef: z.string().min(1).max(512),
    verificationStatus: z.enum(["PROVIDER_REPORTED", "ONCHAIN_VERIFIED"]),
    observedAt: timestamp,
    responseDigest: z.string().regex(HEX_HASH),
  })
  .strict();

/**
 * The payout block a `1.2.0` receipt carries.
 *
 * Bounded on purpose. A receipt is exported, and everything in it is something
 * Ryntra is willing to hand to whoever holds the export — so the block carries
 * hashes and codes, never the raw business facts that produced them. There is
 * no invoice text, no payroll memo and no beneficiary label here; the
 * `externalReferenceHash` is the only link back to an external document, and a
 * hash cannot be read back into one.
 */
const DecisionSettlementPayoutSchema = z
  .object({
    payoutId: z.string().min(3).max(128),
    purposeCode: z.enum(["INVOICE", "PAYROLL", "REFUND", "TREASURY_TRANSFER"]),
    amount: decimalString,
    amountBaseUnits: z.string().regex(/^(0|[1-9]\d*)$/).max(40),
    beneficiaryRef: z.string().min(3).max(128),
    beneficiaryVersion: z.number().int().positive(),
    beneficiaryWalletAddress: z.string().regex(EVM_ADDRESS),
    treasuryWalletAddress: z.string().regex(EVM_ADDRESS),
    payoutInstructionHash: z.string().regex(HEX_HASH),
    beneficiaryVersionHash: z.string().regex(HEX_HASH),
    policyVersionHash: z.string().regex(HEX_HASH),
    approvalSetHash: z.string().regex(HEX_HASH),
    externalReferenceHash: z.string().regex(HEX_HASH).nullable(),
    reservationId: z.string().min(3).max(128),
    requiredApprovalCount: z.number().int().min(1).max(2),
    receivedApprovalCount: z.number().int().min(1).max(2),
    /** Present in the authenticated export, omitted from the redacted one. */
    requesterRef: z.string().min(1).max(256).optional(),
    approverRefs: z.array(z.string().min(1).max(256)).min(1).max(2).optional(),
    maxTotalDebitBaseUnits: z.string().regex(/^(0|[1-9]\d*)$/).max(40),
    actualTotalDebitBaseUnits: z.string().regex(/^(0|[1-9]\d*)$/).max(40),
    chain: z
      .object({
        chainRef: z.string().regex(CAIP2),
        chainId: z.number().int().positive(),
        assetRef: z.string().regex(ASSET_REF),
        contractAddress: z.string().regex(EVM_ADDRESS),
        decimals: z.literal(6),
      })
      .strict(),
    provenance: z
      .object({
        rpcSourceRef: z.string().min(1).max(512),
        blockNumber: z.number().int().nonnegative(),
        blockHash: z.string().regex(HEX_HASH),
        transactionIndex: z.number().int().nonnegative(),
        logIndex: z.number().int().nonnegative(),
        confirmations: z.number().int().nonnegative(),
        observedAt: timestamp,
      })
      .strict(),
  })
  .strict();

/**
 * The four statements a payout receipt must carry, in every projection.
 *
 * They are required rather than encouraged because each one is a claim someone
 * would otherwise reasonably infer from a signed-looking document: that Ryntra
 * moved the money, that the receipt has legal or compliance standing, that the
 * external facts inside it are guaranteed true, or that any of it applies
 * beyond Arc Public Testnet. None of those is the case, and none of them can
 * stop being false.
 *
 * **`SOURCE_IMPLEMENTED_LIVE_PAYOUT_NOT_VERIFIED` was the fifth and is gone.**
 * It was a maturity claim rather than a boundary, and on 2026-08-24 the
 * founder signed a payout that settled `MATCHED` on Arc Public Testnet and
 * finalized receipt `rcp_62a901894bac4b9cbdd335445e101635` — a document
 * carrying, in its own sealed bytes, the statement that the thing it records
 * had not happened. A receipt is immutable, so that one keeps its bytes and
 * its false line forever; what changes is that no later receipt repeats it.
 * `ARC_PUBLIC_TESTNET_ONLY` takes the slot: the service already appended it to
 * every payout receipt, and a boundary every receipt carries anyway belongs in
 * the list that guarantees it.
 */
/**
 * The swap block a `1.3.0` receipt carries.
 *
 * It exists because a swap receipt could state the cost of a swap only by
 * leaving most of it out. `actualEffects.feeAmount` is one decimal string, and
 * for every swap this product has ever settled it has meant *the network fee*
 * — while the router took its own cut inside the input, and while nothing
 * anywhere recorded what the wallet actually paid in total.
 * `lib/product/capabilities.ts` has carried that admission in public since the
 * run that proved the swap. This block is the fix, and it is additive and
 * version-gated for the same reason the payout block was: a receipt already
 * issued must keep its exact bytes, including the ones that were incomplete.
 *
 * Two rules shape it and neither is negotiable.
 *
 * **Every money figure names its source.** The network fee is `CHAIN_RECEIPT`
 * and is exact to the base unit. The route fee is `PROVIDER_QUOTE`, because
 * Circle does not disclose the recipients of `provider` and `swap` fees and
 * there is no honest way to tell a fee transfer from a routing hop without
 * them. A complete account of a cost may mix an observation with a disclosure;
 * it may not mix their labels.
 *
 * **The two debit figures answer two different questions.** The ceiling is what
 * the person authorized and what a `MAX_TOTAL_DEBIT` rule was evaluated
 * against — input plus every disclosed fee, conservative by the route portion
 * because those fees come out of the input. The settled total is what actually
 * left the wallet — input plus network fee, both observed. They are not the
 * same number and a receipt that printed one of them alone would be answering
 * the wrong question half the time.
 */
const DecisionSettlementSwapFeeComponentSchema = z
  .object({
    type: z.string().min(1).max(64),
    token: z.string().min(1).max(32),
    amount: decimalString.nullable(),
    side: z.enum(["NETWORK", "ROUTE"]),
    takenFrom: z.enum(["ON_TOP_OF_INPUT", "INSIDE_INPUT"]),
  })
  .strict();

const SwapFeeCoverageSchema = z.enum([
  "NETWORK_AND_ROUTE",
  "NETWORK_ONLY",
  "ROUTE_ONLY",
  "NONE",
  "INCOMPLETE",
]);

const DecisionSettlementSwapSchema = z
  .object({
    quoteRef: z.string().min(1).max(128),
    provider: z.string().min(1).max(128),
    routeRef: z.string().min(1).max(256),
    /** What the provider would not tell us about its own route, verbatim. */
    routeDisclosure: z.string().min(1).max(128),
    slippageBps: z.string().regex(/^(0|[1-9]\d*)$/).max(8),
    sellAssetRef: z.string().regex(ASSET_REF),
    buyAssetRef: z.string().regex(ASSET_REF),
    quotedFees: z
      .object({
        components: z.array(DecisionSettlementSwapFeeComponentSchema).max(32),
        networkAmount: decimalString.nullable(),
        routeAmount: decimalString.nullable(),
        totalAmount: decimalString.nullable(),
        coverage: SwapFeeCoverageSchema,
      })
      .strict(),
    settledFees: z
      .object({
        networkAmount: decimalString,
        networkSource: z.literal("CHAIN_RECEIPT"),
        routeAmount: decimalString.nullable(),
        routeSource: z.enum(["PROVIDER_QUOTE", "UNAVAILABLE"]),
        routeObservability: z.literal("NOT_ATTRIBUTABLE_ON_CHAIN"),
        coverage: SwapFeeCoverageSchema,
      })
      .strict(),
    debit: z
      .object({
        authorizedCeiling: decimalString,
        settledTotal: decimalString,
        settledSource: z.literal("CHAIN_RECEIPT"),
      })
      .strict(),
    authorizedMinimumAmountOut: decimalString,
    deviations: z.array(z.string().min(1).max(128)).max(32),
  })
  .strict();

/**
 * The four statements a swap receipt must carry.
 *
 * Three are the boundaries every Ryntra receipt has: Ryntra did not sign or
 * broadcast, this is not legal or compliance proof, and it is Arc Public
 * Testnet only. The fourth exists because of what this very block added: the
 * route fee inside it is the provider's own number, carried forward, not
 * something the chain was read for. A document that states a cost more
 * completely than before must also state which half of it is a disclosure —
 * otherwise the improvement reads as a stronger claim than it is.
 */
export const SWAP_RECEIPT_REQUIRED_LIMITATIONS = [
  "RYNTRA_DID_NOT_SIGN_OR_BROADCAST",
  "NOT_LEGAL_OR_COMPLIANCE_PROOF",
  "ARC_PUBLIC_TESTNET_ONLY",
  "SWAP_ROUTE_FEE_PROVIDER_QUOTED_NOT_CHAIN_ATTRIBUTED",
] as const;

export const PAYOUT_RECEIPT_REQUIRED_LIMITATIONS = [
  "RYNTRA_DID_NOT_SIGN_OR_BROADCAST",
  "NOT_LEGAL_OR_COMPLIANCE_PROOF",
  "EXTERNAL_SOURCE_TRUTH_NOT_GUARANTEED",
  "ARC_PUBLIC_TESTNET_ONLY",
] as const;

/**
 * The bridge block a `1.4.0` receipt carries.
 *
 * Every other receipt in this family records one chain. This one records two,
 * and that single difference is what the whole block is shaped around: the
 * source side is evidence this deployment read, the destination side may be
 * evidence it read, evidence a provider reported, or **nothing at all** — and
 * those three are not allowed to look alike.
 *
 * `destination.evidenceKind` is therefore required and has a `NOT_OBSERVED`
 * member. A receipt whose destination was never read is a real and useful
 * document — it records exactly where a transfer got to — but it may not claim
 * a matched reconciliation, and the refinement below refuses one.
 *
 * ## Why the lifecycle state is inside the sealed bytes
 *
 * Canon §16's rule is that Arc finality is not crosschain completion. A receipt
 * that carried amounts and hashes without the state they belong to would let a
 * reader supply the missing half themselves, and the half they supply is
 * "so it worked". `lifecycleState` is `RECEIPT_ISSUED` — there is no other
 * state a receipt can exist in — and `recovery` states where the value ended
 * up in the same breath.
 */
const DecisionSettlementBridgeSideSchema = z
  .object({
    domain: z.number().int().nonnegative().max(65535),
    label: z.string().min(1).max(64),
  })
  .strict();

const DecisionSettlementBridgeSchema = z
  .object({
    transferId: z.string().min(3).max(128),
    protocol: z.literal("CCTP_V2"),
    source: DecisionSettlementBridgeSideSchema,
    destination: DecisionSettlementBridgeSideSchema,
    speed: z.enum(["STANDARD", "FAST"]),
    /** `1000` or below requests Fast, `2000` or above requests Standard. */
    finalityThreshold: z.number().int().positive().max(100000),
    sourceTransactionHash: z.string().regex(HEX_HASH),
    attestation: z
      .object({
        /** Circle's message hash, when the service returned one. */
        messageHash: z.string().regex(HEX_HASH).nullable(),
        providerStatus: z.string().min(1).max(64).nullable(),
        source: z.enum(["CIRCLE_ATTESTATION_API", "NOT_OBSERVED"]),
        observedAt: timestamp.nullable(),
      })
      .strict(),
    destinationEffect: z
      .object({
        transactionHash: z.string().regex(HEX_HASH).nullable(),
        evidenceKind: z.enum(["CHAIN_RECEIPT", "PROVIDER_REPORTED", "NOT_OBSERVED"]),
        amountReceived: decimalString.nullable(),
        observedAt: timestamp.nullable(),
        /** Why the destination was not read, when it was not. */
        absentReason: z.string().min(1).max(128).nullable(),
      })
      .strict(),
    amounts: z
      .object({
        authorized: decimalString,
        sourceDebited: decimalString,
        destinationCredited: decimalString.nullable(),
        /** Debit minus credit. `null` whenever either side is unread. */
        transportCost: decimalString.nullable(),
      })
      .strict(),
    fees: z
      .object({
        authorizedMaxFee: decimalString,
        quotedTransportFee: decimalString.nullable(),
        quotedTransportFeeSource: z.enum(["PROVIDER_QUOTE", "UNAVAILABLE"]),
        sourceNetworkFee: decimalString,
        sourceNetworkFeeSource: z.literal("CHAIN_RECEIPT"),
      })
      .strict(),
    duration: z
      .object({
        burnConfirmedAt: timestamp,
        destinationObservedAt: timestamp.nullable(),
        elapsedMs: z.number().int().nonnegative().nullable(),
      })
      .strict(),
    lifecycleState: z.literal("RECEIPT_ISSUED"),
    recovery: z
      .object({
        action: z.string().min(1).max(128),
        whereTheValueIs: z.string().min(1).max(128),
        fundsAtRest: z.boolean(),
      })
      .strict(),
    deviations: z.array(z.string().min(1).max(128)).max(32),
  })
  .strict();

/**
 * The five statements a bridge receipt must carry.
 *
 * Three are the boundaries every Ryntra receipt has. The fourth is canon §16's
 * rule, in the sealed bytes rather than on a page — a receipt is the artifact
 * most likely to be read years later by somebody who never saw the screen it
 * came from. The fifth names who actually moved the value, because a document
 * describing a burn and a mint that Ryntra recorded reads, to a hurried
 * reader, like a document describing a burn and a mint Ryntra performed.
 */
export const BRIDGE_RECEIPT_REQUIRED_LIMITATIONS = [
  "RYNTRA_DID_NOT_SIGN_OR_BROADCAST",
  "NOT_LEGAL_OR_COMPLIANCE_PROOF",
  "ARC_PUBLIC_TESTNET_ONLY",
  "ARC_FINALITY_IS_NOT_CROSSCHAIN_COMPLETION",
  "CROSSCHAIN_TRANSPORT_PERFORMED_BY_CIRCLE_CCTP_NOT_BY_RYNTRA",
] as const;

export const DecisionSettlementReceiptSchema = z
  .object({
    schemaVersion: z.enum(["1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0"]),
    id: z.string().min(3).max(128),
    tenantId: z.string().min(3).max(128),
    evidenceStatus: z.enum(GUARD_EVIDENCE_STATUSES),
    policyDecision: z.enum(GUARD_POLICY_DECISIONS),
    authorizationStatus: z.literal("APPROVED"),
    executionStatus: z.literal("CONFIRMED"),
    policyVersion: z.number().int().positive(),
    policyDigest: z.string().regex(HEX_HASH),
    preflightHash: z.string().regex(HEX_HASH),
    expectedEffects: ExpectedEffectsSchema,
    actualEffects: FinancialOutcomeSchema,
    reconciliationStatus: z.enum(["MATCHED", "DEVIATION_RECORDED"]),
    intent: z
      .object({
        id: z.string().min(3).max(128),
        revision: z.number().int().positive(),
        hash: z.string().regex(HEX_HASH),
      })
      .strict(),
    evidence: z
      .object({
        root: z.string().regex(HEX_HASH),
        refs: z.array(z.string().min(3).max(128)).max(256),
      })
      .strict(),
    policy: z
      .object({
        id: z.string().min(1).max(128),
        version: z.number().int().positive(),
        hash: z.string().regex(HEX_HASH),
        outcome: z.enum([
          "ALLOWED_BY_POLICY",
          "REVIEW_REQUIRED",
          "BLOCKED_BY_RULE",
          "INSUFFICIENT_EVIDENCE",
          "UNSUPPORTED",
          "EXPIRED",
        ]),
      })
      .strict(),
    authorization: z
      .object({
        id: z.string().min(3).max(128),
        method: z.enum(["PARTNER_AUTHENTICATED", "EIP712"]),
        subjectRef: z.string().min(1).max(256),
        createdAt: timestamp,
        expiresAt: timestamp.optional(),
        executionFingerprintHash: z.string().regex(HEX_HASH).optional(),
      })
      .strict(),
    execution: z
      .object({
        id: z.string().min(3).max(128),
        fingerprintHash: z.string().regex(HEX_HASH),
        bindingKind: z.enum(["EVM_TRANSACTION", "APP_KIT_REQUEST"]),
        productionCalldataBound: z.boolean(),
        transactionHash: z.string().regex(HEX_HASH),
        status: z.literal("CONFIRMED"),
        explorerUrl: z.string().url().regex(ARC_EXPLORER_TRANSACTION),
      })
      .strict(),
    reconciliation: z
      .object({
        status: z.enum(["MATCHED", "DEVIATION_RECORDED"]),
        expected: ExpectedEffectsSchema,
        actual: FinancialOutcomeSchema,
        evidence: DecisionSettlementReconciliationEvidenceSchema,
      })
      .strict(),
    settlement: z
      .object({
        status: z.literal("CONFIRMED"),
        recoveryState: z.literal("NOT_REQUIRED"),
      })
      .strict(),
    createdAt: timestamp,
    finalizedAt: timestamp,
    limitations: z.array(z.string().min(1).max(128)).min(1).max(64),
    /* Additive and version-gated. Absent on 1.0.0 and 1.1.0, where the
       canonical hasher drops it, so every legacy receipt keeps its exact
       bytes. */
    payout: DecisionSettlementPayoutSchema.optional(),
    /* Additive and version-gated, exactly as `payout` is. Absent on 1.0.0,
       1.1.0 and 1.2.0, where the canonical hasher drops it, so every receipt
       issued before this block existed keeps its exact bytes. */
    swap: DecisionSettlementSwapSchema.optional(),
    /* Additive and version-gated, exactly as `payout` and `swap` are. Absent
       on every version before 1.4.0, where the canonical hasher drops it. */
    bridge: DecisionSettlementBridgeSchema.optional(),
    receiptHash: z.string().regex(HEX_HASH),
    integrity: z
      .object({
        algorithm: z.literal("SHA-256"),
        hash: z.string().regex(HEX_HASH),
      })
      .strict(),
  })
  .strict()
  .superRefine((value, context) => {
    /* 1.2.0 is a superset of 1.1.0, so every binding 1.1 introduced applies to
       it too. Writing `!== "1.0.0"` rather than listing versions means the next
       additive version inherits these checks instead of quietly losing them. */
    if (value.schemaVersion !== "1.0.0") {
      const authorizationExpiry = value.authorization.expiresAt;
      const authorizationFingerprint = value.authorization.executionFingerprintHash;
      if (!authorizationExpiry) {
        context.addIssue({
          code: "custom",
          path: ["authorization", "expiresAt"],
          message: "Receipt v1.1 requires the authorization expiry.",
        });
      }
      if (!authorizationFingerprint) {
        context.addIssue({
          code: "custom",
          path: ["authorization", "executionFingerprintHash"],
          message: "Receipt v1.1 requires the authorized execution fingerprint hash.",
        });
      }
      if (
        authorizationFingerprint &&
        authorizationFingerprint !== value.execution.fingerprintHash
      ) {
        context.addIssue({
          code: "custom",
          path: ["authorization", "executionFingerprintHash"],
          message: "Receipt authorization and execution fingerprint hashes must match.",
        });
      }
      if (authorizationExpiry) {
        const createdAt = Date.parse(value.authorization.createdAt);
        const observedAt = Date.parse(value.reconciliation.evidence.observedAt);
        const expiresAt = Date.parse(authorizationExpiry);
        const finalizedAt = Date.parse(value.finalizedAt);
        /* Legacy v1.1 bound the reconciliation observation itself to the
           authorization window and keeps that exact behavior. A payout v1.2
           records an external broadcast before reconciliation; its execution
           record must be in-window, while a later chain observation may happen
           after expiry and still precede finalization. */
        const executionRecordedAt = Date.parse(value.createdAt);
        /* A bridge receipt has the same shape as a payout in this respect: the
           source burn is broadcast inside the authorization window and the
           destination observation necessarily comes later, sometimes much
           later. Binding the observation to the window would make every
           standard-transfer receipt invalid by construction. */
        const externalBroadcast = value.schemaVersion === "1.2.0" || value.schemaVersion === "1.4.0";
        const validTimeline = externalBroadcast
          ? createdAt <= executionRecordedAt &&
            executionRecordedAt < expiresAt &&
            executionRecordedAt <= observedAt &&
            observedAt <= finalizedAt
          : createdAt <= observedAt && observedAt <= expiresAt && observedAt <= finalizedAt;
        if (!validTimeline) {
          context.addIssue({
            code: "custom",
            path: ["reconciliation", "evidence", "observedAt"],
            message: externalBroadcast
              ? "Payout execution must be recorded within authorization and observations must precede finalization."
              : "Receipt observation must fall within authorization and precede finalization.",
          });
        }
      }
    }
    if (value.schemaVersion === "1.2.0") {
      if (!value.payout) {
        context.addIssue({
          code: "custom",
          path: ["payout"],
          message: "A 1.2.0 receipt is a payout receipt and must carry its payout block.",
        });
      }
      for (const limitation of PAYOUT_RECEIPT_REQUIRED_LIMITATIONS) {
        if (!value.limitations.includes(limitation)) {
          context.addIssue({
            code: "custom",
            path: ["limitations"],
            message: `A payout receipt must state ${limitation}.`,
          });
        }
      }
      if (value.payout) {
        if (value.authorization.method !== "PARTNER_AUTHENTICATED") {
          context.addIssue({
            code: "custom",
            path: ["authorization", "method"],
            message: "A payout receipt requires partner-authenticated human authorization.",
          });
        }
        if (value.execution.bindingKind !== "EVM_TRANSACTION" || !value.execution.productionCalldataBound) {
          context.addIssue({
            code: "custom",
            path: ["execution", "bindingKind"],
            message: "A payout receipt requires an exact calldata-bound EVM transaction.",
          });
        }
        if (value.reconciliation.evidence.verificationStatus !== "ONCHAIN_VERIFIED") {
          context.addIssue({
            code: "custom",
            path: ["reconciliation", "evidence", "verificationStatus"],
            message: "A payout receipt requires authoritative onchain reconciliation evidence.",
          });
        }
        if (!value.payout.requesterRef) {
          context.addIssue({
            code: "custom",
            path: ["payout", "requesterRef"],
            message: "The authenticated payout receipt must identify its requester.",
          });
        }
        if (!value.payout.approverRefs) {
          context.addIssue({
            code: "custom",
            path: ["payout", "approverRefs"],
            message: "The authenticated payout receipt must identify its approvers.",
          });
        }
        if (value.payout.receivedApprovalCount < value.payout.requiredApprovalCount) {
          context.addIssue({
            code: "custom",
            path: ["payout", "receivedApprovalCount"],
            message: "A receipt cannot record fewer approvals than the policy required.",
          });
        }
        if (value.payout.approverRefs && value.payout.approverRefs.length !== value.payout.receivedApprovalCount) {
          context.addIssue({
            code: "custom",
            path: ["payout", "approverRefs"],
            message: "The listed approvers must match the received count.",
          });
        }
        if (value.payout.approverRefs && new Set(value.payout.approverRefs).size !== value.payout.approverRefs.length) {
          context.addIssue({
            code: "custom",
            path: ["payout", "approverRefs"],
            message: "One principal cannot fill two approval slots.",
          });
        }
        if (
          value.payout.requesterRef &&
          value.payout.approverRefs?.includes(value.payout.requesterRef)
        ) {
          context.addIssue({
            code: "custom",
            path: ["payout", "approverRefs"],
            message: "The requester cannot appear as an approver of their own payout.",
          });
        }
        if (value.payout.beneficiaryWalletAddress === value.payout.treasuryWalletAddress) {
          context.addIssue({
            code: "custom",
            path: ["payout", "beneficiaryWalletAddress"],
            message: "A payout to the treasury wallet itself moves nothing.",
          });
        }
        if (value.payout.policyVersionHash !== value.policy.hash) {
          context.addIssue({
            code: "custom",
            path: ["payout", "policyVersionHash"],
            message: "The payout policy version hash must match the attributed policy.",
          });
        }

        const payoutAmount = exactSixDecimalBaseUnits(value.payout.amount);
        const payoutAmountBaseUnits = BigInt(value.payout.amountBaseUnits);
        if (payoutAmount === null || payoutAmount !== payoutAmountBaseUnits) {
          context.addIssue({
            code: "custom",
            path: ["payout", "amountBaseUnits"],
            message: "The payout decimal amount and base units must represent the same USDC value.",
          });
        }

        const expectedAmounts = [
          exactSixDecimalBaseUnits(value.expectedEffects.amountIn),
          exactSixDecimalBaseUnits(value.expectedEffects.amountOut),
          exactSixDecimalBaseUnits(value.expectedEffects.minimumAmountOut),
        ];
        if (expectedAmounts.some((amount) => amount === null || amount !== payoutAmountBaseUnits)) {
          context.addIssue({
            code: "custom",
            path: ["expectedEffects"],
            message: "Expected transfer effects must match the payout amount exactly.",
          });
        }
        const expectedFee = exactSixDecimalBaseUnits(value.expectedEffects.feeAmount);
        const expectedTotal = exactSixDecimalBaseUnits(value.expectedEffects.totalDebit);
        const maximumTotal = BigInt(value.payout.maxTotalDebitBaseUnits);
        if (
          expectedFee === null ||
          expectedTotal === null ||
          expectedTotal !== maximumTotal ||
          expectedTotal !== payoutAmountBaseUnits + expectedFee
        ) {
          context.addIssue({
            code: "custom",
            path: ["payout", "maxTotalDebitBaseUnits"],
            message: "The maximum debit must equal the exact expected payout plus fee.",
          });
        }

        const actualAmountIn = exactSixDecimalBaseUnits(value.actualEffects.amountIn);
        const actualAmountOut = exactSixDecimalBaseUnits(value.actualEffects.amountOut);
        const actualFee = exactSixDecimalBaseUnits(value.actualEffects.feeAmount);
        const actualTotal = BigInt(value.payout.actualTotalDebitBaseUnits);
        if (
          actualAmountIn === null ||
          actualAmountOut === null ||
          actualFee === null ||
          actualAmountIn !== payoutAmountBaseUnits ||
          actualAmountOut !== payoutAmountBaseUnits ||
          actualTotal !== actualAmountIn + actualFee
        ) {
          context.addIssue({
            code: "custom",
            path: ["payout", "actualTotalDebitBaseUnits"],
            message: "The actual debit must equal the reconciled payout plus fee.",
          });
        }
        if (
          Date.parse(value.payout.provenance.observedAt) !==
          Date.parse(value.reconciliation.evidence.observedAt)
        ) {
          context.addIssue({
            code: "custom",
            path: ["payout", "provenance", "observedAt"],
            message: "Payout provenance must bind the reconciliation observation instant.",
          });
        }
      }
    } else if (value.payout) {
      context.addIssue({
        code: "custom",
        path: ["payout"],
        message: "Only a 1.2.0 receipt carries a payout block.",
      });
    }
    if (value.schemaVersion === "1.3.0") {
      if (!value.swap) {
        context.addIssue({
          code: "custom",
          path: ["swap"],
          message: "A 1.3.0 receipt is a swap receipt and must carry its swap block.",
        });
      }
      for (const limitation of SWAP_RECEIPT_REQUIRED_LIMITATIONS) {
        if (!value.limitations.includes(limitation)) {
          context.addIssue({
            code: "custom",
            path: ["limitations"],
            message: `A swap receipt must state ${limitation}.`,
          });
        }
      }
      if (value.swap) {
        /* The settled network fee is the one number both halves of the receipt
           state, so they have to be the same number. `actualEffects.feeAmount`
           is what the kernel compared against the authorized ceiling and the
           swap block is what a reader is shown; a receipt in which those two
           disagree is a receipt that argues with itself. */
        if (value.swap.settledFees.networkAmount !== value.actualEffects.feeAmount) {
          context.addIssue({
            code: "custom",
            path: ["swap", "settledFees", "networkAmount"],
            message: "The settled network fee must be the fee the reconciliation recorded.",
          });
        }
        if (value.swap.debit.authorizedCeiling !== value.expectedEffects.totalDebit) {
          context.addIssue({
            code: "custom",
            path: ["swap", "debit", "authorizedCeiling"],
            message: "The authorized debit ceiling must be the one the evaluation sealed.",
          });
        }
        if (value.swap.authorizedMinimumAmountOut !== value.expectedEffects.minimumAmountOut) {
          context.addIssue({
            code: "custom",
            path: ["swap", "authorizedMinimumAmountOut"],
            message: "The authorized output floor must be the one the evaluation sealed.",
          });
        }
        /* A swap's payload does not exist when a person authorizes it, and the
           receipt has said so since v1.1 through `productionCalldataBound`.
           Binding it here means a 1.3.0 receipt cannot be minted for an exact
           calldata operation whose evidence is stronger — that would be a
           payout wearing a swap block. */
        if (value.swap.deviations.length > 0 && value.reconciliationStatus !== "DEVIATION_RECORDED") {
          context.addIssue({
            code: "custom",
            path: ["reconciliationStatus"],
            message: "A swap receipt listing deviations cannot claim a matched reconciliation.",
          });
        }
        if (value.execution.bindingKind !== "APP_KIT_REQUEST" || value.execution.productionCalldataBound) {
          context.addIssue({
            code: "custom",
            path: ["execution", "bindingKind"],
            message: "A swap receipt records an App Kit request binding, not exact calldata.",
          });
        }
      }
    } else if (value.swap) {
      context.addIssue({
        code: "custom",
        path: ["swap"],
        message: "Only a 1.3.0 receipt carries a swap block.",
      });
    }
    if (value.schemaVersion === "1.4.0") {
      if (!value.bridge) {
        context.addIssue({
          code: "custom",
          path: ["bridge"],
          message: "A 1.4.0 receipt is a bridge receipt and must carry its bridge block.",
        });
      }
      for (const limitation of BRIDGE_RECEIPT_REQUIRED_LIMITATIONS) {
        if (!value.limitations.includes(limitation)) {
          context.addIssue({
            code: "custom",
            path: ["limitations"],
            message: `A bridge receipt must state ${limitation}.`,
          });
        }
      }
      if (value.bridge) {
        /* The source burn is the transaction this receipt is about, and the
           execution record already names one. Two hashes in one document that
           are supposed to be the same hash is a document that can disagree
           with itself, so they are bound rather than both trusted. */
        if (value.bridge.sourceTransactionHash.toLowerCase() !== value.execution.transactionHash.toLowerCase()) {
          context.addIssue({
            code: "custom",
            path: ["bridge", "sourceTransactionHash"],
            message: "The bridge source transaction must be the execution this receipt records.",
          });
        }
        if (value.bridge.source.domain === value.bridge.destination.domain) {
          context.addIssue({
            code: "custom",
            path: ["bridge", "destination", "domain"],
            message: "A crosschain transfer cannot have one domain on both sides.",
          });
        }
        /* The rule this whole schema version exists for. An unread destination
           is a legitimate receipt and an illegitimate success: nobody looked at
           the other chain, so nothing there can be reconciled. */
        if (
          value.bridge.destinationEffect.evidenceKind === "NOT_OBSERVED" &&
          value.reconciliationStatus !== "DEVIATION_RECORDED"
        ) {
          context.addIssue({
            code: "custom",
            path: ["reconciliationStatus"],
            message: "A bridge receipt whose destination was never observed cannot claim a matched reconciliation.",
          });
        }
        if (
          value.bridge.destinationEffect.evidenceKind === "NOT_OBSERVED" &&
          !value.bridge.destinationEffect.absentReason
        ) {
          context.addIssue({
            code: "custom",
            path: ["bridge", "destinationEffect", "absentReason"],
            message: "An unobserved destination must record why it was not observed.",
          });
        }
        if (
          value.bridge.destinationEffect.evidenceKind !== "NOT_OBSERVED" &&
          value.bridge.destinationEffect.amountReceived === null
        ) {
          context.addIssue({
            code: "custom",
            path: ["bridge", "destinationEffect", "amountReceived"],
            message: "An observed destination effect must record the amount that arrived.",
          });
        }
        if (value.bridge.deviations.length > 0 && value.reconciliationStatus !== "DEVIATION_RECORDED") {
          context.addIssue({
            code: "custom",
            path: ["reconciliationStatus"],
            message: "A bridge receipt listing deviations cannot claim a matched reconciliation.",
          });
        }
        /* A quoted fee that was never read may not be printed as a number, and
           a number that was read may not be labelled unavailable. The pair is
           checked in both directions because only one of them is the mistake
           somebody makes on purpose. */
        const quoted = value.bridge.fees.quotedTransportFee;
        const quotedSource = value.bridge.fees.quotedTransportFeeSource;
        if ((quoted === null) !== (quotedSource === "UNAVAILABLE")) {
          context.addIssue({
            code: "custom",
            path: ["bridge", "fees", "quotedTransportFeeSource"],
            message: "A transport fee and its source must agree about whether it was read.",
          });
        }
        if (value.bridge.fees.sourceNetworkFee !== value.actualEffects.feeAmount) {
          context.addIssue({
            code: "custom",
            path: ["bridge", "fees", "sourceNetworkFee"],
            message: "The settled source network fee must be the fee the reconciliation recorded.",
          });
        }
        if (value.bridge.amounts.authorized !== value.expectedEffects.amountIn) {
          context.addIssue({
            code: "custom",
            path: ["bridge", "amounts", "authorized"],
            message: "The authorized transfer amount must be the one the evaluation sealed.",
          });
        }
        if (value.bridge.amounts.sourceDebited !== value.actualEffects.amountIn) {
          context.addIssue({
            code: "custom",
            path: ["bridge", "amounts", "sourceDebited"],
            message: "The source debit must be the amount the reconciliation observed leaving the wallet.",
          });
        }
        if (value.execution.bindingKind !== "EVM_TRANSACTION" || !value.execution.productionCalldataBound) {
          context.addIssue({
            code: "custom",
            path: ["execution", "bindingKind"],
            message: "A bridge receipt records an exact calldata-bound burn on the source chain.",
          });
        }
      }
    } else if (value.bridge) {
      context.addIssue({
        code: "custom",
        path: ["bridge"],
        message: "Only a 1.4.0 receipt carries a bridge block.",
      });
    }
    const relationshipsMatch =
      value.policyVersion === value.policy.version &&
      value.policyDigest === value.policy.hash &&
      value.policyDecision === value.policy.outcome &&
      value.executionStatus === value.execution.status &&
      value.reconciliationStatus === value.reconciliation.status &&
      hashCanonical(value.expectedEffects) === hashCanonical(value.reconciliation.expected) &&
      hashCanonical(value.actualEffects) === hashCanonical(value.reconciliation.actual);
    if (!relationshipsMatch) {
      context.addIssue({
        code: "custom",
        message: "Receipt summary fields must match their attributed lifecycle records.",
      });
    }
    const expectedExplorerUrl =
      `https://testnet.arcscan.app/tx/${value.execution.transactionHash.toLowerCase()}`;
    if (value.execution.explorerUrl !== expectedExplorerUrl) {
      context.addIssue({
        code: "custom",
        path: ["execution", "explorerUrl"],
        message: "Receipt explorer URL must match the execution transaction hash.",
      });
    }
    const { receiptHash, integrity, ...receiptCore } = value;
    if (receiptHash !== hashDecisionSettlementReceiptCore(receiptCore)) {
      context.addIssue({
        code: "custom",
        path: ["receiptHash"],
        message: "Receipt hash does not match its canonical core.",
      });
    }
    if (integrity.hash !== hashCanonical({ ...receiptCore, receiptHash })) {
      context.addIssue({
        code: "custom",
        path: ["integrity", "hash"],
        message: "Receipt integrity hash does not match the finalized receipt.",
      });
    }
  });

export type DecisionSettlementReceipt = z.output<typeof DecisionSettlementReceiptSchema>;

/**
 * The projection that may leave the tenant boundary.
 *
 * Every internal principal reference is removed: who asked for the payout, the
 * approval-set members and the authorization subject. They identify people inside a
 * customer's organization, and a receipt is something a customer hands to a
 * counterparty, an auditor or a reviewer. The beneficiary *label* is not removed
 * here because it was never put in — the payout block carries the address and
 * the version hash, never the human name someone typed.
 *
 * What survives is everything a verifier needs to check integrity against the
 * authenticated export: every hash, every amount, the chain provenance and all
 * the limitations.
 *
 * The redacted body deliberately does **not** re-hash to `receiptHash`. It could
 * be made to, by hashing the redacted form separately — and then two documents
 * would both claim to be "the" receipt for one payout, which is worse. The
 * marker says plainly that this is a view of a record, and the full export is
 * the record.
 */
export type RedactedDecisionSettlementReceipt = Omit<
  DecisionSettlementReceipt,
  "payout" | "authorization"
> & {
  readonly redacted: true;
  readonly authorization: Omit<DecisionSettlementReceipt["authorization"], "subjectRef">;
  readonly payout?: Omit<
    NonNullable<DecisionSettlementReceipt["payout"]>,
    "requesterRef" | "approverRefs"
  >;
};

export function redactDecisionSettlementReceipt(
  receipt: DecisionSettlementReceipt,
): RedactedDecisionSettlementReceipt {
  const clone = structuredClone(receipt) as DecisionSettlementReceipt;
  const { payout, authorization, ...rest } = clone;
  const { subjectRef: _subjectRef, ...publicAuthorization } = authorization;
  if (!payout) return { ...rest, authorization: publicAuthorization, redacted: true };
  const { requesterRef: _requesterRef, approverRefs: _approverRefs, ...publicPayout } = payout;
  return { ...rest, authorization: publicAuthorization, payout: publicPayout, redacted: true };
}

const EnvelopeAmendmentSchema = z
  .object({
    id: z.string().min(3).max(128),
    executionStatus: ReadinessEnvelopeSchema.shape.executionStatus,
    executionReference: ExecutionReferenceSchema.nullable(),
    actualOutcome: FinancialOutcomeSchema.nullable(),
    actualEffects: FinancialOutcomeSchema.nullable(),
    reconciliationStatus: ReconciliationStatusSchema,
    settlementState: ReadinessEnvelopeSchema.shape.settlementState,
    recoveryState: ReadinessEnvelopeSchema.shape.recoveryState.optional(),
    receiptHash: z.string().regex(HEX_HASH).nullable(),
    finalizedAt: timestamp.nullable(),
  })
  .strict();

export function amendReadinessEnvelope(
  previousInput: z.input<typeof ReadinessEnvelopeSchema>,
  amendmentInput: z.input<typeof EnvelopeAmendmentSchema>,
): z.output<typeof ReadinessEnvelopeSchema> {
  const previous = ReadinessEnvelopeSchema.parse(previousInput);
  const amendment = EnvelopeAmendmentSchema.parse(amendmentInput);
  return ReadinessEnvelopeSchema.parse({
    ...structuredClone(previous),
    ...amendment,
    version: previous.version + 1,
    amends: previous.id,
  });
}
