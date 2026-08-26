// Run from repo root: node --test lib/guard/schemas.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";

const HASH_A = `0x${"ab".repeat(32)}`;
const HASH_B = `0x${"cd".repeat(32)}`;
const HASH_C = `0x${"ef".repeat(32)}`;
const WALLET = "0x1111111111111111111111111111111111111111";
const USDC = "eip155:5042002/erc20:0x3600000000000000000000000000000000000000";
const EURC = "eip155:5042002/erc20:0x89b50855aa3be2f677cd6303cec089b5f319d72a";

async function loadSchemas() {
  try {
    return await import("./contracts.ts");
  } catch (error) {
    assert.fail(`Guard schemas are unavailable: ${error instanceof Error ? error.message : String(error)}`);
  }
}

test("versioned Guard schemas preserve independent states and append-only envelope amendments", async () => {
  const {
    EvidenceItemSchema,
    EvidenceReceiptSchema,
    ExecutionFingerprintSchema,
    GuardPolicySchema,
    HumanAuthorizationSchema,
    PolicyResultSchema,
    ReadinessEnvelopeSchema,
    RiskSignalSchema,
    amendReadinessEnvelope,
  } = await loadSchemas();

  for (const [name, schema] of Object.entries({
    EvidenceItemSchema,
    EvidenceReceiptSchema,
    ExecutionFingerprintSchema,
    GuardPolicySchema,
    HumanAuthorizationSchema,
    PolicyResultSchema,
    ReadinessEnvelopeSchema,
    RiskSignalSchema,
  })) {
    assert.equal(typeof schema?.parse, "function", `${name} must be a runtime schema`);
  }
  assert.equal(typeof amendReadinessEnvelope, "function");

  const evidence = EvidenceItemSchema.parse({
    schemaVersion: "1.0.0",
    id: "ev_schema_001",
    provider: "Circle App Kit",
    sourceRef: "circle-app-kit:estimateSwap",
    adapter: "circle-app-kit",
    adapterVersion: "1.0.0",
    sourceType: "SWAP_QUOTE",
    observedAt: "2026-08-06T11:59:30.000Z",
    receivedAt: "2026-08-06T11:59:31.000Z",
    validUntil: "2026-08-06T12:01:30.000Z",
    confidence: "PROVIDER_REPORTED",
    coverage: {
      subjectRefs: ["eip155:5042002", USDC, EURC],
      fields: ["amountIn", "expectedAmountOut"],
      limitations: ["UNDERLYING_ROUTE_UNAVAILABLE"],
    },
    availability: "AVAILABLE",
    verificationStatus: "PROVIDER_REPORTED",
    chainRef: "eip155:5042002",
    blockRef: null,
    transactionRef: null,
    status: "VALID",
    requestHash: HASH_A,
    responseHash: HASH_B,
    responseDigest: HASH_B,
    reason: null,
    transformationVersion: "arc-swap-quote-v1",
    fallbackUsed: false,
    facts: { amountIn: "10.00", expectedAmountOut: "9.96" },
  });
  assert.equal(evidence.status, "VALID");
  assert.equal(EvidenceItemSchema.safeParse({ ...evidence, status: "SAFE" }).success, false);

  const signal = RiskSignalSchema.parse({
    id: "sig_slippage",
    schemaVersion: "1.0.0",
    category: "SLIPPAGE",
    subjectRef: "int_schema_001",
    status: "VALID",
    severity: "WARNING",
    observedValue: "30",
    unit: "bps",
    threshold: "25",
    evidenceRefs: [evidence.id],
    sourceTimestamp: evidence.observedAt,
    validUntil: evidence.validUntil,
    confidence: "PROVIDER_REPORTED",
    explanationCode: "SLIPPAGE_ABOVE_SOFT_LIMIT",
    remediation: "Review the estimate or lower the amount.",
  });
  assert.equal(signal.severity, "WARNING");
  assert.equal(RiskSignalSchema.safeParse({ ...signal, severity: "SAFE" }).success, false);

  const policy = GuardPolicySchema.parse({
    schemaVersion: "1.0.0",
    id: "demo-stablecoin-policy",
    version: 1,
    publishedAt: "2026-08-06T00:00:00.000Z",
    immutable: true,
    rules: [
      { id: "allowed-chain", type: "ALLOWED_CHAIN", value: "eip155:5042002", onViolation: "BLOCK" },
      { id: "allowed-pair", type: "ALLOWED_PAIR", value: [USDC, EURC], onViolation: "BLOCK" },
      { id: "max-total-debit", type: "MAX_TOTAL_DEBIT", value: "100.00", currencyAssetRef: USDC, onViolation: "BLOCK" },
      { id: "max-quote-age", type: "MAX_QUOTE_AGE_SECONDS", value: 120, onViolation: "INSUFFICIENT_EVIDENCE" },
      { id: "max-slippage", type: "MAX_SLIPPAGE_BPS", value: "25", onViolation: "REVIEW" },
      { id: "human-auth", type: "HUMAN_AUTHORIZATION_REQUIRED", value: true, onViolation: "REQUIRE_AUTHORIZATION" },
    ],
  });
  assert.equal(policy.immutable, true);

  const policyResult = PolicyResultSchema.parse({
    schemaVersion: "1.0.0",
    id: "policy_result_schema_001",
    intentId: "int_schema_001",
    intentRevision: 1,
    policyRef: { id: policy.id, version: policy.version },
    policyVersion: policy.version,
    policyDigest: HASH_C,
    evidenceRoot: HASH_B,
    evidenceRefs: [evidence.id],
    decision: "REVIEW_REQUIRED",
    status: "WARN",
    blockers: [],
    warnings: ["SLIPPAGE_ABOVE_SOFT_LIMIT"],
    evaluatedAt: "2026-08-06T12:00:00.000Z",
  });
  assert.equal(policyResult.decision, "REVIEW_REQUIRED");
  assert.equal(
    PolicyResultSchema.safeParse({ ...policyResult, policyVersion: 2 }).success,
    false,
    "policy result version must agree with the bound policy reference",
  );

  const fingerprint = ExecutionFingerprintSchema.parse({
    schemaVersion: "1.0.0",
    intentId: "int_schema_001",
    intentRevision: 1,
    chainRef: "eip155:5042002",
    walletAddress: WALLET,
    target: "0x2222222222222222222222222222222222222222",
    calldataHash: HASH_A,
    nativeValue: "0",
    sellAssetRef: USDC,
    buyAssetRef: EURC,
    amount: "10.00",
    leverage: null,
    recipient: WALLET,
    venueRef: "circle-app-kit",
    routeRef: "circle-app-kit:swap",
    quoteHash: HASH_B,
    maxFee: "0.02",
    minimumOutput: "9.93",
    expiresAt: "2026-08-06T12:01:30.000Z",
  });
  assert.equal(fingerprint.leverage, null);

  const authorization = HumanAuthorizationSchema.parse({
    schemaVersion: "1.0.0",
    id: "auth_schema_001",
    tenantId: "tenant_demo",
    intentId: fingerprint.intentId,
    intentRevision: 1,
    evaluationId: "eval_schema_001",
    intentHash: HASH_A,
    evidenceRoot: HASH_B,
    policyHash: HASH_C,
    policyVersion: 1,
    policyDigest: HASH_C,
    preflightHash: HASH_A,
    executionFingerprintHash: HASH_A,
    materialWarningsShown: ["SLIPPAGE_ABOVE_SOFT_LIMIT"],
    subjectRef: "subject:demo",
    method: "PARTNER_AUTHENTICATED",
    decision: "APPROVED",
    createdAt: "2026-08-06T12:00:00.000Z",
    expiresAt: "2026-08-06T12:01:30.000Z",
    signatureRef: null,
  });
  assert.equal(authorization.method, "PARTNER_AUTHENTICATED");
  const authorizationWithoutPolicyVersion = { ...authorization };
  delete authorizationWithoutPolicyVersion.policyVersion;
  assert.equal(HumanAuthorizationSchema.safeParse(authorizationWithoutPolicyVersion).success, false);
  assert.equal(
    HumanAuthorizationSchema.safeParse({ ...authorization, policyDigest: HASH_A }).success,
    false,
  );
  assert.equal(
    HumanAuthorizationSchema.safeParse({
      ...authorization,
      method: "EIP712",
      signatureRef: null,
    }).success,
    false,
    "EIP-712 authorization without a signature reference must fail closed",
  );

  const original = ReadinessEnvelopeSchema.parse({
    schemaVersion: "1.0.0",
    id: "env_schema_001",
    tenantId: "tenant_demo",
    intentId: fingerprint.intentId,
    intentRevision: 1,
    version: 1,
    amends: null,
    intentHash: HASH_A,
    instrumentRef: "arc-testnet:stablecoin-fx:usdc-eurc",
    evidenceRoot: HASH_B,
    evidenceRefs: [evidence.id],
    policyRef: { id: policy.id, version: policy.version },
    policyHash: HASH_C,
    policyVersion: policy.version,
    policyDigest: HASH_C,
    preflightHash: HASH_A,
    dataStatus: "COMPLETE",
    evidenceStatus: "COMPLETE",
    outcome: "REVIEW_REQUIRED",
    policyDecision: "REVIEW_REQUIRED",
    policyStatus: "WARN",
    authorizationStatus: "APPROVED",
    executionStatus: "NOT_STARTED",
    riskSignals: [signal],
    warnings: ["SLIPPAGE_ABOVE_SOFT_LIMIT"],
    blockers: [],
    missingEvidence: [],
    humanAuthorizationId: authorization.id,
    expectedOutcome: { amountIn: "10.00", amountOut: "9.96", feeAmount: "0.02" },
    expectedEffects: {
      amountIn: "10.00",
      amountOut: "9.96",
      minimumAmountOut: "9.93",
      feeAmount: "0.02",
      totalDebit: "10.02",
    },
    executionReference: null,
    actualOutcome: null,
    actualEffects: null,
    reconciliationStatus: "NOT_RECONCILED",
    settlementState: "NOT_STARTED",
    recoveryState: "NOT_REQUIRED",
    receiptHash: null,
    createdAt: "2026-08-06T12:00:00.000Z",
    finalizedAt: null,
    limitations: ["ARC_TESTNET", "HACKATHON_PROTOTYPE", "NOT_AUDITED"],
  });

  const amended = amendReadinessEnvelope(original, {
    id: "env_schema_002",
    executionStatus: "CONFIRMED",
    executionReference: {
      transactionHash: `0x${"12".repeat(32)}`,
      explorerUrl: `https://testnet.arcscan.app/tx/0x${"12".repeat(32)}`,
    },
    actualOutcome: { amountIn: "10.00", amountOut: "9.95", feeAmount: "0.02" },
    actualEffects: {
      amountIn: "10.00",
      amountOut: "9.95",
      feeAmount: "0.02",
    },
    reconciliationStatus: "MATCHED",
    settlementState: "CONFIRMED",
    finalizedAt: "2026-08-06T12:02:00.000Z",
    receiptHash: HASH_B,
  });

  assert.equal(original.version, 1);
  assert.equal(original.executionStatus, "NOT_STARTED");
  assert.equal(original.finalizedAt, null);
  assert.equal(amended.version, 2);
  assert.equal(amended.amends, original.id);
  assert.equal(amended.executionStatus, "CONFIRMED");
  assert.equal(amended.evidenceStatus, "COMPLETE");
  assert.equal(amended.policyDecision, "REVIEW_REQUIRED");
  assert.equal(amended.reconciliationStatus, "MATCHED");
  assert.equal(amended.receiptHash, HASH_B);
  assert.equal(EvidenceReceiptSchema.safeParse(amended).success, true);
  assert.equal(
    EvidenceReceiptSchema.safeParse({
      ...amended,
      executionStatus: "SUBMITTED",
      finalizedAt: null,
    }).success,
    false,
  );
});
