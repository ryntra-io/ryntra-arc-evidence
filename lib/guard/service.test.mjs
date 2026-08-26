// Run from repo root: node --test lib/guard/service.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";

const NOW = "2026-08-06T12:00:00.000Z";
const WALLET = "0x1111111111111111111111111111111111111111";
const USDC = "eip155:5042002/erc20:0x3600000000000000000000000000000000000000";
const EURC = "eip155:5042002/erc20:0x89b50855aa3be2f677cd6303cec089b5f319d72a";
const TX_HASH = `0x${"de".repeat(32)}`;

const intent = {
  schemaVersion: "1.0.0",
  id: "int_arc_demo_001",
  tenantId: "tenant_demo",
  applicationId: "partner_arc_app",
  externalPartnerId: "partner-order-001",
  subjectRef: "subject:demo",
  walletAddress: WALLET,
  walletType: "EOA",
  chainRef: "eip155:5042002",
  environment: "ARC_TESTNET",
  actionType: "SWAP",
  instrumentRef: "arc-testnet:stablecoin-fx:usdc-eurc",
  sellAssetRef: USDC,
  buyAssetRef: EURC,
  amount: "10.00",
  amountType: "EXACT_INPUT",
  recipient: WALLET,
  venueRef: "circle-app-kit",
  routeRef: "circle-app-kit:swap",
  quoteRef: "quote_arc_001",
  target: "0x2222222222222222222222222222222222222222",
  calldataHash: `0x${"ab".repeat(32)}`,
  nativeValue: "0",
  portfolioSnapshotRef: null,
  policyRef: { id: "demo-stablecoin-policy", version: 1 },
  createdAt: "2026-08-06T11:59:00.000Z",
  expiresAt: "2026-08-06T12:02:00.000Z",
  revision: 1,
  idempotencyKey: "idem-intent-001",
};

const quote = {
  schemaVersion: "1.0.0",
  id: "ev_quote_001",
  provider: "Circle App Kit",
  sourceRef: "circle-app-kit:estimateSwap",
  adapter: "circle-app-kit",
  adapterVersion: "current-official-contract",
  sourceType: "SWAP_QUOTE",
  observedAt: "2026-08-06T11:59:30.000Z",
  receivedAt: "2026-08-06T11:59:31.000Z",
  validUntil: "2026-08-06T12:01:30.000Z",
  confidence: "PROVIDER_REPORTED",
  coverage: {
    subjectRefs: ["eip155:5042002", USDC, EURC],
    fields: ["amountIn", "expectedAmountOut", "minimumAmountOut", "fees"],
    limitations: ["UNDERLYING_ROUTE_UNAVAILABLE"],
  },
  availability: "AVAILABLE",
  verificationStatus: "PROVIDER_REPORTED",
  chainRef: "eip155:5042002",
  blockRef: null,
  transactionRef: null,
  status: "VALID",
  requestHash: `0x${"01".repeat(32)}`,
  responseHash: `0x${"02".repeat(32)}`,
  responseDigest: `0x${"02".repeat(32)}`,
  reason: null,
  transformationVersion: "arc-swap-quote-v1",
  fallbackUsed: false,
  facts: {
    quoteRef: "quote_arc_001",
    providerRef: "circle-app-kit",
    venueRef: "circle-app-kit",
    routeRef: "circle-app-kit:swap",
    sellAssetRef: USDC,
    buyAssetRef: EURC,
    amountIn: "10.00",
    recipientAddress: WALLET,
    leverage: null,
    expectedAmountOut: "9.96",
    minimumAmountOut: "9.94",
    feeAmount: "0.02",
    feeAssetRef: USDC,
    totalDebit: "10.02",
    slippageBps: "20",
  },
};

const policy = {
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
};

async function loadService() {
  try {
    return await import("./service.ts");
  } catch (error) {
    assert.fail(`Guard service is missing: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function createEvaluation(service, tenantId, suffix, overrides = {}) {
  const { buildExecutionFingerprint } = await loadService();
  const scopedIntent = {
    ...intent,
    ...overrides,
    id: `int_${suffix}`,
    tenantId,
    externalPartnerId: `partner-order-${suffix}`,
    idempotencyKey: `idem-${suffix}`,
  };
  await service.createIntent({
    tenantId,
    intent: scopedIntent,
    idempotencyKey: `create-${suffix}`,
  });
  const evaluation = await service.preflight({
    tenantId,
    intentId: scopedIntent.id,
    evidence: [quote],
    policy,
    idempotencyKey: `preflight-${suffix}`,
  });
  return {
    intent: scopedIntent,
    evaluation,
    fingerprint: buildExecutionFingerprint({ intent: scopedIntent, quote }),
  };
}

async function createAuthorizedExecution(service, tenantId, suffix, transactionHash = TX_HASH) {
  const lifecycle = await createEvaluation(service, tenantId, suffix);
  const authorization = await service.authorize({
    tenantId,
    intentId: lifecycle.intent.id,
    evaluationId: lifecycle.evaluation.id,
    fingerprint: lifecycle.fingerprint,
    subjectRef: lifecycle.intent.subjectRef,
    method: "PARTNER_AUTHENTICATED",
    idempotencyKey: `authorize-${suffix}`,
  });
  const execution = await service.recordExecution({
    tenantId,
    intentId: lifecycle.intent.id,
    authorizationId: authorization.id,
    fingerprint: lifecycle.fingerprint,
    transactionHash,
    idempotencyKey: `execute-${suffix}`,
  });
  return { ...lifecycle, authorization, execution };
}

test("preflight rejects a policy that does not exactly match the intent policyRef", async () => {
  const { createGuardService, isGuardError } = await loadService();
  const service = createGuardService({ now: () => NOW, createId: (prefix) => `${prefix}_policy` });
  const mismatchedIntent = {
    ...intent,
    id: "int_policy_mismatch",
    policyRef: { id: "client-selected-policy", version: 99 },
  };
  await service.createIntent({
    tenantId: mismatchedIntent.tenantId,
    intent: mismatchedIntent,
    idempotencyKey: "create-policy-mismatch",
  });
  await assert.rejects(
    () => service.preflight({
      tenantId: mismatchedIntent.tenantId,
      intentId: mismatchedIntent.id,
      evidence: [quote],
      policy,
      idempotencyKey: "preflight-policy-mismatch",
    }),
    (error) => isGuardError(error, "FINGERPRINT_MISMATCH"),
  );
});

test("SEND preflight selects its transfer plan even when unrelated swap evidence comes first", async () => {
  const { createGuardService } = await loadService();
  const service = createGuardService({ now: () => NOW, createId: (prefix) => `${prefix}_send_plan` });
  const transferIntent = {
    ...intent,
    id: "int_send_plan",
    actionType: "SEND",
    buyAssetRef: USDC,
    venueRef: "arc-testnet-eoa",
    routeRef: "arc-usdc-erc20:eoa-transfer",
    quoteRef: "transfer_plan_001",
  };
  const transferPolicy = {
    ...policy,
    rules: policy.rules.map((rule) =>
      rule.type === "ALLOWED_PAIR" ? { ...rule, value: [USDC, USDC] } : rule,
    ),
  };
  const transferPlan = {
    ...quote,
    id: "ev_transfer_plan_001",
    sourceType: "TRANSFER_PLAN",
    responseHash: `0x${"03".repeat(32)}`,
    responseDigest: `0x${"03".repeat(32)}`,
    facts: {
      ...quote.facts,
      quoteRef: transferIntent.quoteRef,
      venueRef: transferIntent.venueRef,
      routeRef: transferIntent.routeRef,
      buyAssetRef: USDC,
      expectedAmountOut: "10.00",
      minimumAmountOut: "10.00",
      feeAmount: "0.01",
      totalDebit: "10.01",
      slippageBps: "0",
      tokenAddress: transferIntent.target,
      calldataHash: transferIntent.calldataHash,
    },
  };
  await service.createIntent({
    tenantId: transferIntent.tenantId,
    intent: transferIntent,
    idempotencyKey: "create-send-plan",
  });
  const evaluation = await service.preflight({
    tenantId: transferIntent.tenantId,
    intentId: transferIntent.id,
    evidence: [quote, transferPlan],
    policy: transferPolicy,
    idempotencyKey: "preflight-send-plan",
  });
  assert.equal(evaluation.outcome, "ALLOWED_BY_POLICY");
  assert.equal(evaluation.expiresAt, transferPlan.validUntil);
  assert.deepEqual(evaluation.expectedEffects, {
    amountIn: "10.00",
    amountOut: "10.00",
    minimumAmountOut: "10.00",
    feeAmount: "0.01",
    totalDebit: "10.01",
  });
});

test("policy quote freshness caps preflight, authorization and execution at the same instant", async () => {
  const { buildExecutionFingerprint, createGuardService, isGuardError } = await loadService();
  let clock = NOW;
  let idCounter = 0;
  const service = createGuardService({
    now: () => clock,
    createId: (prefix) => `${prefix}_freshness_${++idCounter}`,
  });
  const shortFreshnessPolicy = {
    ...policy,
    rules: policy.rules.map((rule) =>
      rule.type === "MAX_QUOTE_AGE_SECONDS" ? { ...rule, value: 60 } : rule,
    ),
  };
  const freshnessExpiresAt = "2026-08-06T12:00:30.000Z";

  async function createFreshnessLifecycle(tenantId, suffix) {
    const scopedIntent = {
      ...intent,
      id: `int_freshness_${suffix}`,
      tenantId,
      externalPartnerId: `partner-freshness-${suffix}`,
      idempotencyKey: `intent-freshness-${suffix}`,
    };
    await service.createIntent({
      tenantId,
      intent: scopedIntent,
      idempotencyKey: `create-freshness-${suffix}`,
    });
    const evaluation = await service.preflight({
      tenantId,
      intentId: scopedIntent.id,
      evidence: [quote],
      policy: shortFreshnessPolicy,
      idempotencyKey: `preflight-freshness-${suffix}`,
    });
    return {
      intent: scopedIntent,
      evaluation,
      fingerprint: buildExecutionFingerprint({ intent: scopedIntent, quote }),
    };
  }

  const authorizeBoundary = await createFreshnessLifecycle(
    "tenant_freshness_authorize",
    "authorize",
  );
  assert.equal(authorizeBoundary.evaluation.expiresAt, freshnessExpiresAt);
  clock = freshnessExpiresAt;
  await assert.rejects(
    () =>
      service.authorize({
        tenantId: "tenant_freshness_authorize",
        intentId: authorizeBoundary.intent.id,
        evaluationId: authorizeBoundary.evaluation.id,
        fingerprint: authorizeBoundary.fingerprint,
        subjectRef: authorizeBoundary.intent.subjectRef,
        method: "PARTNER_AUTHENTICATED",
        idempotencyKey: "authorize-freshness-at-boundary",
      }),
    (error) => isGuardError(error, "EVALUATION_EXPIRED"),
  );

  clock = NOW;
  const executionBoundary = await createFreshnessLifecycle(
    "tenant_freshness_execution",
    "execution",
  );
  clock = "2026-08-06T12:00:29.999Z";
  const authorization = await service.authorize({
    tenantId: "tenant_freshness_execution",
    intentId: executionBoundary.intent.id,
    evaluationId: executionBoundary.evaluation.id,
    fingerprint: executionBoundary.fingerprint,
    subjectRef: executionBoundary.intent.subjectRef,
    method: "PARTNER_AUTHENTICATED",
    idempotencyKey: "authorize-freshness-before-boundary",
  });
  assert.equal(authorization.expiresAt, freshnessExpiresAt);

  clock = freshnessExpiresAt;
  await assert.rejects(
    () =>
      service.recordExecution({
        tenantId: "tenant_freshness_execution",
        intentId: executionBoundary.intent.id,
        authorizationId: authorization.id,
        fingerprint: executionBoundary.fingerprint,
        transactionHash: TX_HASH,
        idempotencyKey: "execute-freshness-at-boundary",
      }),
    (error) => isGuardError(error, "AUTHORIZATION_EXPIRED"),
  );
  assert.equal(
    await service.store.collection("executions").has(
      `tenant_freshness_execution:${executionBoundary.intent.id}`,
    ),
    false,
  );
});

test("authorization fails closed for unknown, malformed, tampered and non-positive stored evaluations", async () => {
  const { createGuardService, hashCanonical, isGuardError } = await loadService();
  let idCounter = 0;
  const service = createGuardService({
    now: () => NOW,
    createId: (prefix) => `${prefix}_stored_evaluation_${++idCounter}`,
  });
  const evaluations = service.store.collection("evaluations");

  function withIntegrity(value) {
    const { _integrity: _discarded, ...payload } = structuredClone(value);
    return {
      ...payload,
      _integrity: {
        algorithm: "SHA-256",
        hash: hashCanonical(payload),
      },
    };
  }

  const cases = [
    {
      name: "unknown-outcome",
      expectedCode: "RECOVERY_REQUIRED",
      mutate(value) {
        return withIntegrity({ ...value, outcome: "UNKNOWN_ALLOWED_STATE" });
      },
    },
    {
      name: "missing-preflight-hash",
      expectedCode: "RECOVERY_REQUIRED",
      mutate(value) {
        const { preflightHash: _discarded, ...malformed } = value;
        return withIntegrity(malformed);
      },
    },
    {
      name: "integrity-mismatch",
      expectedCode: "RECOVERY_REQUIRED",
      mutate(value) {
        const sealed = withIntegrity(value);
        return { ...sealed, evidenceRoot: `0x${"ff".repeat(32)}` };
      },
    },
    {
      name: "missing-financial-fact",
      expectedCode: "RECOVERY_REQUIRED",
      mutate(value) {
        const changedEvidence = structuredClone(value._evidence);
        delete changedEvidence[0].facts.feeAssetRef;
        const evidenceRoot = hashCanonical(changedEvidence);
        return withIntegrity({
          ...value,
          evidenceRoot,
          policyResult: { ...value.policyResult, evidenceRoot },
          _evidence: changedEvidence,
        });
      },
    },
    {
      name: "review-required",
      expectedCode: "POLICY_BLOCKED",
      mutate(value) {
        return withIntegrity({
          ...value,
          outcome: "REVIEW_REQUIRED",
          policyDecision: "REVIEW_REQUIRED",
          policyStatus: "WARN",
          policyResult: {
            ...value.policyResult,
            decision: "REVIEW_REQUIRED",
            status: "WARN",
            warnings: ["MAX_SLIPPAGE_BPS"],
          },
        });
      },
    },
  ];

  for (const scenario of cases) {
    const tenantId = `tenant_${scenario.name}`;
    const lifecycle = await createEvaluation(service, tenantId, scenario.name);
    const evaluationKey = `${tenantId}:${lifecycle.evaluation.id}`;
    const stored = await evaluations.get(evaluationKey);
    assert.ok(stored);
    await evaluations.set(evaluationKey, scenario.mutate(stored));

    await assert.rejects(
      () =>
        service.authorize({
          tenantId,
          intentId: lifecycle.intent.id,
          evaluationId: lifecycle.evaluation.id,
          fingerprint: lifecycle.fingerprint,
          subjectRef: lifecycle.intent.subjectRef,
          method: "PARTNER_AUTHENTICATED",
          idempotencyKey: `authorize-${scenario.name}`,
        }),
      (error) => isGuardError(error, scenario.expectedCode),
      scenario.name,
    );
  }
});

test("authorization and execution recording reject same-revision persisted intent drift", async () => {
  const { buildExecutionFingerprint, createGuardService, isGuardError } = await loadService();
  let idCounter = 0;
  const service = createGuardService({
    now: () => NOW,
    createId: (prefix) => `${prefix}_intent_drift_${++idCounter}`,
  });
  const intents = service.store.collection("intents");

  const beforeAuthorization = await createEvaluation(
    service,
    "tenant_intent_drift_authorize",
    "intent_drift_authorize",
  );
  const authorizationIntentKey =
    `tenant_intent_drift_authorize:${beforeAuthorization.intent.id}`;
  const storedBeforeAuthorization = await intents.get(authorizationIntentKey);
  assert.ok(storedBeforeAuthorization);
  const authorizationDrift = {
    ...storedBeforeAuthorization,
    target: "0x3333333333333333333333333333333333333333",
    calldataHash: `0x${"cd".repeat(32)}`,
  };
  assert.equal(authorizationDrift.id, storedBeforeAuthorization.id);
  assert.equal(authorizationDrift.revision, storedBeforeAuthorization.revision);
  await intents.set(authorizationIntentKey, authorizationDrift);

  await assert.rejects(
    () =>
      service.authorize({
        tenantId: "tenant_intent_drift_authorize",
        intentId: beforeAuthorization.intent.id,
        evaluationId: beforeAuthorization.evaluation.id,
        fingerprint: buildExecutionFingerprint({ intent: authorizationDrift, quote }),
        subjectRef: beforeAuthorization.intent.subjectRef,
        method: "PARTNER_AUTHENTICATED",
        idempotencyKey: "authorize-intent-drift",
      }),
    (error) => isGuardError(error, "RECOVERY_REQUIRED"),
  );
  assert.equal(
    (await service.store.collection("authorizations").valuesWithPrefix(
      "tenant_intent_drift_authorize:",
    )).length,
    0,
  );

  const beforeExecution = await createEvaluation(
    service,
    "tenant_intent_drift_execute",
    "intent_drift_execute",
  );
  const authorization = await service.authorize({
    tenantId: "tenant_intent_drift_execute",
    intentId: beforeExecution.intent.id,
    evaluationId: beforeExecution.evaluation.id,
    fingerprint: beforeExecution.fingerprint,
    subjectRef: beforeExecution.intent.subjectRef,
    method: "PARTNER_AUTHENTICATED",
    idempotencyKey: "authorize-before-intent-drift",
  });
  const executionIntentKey = `tenant_intent_drift_execute:${beforeExecution.intent.id}`;
  const storedBeforeExecution = await intents.get(executionIntentKey);
  assert.ok(storedBeforeExecution);
  const executionDrift = {
    ...storedBeforeExecution,
    target: "0x4444444444444444444444444444444444444444",
    calldataHash: `0x${"ef".repeat(32)}`,
  };
  assert.equal(executionDrift.id, storedBeforeExecution.id);
  assert.equal(executionDrift.revision, storedBeforeExecution.revision);
  await intents.set(executionIntentKey, executionDrift);

  await assert.rejects(
    () =>
      service.authorize({
        tenantId: "tenant_intent_drift_execute",
        intentId: beforeExecution.intent.id,
        evaluationId: beforeExecution.evaluation.id,
        fingerprint: beforeExecution.fingerprint,
        subjectRef: beforeExecution.intent.subjectRef,
        method: "PARTNER_AUTHENTICATED",
        idempotencyKey: "authorize-before-intent-drift",
      }),
    (error) => isGuardError(error, "RECOVERY_REQUIRED"),
  );

  await assert.rejects(
    () =>
      service.recordExecution({
        tenantId: "tenant_intent_drift_execute",
        intentId: beforeExecution.intent.id,
        authorizationId: authorization.id,
        fingerprint: beforeExecution.fingerprint,
        transactionHash: `0x${"ac".repeat(32)}`,
        idempotencyKey: "execute-after-intent-drift",
      }),
    (error) => isGuardError(error, "RECOVERY_REQUIRED"),
  );
  assert.equal(
    await service.store.collection("executions").has(executionIntentKey),
    false,
  );
});

test("execution recording recomputes the authorized fingerprint from sealed evidence", async () => {
  const { buildExecutionFingerprint, createGuardService, hashCanonical, isGuardError } =
    await loadService();
  let idCounter = 0;
  const service = createGuardService({
    now: () => NOW,
    createId: (prefix) => `${prefix}_authorization_fingerprint_${++idCounter}`,
  });
  const lifecycle = await createEvaluation(
    service,
    "tenant_authorization_fingerprint",
    "authorization_fingerprint",
  );
  const authorization = await service.authorize({
    tenantId: "tenant_authorization_fingerprint",
    intentId: lifecycle.intent.id,
    evaluationId: lifecycle.evaluation.id,
    fingerprint: lifecycle.fingerprint,
    subjectRef: lifecycle.intent.subjectRef,
    method: "PARTNER_AUTHENTICATED",
    idempotencyKey: "authorize-fingerprint-control",
  });
  const maliciousFingerprint = buildExecutionFingerprint({
    intent: {
      ...lifecycle.intent,
      target: "0x5555555555555555555555555555555555555555",
      calldataHash: `0x${"aa".repeat(32)}`,
    },
    quote,
  });
  const authorizations = service.store.collection("authorizations");
  const authorizationKey = `tenant_authorization_fingerprint:${authorization.id}`;
  const storedAuthorization = await authorizations.get(authorizationKey);
  assert.ok(storedAuthorization);
  await authorizations.set(authorizationKey, {
    ...storedAuthorization,
    executionFingerprintHash: hashCanonical(maliciousFingerprint),
  });

  await assert.rejects(
    () =>
      service.recordExecution({
        tenantId: "tenant_authorization_fingerprint",
        intentId: lifecycle.intent.id,
        authorizationId: authorization.id,
        fingerprint: maliciousFingerprint,
        transactionHash: `0x${"ad".repeat(32)}`,
        idempotencyKey: "execute-tampered-authorization-fingerprint",
      }),
    (error) => isGuardError(error, "RECOVERY_REQUIRED"),
  );
  assert.equal(
    await service.store.collection("executions").has(
      `tenant_authorization_fingerprint:${lifecycle.intent.id}`,
    ),
    false,
  );
});

test("authorization integrity rejects persisted creation and expiry drift", async () => {
  const { createGuardService, isGuardError } = await loadService();
  let clock = NOW;
  let idCounter = 0;
  const service = createGuardService({
    now: () => clock,
    createId: (prefix) => `${prefix}_authorization_time_${++idCounter}`,
  });
  const authorizations = service.store.collection("authorizations");

  const beforeRecord = await createEvaluation(
    service,
    "tenant_authorization_expiry_drift",
    "authorization_expiry_drift",
  );
  const recordAuthorization = await service.authorize({
    tenantId: "tenant_authorization_expiry_drift",
    intentId: beforeRecord.intent.id,
    evaluationId: beforeRecord.evaluation.id,
    fingerprint: beforeRecord.fingerprint,
    subjectRef: beforeRecord.intent.subjectRef,
    method: "PARTNER_AUTHENTICATED",
    idempotencyKey: "authorize-before-expiry-drift",
  });
  const recordAuthorizationKey =
    `tenant_authorization_expiry_drift:${recordAuthorization.id}`;
  const storedRecordAuthorization = await authorizations.get(recordAuthorizationKey);
  assert.ok(storedRecordAuthorization);
  await authorizations.set(recordAuthorizationKey, {
    ...storedRecordAuthorization,
    expiresAt: "2026-08-06T13:00:00.000Z",
  });
  clock = quote.validUntil;
  await assert.rejects(
    () =>
      service.recordExecution({
        tenantId: "tenant_authorization_expiry_drift",
        intentId: beforeRecord.intent.id,
        authorizationId: recordAuthorization.id,
        fingerprint: beforeRecord.fingerprint,
        transactionHash: `0x${"af".repeat(32)}`,
        idempotencyKey: "execute-after-expiry-drift",
      }),
    (error) => isGuardError(error, "RECOVERY_REQUIRED"),
  );

  clock = NOW;
  const reconciliationHash = `0x${"b0".repeat(32)}`;
  const beforeReconciliation = await createAuthorizedExecution(
    service,
    "tenant_authorization_created_drift",
    "authorization_created_drift",
    reconciliationHash,
  );
  const reconciliationAuthorizationKey =
    `tenant_authorization_created_drift:${beforeReconciliation.authorization.id}`;
  const storedReconciliationAuthorization = await authorizations.get(
    reconciliationAuthorizationKey,
  );
  assert.ok(storedReconciliationAuthorization);
  await authorizations.set(reconciliationAuthorizationKey, {
    ...storedReconciliationAuthorization,
    createdAt: "2026-08-06T11:00:00.000Z",
  });
  await assert.rejects(
    () =>
      service.reconcileExecution({
        tenantId: "tenant_authorization_created_drift",
        intentId: beforeReconciliation.intent.id,
        transactionHash: reconciliationHash,
        observedState: "CONFIRMED",
        actualOutcome: {
          amountIn: "10.00",
          amountOut: "9.95",
          feeAmount: "0.02",
          explorerUrl: `https://testnet.arcscan.app/tx/${reconciliationHash}`,
        },
        reconciliationEvidence: {
          provider: "Arc RPC",
          sourceRef: `arc-rpc:${reconciliationHash}`,
          verificationStatus: "ONCHAIN_VERIFIED",
          observedAt: NOW,
          responseDigest: `0x${"cf".repeat(32)}`,
        },
        idempotencyKey: "reconcile-after-created-drift",
      }),
    (error) => isGuardError(error, "RECOVERY_REQUIRED"),
  );
  assert.equal(
    await service.store.collection("receipts").has(
      `tenant_authorization_created_drift:${beforeReconciliation.intent.id}`,
    ),
    false,
  );
});

test("reconciliation create and recovery reject same-revision persisted intent drift", async () => {
  const { createGuardService, isGuardError } = await loadService();
  let idCounter = 0;
  const service = createGuardService({
    now: () => NOW,
    createId: (prefix) => `${prefix}_reconcile_intent_drift_${++idCounter}`,
  });
  const intents = service.store.collection("intents");
  const executions = service.store.collection("executions");
  const receipts = service.store.collection("receipts");
  const outcome = {
    amountIn: "10.00",
    amountOut: "9.95",
    feeAmount: "0.02",
    explorerUrl: `https://testnet.arcscan.app/tx/${TX_HASH}`,
  };
  const evidence = {
    provider: "Arc RPC",
    sourceRef: `arc-rpc:${TX_HASH}`,
    verificationStatus: "ONCHAIN_VERIFIED",
    observedAt: NOW,
    responseDigest: `0x${"ce".repeat(32)}`,
  };

  const pending = await createAuthorizedExecution(
    service,
    "tenant_reconcile_intent_drift",
    "reconcile_intent_drift",
  );
  const pendingKey = `tenant_reconcile_intent_drift:${pending.intent.id}`;
  const storedPendingIntent = await intents.get(pendingKey);
  assert.ok(storedPendingIntent);
  await intents.set(pendingKey, {
    ...storedPendingIntent,
    target: "0x6666666666666666666666666666666666666666",
    calldataHash: `0x${"bc".repeat(32)}`,
  });

  await assert.rejects(
    () =>
      service.reconcileExecution({
        tenantId: "tenant_reconcile_intent_drift",
        intentId: pending.intent.id,
        transactionHash: TX_HASH,
        observedState: "RPC_UNCERTAIN_AFTER_BROADCAST",
        idempotencyKey: "reconcile-uncertain-after-intent-drift",
      }),
    (error) => isGuardError(error, "RECOVERY_REQUIRED"),
  );
  await assert.rejects(
    () =>
      service.reconcileExecution({
        tenantId: "tenant_reconcile_intent_drift",
        intentId: pending.intent.id,
        transactionHash: TX_HASH,
        observedState: "CONFIRMED",
        actualOutcome: outcome,
        reconciliationEvidence: evidence,
        idempotencyKey: "reconcile-confirmed-after-intent-drift",
      }),
    (error) => isGuardError(error, "RECOVERY_REQUIRED"),
  );
  assert.equal((await executions.get(pendingKey)).status, "SUBMITTED");
  assert.equal(await receipts.has(pendingKey), false);

  const finalizedHash = `0x${"ae".repeat(32)}`;
  const finalized = await createAuthorizedExecution(
    service,
    "tenant_reconcile_recovery_drift",
    "reconcile_recovery_drift",
    finalizedHash,
  );
  const finalizedOutcome = {
    ...outcome,
    explorerUrl: `https://testnet.arcscan.app/tx/${finalizedHash}`,
  };
  const finalizedEvidence = {
    ...evidence,
    sourceRef: `arc-rpc:${finalizedHash}`,
  };
  const finalizedRequest = {
    tenantId: "tenant_reconcile_recovery_drift",
    intentId: finalized.intent.id,
    transactionHash: finalizedHash,
    observedState: "CONFIRMED",
    actualOutcome: finalizedOutcome,
    reconciliationEvidence: finalizedEvidence,
    idempotencyKey: "reconcile-before-recovery-drift",
  };
  await service.reconcileExecution(finalizedRequest);
  const finalizedKey = `tenant_reconcile_recovery_drift:${finalized.intent.id}`;
  const storedFinalizedIntent = await intents.get(finalizedKey);
  assert.ok(storedFinalizedIntent);
  await intents.set(finalizedKey, {
    ...storedFinalizedIntent,
    target: "0x7777777777777777777777777777777777777777",
    calldataHash: `0x${"bd".repeat(32)}`,
  });
  await assert.rejects(
    () => service.reconcileExecution(finalizedRequest),
    (error) => isGuardError(error, "RECOVERY_REQUIRED"),
  );
});

test("confirmed reconciliation replay uses one deterministic finalization timestamp", async () => {
  const { createGuardService } = await loadService();
  let clockMs = Date.parse(NOW);
  let idCounter = 0;
  const service = createGuardService({
    now: () => new Date(clockMs++).toISOString(),
    createId: (prefix) => `${prefix}_ticking_reconcile_${++idCounter}`,
  });
  const lifecycle = await createAuthorizedExecution(
    service,
    "tenant_ticking_reconcile",
    "ticking_reconcile",
  );
  const request = {
    tenantId: "tenant_ticking_reconcile",
    intentId: lifecycle.intent.id,
    transactionHash: TX_HASH,
    observedState: "CONFIRMED",
    actualOutcome: {
      amountIn: "10.00",
      amountOut: "9.95",
      feeAmount: "0.02",
      explorerUrl: `https://testnet.arcscan.app/tx/${TX_HASH}`,
    },
    reconciliationEvidence: {
      provider: "Arc RPC",
      sourceRef: `arc-rpc:${TX_HASH}`,
      verificationStatus: "ONCHAIN_VERIFIED",
      observedAt: lifecycle.authorization.createdAt,
      responseDigest: `0x${"d0".repeat(32)}`,
    },
    idempotencyKey: "reconcile-ticking-clock",
  };
  const completed = await service.reconcileExecution(request);
  const replay = await service.reconcileExecution(request);
  assert.equal(completed.status, "CONFIRMED");
  assert.equal(replay.status, "CONFIRMED");
  assert.equal(replay.confirmedAt, completed.confirmedAt);
  assert.equal(replay.idempotentReplay, true);
});

test("EIP-712 authorization rejects missing and wrong signatures, then stores only a hash reference", async () => {
  const { buildExecutionFingerprint, createGuardService, isGuardError } = await loadService();
  const {
    arcWalletAuthorizationSignatureRef,
    buildArcWalletAuthorizationChallenge,
  } = await import("./arc-wallet-authorization.ts");
  const { generatePrivateKey, privateKeyToAccount } = await import("viem/accounts");
  const account = privateKeyToAccount(generatePrivateKey());
  const wrongAccount = privateKeyToAccount(generatePrivateKey());
  let idCounter = 0;
  const service = createGuardService({
    now: () => NOW,
    createId: (prefix) => `${prefix}_eip712_${++idCounter}`,
  });
  const tenantId = "tenant_eip712";
  const walletAddress = account.address.toLowerCase();
  const scopedIntent = {
    ...intent,
    id: "int_eip712",
    tenantId,
    subjectRef: `wallet:${walletAddress}`,
    walletAddress,
    recipient: walletAddress,
    externalPartnerId: "partner-order-eip712",
    idempotencyKey: "idem-eip712",
  };
  const scopedQuote = {
    ...quote,
    id: "ev_quote_eip712",
    responseHash: `0x${"12".repeat(32)}`,
    responseDigest: `0x${"12".repeat(32)}`,
    facts: {
      ...quote.facts,
      recipientAddress: walletAddress,
    },
  };
  await service.createIntent({
    tenantId,
    intent: scopedIntent,
    idempotencyKey: "create-eip712",
  });
  const evaluation = await service.preflight({
    tenantId,
    intentId: scopedIntent.id,
    evidence: [scopedQuote],
    policy,
    idempotencyKey: "preflight-eip712",
  });
  const fingerprint = buildExecutionFingerprint({ intent: scopedIntent, quote: scopedQuote });
  const audience = "https://ryntra.example";
  const challenge = buildArcWalletAuthorizationChallenge({
    intentId: scopedIntent.id,
    evaluationId: evaluation.id,
    fingerprint,
    audience,
  });
  const wrongSignature = await wrongAccount.signTypedData(challenge);

  await assert.rejects(
    () => service.authorize({
      tenantId,
      intentId: scopedIntent.id,
      evaluationId: evaluation.id,
      fingerprint,
      subjectRef: scopedIntent.subjectRef,
      method: "EIP712",
      audience,
      idempotencyKey: "authorize-eip712-missing",
    }),
    (error) => isGuardError(error, "HUMAN_AUTHORIZATION_REQUIRED"),
  );
  await assert.rejects(
    () => service.authorize({
      tenantId,
      intentId: scopedIntent.id,
      evaluationId: evaluation.id,
      fingerprint,
      subjectRef: scopedIntent.subjectRef,
      method: "EIP712",
      signature: wrongSignature,
      audience,
      idempotencyKey: "authorize-eip712-wrong-wallet",
    }),
    (error) => isGuardError(error, "FINGERPRINT_MISMATCH"),
  );

  const signature = await account.signTypedData(challenge);
  const authorization = await service.authorize({
    tenantId,
    intentId: scopedIntent.id,
    evaluationId: evaluation.id,
    fingerprint,
    subjectRef: scopedIntent.subjectRef,
    method: "EIP712",
    signature,
    audience,
    idempotencyKey: "authorize-eip712-valid",
  });
  assert.equal(authorization.method, "EIP712");
  assert.equal(authorization.signatureRef, arcWalletAuthorizationSignatureRef(signature));
  assert.match(authorization.signatureRef, /^eip712:0x[0-9a-f]{64}$/);

  const stored = await service.store
    .collection("authorizations")
    .get(`${tenantId}:${authorization.id}`);
  assert.ok(stored);
  assert.equal(stored.signatureRef, authorization.signatureRef);
  assert.equal(JSON.stringify(authorization).includes(signature), false);
  assert.equal(JSON.stringify(stored).includes(signature), false);
  const idempotencyRecord = await service.store
    .collection("idempotency")
    .get(`${tenantId}:intent.authorize:authorize-eip712-valid`);
  assert.ok(idempotencyRecord);
  assert.equal(JSON.stringify(idempotencyRecord).includes(signature), false);
});

test("authorization expiry is enforced at creation and status while finalized history stays approved", async () => {
  const { createGuardService, isGuardError } = await loadService();
  let clock = NOW;
  let idCounter = 0;
  const service = createGuardService({
    now: () => clock,
    createId: (prefix) => `${prefix}_auth_window_${++idCounter}`,
  });

  const crossing = await createEvaluation(service, "tenant_crossing", "crossing");
  clock = quote.validUntil;
  await assert.rejects(
    () => service.authorize({
      tenantId: "tenant_crossing",
      intentId: crossing.intent.id,
      evaluationId: crossing.evaluation.id,
      fingerprint: crossing.fingerprint,
      subjectRef: crossing.intent.subjectRef,
      method: "PARTNER_AUTHENTICATED",
      idempotencyKey: "authorize-crossing-expired",
    }),
    (error) => isGuardError(error, "EVALUATION_EXPIRED"),
  );

  clock = NOW;
  const expiring = await createEvaluation(service, "tenant_expiring", "expiring");
  const expiringAuthorization = await service.authorize({
    tenantId: "tenant_expiring",
    intentId: expiring.intent.id,
    evaluationId: expiring.evaluation.id,
    fingerprint: expiring.fingerprint,
    subjectRef: expiring.intent.subjectRef,
    method: "PARTNER_AUTHENTICATED",
    idempotencyKey: "authorize-expiring",
  });
  assert.equal(expiringAuthorization.decision, "APPROVED");
  clock = quote.validUntil;
  assert.equal(
    (await service.getStatus({ tenantId: "tenant_expiring", intentId: expiring.intent.id }))
      .authorizationStatus,
    "EXPIRED",
  );

  clock = NOW;
  const finalized = await createAuthorizedExecution(service, "tenant_final_history", "final_history");
  await service.reconcileExecution({
    tenantId: "tenant_final_history",
    intentId: finalized.intent.id,
    transactionHash: TX_HASH,
    observedState: "CONFIRMED",
    actualOutcome: {
      amountIn: "10.00",
      amountOut: "9.95",
      feeAmount: "0.02",
      explorerUrl: `https://testnet.arcscan.app/tx/${TX_HASH}`,
    },
    reconciliationEvidence: {
      provider: "Arc RPC",
      sourceRef: `arc-rpc:${TX_HASH}`,
      verificationStatus: "ONCHAIN_VERIFIED",
      observedAt: NOW,
      responseDigest: `0x${"cd".repeat(32)}`,
    },
    idempotencyKey: "reconcile-final-history",
  });
  clock = "2026-08-06T12:03:00.000Z";
  assert.equal(
    (await service.getStatus({
      tenantId: "tenant_final_history",
      intentId: finalized.intent.id,
    })).authorizationStatus,
    "APPROVED",
  );
});

test("reconciliation observation time enforces authorization boundaries at minus, exact and plus one millisecond", async () => {
  const { createGuardService, isGuardError } = await loadService();
  let clock = NOW;
  let idCounter = 0;
  const service = createGuardService({
    now: () => clock,
    createId: (prefix) => `${prefix}_temporal_${++idCounter}`,
  });
  const outcome = {
    amountIn: "10.00",
    amountOut: "9.95",
    feeAmount: "0.02",
    explorerUrl: `https://testnet.arcscan.app/tx/${TX_HASH}`,
  };

  const exact = await createAuthorizedExecution(service, "tenant_temporal_exact", "temporal_exact");
  clock = quote.validUntil;
  const exactResult = await service.reconcileExecution({
    tenantId: "tenant_temporal_exact",
    intentId: exact.intent.id,
    transactionHash: TX_HASH,
    observedState: "CONFIRMED",
    actualOutcome: outcome,
    reconciliationEvidence: {
      provider: "Arc RPC",
      sourceRef: `arc-rpc:${TX_HASH}`,
      verificationStatus: "ONCHAIN_VERIFIED",
      observedAt: quote.validUntil,
      responseDigest: `0x${"cd".repeat(32)}`,
    },
    idempotencyKey: "reconcile-temporal-exact",
  });
  assert.equal(exactResult.status, "CONFIRMED");

  clock = NOW;
  const secondHash = `0x${"ef".repeat(32)}`;
  const rejected = await createAuthorizedExecution(
    service,
    "tenant_temporal_rejected",
    "temporal_rejected",
    secondHash,
  );
  const invalidObservations = [
    {
      name: "before",
      observedAt: new Date(Date.parse(NOW) - 1).toISOString(),
      verificationStatus: "PROVIDER_REPORTED",
      now: NOW,
    },
    {
      name: "future",
      observedAt: new Date(Date.parse(NOW) + 1).toISOString(),
      verificationStatus: "ONCHAIN_VERIFIED",
      now: NOW,
    },
    {
      name: "after-expiry",
      observedAt: new Date(Date.parse(quote.validUntil) + 1).toISOString(),
      verificationStatus: "ONCHAIN_VERIFIED",
      now: new Date(Date.parse(quote.validUntil) + 1).toISOString(),
    },
  ];
  for (const invalid of invalidObservations) {
    clock = invalid.now;
    await assert.rejects(
      () => service.reconcileExecution({
        tenantId: "tenant_temporal_rejected",
        intentId: rejected.intent.id,
        transactionHash: secondHash,
        observedState: "CONFIRMED",
        actualOutcome: { ...outcome, explorerUrl: `https://testnet.arcscan.app/tx/${secondHash}` },
        reconciliationEvidence: {
          provider: "Arc RPC",
          sourceRef: `arc-rpc:${secondHash}`,
          verificationStatus: invalid.verificationStatus,
          observedAt: invalid.observedAt,
          responseDigest: `0x${"ce".repeat(32)}`,
        },
        idempotencyKey: `reconcile-temporal-${invalid.name}`,
      }),
      (error) => isGuardError(error, "FINGERPRINT_MISMATCH"),
      invalid.name,
    );
  }
  assert.equal(
    await service.store.collection("receipts").has(
      `tenant_temporal_rejected:${rejected.intent.id}`,
    ),
    false,
  );

});

test("a transaction hash is globally unique per chain across tenants", async () => {
  const { createGuardService, hashCanonical, isGuardError } = await loadService();
  let idCounter = 0;
  const service = createGuardService({
    now: () => NOW,
    createId: (prefix) => `${prefix}_global_tx_${++idCounter}`,
  });
  const first = await createAuthorizedExecution(service, "tenant_first", "global_first");
  const second = await createEvaluation(service, "tenant_second", "global_second");
  const secondAuthorization = await service.authorize({
    tenantId: "tenant_second",
    intentId: second.intent.id,
    evaluationId: second.evaluation.id,
    fingerprint: second.fingerprint,
    subjectRef: second.intent.subjectRef,
    method: "PARTNER_AUTHENTICATED",
    idempotencyKey: "authorize-global-second",
  });
  assert.equal(first.execution.transactionHash, TX_HASH);
  await assert.rejects(
    () => service.recordExecution({
      tenantId: "tenant_second",
      intentId: second.intent.id,
      authorizationId: secondAuthorization.id,
      fingerprint: second.fingerprint,
      transactionHash: TX_HASH,
      idempotencyKey: "execute-global-second",
    }),
    (error) => isGuardError(error, "IDEMPOTENCY_CONFLICT"),
  );

  /* Even if a stale/buggy writer leaves a loser execution row behind, the
     reconciliation owner check must stop it from minting a second receipt. */
  await service.store.collection("executions").set(`tenant_second:${second.intent.id}`, {
    ...first.execution,
    id: "exec_orphan_loser",
    tenantId: "tenant_second",
    intentId: second.intent.id,
    authorizationId: secondAuthorization.id,
    executionFingerprintHash: hashCanonical(second.fingerprint),
  });
  await assert.rejects(
    () => service.reconcileExecution({
      tenantId: "tenant_second",
      intentId: second.intent.id,
      transactionHash: TX_HASH,
      observedState: "CONFIRMED",
      actualOutcome: {
        amountIn: "10.00",
        amountOut: "9.95",
        feeAmount: "0.02",
        explorerUrl: `https://testnet.arcscan.app/tx/${TX_HASH}`,
      },
      reconciliationEvidence: {
        provider: "Arc RPC",
        sourceRef: `arc-rpc:${TX_HASH}`,
        verificationStatus: "ONCHAIN_VERIFIED",
        observedAt: NOW,
        responseDigest: `0x${"cd".repeat(32)}`,
      },
      idempotencyKey: "reconcile-global-loser",
    }),
    (error) => isGuardError(error, "FINGERPRINT_MISMATCH"),
  );
  assert.equal(
    await service.store.collection("receipts").has(`tenant_second:${second.intent.id}`),
    false,
  );
});

test("a finalized receipt is immutable across new reconciliation keys", async () => {
  const { createGuardService, hashCanonical, isGuardError } = await loadService();
  let idCounter = 0;
  const service = createGuardService({
    now: () => NOW,
    createId: (prefix) => `${prefix}_immutable_${++idCounter}`,
  });
  const lifecycle = await createAuthorizedExecution(service, "tenant_final", "immutable");
  const reconciliationEvidence = {
    provider: "Arc Testnet JSON-RPC",
    sourceRef: `arc-rpc:${TX_HASH}`,
    verificationStatus: "ONCHAIN_VERIFIED",
    observedAt: NOW,
    responseDigest: `0x${"cd".repeat(32)}`,
  };

  const actualOutcome = {
    amountIn: "10.00",
    amountOut: "9.95",
    feeAmount: "0.02",
    explorerUrl: `https://testnet.arcscan.app/tx/${TX_HASH}`,
  };
  await service.reconcileExecution({
    tenantId: "tenant_final",
    intentId: lifecycle.intent.id,
    transactionHash: TX_HASH,
    observedState: "CONFIRMED",
    actualOutcome,
    reconciliationEvidence,
    idempotencyKey: "reconcile-final-first",
  });
  const original = await service.getReceipt({ tenantId: "tenant_final", intentId: lifecycle.intent.id });

  await assert.rejects(
    () => service.reconcileExecution({
      tenantId: "tenant_final",
      intentId: lifecycle.intent.id,
      transactionHash: TX_HASH,
      observedState: "RPC_UNCERTAIN_AFTER_BROADCAST",
      idempotencyKey: "reconcile-final-downgrade",
    }),
    (error) => isGuardError(error, "IDEMPOTENCY_CONFLICT"),
  );
  await assert.rejects(
    () => service.reconcileExecution({
      tenantId: "tenant_final",
      intentId: lifecycle.intent.id,
      transactionHash: TX_HASH,
      observedState: "CONFIRMED",
      actualOutcome: { ...actualOutcome, amountOut: "1.00" },
      reconciliationEvidence,
      idempotencyKey: "reconcile-final-overwrite",
    }),
    (error) => isGuardError(error, "IDEMPOTENCY_CONFLICT"),
  );
  assert.deepEqual(
    await service.getReceipt({ tenantId: "tenant_final", intentId: lifecycle.intent.id }),
    original,
  );
  assert.equal((await service.getStatus({ tenantId: "tenant_final", intentId: lifecycle.intent.id })).executionStatus, "CONFIRMED");

  const tampered = {
    ...original,
    actualEffects: { ...original.actualEffects, amountOut: "1.00" },
  };
  await service.store.collection("receipts").set(
    `tenant_final:${lifecycle.intent.id}`,
    tampered,
  );
  for (const read of [
    () => service.getReceipt({ tenantId: "tenant_final", intentId: lifecycle.intent.id }),
    () => service.getStatus({ tenantId: "tenant_final", intentId: lifecycle.intent.id }),
    () => service.listIntents({ tenantId: "tenant_final" }),
  ]) {
    await assert.rejects(read, (error) => isGuardError(error, "RECOVERY_REQUIRED"));
  }
  const reconciliationRequest = {
    intentId: lifecycle.intent.id,
    transactionHash: TX_HASH,
    observedState: "CONFIRMED",
    actualOutcome,
    reconciliationEvidence,
  };
  await service.store.collection("idempotency").set(
    "tenant_final:intent.reconcile:reconcile-final-first",
    {
      requestHash: hashCanonical(reconciliationRequest),
      inFlight: true,
      startedAt: NOW,
    },
  );
  await assert.rejects(
    () => service.reconcileExecution({
      tenantId: "tenant_final",
      ...reconciliationRequest,
      idempotencyKey: "reconcile-final-first",
    }),
    (error) => isGuardError(error, "RECOVERY_REQUIRED"),
  );
});

test("persisted in-flight money operations recover their original execution and receipt result", async () => {
  const { createGuardService, hashCanonical } = await loadService();
  let idCounter = 0;
  const service = createGuardService({
    now: () => NOW,
    createId: (prefix) => `${prefix}_recovery_${++idCounter}`,
  });
  const tenantId = "tenant_recovery";
  const suffix = "recovery";
  const lifecycle = await createAuthorizedExecution(service, tenantId, suffix, TX_HASH);
  const idempotency = service.store.collection("idempotency");

  const executionRequest = {
    intentId: lifecycle.intent.id,
    authorizationId: lifecycle.authorization.id,
    fingerprint: lifecycle.fingerprint,
    transactionHash: TX_HASH,
  };
  const transactionIndex = service.store.collection("transactionIndex");
  await transactionIndex.delete(`${lifecycle.fingerprint.chainRef}:${TX_HASH}`);
  await transactionIndex.delete(`intent:${tenantId}:${lifecycle.intent.id}`);
  await idempotency.set(`${tenantId}:intent.execute:execute-${suffix}`, {
    requestHash: hashCanonical(executionRequest),
    inFlight: true,
    startedAt: NOW,
  });
  const recoveredExecution = await service.recordExecution({
    tenantId,
    ...executionRequest,
    idempotencyKey: `execute-${suffix}`,
  });
  assert.equal(recoveredExecution.id, lifecycle.execution.id);
  assert.equal(recoveredExecution.idempotentReplay, true);
  assert.equal(
    await transactionIndex.get(`${lifecycle.fingerprint.chainRef}:${TX_HASH}`),
    `${tenantId}:${lifecycle.intent.id}`,
  );
  assert.equal(
    await transactionIndex.get(`intent:${tenantId}:${lifecycle.intent.id}`),
    `${lifecycle.fingerprint.chainRef}:${TX_HASH}`,
  );

  const actualOutcome = {
    amountIn: "10.00",
    amountOut: "9.95",
    feeAmount: "0.02",
    explorerUrl: `https://testnet.arcscan.app/tx/${TX_HASH}`,
  };
  const reconciliationEvidence = {
    provider: "Arc RPC",
    sourceRef: `arc-rpc:${TX_HASH}`,
    verificationStatus: "ONCHAIN_VERIFIED",
    observedAt: NOW,
    responseDigest: `0x${"cd".repeat(32)}`,
  };
  const reconciliationRequest = {
    intentId: lifecycle.intent.id,
    transactionHash: TX_HASH,
    observedState: "CONFIRMED",
    actualOutcome,
    reconciliationEvidence,
  };
  const finalized = await service.reconcileExecution({
    tenantId,
    ...reconciliationRequest,
    idempotencyKey: `reconcile-${suffix}`,
  });
  await idempotency.set(`${tenantId}:intent.reconcile:reconcile-${suffix}`, {
    requestHash: hashCanonical(reconciliationRequest),
    inFlight: true,
    startedAt: NOW,
  });
  const recoveredFinalization = await service.reconcileExecution({
    tenantId,
    ...reconciliationRequest,
    idempotencyKey: `reconcile-${suffix}`,
  });
  assert.equal(recoveredFinalization.id, finalized.id);
  assert.equal(recoveredFinalization.status, "CONFIRMED");
  assert.equal(recoveredFinalization.idempotentReplay, true);
});

test("a tx-claim store failure leaves a non-finalizable row and the same key recovers it", async () => {
  const { createMemoryGuardStore } = await import("./store.ts");
  const { createGuardService, isGuardError } = await loadService();
  const base = createMemoryGuardStore();
  let failTransactionClaims = false;
  const store = {
    ...base,
    collection(name) {
      const collection = base.collection(name);
      if (name !== "transactionIndex") return collection;
      return {
        ...collection,
        async insertAllIfAbsent(entries) {
          if (failTransactionClaims) throw new Error("SIMULATED_TX_CLAIM_STORE_FAILURE");
          return collection.insertAllIfAbsent(entries);
        },
      };
    },
  };
  let idCounter = 0;
  const service = createGuardService({
    now: () => NOW,
    createId: (prefix) => `${prefix}_fault_${++idCounter}`,
    store,
  });
  const tenantId = "tenant_fault_recovery";
  const lifecycle = await createEvaluation(service, tenantId, "fault_recovery");
  const authorization = await service.authorize({
    tenantId,
    intentId: lifecycle.intent.id,
    evaluationId: lifecycle.evaluation.id,
    fingerprint: lifecycle.fingerprint,
    subjectRef: lifecycle.intent.subjectRef,
    method: "PARTNER_AUTHENTICATED",
    idempotencyKey: "authorize-fault-recovery",
  });

  failTransactionClaims = true;
  await assert.rejects(
    () => service.recordExecution({
      tenantId,
      intentId: lifecycle.intent.id,
      authorizationId: authorization.id,
      fingerprint: lifecycle.fingerprint,
      transactionHash: TX_HASH,
      idempotencyKey: "execute-fault-recovery",
    }),
    /SIMULATED_TX_CLAIM_STORE_FAILURE/,
  );
  assert.equal(
    await base.collection("executions").has(`${tenantId}:${lifecycle.intent.id}`),
    true,
  );
  assert.equal(
    await base.collection("transactionIndex").has(`${lifecycle.fingerprint.chainRef}:${TX_HASH}`),
    false,
  );
  await assert.rejects(
    () => service.reconcileExecution({
      tenantId,
      intentId: lifecycle.intent.id,
      transactionHash: TX_HASH,
      observedState: "RPC_UNCERTAIN_AFTER_BROADCAST",
      idempotencyKey: "reconcile-unowned-fault-row",
    }),
    (error) => isGuardError(error, "FINGERPRINT_MISMATCH"),
  );

  failTransactionClaims = false;
  const recovered = await service.recordExecution({
    tenantId,
    intentId: lifecycle.intent.id,
    authorizationId: authorization.id,
    fingerprint: lifecycle.fingerprint,
    transactionHash: TX_HASH,
    idempotencyKey: "execute-fault-recovery",
  });
  assert.equal(recovered.idempotentReplay, true);
  assert.equal(
    await base.collection("transactionIndex").get(`${lifecycle.fingerprint.chainRef}:${TX_HASH}`),
    `${tenantId}:${lifecycle.intent.id}`,
  );
});

test("persisted in-flight intent, preflight and authorization operations recover one result", async () => {
  const { buildExecutionFingerprint, createGuardService, hashCanonical } = await loadService();
  let idCounter = 0;
  const service = createGuardService({
    now: () => NOW,
    createId: (prefix) => `${prefix}_control_recovery_${++idCounter}`,
  });
  const tenantId = "tenant_control_recovery";
  const scopedIntent = {
    ...intent,
    id: "int_control_recovery",
    tenantId,
    externalPartnerId: "partner-control-recovery",
    idempotencyKey: "intent-control-recovery",
  };
  const idempotency = service.store.collection("idempotency");
  const created = await service.createIntent({
    tenantId,
    intent: scopedIntent,
    idempotencyKey: "create-control-recovery",
  });
  const {
    id: _serverAssignedId,
    createdAt: _serverAssignedCreatedAt,
    idempotencyKey: _transportIdempotencyKey,
    ...logicalCreateRequest
  } = scopedIntent;
  await idempotency.set(`${tenantId}:intent.create:create-control-recovery`, {
    requestHash: hashCanonical(logicalCreateRequest),
    inFlight: true,
    startedAt: NOW,
  });
  const recoveredIntent = await service.createIntent({
    tenantId,
    intent: scopedIntent,
    idempotencyKey: "create-control-recovery",
  });
  assert.equal(recoveredIntent.id, created.id);
  assert.equal(recoveredIntent.idempotentReplay, true);

  const preflightRequest = { intentId: scopedIntent.id, evidence: [quote], policy };
  const evaluation = await service.preflight({
    tenantId,
    ...preflightRequest,
    idempotencyKey: "preflight-control-recovery",
  });
  await idempotency.set(`${tenantId}:intent.preflight:preflight-control-recovery`, {
    requestHash: hashCanonical(preflightRequest),
    inFlight: true,
    startedAt: NOW,
  });
  const recoveredEvaluation = await service.preflight({
    tenantId,
    ...preflightRequest,
    idempotencyKey: "preflight-control-recovery",
  });
  assert.equal(recoveredEvaluation.id, evaluation.id);
  assert.equal(recoveredEvaluation.idempotentReplay, true);

  const fingerprint = buildExecutionFingerprint({ intent: scopedIntent, quote });
  const authorizationRequest = {
    intentId: scopedIntent.id,
    evaluationId: evaluation.id,
    fingerprint,
    subjectRef: scopedIntent.subjectRef,
    method: "PARTNER_AUTHENTICATED",
    signature: null,
    audience: null,
  };
  const authorization = await service.authorize({
    tenantId,
    ...authorizationRequest,
    idempotencyKey: "authorize-control-recovery",
  });
  await idempotency.set(`${tenantId}:intent.authorize:authorize-control-recovery`, {
    requestHash: hashCanonical(authorizationRequest),
    inFlight: true,
    startedAt: NOW,
  });
  const recoveredAuthorization = await service.authorize({
    tenantId,
    ...authorizationRequest,
    idempotencyKey: "authorize-control-recovery",
  });
  assert.equal(recoveredAuthorization.id, authorization.id);
  assert.equal(recoveredAuthorization.idempotentReplay, true);
});

test("intent recovery distinguishes identical business payloads by server idempotency identity", async () => {
  const { createGuardService, hashCanonical } = await loadService();
  const service = createGuardService({ now: () => NOW });
  const tenantId = "tenant_identical_intents";
  const firstIntent = {
    ...intent,
    id: "int_identical_first",
    tenantId,
    externalPartnerId: "partner-identical-payload",
    idempotencyKey: "embedded-identical-first",
  };
  const secondIntent = {
    ...firstIntent,
    id: "int_identical_second",
    createdAt: "2026-08-06T11:59:01.000Z",
    idempotencyKey: "embedded-identical-second",
  };
  await service.createIntent({
    tenantId,
    intent: firstIntent,
    idempotencyKey: "transport-identical-first",
  });
  const second = await service.createIntent({
    tenantId,
    intent: secondIntent,
    idempotencyKey: "transport-identical-second",
  });
  const {
    id: _serverAssignedId,
    createdAt: _serverAssignedCreatedAt,
    idempotencyKey: _embeddedIdempotencyKey,
    ...logicalRequest
  } = secondIntent;
  await service.store.collection("idempotency").set(
    `${tenantId}:intent.create:transport-identical-second`,
    {
      requestHash: hashCanonical(logicalRequest),
      inFlight: true,
      startedAt: NOW,
    },
  );

  const recovered = await service.createIntent({
    tenantId,
    intent: {
      ...secondIntent,
      id: "int_identical_retry_random_id",
      createdAt: "2026-08-06T11:59:02.000Z",
    },
    idempotencyKey: "transport-identical-second",
  });
  assert.equal(recovered.id, second.id);
  assert.equal(recovered.idempotentReplay, true);
});

test("a malformed completed idempotency row fails closed instead of replaying an empty success", async () => {
  const { createGuardService, hashCanonical, isGuardError } = await loadService();
  const service = createGuardService({ now: () => NOW, createId: (prefix) => `${prefix}_corrupt` });
  const malformedIntent = {
    ...intent,
    id: "int_corrupt_idempotency",
    tenantId: "tenant_corrupt_idempotency",
  };
  const {
    id: _serverAssignedId,
    createdAt: _serverAssignedCreatedAt,
    idempotencyKey: _transportIdempotencyKey,
    ...logicalCreateRequest
  } = malformedIntent;
  await service.store.collection("idempotency").set(
    "tenant_corrupt_idempotency:intent.create:create-corrupt-idempotency",
    { requestHash: hashCanonical(logicalCreateRequest) },
  );

  await assert.rejects(
    () => service.createIntent({
      tenantId: "tenant_corrupt_idempotency",
      intent: malformedIntent,
      idempotencyKey: "create-corrupt-idempotency",
    }),
    (error) => isGuardError(error, "RECOVERY_REQUIRED"),
  );
  assert.equal(
    await service.store.collection("intents").has(
      "tenant_corrupt_idempotency:int_corrupt_idempotency",
    ),
    false,
  );

  await service.store.collection("idempotency").set(
    "tenant_corrupt_idempotency:intent.create:create-empty-response",
    { requestHash: hashCanonical(logicalCreateRequest), response: {} },
  );
  await assert.rejects(
    () => service.createIntent({
      tenantId: "tenant_corrupt_idempotency",
      intent: malformedIntent,
      idempotencyKey: "create-empty-response",
    }),
    (error) => isGuardError(error, "RECOVERY_REQUIRED"),
  );
});

test("authorization and exact fingerprint bind one execution through uncertainty to a finalized receipt", async () => {
  const {
    DecisionSettlementReceiptSchema,
    HumanAuthorizationSchema,
    PolicyResultSchema,
    verifyIntegrityEnvelope,
  } = await import("./contracts.ts");
  const { buildExecutionFingerprint, createGuardService, hashCanonical, isGuardError } = await loadService();
  let idCounter = 0;
  const service = createGuardService({
    now: () => NOW,
    createId: (prefix) => `${prefix}_test_${++idCounter}`,
  });

  await service.createIntent({ tenantId: "tenant_demo", intent, idempotencyKey: "create-001" });
  const evaluation = await service.preflight({
    tenantId: "tenant_demo",
    intentId: intent.id,
    evidence: [quote],
    policy,
    idempotencyKey: "preflight-001",
  });
  assert.equal(evaluation.evidenceStatus, "COMPLETE");
  assert.equal(evaluation.policyDecision, "ALLOWED_BY_POLICY");
  assert.equal(evaluation.executionStatus, "NOT_STARTED");
  assert.equal(evaluation.policyVersion, 1);
  assert.equal(evaluation.policyDigest, evaluation.policyHash);
  const parsedPolicyResult = PolicyResultSchema.safeParse(evaluation.policyResult);
  assert.equal(
    parsedPolicyResult.success,
    true,
    parsedPolicyResult.success ? undefined : JSON.stringify(parsedPolicyResult.error.issues),
  );
  assert.equal(evaluation.policyResult.policyDigest, evaluation.policyDigest);
  assert.equal(evaluation.policyResult.decision, evaluation.policyDecision);
  assert.equal(evaluation.policyResult.status, evaluation.policyStatus);
  assert.match(evaluation.preflightHash, /^0x[0-9a-f]{64}$/);
  assert.deepEqual(evaluation.expectedEffects, {
    amountIn: "10.00",
    amountOut: "9.96",
    minimumAmountOut: "9.94",
    feeAmount: "0.02",
    totalDebit: "10.02",
  });
  assert.equal(evaluation.actualEffects, null);
  assert.equal(evaluation.reconciliationStatus, "NOT_RECONCILED");
  const fingerprint = buildExecutionFingerprint({ intent, quote });

  await assert.rejects(
    () => service.recordExecution({
        tenantId: "tenant_demo",
        intentId: intent.id,
        authorizationId: null,
        fingerprint,
        transactionHash: TX_HASH,
        idempotencyKey: "execute-without-auth",
      }),
    (error) => isGuardError(error, "HUMAN_AUTHORIZATION_REQUIRED"),
  );

  const authorization = await service.authorize({
    tenantId: "tenant_demo",
    intentId: intent.id,
    evaluationId: evaluation.id,
    fingerprint,
    subjectRef: "subject:demo",
    method: "PARTNER_AUTHENTICATED",
    idempotencyKey: "authorize-001",
  });
  assert.equal(authorization.preflightHash, evaluation.preflightHash);
  const parsedAuthorization = HumanAuthorizationSchema.safeParse(authorization);
  assert.equal(
    parsedAuthorization.success,
    true,
    parsedAuthorization.success ? undefined : JSON.stringify(parsedAuthorization.error.issues),
  );
  assert.equal(authorization.policyDigest, authorization.policyHash);
  assert.equal(authorization.policyVersion, evaluation.policyVersion);

  for (const changed of [
    { ...fingerprint, amount: "10.01" },
    { ...fingerprint, leverage: "2" },
    { ...fingerprint, recipient: "0x3333333333333333333333333333333333333333" },
    { ...fingerprint, routeRef: "different-route" },
  ]) {
    await assert.rejects(
      () => service.recordExecution({
          tenantId: "tenant_demo",
          intentId: intent.id,
          authorizationId: authorization.id,
          fingerprint: changed,
          transactionHash: TX_HASH,
          idempotencyKey: `mismatch-${changed.amount}-${changed.routeRef}`,
        }),
      (error) => isGuardError(error, "FINGERPRINT_MISMATCH"),
    );
  }

  const submitted = await service.recordExecution({
    tenantId: "tenant_demo",
    intentId: intent.id,
    authorizationId: authorization.id,
    fingerprint,
    transactionHash: TX_HASH,
    idempotencyKey: "execute-001",
  });
  assert.equal(submitted.status, "SUBMITTED");

  const duplicate = await service.recordExecution({
    tenantId: "tenant_demo",
    intentId: intent.id,
    authorizationId: authorization.id,
    fingerprint,
    transactionHash: TX_HASH,
    idempotencyKey: "execute-001",
  });
  assert.equal(duplicate.id, submitted.id);
  assert.equal(duplicate.idempotentReplay, true);

  await assert.rejects(
    () => service.recordExecution({
        tenantId: "tenant_demo",
        intentId: intent.id,
        authorizationId: authorization.id,
        fingerprint,
        transactionHash: `0x${"ef".repeat(32)}`,
        idempotencyKey: "execute-second-broadcast",
      }),
    (error) => isGuardError(error, "IDEMPOTENCY_CONFLICT"),
    "one authorization/intent cannot record a second broadcast",
  );

  const uncertain = await service.reconcileExecution({
    tenantId: "tenant_demo",
    intentId: intent.id,
    transactionHash: TX_HASH,
    observedState: "RPC_UNCERTAIN_AFTER_BROADCAST",
    idempotencyKey: "reconcile-uncertain-001",
  });
  assert.equal(uncertain.status, "RECONCILIATION_REQUIRED");
  assert.equal(uncertain.reconciliationStatus, "RECONCILIATION_REQUIRED");
  const uncertainReplay = await service.reconcileExecution({
    tenantId: "tenant_demo",
    intentId: intent.id,
    transactionHash: TX_HASH,
    observedState: "RPC_UNCERTAIN_AFTER_BROADCAST",
    idempotencyKey: "reconcile-uncertain-001",
  });
  assert.equal(uncertainReplay.idempotentReplay, true);

  await assert.rejects(
    () => service.reconcileExecution({
        tenantId: "tenant_demo",
        intentId: intent.id,
        transactionHash: TX_HASH,
        observedState: "CONFIRMED",
        actualOutcome: {
          amountIn: "10.00",
          amountOut: "9.95",
          feeAmount: "0.02",
          explorerUrl: `https://testnet.arcscan.app/tx/${TX_HASH}`,
        },
        idempotencyKey: "reconcile-confirmed-without-provenance",
      }),
    (error) => isGuardError(error, "EVIDENCE_INSUFFICIENT"),
  );

  const reconciliationEvidence = {
    provider: "Partner application",
    sourceRef: `partner-reported:${TX_HASH}`,
    verificationStatus: "PROVIDER_REPORTED",
    observedAt: NOW,
    responseDigest: `0x${"cd".repeat(32)}`,
  };

  for (const [idempotencyKey, actualOutcome] of [
    [
      "reconcile-explorer-mismatch",
      {
        amountIn: "10.00",
        amountOut: "9.95",
        feeAmount: "0.02",
        explorerUrl: `https://testnet.arcscan.app/tx/0x${"ab".repeat(32)}`,
      },
    ],
    [
      "reconcile-oversized-decimal",
      {
        amountIn: "10.00",
        amountOut: "1".repeat(129),
        feeAmount: "0.02",
        explorerUrl: `https://testnet.arcscan.app/tx/${TX_HASH}`,
      },
    ],
  ]) {
    await assert.rejects(
      () =>
        service.reconcileExecution({
          tenantId: "tenant_demo",
          intentId: intent.id,
          transactionHash: TX_HASH,
          observedState: "CONFIRMED",
          actualOutcome,
          reconciliationEvidence,
          idempotencyKey,
        }),
      (error) =>
        isGuardError(
          error,
          idempotencyKey === "reconcile-explorer-mismatch"
            ? "FINGERPRINT_MISMATCH"
            : "VALIDATION_ERROR",
        ),
    );
  }
  assert.equal(
    await service.store.collection("receipts").has(`tenant_demo:${intent.id}`),
    false,
  );

  await assert.rejects(
    () =>
      service.reconcileExecution({
        tenantId: "tenant_demo",
        intentId: intent.id,
        transactionHash: TX_HASH,
        observedState: "CONFIRMED",
        actualOutcome: {
          amountIn: "10.00",
          amountOut: "9.95",
          feeAmount: "0.02",
          explorerUrl: `https://testnet.arcscan.app/tx/${TX_HASH}`,
        },
        reconciliationEvidence: {
          ...reconciliationEvidence,
          observedAt: "2026-08-05T12:00:00.000Z",
        },
        idempotencyKey: "reconcile-pre-authorization-001",
      }),
    (error) => isGuardError(error, "FINGERPRINT_MISMATCH"),
  );

  const confirmed = await service.reconcileExecution({
    tenantId: "tenant_demo",
    intentId: intent.id,
    transactionHash: TX_HASH,
    observedState: "CONFIRMED",
    actualOutcome: {
      amountIn: "10.00",
      amountOut: "9.95",
      feeAmount: "0.02",
      explorerUrl: `https://testnet.arcscan.app/tx/${TX_HASH}`,
    },
    reconciliationEvidence,
    idempotencyKey: "reconcile-confirmed-001",
  });
  assert.equal(confirmed.status, "CONFIRMED");
  const confirmedReplay = await service.reconcileExecution({
    tenantId: "tenant_demo",
    intentId: intent.id,
    transactionHash: TX_HASH,
    observedState: "CONFIRMED",
    actualOutcome: {
      amountIn: "10.00",
      amountOut: "9.95",
      feeAmount: "0.02",
      explorerUrl: `https://testnet.arcscan.app/tx/${TX_HASH}`,
    },
    reconciliationEvidence,
    idempotencyKey: "reconcile-confirmed-001",
  });
  assert.equal(confirmedReplay.idempotentReplay, true);

  const receipt = await service.getReceipt({ tenantId: "tenant_demo", intentId: intent.id });
  assert.equal(receipt.execution.transactionHash, TX_HASH);
  assert.equal(receipt.execution.status, "CONFIRMED");
  assert.equal(receipt.authorization.method, "PARTNER_AUTHENTICATED");
  assert.equal(receipt.schemaVersion, "1.1.0");
  assert.equal(receipt.authorization.expiresAt, authorization.expiresAt);
  assert.equal(
    receipt.authorization.executionFingerprintHash,
    receipt.execution.fingerprintHash,
  );
  assert.equal(receipt.reconciliation.expected.amountOut, "9.96");
  assert.equal(receipt.reconciliation.actual.amountOut, "9.95");
  assert.deepEqual(receipt.expectedEffects, receipt.reconciliation.expected);
  assert.deepEqual(receipt.actualEffects, receipt.reconciliation.actual);
  assert.equal(receipt.reconciliationStatus, "MATCHED");
  assert.equal(receipt.evidenceStatus, "COMPLETE");
  assert.equal(receipt.policyDecision, "ALLOWED_BY_POLICY");
  assert.equal(receipt.authorizationStatus, "APPROVED");
  assert.equal(receipt.executionStatus, "CONFIRMED");
  assert.equal(receipt.policyVersion, 1);
  assert.equal(receipt.policyDigest, evaluation.policyDigest);
  assert.equal(receipt.preflightHash, evaluation.preflightHash);
  assert.match(receipt.receiptHash, /^0x[0-9a-f]{64}$/);
  assert.equal(DecisionSettlementReceiptSchema.safeParse(receipt).success, true);
  assert.equal(verifyIntegrityEnvelope(receipt), true);
  assert.equal(verifyIntegrityEnvelope({ ...receipt, actualEffects: { ...receipt.actualEffects, amountOut: "9.94" } }), false);

  assert.equal(receipt.reconciliation.evidence.verificationStatus, "PROVIDER_REPORTED");
  assert.equal(receipt.reconciliation.evidence.responseDigest, reconciliationEvidence.responseDigest);
  assert.equal(receipt.limitations.includes("PARTNER_REPORTED_RECONCILIATION"), true);
  assert.equal(receipt.finalizedAt, NOW);
  assert.equal(receipt.limitations.includes("HACKATHON_PROTOTYPE"), true);

  const wrongExplorerCore = {
    ...receipt,
    execution: {
      ...receipt.execution,
      explorerUrl: `https://testnet.arcscan.app/tx/0x${"ab".repeat(32)}`,
    },
  };
  delete wrongExplorerCore.receiptHash;
  delete wrongExplorerCore.integrity;
  const wrongExplorerHash = hashCanonical(wrongExplorerCore);
  const wrongExplorerWithoutIntegrity = {
    ...wrongExplorerCore,
    receiptHash: wrongExplorerHash,
  };
  assert.equal(
    DecisionSettlementReceiptSchema.safeParse({
      ...wrongExplorerWithoutIntegrity,
      integrity: {
        algorithm: "SHA-256",
        hash: hashCanonical(wrongExplorerWithoutIntegrity),
      },
    }).success,
    false,
    "a self-consistent receipt still cannot point at a different Arc transaction",
  );

  const legacyAuthorization = { ...receipt.authorization };
  delete legacyAuthorization.expiresAt;
  delete legacyAuthorization.executionFingerprintHash;
  const legacyCore = { ...receipt, schemaVersion: "1.0.0", authorization: legacyAuthorization };
  delete legacyCore.receiptHash;
  delete legacyCore.integrity;
  const legacyReceiptHash = hashCanonical(legacyCore);
  const legacyWithoutIntegrity = { ...legacyCore, receiptHash: legacyReceiptHash };
  const legacyReceipt = {
    ...legacyWithoutIntegrity,
    integrity: { algorithm: "SHA-256", hash: hashCanonical(legacyWithoutIntegrity) },
  };
  assert.equal(
    DecisionSettlementReceiptSchema.safeParse(legacyReceipt).success,
    true,
    "the archived v1 shape remains parseable without changing its hash contract",
  );
});

test("read and recovery paths re-validate stored evaluations instead of replaying them", async () => {
  const { createGuardService, hashCanonical, isGuardError } = await loadService();
  let idCounter = 0;
  const service = createGuardService({
    now: () => NOW,
    createId: (prefix) => `${prefix}_read_validation_${++idCounter}`,
  });
  const evaluations = service.store.collection("evaluations");

  function resealed(value, mutate) {
    const { _integrity: _discarded, ...payload } = structuredClone(value);
    const mutated = mutate(payload);
    return {
      ...mutated,
      _integrity: { algorithm: "SHA-256", hash: hashCanonical(mutated) },
    };
  }

  /* An authenticated GET must apply the same gates as the authorize path: a
     row whose seal no longer matches its bytes fails closed rather than being
     served back as COMPLETE / ALLOWED_BY_POLICY. */
  const readCase = await createEvaluation(service, "tenant_read_validation", "read_validation");
  const readKey = `tenant_read_validation:${readCase.evaluation.id}`;
  const readStored = await evaluations.get(readKey);
  assert.ok(readStored);
  await evaluations.set(readKey, {
    ...structuredClone(readStored),
    evidenceRoot: `0x${"aa".repeat(32)}`,
  });
  await assert.rejects(
    () =>
      service.getEvaluation({
        tenantId: "tenant_read_validation",
        evaluationId: readCase.evaluation.id,
      }),
    (error) => isGuardError(error, "RECOVERY_REQUIRED"),
    "getEvaluation must reject a tampered stored evaluation",
  );

  /* Status assembles only rows that still validate — the same corrupted row
     cannot be combined into an APPROVED-looking status. */
  await assert.rejects(
    () =>
      service.getStatus({
        tenantId: "tenant_read_validation",
        intentId: readCase.intent.id,
      }),
    (error) => isGuardError(error, "RECOVERY_REQUIRED"),
    "getStatus must reject a tampered stored evaluation",
  );

  /* Idempotent preflight recovery: a RESEALED row — valid hash, valid schema —
     whose intent binding no longer matches the persisted intent bytes is the
     same-revision drift case. Only the current-intent check can catch it, and
     the recovery path must apply that check instead of replaying the row. */
  const recoveryCase = await createEvaluation(
    service,
    "tenant_recovery_validation",
    "recovery_validation",
  );
  const recoveryKey = `tenant_recovery_validation:${recoveryCase.evaluation.id}`;
  const recoveryStored = await evaluations.get(recoveryKey);
  assert.ok(recoveryStored);
  await evaluations.set(
    recoveryKey,
    resealed(recoveryStored, (payload) => ({ ...payload, intentHash: `0x${"bb".repeat(32)}` })),
  );
  await assert.rejects(
    () =>
      service.preflight({
        tenantId: "tenant_recovery_validation",
        intentId: recoveryCase.intent.id,
        evidence: [quote],
        policy,
        idempotencyKey: "preflight-recovery_validation",
      }),
    (error) => isGuardError(error, "RECOVERY_REQUIRED"),
    "idempotent preflight recovery must reject same-revision intent drift",
  );
});

/* ================================================================== *
 * Global transaction-hash ownership (exceptional-review P1-2)
 * ================================================================== */

test("a payout-claimed transaction cannot back a legacy intent execution", async () => {
  const { createGuardService, isGuardError } = await loadService();
  const { payoutStorageKey } = await import("./payout-canonical.ts");
  const service = createGuardService({ now: () => NOW, createId: (prefix) => `${prefix}_txclaim_a` });

  /* The payout lifecycle's claim at the shared `${chainRef}:${hash}` key, in
     the exact versioned shape the payout service writes. */
  const globalKey = `eip155:5042002:${TX_HASH.toLowerCase()}`;
  assert.equal(
    await service.store.versioned("transactionIndex").compareAndSet(globalKey, null, {
      version: 1,
      ownerKey: payoutStorageKey("payout", "tenant_txclaim_a", "pay_0001"),
      transactionHash: TX_HASH.toLowerCase(),
    }),
    true,
  );

  await assert.rejects(
    () => createAuthorizedExecution(service, "tenant_txclaim_a", "txclaim_a"),
    (error) => isGuardError(error, "IDEMPOTENCY_CONFLICT"),
  );
  assert.equal(
    await service.store.collection("executions").has("tenant_txclaim_a:int_txclaim_a"),
    false,
    "the losing legacy path leaves no execution record",
  );
  const stored = await service.store.versioned("transactionIndex").get(globalKey);
  assert.equal(stored.ownerKey, payoutStorageKey("payout", "tenant_txclaim_a", "pay_0001"));
});

test("a historical payout-namespace claim also blocks a legacy execution, untouched", async () => {
  const { createGuardService, isGuardError } = await loadService();
  const { payoutStorageKey } = await import("./payout-canonical.ts");
  const service = createGuardService({ now: () => NOW, createId: (prefix) => `${prefix}_txclaim_b` });

  /* A claim written before the shared namespace existed: only the
     payout-specific key holds it, and it is honored read-only. */
  const historicalKey = payoutStorageKey("payout-transaction", TX_HASH.toLowerCase());
  assert.equal(
    await service.store.versioned("transactionIndex").compareAndSet(historicalKey, null, {
      version: 1,
      ownerKey: payoutStorageKey("payout", "tenant_txclaim_b", "pay_0001"),
      transactionHash: TX_HASH.toLowerCase(),
    }),
    true,
  );

  await assert.rejects(
    () => createAuthorizedExecution(service, "tenant_txclaim_b", "txclaim_b"),
    (error) => isGuardError(error, "IDEMPOTENCY_CONFLICT"),
  );
  assert.equal(
    await service.store.collection("executions").has("tenant_txclaim_b:int_txclaim_b"),
    false,
  );
  const stored = await service.store.versioned("transactionIndex").get(historicalKey);
  assert.equal(
    stored.ownerKey,
    payoutStorageKey("payout", "tenant_txclaim_b", "pay_0001"),
    "no destructive migration touches the historical row",
  );
});
