// Run from repo root: node --test lib/guard/contracts.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";

const WALLET = "0x1111111111111111111111111111111111111111";
const USDC = "eip155:5042002/erc20:0x3600000000000000000000000000000000000000";
const EURC = "eip155:5042002/erc20:0x89b50855aa3be2f677cd6303cec089b5f319d72a";
const HASH_A = `0x${"ab".repeat(32)}`;
const HASH_B = `0x${"cd".repeat(32)}`;

async function loadContracts() {
  try {
    return await import("./contracts.ts");
  } catch (error) {
    assert.fail(`Guard contracts are missing: ${error instanceof Error ? error.message : String(error)}`);
  }
}

async function loadKernel() {
  return import("./kernel.ts");
}

const validIntent = {
  schemaVersion: "1.0.0",
  id: "int_contract_001",
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
  amount: "90071992547409931234567890.123456",
  amountType: "EXACT_INPUT",
  recipient: WALLET,
  venueRef: "circle-app-kit",
  routeRef: "circle-app-kit:swap",
  quoteRef: "quote_arc_001",
  target: "0x2222222222222222222222222222222222222222",
  calldataHash: HASH_A,
  nativeValue: "0",
  portfolioSnapshotRef: null,
  policyRef: { id: "demo-stablecoin-policy", version: 1 },
  createdAt: "2026-08-06T11:59:00.000Z",
  expiresAt: "2026-08-06T12:02:00.000Z",
  revision: 1,
  idempotencyKey: "idem-contract-001",
};

const unavailableQuote = {
  schemaVersion: "1.0.0",
  id: "ev_unavailable_001",
  provider: "Circle App Kit",
  sourceRef: "circle-app-kit:estimateSwap",
  adapter: "circle-app-kit",
  adapterVersion: "current-official-contract",
  sourceType: "SWAP_QUOTE",
  observedAt: "2026-08-06T11:59:30.000Z",
  receivedAt: "2026-08-06T11:59:31.000Z",
  validUntil: "2026-08-06T12:01:30.000Z",
  confidence: "UNAVAILABLE",
  coverage: {
    subjectRefs: ["eip155:5042002", USDC, EURC],
    fields: ["amountIn", "expectedAmountOut", "minimumAmountOut", "fees"],
    limitations: ["PROVIDER_TIMEOUT"],
  },
  availability: "UNAVAILABLE",
  verificationStatus: "NOT_VERIFIED",
  chainRef: "eip155:5042002",
  blockRef: null,
  transactionRef: null,
  status: "UNAVAILABLE",
  requestHash: HASH_A,
  responseHash: HASH_B,
  responseDigest: HASH_B,
  reason: "PROVIDER_TIMEOUT",
  transformationVersion: "arc-swap-quote-v1",
  fallbackUsed: false,
  facts: {
    quoteRef: "quote_arc_001",
    providerRef: "circle-app-kit",
    routeRef: "circle-app-kit:swap",
    venueRef: "circle-app-kit",
    recipientAddress: WALLET,
    sellAssetRef: USDC,
    buyAssetRef: EURC,
    amountIn: "10.00",
    expectedAmountOut: null,
    minimumAmountOut: null,
    feeAmount: null,
    totalDebit: null,
    slippageBps: null,
  },
};

const policy = {
  id: "demo-stablecoin-policy",
  version: 1,
  rules: [
    { id: "allowed-chain", type: "ALLOWED_CHAIN", value: "eip155:5042002" },
    { id: "allowed-pair", type: "ALLOWED_PAIR", value: [USDC, EURC] },
    { id: "max-total-debit", type: "MAX_TOTAL_DEBIT", value: "100.00", currencyAssetRef: USDC },
    { id: "max-quote-age", type: "MAX_QUOTE_AGE_SECONDS", value: 120 },
    { id: "max-slippage", type: "MAX_SLIPPAGE_BPS", value: "25" },
    { id: "human-auth", type: "HUMAN_AUTHORIZATION_REQUIRED", value: true },
  ],
};

test("Guard contract matrix fails closed without precision loss or hidden evidence state", async () => {
  const {
    ArcMemoSchema,
    ExecutionIntentSchema,
    assertCapabilityEnvironment,
    assertCredentialEnvironment,
    createIntegrityEnvelope,
    redactGuardLog,
    verifyIntegrityEnvelope,
  } = await loadContracts();
  const { compareDecimalStrings, evaluateGuardReadiness } = await loadKernel();

  const parsed = ExecutionIntentSchema.parse(validIntent);
  assert.equal(parsed.amount, "90071992547409931234567890.123456");
  assert.equal(
    compareDecimalStrings(
      "90071992547409931234567890.123456",
      "90071992547409931234567890.123455",
    ),
    1,
  );
  assert.equal(ExecutionIntentSchema.safeParse({ ...validIntent, amount: 10 }).success, false);
  assert.equal(ExecutionIntentSchema.safeParse({ ...validIntent, amount: "1e9" }).success, false);

  assert.equal(
    ArcMemoSchema.safeParse({
      intentHash: HASH_A,
      evidenceRoot: HASH_B,
      policyHash: `0x${"ef".repeat(32)}`,
      receiptSchemaVersion: "1.0.0",
    }).success,
    true,
  );
  assert.equal(
    ArcMemoSchema.safeParse({
      intentHash: "founder@example.com",
      evidenceRoot: HASH_B,
      policyHash: HASH_A,
      receiptSchemaVersion: "1.0.0",
      email: "founder@example.com",
    }).success,
    false,
  );

  assert.throws(
    () => assertCapabilityEnvironment({ state: "PLANNED", runtimeEnvironment: "PRODUCTION" }),
    (error) => error?.code === "CAPABILITY_UNAVAILABLE",
  );
  assert.throws(
    () =>
      assertCredentialEnvironment({
        credentialEnvironment: "ARC_TESTNET",
        runtimeEnvironment: "PRODUCTION",
      }),
    (error) => error?.code === "VALIDATION_ERROR",
  );

  const unavailable = evaluateGuardReadiness({
    intent: { ...validIntent, amount: "10.00" },
    evidence: [unavailableQuote],
    policy,
    now: "2026-08-06T12:00:00.000Z",
  });
  assert.equal(unavailable.outcome, "INSUFFICIENT_EVIDENCE");
  assert.equal(unavailable.dataStatus, "UNAVAILABLE");
  assert.deepEqual(unavailable.evidenceSummary, [
    {
      id: "ev_unavailable_001",
      provider: "Circle App Kit",
      sourceRef: "circle-app-kit:estimateSwap",
      status: "UNAVAILABLE",
      availability: "UNAVAILABLE",
      verificationStatus: "NOT_VERIFIED",
      fallbackUsed: false,
    },
  ]);

  const fallback = evaluateGuardReadiness({
    intent: { ...validIntent, amount: "10.00" },
    evidence: [
      {
        ...unavailableQuote,
        id: "ev_fallback_001",
        provider: "Fallback Quote Provider",
        sourceRef: "fallback-provider:quote",
        status: "VALID",
        availability: "AVAILABLE",
        verificationStatus: "PROVIDER_REPORTED",
        confidence: "PROVIDER_REPORTED",
        reason: "PRIMARY_PROVIDER_TIMEOUT",
        fallbackUsed: true,
        facts: {
          ...unavailableQuote.facts,
          expectedAmountOut: "9.96",
          minimumAmountOut: "9.94",
          feeAmount: "0.02",
          feeAssetRef: USDC,
          totalDebit: "10.02",
          slippageBps: "20",
        },
      },
    ],
    policy,
    now: "2026-08-06T12:00:00.000Z",
  });
  assert.equal(fallback.outcome, "ALLOWED_BY_POLICY");
  assert.equal(fallback.evidenceSummary[0].provider, "Fallback Quote Provider");
  assert.equal(fallback.evidenceSummary[0].fallbackUsed, true);

  const signed = createIntegrityEnvelope({
    schemaVersion: "1.0.0",
    intentId: "int_contract_001",
    amountOut: "9.95",
  });
  assert.equal(verifyIntegrityEnvelope(signed), true);
  assert.equal(verifyIntegrityEnvelope({ ...signed, amountOut: "99.95" }), false);

  assert.deepEqual(
    redactGuardLog({
      apiKey: "demo-secret",
      authorization: "Bearer demo-secret",
      nested: { entitySecret: "entity-secret", walletAddress: WALLET },
    }),
    {
      apiKey: "[REDACTED]",
      authorization: "[REDACTED]",
      nested: { entitySecret: "[REDACTED]", walletAddress: WALLET },
    },
  );
});

test("canonical hashing and batch ordering are locale independent", async () => {
  const { compareCanonicalStrings, hashCanonical } = await import("./canonical.ts");
  assert.equal(compareCanonicalStrings("z", "ä"), -1);
  assert.equal(compareCanonicalStrings("ä", "z"), 1);
  assert.equal(
    hashCanonical({ ä: 1, z: 2, A: 3 }),
    hashCanonical({ A: 3, z: 2, ä: 1 }),
  );
});
