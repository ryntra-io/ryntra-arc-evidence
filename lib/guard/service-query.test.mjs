// Run from repo root: node --test lib/guard/service-query.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";

const WALLET = "0x1111111111111111111111111111111111111111";
const USDC = "eip155:5042002/erc20:0x3600000000000000000000000000000000000000";
const EURC = "eip155:5042002/erc20:0x89b50855aa3be2f677cd6303cec089b5f319d72a";

const intent = {
  schemaVersion: "1.0.0",
  id: "int_query_001",
  tenantId: "tenant_demo",
  applicationId: "partner_arc_app",
  externalPartnerId: "partner-order-query",
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
  routeRef: "circle-app-kit:swap:Arc_Testnet",
  quoteRef: "quote_query_001",
  target: "0x2222222222222222222222222222222222222222",
  calldataHash: `0x${"ab".repeat(32)}`,
  nativeValue: "0",
  portfolioSnapshotRef: null,
  policyRef: { id: "demo-stablecoin-policy", version: 1 },
  createdAt: "2026-08-06T11:59:00.000Z",
  expiresAt: "2026-08-06T12:02:00.000Z",
  revision: 1,
  idempotencyKey: "idem-query-001",
};

/* The full canonical EvidenceItem shape, exactly as the API contract requires.
   An earlier version of this fixture carried a trimmed item; that only worked
   because reads did not re-validate stored rows — the same blind spot the
   service has since closed, so the fixture now has to be contract-complete. */
const evidence = [{
  schemaVersion: "1.0.0",
  id: "ev_query_001",
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
  requestHash: `0x${"cc".repeat(32)}`,
  responseHash: `0x${"cd".repeat(32)}`,
  responseDigest: `0x${"cd".repeat(32)}`,
  reason: null,
  transformationVersion: "arc-swap-quote-v1",
  fallbackUsed: false,
  facts: {
    quoteRef: "quote_query_001",
    providerRef: "circle-app-kit",
    venueRef: "circle-app-kit",
    routeRef: "circle-app-kit:swap:Arc_Testnet",
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
}];

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

test("tenant-scoped query methods expose public state but not private evaluation material", async () => {
  const { createGuardService, isGuardError } = await import("./service.ts");
  let sequence = 0;
  const service = createGuardService({
    now: () => "2026-08-06T12:00:00.000Z",
    createId: (prefix) => `${prefix}_query_${++sequence}`,
  });
  await service.createIntent({ tenantId: "tenant_demo", intent, idempotencyKey: "create-query" });
  assert.equal((await service.getIntent({ tenantId: "tenant_demo", intentId: intent.id })).id, intent.id);
  await assert.rejects(
    () => service.getIntent({ tenantId: "other_tenant", intentId: intent.id }),
    (error) => isGuardError(error, "TENANT_FORBIDDEN"),
  );
  assert.equal((await service.getStatus({ tenantId: "tenant_demo", intentId: intent.id })).executionStatus, "NOT_STARTED");
  const evaluation = await service.preflight({
    tenantId: "tenant_demo",
    intentId: intent.id,
    evidence,
    policy,
    idempotencyKey: "preflight-query",
  });
  assert.equal("_evidence" in evaluation, false);
  const fetched = await service.getEvaluation({ tenantId: "tenant_demo", evaluationId: evaluation.id });
  assert.equal("_policy" in fetched, false);
  assert.equal((await service.getStatus({ tenantId: "tenant_demo", intentId: intent.id })).policyStatus, "PASS");
  await assert.rejects(
    () => service.getReceipt({ tenantId: "tenant_demo", intentId: intent.id }),
    (error) => isGuardError(error, "EXECUTION_NOT_CONFIRMED"),
  );
});

test("the ledger reads the canonical intent field names, not plausible ones", async () => {
  /* This test exists because the first version of listIntents read
     `operationType`, `amountIn`, `assetRefIn` and `recipientRef` — plausible
     names, none of them the contract's. TypeScript did not object because
     Intent is typed loosely, and the result was not an error: every one of
     those reads returned `undefined` and rendered as a blank cell in a ledger
     that otherwise looked correct. A blank cell in an evidence surface is worse
     than a crash, because nobody investigates it. */
  const { createGuardService } = await import("./service.ts");
  const service = createGuardService({
    now: () => "2026-08-06T12:00:00.000Z",
    createId: (prefix) => `${prefix}_ledger`,
  });

  await service.createIntent({ tenantId: "tenant_demo", intent, idempotencyKey: "ledger-key" });
  const ledger = await service.listIntents({ tenantId: "tenant_demo" });

  assert.equal(ledger.total, 1);
  const [row] = ledger.intents;

  /* Every field the ledger renders must carry a real value. Asserting "not
     undefined" is the whole point: the bug produced a well-formed row of
     nothing. */
  for (const field of ["intentId", "createdAt", "actionType", "amount", "sellAssetRef", "chainRef"]) {
    assert.notEqual(row[field], undefined, `ledger row is missing ${field}`);
  }
  assert.equal(row.intentId, intent.id);
  assert.equal(row.actionType, intent.actionType);
  assert.equal(row.amount, intent.amount);
  assert.equal(row.executionStatus, "NOT_STARTED");
  assert.equal(row.receiptStatus, "NOT_FINALIZED");
  assert.equal(row.transactionHash, null);
});

test("one tenant's ledger never contains another tenant's operations", async () => {
  const { createGuardService } = await import("./service.ts");
  let sequence = 0;
  const service = createGuardService({
    now: () => "2026-08-06T12:00:00.000Z",
    createId: (prefix) => `${prefix}_iso_${++sequence}`,
  });

  await service.createIntent({ tenantId: "tenant_demo", intent, idempotencyKey: "iso-a" });
  await service.createIntent({
    tenantId: "tenant_other",
    intent: { ...intent, id: "int_other_001", tenantId: "tenant_other" },
    idempotencyKey: "iso-b",
  });

  const mine = await service.listIntents({ tenantId: "tenant_demo" });
  const theirs = await service.listIntents({ tenantId: "tenant_other" });

  assert.deepEqual(mine.intents.map((row) => row.intentId), [intent.id]);
  assert.deepEqual(theirs.intents.map((row) => row.intentId), ["int_other_001"]);
});

test("direct legacy service reads reject separator-crafted cross-tenant keys", async () => {
  const { createGuardService, isGuardError } = await import("./service.ts");
  const service = createGuardService({
    now: () => "2026-08-06T12:00:00.000Z",
    createId: (prefix) => `${prefix}_tenant_separator`,
  });
  const ownerTenantId = "tenant_alpha:tenant_beta";
  const ownerIntent = {
    ...intent,
    id: "int_private_001",
    tenantId: ownerTenantId,
    externalPartnerId: "partner-order-private",
    idempotencyKey: "idem-private-001",
  };

  await service.createIntent({
    tenantId: ownerTenantId,
    intent: ownerIntent,
    idempotencyKey: "create-private",
  });
  assert.equal(
    (await service.getIntent({ tenantId: ownerTenantId, intentId: ownerIntent.id })).id,
    ownerIntent.id,
  );
  await assert.rejects(
    () => service.getIntent({
      tenantId: "tenant_alpha",
      intentId: "tenant_beta:int_private_001",
    }),
    (error) => isGuardError(error, "TENANT_FORBIDDEN"),
  );
});
