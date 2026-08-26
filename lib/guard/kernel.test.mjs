// Run from repo root: node --test lib/guard/kernel.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";

const NOW = "2026-08-06T12:00:00.000Z";
const WALLET = "0x1111111111111111111111111111111111111111";
const USDC = "eip155:5042002/erc20:0x3600000000000000000000000000000000000000";
const EURC = "eip155:5042002/erc20:0x89b50855aa3be2f677cd6303cec089b5f319d72a";

const intent = (overrides = {}) => ({
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
  ...overrides,
});

const quoteEvidence = (overrides = {}) => ({
  schemaVersion: "1.0.0",
  id: "ev_quote_001",
  provider: "Circle App Kit",
  adapter: "circle-app-kit",
  adapterVersion: "current-official-contract",
  sourceType: "SWAP_QUOTE",
  observedAt: "2026-08-06T11:59:30.000Z",
  receivedAt: "2026-08-06T11:59:31.000Z",
  validUntil: "2026-08-06T12:01:30.000Z",
  confidence: "PROVIDER_REPORTED",
  availability: "AVAILABLE",
  verificationStatus: "PROVIDER_REPORTED",
  chainRef: "eip155:5042002",
  blockRef: null,
  transactionRef: null,
  status: "VALID",
  requestHash: `0x${"01".repeat(32)}`,
  responseHash: `0x${"02".repeat(32)}`,
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
  ...overrides,
});

const policy = {
  schemaVersion: "1.0.0",
  id: "demo-stablecoin-policy",
  version: 1,
  publishedAt: "2026-08-06T00:00:00.000Z",
  rules: [
    { id: "allowed-chain", type: "ALLOWED_CHAIN", value: "eip155:5042002", onViolation: "BLOCK" },
    { id: "allowed-pair", type: "ALLOWED_PAIR", value: [USDC, EURC], onViolation: "BLOCK" },
    { id: "max-total-debit", type: "MAX_TOTAL_DEBIT", value: "100.00", currencyAssetRef: USDC, onViolation: "BLOCK" },
    { id: "max-quote-age", type: "MAX_QUOTE_AGE_SECONDS", value: 120, onViolation: "INSUFFICIENT_EVIDENCE" },
    { id: "max-slippage", type: "MAX_SLIPPAGE_BPS", value: "25", onViolation: "REVIEW" },
    { id: "human-auth", type: "HUMAN_AUTHORIZATION_REQUIRED", value: true, onViolation: "REQUIRE_AUTHORIZATION" },
  ],
};

async function loadKernel() {
  try {
    return await import("./kernel.ts");
  } catch (error) {
    assert.fail(`Guard kernel is missing: ${error instanceof Error ? error.message : String(error)}`);
  }
}

test("fresh supported Arc quote passes deterministic policy and awaits human authorization", async () => {
  const { evaluateGuardReadiness } = await loadKernel();

  const evaluation = evaluateGuardReadiness({
    intent: intent(),
    evidence: [quoteEvidence()],
    policy,
    now: NOW,
  });

  assert.equal(evaluation.outcome, "ALLOWED_BY_POLICY");
  assert.equal(evaluation.dataStatus, "COMPLETE");
  assert.equal(evaluation.policyStatus, "PASS");
  assert.equal(evaluation.authorizationStatus, "PENDING");
  assert.equal(evaluation.executionStatus, "NOT_STARTED");
  assert.deepEqual(evaluation.blockers, []);
  assert.deepEqual(evaluation.missingEvidence, []);
});

test("policy freshness expires exactly at the maximum quote age boundary", async () => {
  const { evaluateGuardReadiness } = await loadKernel();
  const evaluation = evaluateGuardReadiness({
    intent: intent({ expiresAt: "2026-08-06T12:03:00.000Z" }),
    evidence: [quoteEvidence({ validUntil: "2026-08-06T12:03:00.000Z" })],
    policy,
    now: "2026-08-06T12:01:30.000Z",
  });

  assert.equal(evaluation.outcome, "EXPIRED");
  assert.deepEqual(evaluation.missingEvidence, ["FRESH_SWAP_QUOTE"]);
});

test("policy evaluation rejects evidence borrowed from a materially different intent", async () => {
  const { evaluateGuardReadiness } = await loadKernel();
  const cases = [
    ["amount", { amountIn: "1.00" }],
    ["recipient", { recipientAddress: "0x3333333333333333333333333333333333333333" }],
    ["venue", { venueRef: "different-venue" }],
    ["route", { routeRef: "different-route" }],
  ];

  for (const [name, changedFacts] of cases) {
    const evaluation = evaluateGuardReadiness({
      intent: intent(),
      evidence: [
        quoteEvidence({ facts: { ...quoteEvidence().facts, ...changedFacts } }),
      ],
      policy,
      now: NOW,
    });
    assert.equal(evaluation.outcome, "INSUFFICIENT_EVIDENCE", name);
    assert.deepEqual(evaluation.missingEvidence, ["INTENT_BOUND_SWAP_QUOTE"], name);
  }

  const leveraged = evaluateGuardReadiness({
    intent: intent({ leverage: "2" }),
    evidence: [quoteEvidence()],
    policy,
    now: NOW,
  });
  assert.equal(leveraged.outcome, "INSUFFICIENT_EVIDENCE");
  assert.deepEqual(leveraged.missingEvidence, ["INTENT_BOUND_SWAP_QUOTE"]);

  const ambiguous = evaluateGuardReadiness({
    intent: intent(),
    evidence: [
      quoteEvidence(),
      quoteEvidence({ id: "ev_quote_duplicate", responseHash: `0x${"03".repeat(32)}` }),
    ],
    policy,
    now: NOW,
  });
  assert.equal(ambiguous.outcome, "INSUFFICIENT_EVIDENCE");
  assert.deepEqual(ambiguous.missingEvidence, ["UNAMBIGUOUS_SWAP_QUOTE"]);
});

test("policy evaluation rejects internally inconsistent financial-plan arithmetic", async () => {
  const { addDecimalStrings, evaluateGuardReadiness } = await loadKernel();
  assert.equal(addDecimalStrings("99", "10.00"), "109");
  assert.equal(addDecimalStrings("0.009", "0.001"), "0.01");

  for (const [name, facts, missing] of [
    [
      "understated debit",
      { ...quoteEvidence().facts, amountIn: "99", feeAmount: "10", totalDebit: "99" },
    ],
    [
      "impossible minimum output",
      { ...quoteEvidence().facts, minimumAmountOut: "10.01", expectedAmountOut: "9.96" },
    ],
    [
      "oversized financial value",
      { ...quoteEvidence().facts, expectedAmountOut: "1".repeat(129) },
      "BOUNDED_FINANCIAL_PLAN",
    ],
  ].map(([name, facts, missing = "CONSISTENT_FINANCIAL_PLAN"]) => [name, facts, missing])) {
    const evaluation = evaluateGuardReadiness({
      intent: intent({ amount: facts.amountIn }),
      evidence: [quoteEvidence({ facts })],
      policy,
      now: NOW,
    });
    assert.equal(evaluation.outcome, "INSUFFICIENT_EVIDENCE", name);
    assert.equal(evaluation.dataStatus, "CONFLICTING", name);
    assert.deepEqual(evaluation.missingEvidence, [missing], name);
  }

  const wrongDebitAsset = evaluateGuardReadiness({
    intent: intent(),
    evidence: [quoteEvidence()],
    policy: {
      ...policy,
      rules: policy.rules.map((rule) =>
        rule.type === "MAX_TOTAL_DEBIT" ? { ...rule, currencyAssetRef: EURC } : rule,
      ),
    },
    now: NOW,
  });
  assert.equal(wrongDebitAsset.outcome, "BLOCKED_BY_RULE");
  assert.deepEqual(wrongDebitAsset.blockers, ["max-total-debit"]);
});

test("policy derives slippage from expected and minimum output when the supplied scalar understates it", async () => {
  const { evaluateGuardReadiness } = await loadKernel();
  const evaluation = evaluateGuardReadiness({
    intent: intent(),
    evidence: [
      quoteEvidence({
        facts: {
          ...quoteEvidence().facts,
          expectedAmountOut: "100",
          minimumAmountOut: "99",
          slippageBps: "0",
        },
      }),
    ],
    policy,
    now: NOW,
  });

  assert.equal(evaluation.outcome, "REVIEW_REQUIRED");
  assert.equal(evaluation.policyStatus, "WARN");
});

test("fee arithmetic requires feeAssetRef to equal the sell asset", async () => {
  const { evaluateGuardReadiness } = await loadKernel();
  for (const [name, feeAssetRef] of [
    ["cross-asset", EURC],
    ["unattributed", undefined],
  ]) {
    const facts = { ...quoteEvidence().facts, feeAssetRef };
    if (feeAssetRef === undefined) delete facts.feeAssetRef;
    const evaluation = evaluateGuardReadiness({
      intent: intent(),
      evidence: [quoteEvidence({ facts })],
      policy,
      now: NOW,
    });

    assert.equal(evaluation.outcome, "INSUFFICIENT_EVIDENCE", name);
    assert.equal(evaluation.dataStatus, "CONFLICTING", name);
    assert.deepEqual(evaluation.missingEvidence, ["CONSISTENT_FINANCIAL_PLAN"], name);
  }
});

test("deterministic Arc policy matrix distinguishes review, block, insufficient, expired, and unsupported", async () => {
  const { evaluateGuardReadiness } = await loadKernel();
  const cases = [
    {
      name: "soft slippage",
      input: {
        intent: intent(),
        evidence: [
          quoteEvidence({
            facts: { ...quoteEvidence().facts, slippageBps: "30" },
          }),
        ],
        policy,
        now: NOW,
      },
      expected: ["REVIEW_REQUIRED", "WARN", [], []],
    },
    {
      name: "amount over maximum",
      input: {
        intent: intent({ amount: "100.01" }),
        evidence: [
          quoteEvidence({
            facts: {
              ...quoteEvidence().facts,
              amountIn: "100.01",
              totalDebit: "100.03",
            },
          }),
        ],
        policy,
        now: NOW,
      },
      expected: ["BLOCKED_BY_RULE", "BLOCK", ["max-total-debit"], []],
    },
    {
      name: "missing quote",
      input: { intent: intent({ quoteRef: null }), evidence: [], policy, now: NOW },
      expected: ["INSUFFICIENT_EVIDENCE", "NOT_EVALUATED", [], ["SWAP_QUOTE"]],
    },
    {
      name: "expired quote",
      input: {
        intent: intent(),
        evidence: [
          quoteEvidence({
            observedAt: "2026-08-06T11:56:00.000Z",
            receivedAt: "2026-08-06T11:56:01.000Z",
            validUntil: "2026-08-06T11:58:00.000Z",
          }),
        ],
        policy,
        now: NOW,
      },
      expected: ["EXPIRED", "NOT_EVALUATED", [], ["FRESH_SWAP_QUOTE"]],
    },
    {
      name: "unsupported chain",
      input: {
        intent: intent({ chainRef: "eip155:1", environment: "PRODUCTION" }),
        evidence: [quoteEvidence({ chainRef: "eip155:1" })],
        policy,
        now: NOW,
      },
      expected: ["UNSUPPORTED", "BLOCK", ["allowed-chain"], []],
    },
  ];

  for (const entry of cases) {
    const actual = evaluateGuardReadiness(entry.input);
    assert.deepEqual(
      [actual.outcome, actual.policyStatus, actual.blockers, actual.missingEvidence],
      entry.expected,
      entry.name,
    );
  }
});

test("unverified, future-dated, and unsupported-action evidence fails closed", async () => {
  const { evaluateGuardReadiness } = await loadKernel();

  for (const verificationStatus of ["NOT_VERIFIED", "CONFLICTING"]) {
    const result = evaluateGuardReadiness({
      intent: intent(),
      evidence: [quoteEvidence({ verificationStatus })],
      policy,
      now: NOW,
    });
    assert.equal(result.outcome, "INSUFFICIENT_EVIDENCE", verificationStatus);
    assert.equal(result.policyStatus, "NOT_EVALUATED", verificationStatus);
  }

  const future = evaluateGuardReadiness({
    intent: intent(),
    evidence: [
      quoteEvidence({
        observedAt: "2026-08-06T12:00:30.000Z",
        receivedAt: "2026-08-06T12:00:31.000Z",
        validUntil: "2026-08-06T12:01:30.000Z",
      }),
    ],
    policy,
    now: NOW,
  });
  assert.equal(future.outcome, "EXPIRED");

  const expiredIntent = evaluateGuardReadiness({
    intent: intent({ expiresAt: NOW }),
    evidence: [quoteEvidence()],
    policy,
    now: NOW,
  });
  assert.equal(expiredIntent.outcome, "EXPIRED");
  assert.deepEqual(expiredIntent.missingEvidence, ["ACTIVE_INTENT"]);

  for (const actionType of ["SPEND", "BRIDGE"]) {
    const result = evaluateGuardReadiness({
      intent: intent({ actionType }),
      evidence: [quoteEvidence()],
      policy,
      now: NOW,
    });
    assert.equal(result.outcome, "UNSUPPORTED", actionType);
    assert.deepEqual(result.blockers, ["unsupported-action-type"], actionType);
  }
});
