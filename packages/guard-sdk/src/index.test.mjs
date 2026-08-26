// Run from repo root: node --test packages/guard-sdk/src/index.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";
import ts from "typescript";

async function loadSdk() {
  try {
    return await import("./index.ts");
  } catch (error) {
    assert.fail(`Headless Guard SDK is missing: ${error instanceof Error ? error.message : String(error)}`);
  }
}

test("the SDK sends server credentials in headers and idempotency on every mutation", async () => {
  const { RyntraGuardClient } = await loadSdk();
  const calls = [];
  const fetch = async (url, init) => {
    calls.push({ url, init });
    return new Response(JSON.stringify({ data: { id: "int_sdk_001" } }), {
      status: 201,
      headers: { "content-type": "application/json", "x-correlation-id": "corr_server_001" },
    });
  };
  const client = new RyntraGuardClient({
    baseUrl: "https://guard.example/",
    apiKey: "server-only-key",
    fetch,
    createCorrelationId: () => "corr_sdk_001",
  });
  const result = await client.intents.create(
    { amount: "10.00", chainRef: "eip155:5042002" },
    { idempotencyKey: "idem-sdk-create-001" },
  );
  assert.equal(result.id, "int_sdk_001");
  assert.equal(calls[0].url, "https://guard.example/v1/intents");
  assert.equal(calls[0].init.headers.authorization, "Bearer server-only-key");
  assert.equal(calls[0].init.headers["idempotency-key"], "idem-sdk-create-001");
  assert.equal(calls[0].init.headers["x-correlation-id"], "corr_sdk_001");
  assert.equal(new URL(calls[0].url).searchParams.has("key"), false);
  assert.deepEqual(JSON.parse(calls[0].init.body), { amount: "10.00", chainRef: "eip155:5042002" });
});

test("the SDK exposes the exact intent lifecycle endpoints", async () => {
  const { RyntraGuardClient } = await loadSdk();
  const calls = [];
  const fetch = async (url, init = {}) => {
    calls.push({ url, init });
    return new Response(JSON.stringify({ data: { ok: true } }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new RyntraGuardClient({ baseUrl: "https://guard.example", apiKey: "key", fetch });
  await client.intents.list({ limit: 25 });
  await client.intents.get("int_001");
  await client.preflight("int_001", { evidence: [] }, { idempotencyKey: "idem-preflight-001" });
  await client.evaluations.get("eval_001");
  await client.authorize(
    { intentId: "int_001", evaluationId: "eval_001", fingerprint: {}, subjectRef: "subject", method: "PARTNER_AUTHENTICATED" },
    { idempotencyKey: "idem-authorize-001" },
  );
  await client.executions.record(
    { intentId: "int_001", authorizationId: "auth_001", fingerprint: {}, transactionHash: `0x${"ab".repeat(32)}` },
    { idempotencyKey: "idem-execute-001" },
  );
  await client.executions.reconcile(
    {
      intentId: "int_001",
      transactionHash: `0x${"ab".repeat(32)}`,
      observedState: "CONFIRMED",
      observedAt: "2026-08-08T12:00:00.000Z",
      actualOutcome: {
        amountIn: "10.00",
        amountOut: "9.95",
        feeAmount: "0.02",
        explorerUrl: `https://testnet.arcscan.app/tx/0x${"ab".repeat(32)}`,
      },
    },
    { idempotencyKey: "idem-reconcile-001" },
  );
  await client.status.getByIntent("int_001");
  await client.receipts.getByIntent("int_001");
  assert.deepEqual(calls.map((call) => new URL(call.url).pathname), [
    "/v1/intents",
    "/v1/intents/int_001",
    "/v1/intents/int_001/preflight",
    "/v1/evaluations/eval_001",
    "/v1/intents/int_001/authorize",
    "/v1/intents/int_001/executions",
    "/v1/intents/int_001/executions",
    "/v1/intents/int_001/status",
    "/v1/intents/int_001/receipt",
  ]);
  assert.equal(new URL(calls[0].url).searchParams.get("limit"), "25");
  assert.equal(
    JSON.parse(calls[6].init.body).observedAt,
    "2026-08-08T12:00:00.000Z",
  );
});

test("the SDK reconcile input is a generated-client-safe conditional union", () => {
  const fixturePath = fileURLToPath(new URL("./reconcile-contract.fixture.ts", import.meta.url));
  const fixtureSource = `
    import { RyntraGuardClient } from "./index.ts";
    declare const client: RyntraGuardClient;
    declare const options: { idempotencyKey: string };
    const transactionHash = "0x${"ab".repeat(32)}";
    const actualOutcome = {
      amountIn: "10.00",
      amountOut: "9.95",
      feeAmount: "0.02",
      explorerUrl: "https://testnet.arcscan.app/tx/0x${"ab".repeat(32)}",
    };

    client.executions.reconcile({
      intentId: "int_001",
      transactionHash,
      observedState: "CONFIRMED",
      observedAt: "2026-08-08T12:00:00.000Z",
      actualOutcome,
    }, options);
    client.executions.reconcile({
      intentId: "int_001",
      transactionHash,
      observedState: "RPC_UNCERTAIN_AFTER_BROADCAST",
    }, options);
    client.executions.reconcile({
      intentId: "int_001",
      transactionHash,
      observedState: "RPC_UNCERTAIN_AFTER_BROADCAST",
      observedAt: "2026-08-08T12:00:00.000Z",
      actualOutcome,
    }, options);
    // @ts-expect-error CONFIRMED requires observedAt and actualOutcome.
    client.executions.reconcile({
      intentId: "int_001",
      transactionHash,
      observedState: "CONFIRMED",
    }, options);
  `;
  const compilerOptions = {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.ESNext,
    moduleResolution: ts.ModuleResolutionKind.Bundler,
    allowImportingTsExtensions: true,
    strict: true,
    noEmit: true,
    skipLibCheck: true,
  };
  const host = ts.createCompilerHost(compilerOptions);
  const normalizedFixturePath = path.normalize(fixturePath);
  const originalFileExists = host.fileExists.bind(host);
  const originalReadFile = host.readFile.bind(host);
  const originalGetSourceFile = host.getSourceFile.bind(host);
  host.fileExists = (fileName) =>
    path.normalize(fileName) === normalizedFixturePath || originalFileExists(fileName);
  host.readFile = (fileName) =>
    path.normalize(fileName) === normalizedFixturePath ? fixtureSource : originalReadFile(fileName);
  host.getSourceFile = (fileName, languageVersion, onError, shouldCreateNewSourceFile) =>
    path.normalize(fileName) === normalizedFixturePath
      ? ts.createSourceFile(fileName, fixtureSource, languageVersion, true)
      : originalGetSourceFile(fileName, languageVersion, onError, shouldCreateNewSourceFile);
  const program = ts.createProgram([fixturePath], compilerOptions, host);
  const diagnostics = ts.getPreEmitDiagnostics(program);
  assert.deepEqual(
    diagnostics.map((diagnostic) => ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n")),
    [],
  );
});

test("the SDK rejects unsupported list limits and authorization methods", async () => {
  const { RyntraGuardClient } = await loadSdk();
  const client = new RyntraGuardClient({
    baseUrl: "https://guard.example",
    fetch: async () => new Response(JSON.stringify({ data: {} })),
  });
  assert.throws(() => client.intents.list({ limit: 0 }), /integer from 1 to 200/);
  for (const craftedLegacyId of ["tenantB:int_001", "tenantB.int_001", "..."]) {
    assert.throws(
      () => client.intents.get(craftedLegacyId),
      /Invalid Guard identifier/,
    );
  }
  const source = await readFile(new URL("./index.ts", import.meta.url), "utf8");
  const authorizeInput = source.slice(source.indexOf("readonly authorize"), source.indexOf("readonly executions"));
  assert.doesNotMatch(authorizeInput, /EIP712/);
  assert.match(authorizeInput, /method: "PARTNER_AUTHENTICATED"/);
});

test("structured API failures become typed SDK errors with correlation and remediation", async () => {
  const { RyntraGuardApiError, RyntraGuardClient } = await loadSdk();
  const fetch = async () =>
    new Response(
      JSON.stringify({
        error: {
          code: "FINGERPRINT_MISMATCH",
          message: "Execution differs from authorization.",
          retryable: false,
          requiredAction: "CREATE_NEW_EVALUATION",
          correlationId: "corr_failure_001",
        },
      }),
      { status: 409, headers: { "content-type": "application/json" } },
    );
  const client = new RyntraGuardClient({ baseUrl: "https://guard.example", apiKey: "key", fetch });
  await assert.rejects(
    () => client.receipts.getByIntent("int_001"),
    (error) => {
      assert.equal(error instanceof RyntraGuardApiError, true);
      assert.equal(error.code, "FINGERPRINT_MISMATCH");
      assert.equal(error.status, 409);
      assert.equal(error.correlationId, "corr_failure_001");
      return true;
    },
  );
});

test("the headless SDK contains no private-key or seed-phrase execution surface", async () => {
  const source = await readFile(new URL("./index.ts", import.meta.url), "utf8");
  assert.doesNotMatch(source, /privateKey|private_key|seedPhrase|seed_phrase|wallet\.execute/i);
});

test("the SDK exposes all seventeen payout operations with a dedicated principal credential", async () => {
  const { RyntraGuardClient } = await loadSdk();
  const calls = [];
  const fetch = async (url, init = {}) => {
    calls.push({ url, init });
    return new Response(JSON.stringify({ data: { ok: true } }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  const client = new RyntraGuardClient({
    baseUrl: "https://guard.example",
    apiKey: "legacy-intent-key",
    payoutPrincipalToken: "payout-principal-token",
    fetch,
    createCorrelationId: () => "corr_payout_sdk_001",
  });
  const options = { idempotencyKey: "idem-payout-sdk-001" };
  const payoutId = "pay.partner:v1";
  const policyId = "pol.partner:v1";
  const beneficiaryId = "ben.partner:v1";
  const policy = {
    maxPerPayoutBaseUnits: "500000000",
    dailyOutflowLimitBaseUnits: "1000000000",
    minimumPostPayoutReserveBaseUnits: "10000000",
    maxFeeNativeUnits: "2000000000000000",
    evidenceMaxAgeSeconds: 120,
    authorizationTtlSeconds: 900,
    beneficiaryActivationDelaySeconds: 0,
    secondApprovalThresholdBaseUnits: "100000000",
    allowedPurposeCodes: ["INVOICE"],
  };
  const beneficiary = {
    label: "Supplier",
    walletAddress: "0x2222222222222222222222222222222222222222",
    activationDelaySeconds: 0,
  };

  await client.payouts.list({ limit: 25, offset: 5 });
  await client.payouts.create({
    applicationId: "app_001",
    businessKey: "invoice-1",
    treasuryWalletAddress: "0x1111111111111111111111111111111111111111",
    beneficiaryId,
    amount: "50.000000",
    purposeCode: "INVOICE",
    externalReferenceHash: null,
    policyId,
  }, options);
  await client.payouts.get(payoutId);
  await client.payouts.preflight(payoutId, options);
  await client.payouts.approve(payoutId, { decision: "APPROVED", fingerprintHash: `0x${"aa".repeat(32)}` }, options);
  await client.payouts.executionPackage(payoutId);
  await client.payouts.recordExecution(payoutId, `0x${"ab".repeat(32)}`, options);
  await client.payouts.status(payoutId);
  await client.payouts.receipt(payoutId);
  await client.payoutPolicies.list({ limit: 10, offset: 2 });
  await client.payoutPolicies.createVersion(policyId, policy, options);
  await client.payoutPolicies.activate(policyId, 1, options);
  await client.payoutBeneficiaries.list({ limit: 11, offset: 3 });
  await client.payoutBeneficiaries.create({ beneficiaryId, ...beneficiary }, options);
  await client.payoutBeneficiaries.createVersion(beneficiaryId, beneficiary, options);
  await client.payoutBeneficiaries.activate(beneficiaryId, 1, options);
  await client.payoutBeneficiaries.disable(beneficiaryId, options);

  assert.equal(calls.length, 17);
  assert.deepEqual(calls.map((call) => `${call.init.method ?? "GET"} ${new URL(call.url).pathname}`), [
    "GET /v1/payouts",
    "POST /v1/payouts",
    "GET /v1/payouts/pay.partner%3Av1",
    "POST /v1/payouts/pay.partner%3Av1/preflight",
    "POST /v1/payouts/pay.partner%3Av1/approvals",
    "GET /v1/payouts/pay.partner%3Av1/execution-package",
    "POST /v1/payouts/pay.partner%3Av1/executions",
    "GET /v1/payouts/pay.partner%3Av1/status",
    "GET /v1/payouts/pay.partner%3Av1/receipt",
    "GET /v1/payout-policies",
    "POST /v1/payout-policies/pol.partner%3Av1/versions",
    "POST /v1/payout-policies/pol.partner%3Av1/versions/1/activate",
    "GET /v1/payout-beneficiaries",
    "POST /v1/payout-beneficiaries",
    "POST /v1/payout-beneficiaries/ben.partner%3Av1/versions",
    "POST /v1/payout-beneficiaries/ben.partner%3Av1/versions/1/activate",
    "POST /v1/payout-beneficiaries/ben.partner%3Av1/disable",
  ]);
  assert.equal(new URL(calls[0].url).search, "?limit=25&offset=5");
  assert.equal(new URL(calls[9].url).search, "?limit=10&offset=2");
  assert.equal(new URL(calls[12].url).search, "?limit=11&offset=3");
  for (const index of [3, 11, 15, 16]) {
    assert.deepEqual(JSON.parse(calls[index].init.body), {}, "empty mutations still send a validated JSON object");
  }
  for (const call of calls) {
    assert.equal(call.init.headers.authorization, "Bearer payout-principal-token");
    assert.notEqual(call.init.headers.authorization, "Bearer legacy-intent-key");
  }
  assert.deepEqual(JSON.parse(calls[4].init.body), {
    decision: "APPROVED",
    fingerprintHash: `0x${"aa".repeat(32)}`,
  });
  assert.deepEqual(JSON.parse(calls[6].init.body), { transactionHash: `0x${"ab".repeat(32)}` });
});
