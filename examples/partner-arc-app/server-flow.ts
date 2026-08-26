import { RyntraGuardClient } from "../../packages/guard-sdk/src/index.ts";

type PartnerArcFlowInput = {
  intentInput: Record<string, unknown>;
  evidence: Record<string, unknown>;
  fingerprint: Record<string, unknown>;
  subjectRef: string;
  transactionHash: string;
};

/**
 * Server-side partner integration example. The partner application obtains the
 * Arc transactionHash only after its user separately approves the transaction
 * in their own wallet. Ryntra receives no signing credential.
 */
export async function recordPartnerArcFlow(input: PartnerArcFlowInput) {
  const client = new RyntraGuardClient({
    baseUrl: process.env.RYNTRA_GUARD_BASE_URL ?? "http://localhost:3000",
    apiKey: process.env.RYNTRA_GUARD_API_KEY,
  });

  const intent = await client.intents.create<{ id: string }>(input.intentInput, {
    idempotencyKey: "partner-create-order-001",
  });
  const evaluation = await client.preflight<{
    id: string;
    evidenceStatus: string;
    policyDecision: string;
  }>(
    intent.id,
    { evidence: [input.evidence] },
    { idempotencyKey: "partner-preflight-order-001" },
  );
  if (["BLOCKED_BY_RULE", "INSUFFICIENT_EVIDENCE", "EXPIRED", "UNSUPPORTED"].includes(evaluation.policyDecision)) {
    return { intent, evaluation, authorization: null, execution: null };
  }

  const authorization = await client.authorize<{ id: string }>(
    {
      intentId: intent.id,
      evaluationId: evaluation.id,
      fingerprint: input.fingerprint,
      subjectRef: input.subjectRef,
      method: "PARTNER_AUTHENTICATED",
    },
    { idempotencyKey: "partner-authorize-order-001" },
  );

  const execution = await client.executions.record(
    {
      intentId: intent.id,
      authorizationId: authorization.id,
      fingerprint: input.fingerprint,
      transactionHash: input.transactionHash,
    },
    { idempotencyKey: "partner-record-order-001" },
  );
  return { intent, evaluation, authorization, execution };
}
