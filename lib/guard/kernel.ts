export type GuardReadinessOutcome =
  | "ALLOWED_BY_POLICY"
  | "REVIEW_REQUIRED"
  | "BLOCKED_BY_RULE"
  | "INSUFFICIENT_EVIDENCE"
  | "UNSUPPORTED"
  | "EXPIRED";

export type GuardEvaluation = {
  outcome: GuardReadinessOutcome;
  policyDecision: GuardReadinessOutcome;
  dataStatus: "COMPLETE" | "PARTIAL" | "INSUFFICIENT" | "CONFLICTING" | "UNAVAILABLE";
  evidenceStatus: "COMPLETE" | "PARTIAL" | "INSUFFICIENT" | "CONFLICTING" | "UNAVAILABLE";
  policyStatus: "PASS" | "WARN" | "BLOCK" | "NOT_EVALUATED";
  authorizationStatus: "NOT_REQUIRED" | "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED" | "REVOKED";
  executionStatus:
    | "NOT_STARTED"
    | "SUBMITTED"
    | "SOURCE_CONFIRMED"
    | "IN_TRANSIT"
    | "DESTINATION_PENDING"
    | "CONFIRMED"
    | "FAILED"
    | "RECOVERY_REQUIRED"
    | "RECONCILIATION_REQUIRED"
    | "CANCELLED";
  blockers: string[];
  missingEvidence: string[];
  evidenceSummary?: Array<{
    id: string;
    provider: string;
    sourceRef: string;
    status: GuardEvidenceInput["status"];
    availability: GuardEvidenceInput["availability"];
    verificationStatus: GuardEvidenceInput["verificationStatus"];
    fallbackUsed: boolean;
  }>;
};

type GuardIntentInput = {
  chainRef: string;
  sellAssetRef: string;
  buyAssetRef: string;
  actionType?: string;
  executionBindingKind?: "EVM_TRANSACTION" | "APP_KIT_REQUEST";
  amount: string;
  leverage?: string | null;
  recipient: string;
  venueRef: string;
  routeRef: string;
  quoteRef: string | null;
  target?: string | null;
  calldataHash?: string | null;
  adapterRequestHash?: string | null;
  expiresAt: string;
};

type QuoteFacts = {
  quoteRef: string;
  providerRef: string;
  routeRef: string;
  sellAssetRef: string;
  buyAssetRef: string;
  amountIn: string;
  leverage?: string | null;
  venueRef?: string;
  recipientAddress?: string;
  tokenAddress?: string;
  calldataHash?: string;
  bindingHash?: string;
  expectedAmountOut: string;
  minimumAmountOut: string;
  feeAmount: string;
  feeAssetRef: string;
  totalDebit: string;
  slippageBps: string;
};

type GuardEvidenceInput = {
  sourceType: string;
  id: string;
  provider: string;
  sourceRef?: string;
  fallbackUsed: boolean;
  observedAt: string;
  validUntil: string;
  status: "VALID" | "STALE" | "MISSING" | "CONFLICTING" | "UNAVAILABLE" | "UNSUPPORTED";
  availability?: "AVAILABLE" | "PARTIAL" | "UNAVAILABLE" | "UNSUPPORTED";
  verificationStatus?: string;
  chainRef: string;
  facts: QuoteFacts;
};

type GuardRuleInput =
  | { id: string; type: "ALLOWED_CHAIN"; value: string }
  | { id: string; type: "ALLOWED_PAIR"; value: [string, string] }
  | { id: string; type: "MAX_TOTAL_DEBIT"; value: string; currencyAssetRef: string }
  | { id: string; type: "MAX_QUOTE_AGE_SECONDS"; value: number }
  | { id: string; type: "MAX_SLIPPAGE_BPS"; value: string }
  | { id: string; type: "HUMAN_AUTHORIZATION_REQUIRED"; value: boolean };

type GuardEvaluationInput = {
  intent: GuardIntentInput;
  evidence: GuardEvidenceInput[];
  policy: { rules: GuardRuleInput[] };
  now: string;
};

const DECIMAL_PATTERN = /^(?:0|[1-9]\d*)(?:\.\d+)?$/;

function normalizedDecimal(value: string): { integer: string; fraction: string } {
  if (value.length < 1 || value.length > 128 || !DECIMAL_PATTERN.test(value)) {
    throw new Error("INVALID_DECIMAL_STRING");
  }
  const [rawInteger, rawFraction = ""] = value.split(".");
  return {
    integer: rawInteger.replace(/^0+(?=\d)/, ""),
    fraction: rawFraction.replace(/0+$/, ""),
  };
}

/**
 * Compares unsigned financial decimal strings without converting them to a
 * JavaScript number. Returns -1, 0, or 1.
 */
export function compareDecimalStrings(left: string, right: string): -1 | 0 | 1 {
  const a = normalizedDecimal(left);
  const b = normalizedDecimal(right);
  if (a.integer.length !== b.integer.length) {
    return a.integer.length < b.integer.length ? -1 : 1;
  }
  if (a.integer !== b.integer) {
    return a.integer < b.integer ? -1 : 1;
  }
  const width = Math.max(a.fraction.length, b.fraction.length);
  const aFraction = a.fraction.padEnd(width, "0");
  const bFraction = b.fraction.padEnd(width, "0");
  if (aFraction === bFraction) return 0;
  return aFraction < bFraction ? -1 : 1;
}

/** Adds unsigned financial decimal strings without binary floating point. */
export function addDecimalStrings(left: string, right: string): string {
  const a = normalizedDecimal(left);
  const b = normalizedDecimal(right);
  const width = Math.max(a.fraction.length, b.fraction.length);
  const aUnits = BigInt(`${a.integer}${a.fraction.padEnd(width, "0")}`);
  const bUnits = BigInt(`${b.integer}${b.fraction.padEnd(width, "0")}`);
  const rendered = (aUnits + bUnits).toString().padStart(width + 1, "0");
  if (width === 0) return rendered;
  const integer = rendered.slice(0, -width);
  const fraction = rendered.slice(-width).replace(/0+$/, "");
  return fraction ? `${integer}.${fraction}` : integer;
}

function decimalUnits(value: string, scale: number): bigint {
  const parsed = normalizedDecimal(value);
  return BigInt(`${parsed.integer}${parsed.fraction.padEnd(scale, "0")}`);
}

function derivedSlippageExceedsBps({
  expectedAmountOut,
  minimumAmountOut,
  maximumBps,
}: {
  expectedAmountOut: string;
  minimumAmountOut: string;
  maximumBps: string;
}): boolean {
  const expected = normalizedDecimal(expectedAmountOut);
  const minimum = normalizedDecimal(minimumAmountOut);
  const bps = normalizedDecimal(maximumBps);
  const outputScale = Math.max(expected.fraction.length, minimum.fraction.length);
  const bpsScale = bps.fraction.length;
  const expectedUnits = decimalUnits(expectedAmountOut, outputScale);
  const minimumUnits = decimalUnits(minimumAmountOut, outputScale);
  if (expectedUnits <= 0n || minimumUnits > expectedUnits) {
    throw new Error("INVALID_SLIPPAGE_OUTPUTS");
  }
  const maximumBpsUnits = decimalUnits(maximumBps, bpsScale);
  const bpsScaleFactor = 10n ** BigInt(bpsScale);
  return (
    (expectedUnits - minimumUnits) * 10_000n * bpsScaleFactor >
    expectedUnits * maximumBpsUnits
  );
}

type GuardEvaluationWithoutAliases = Omit<
  GuardEvaluation,
  "evidenceStatus" | "policyDecision"
>;

function withIndependentAxes(value: GuardEvaluationWithoutAliases): GuardEvaluation {
  return {
    ...value,
    evidenceStatus: value.dataStatus,
    policyDecision: value.outcome,
  };
}

function incomplete(
  outcome: "INSUFFICIENT_EVIDENCE" | "EXPIRED",
  missing: string[],
  options: {
    dataStatus?: GuardEvaluation["dataStatus"];
    evidenceSummary?: GuardEvaluation["evidenceSummary"];
  } = {},
): GuardEvaluation {
  return withIndependentAxes({
    outcome,
    dataStatus: options.dataStatus ?? "INSUFFICIENT",
    policyStatus: "NOT_EVALUATED",
    authorizationStatus: "PENDING",
    executionStatus: "NOT_STARTED",
    blockers: [],
    missingEvidence: missing,
    evidenceSummary: options.evidenceSummary,
  });
}

export function evaluateGuardReadiness(input: GuardEvaluationInput): GuardEvaluation {
  const normalizedAvailability = (item: GuardEvidenceInput) =>
    item.availability ??
    ({
      VALID: "AVAILABLE",
      STALE: "PARTIAL",
      MISSING: "PARTIAL",
      CONFLICTING: "PARTIAL",
      UNAVAILABLE: "UNAVAILABLE",
      UNSUPPORTED: "UNSUPPORTED",
    } as const)[item.status];
  const evidenceSummary = input.evidence.map((item) => ({
    id: item.id,
    provider: item.provider,
    sourceRef: item.sourceRef ?? "UNSPECIFIED_LEGACY_SOURCE",
    status: item.status,
    availability: normalizedAvailability(item),
    verificationStatus: item.verificationStatus ?? "NOT_VERIFIED",
    fallbackUsed: item.fallbackUsed,
  }));
  if (input.intent.actionType !== "SWAP" && input.intent.actionType !== "SEND") {
    return withIndependentAxes({
      outcome: "UNSUPPORTED",
      dataStatus: "INSUFFICIENT",
      policyStatus: "NOT_EVALUATED",
      authorizationStatus: "PENDING",
      executionStatus: "NOT_STARTED",
      blockers: ["unsupported-action-type"],
      missingEvidence: [],
      evidenceSummary,
    });
  }
  const intentExpiresAt = Date.parse(input.intent.expiresAt);
  if (!Number.isFinite(intentExpiresAt) || intentExpiresAt <= Date.parse(input.now)) {
    return incomplete("EXPIRED", ["ACTIVE_INTENT"], { evidenceSummary });
  }
  const chainRule = input.policy.rules.find(
    (rule): rule is Extract<GuardRuleInput, { type: "ALLOWED_CHAIN" }> =>
      rule.type === "ALLOWED_CHAIN",
  );
  if (!chainRule || input.intent.chainRef !== chainRule.value) {
    return withIndependentAxes({
      outcome: "UNSUPPORTED",
      dataStatus: "PARTIAL",
      policyStatus: "BLOCK",
      authorizationStatus: "PENDING",
      executionStatus: "NOT_STARTED",
      blockers: [chainRule?.id ?? "allowed-chain"],
      missingEvidence: [],
    });
  }

  const pairRule = input.policy.rules.find(
    (rule): rule is Extract<GuardRuleInput, { type: "ALLOWED_PAIR" }> =>
      rule.type === "ALLOWED_PAIR",
  );
  if (
    !pairRule ||
    input.intent.sellAssetRef !== pairRule.value[0] ||
    input.intent.buyAssetRef !== pairRule.value[1]
  ) {
    return withIndependentAxes({
      outcome: "BLOCKED_BY_RULE",
      dataStatus: "PARTIAL",
      policyStatus: "BLOCK",
      authorizationStatus: "PENDING",
      executionStatus: "NOT_STARTED",
      blockers: [pairRule?.id ?? "allowed-pair"],
      missingEvidence: [],
    });
  }

  const requiredSourceType = input.intent.actionType === "SEND" ? "TRANSFER_PLAN" : "SWAP_QUOTE";
  const relevantEvidence = input.evidence.filter((item) => item.sourceType === requiredSourceType);
  if (relevantEvidence.length === 0) {
    return incomplete("INSUFFICIENT_EVIDENCE", [requiredSourceType]);
  }
  if (relevantEvidence.length !== 1) {
    return incomplete("INSUFFICIENT_EVIDENCE", [`UNAMBIGUOUS_${requiredSourceType}`]);
  }
  const quote = relevantEvidence[0];
  const quoteAvailability = normalizedAvailability(quote);
  const verificationAccepted = [
    "PROVIDER_REPORTED",
    "DETERMINISTICALLY_DERIVED",
    "ONCHAIN_VERIFIED",
  ].includes(quote.verificationStatus ?? "");
  if (
    quote.status !== "VALID" ||
    quoteAvailability !== "AVAILABLE" ||
    !verificationAccepted
  ) {
    return incomplete("INSUFFICIENT_EVIDENCE", [`VALID_${requiredSourceType}`], {
      dataStatus:
        quote.status === "UNAVAILABLE" || quoteAvailability === "UNAVAILABLE"
          ? "UNAVAILABLE"
          : quote.status === "CONFLICTING"
            ? "CONFLICTING"
            : "INSUFFICIENT",
      evidenceSummary,
    });
  }

  const now = Date.parse(input.now);
  const observedAt = Date.parse(quote.observedAt);
  const validUntil = Date.parse(quote.validUntil);
  const ageRule = input.policy.rules.find(
    (rule): rule is Extract<GuardRuleInput, { type: "MAX_QUOTE_AGE_SECONDS" }> =>
      rule.type === "MAX_QUOTE_AGE_SECONDS",
  );
  if (
    !Number.isFinite(now) ||
    !Number.isFinite(observedAt) ||
    !Number.isFinite(validUntil) ||
    observedAt > now ||
    validUntil <= now ||
    !ageRule ||
    now - observedAt >= ageRule.value * 1_000
  ) {
    return incomplete("EXPIRED", [`FRESH_${requiredSourceType}`]);
  }

  const financialValues = [
    input.intent.amount,
    quote.facts.amountIn,
    quote.facts.expectedAmountOut,
    quote.facts.minimumAmountOut,
    quote.facts.feeAmount,
    quote.facts.totalDebit,
    quote.facts.slippageBps,
  ];
  if (
    !financialValues.every(
      (value) =>
        typeof value === "string" &&
        value.length >= 1 &&
        value.length <= 128 &&
        DECIMAL_PATTERN.test(value),
    )
  ) {
    return incomplete("INSUFFICIENT_EVIDENCE", ["BOUNDED_FINANCIAL_PLAN"], {
      dataStatus: "CONFLICTING",
      evidenceSummary,
    });
  }

  if (
    quote.chainRef !== input.intent.chainRef ||
    quote.facts.quoteRef !== input.intent.quoteRef ||
    quote.facts.sellAssetRef !== input.intent.sellAssetRef ||
    quote.facts.buyAssetRef !== input.intent.buyAssetRef ||
    typeof quote.facts.amountIn !== "string" ||
    compareDecimalStrings(quote.facts.amountIn, input.intent.amount) !== 0 ||
    (quote.facts.leverage ?? null) !== (input.intent.leverage ?? null) ||
    quote.facts.routeRef !== input.intent.routeRef ||
    quote.facts.venueRef !== input.intent.venueRef ||
    typeof quote.facts.recipientAddress !== "string" ||
    quote.facts.recipientAddress.toLowerCase() !== input.intent.recipient.toLowerCase() ||
    (input.intent.actionType === "SEND" &&
      (typeof quote.facts.tokenAddress !== "string" ||
        quote.facts.tokenAddress.toLowerCase() !== input.intent.target?.toLowerCase() ||
        typeof quote.facts.calldataHash !== "string" ||
        quote.facts.calldataHash.toLowerCase() !== input.intent.calldataHash?.toLowerCase())) ||
    (input.intent.actionType === "SWAP" &&
      input.intent.executionBindingKind === "APP_KIT_REQUEST" &&
      (typeof quote.facts.bindingHash !== "string" ||
        quote.facts.bindingHash.toLowerCase() !== input.intent.adapterRequestHash?.toLowerCase()))
  ) {
    return incomplete("INSUFFICIENT_EVIDENCE", [`INTENT_BOUND_${requiredSourceType}`]);
  }

  try {
    if (
      typeof quote.facts.feeAssetRef !== "string" ||
      quote.facts.feeAssetRef.toLowerCase() !== input.intent.sellAssetRef.toLowerCase()
    ) {
      return incomplete("INSUFFICIENT_EVIDENCE", ["CONSISTENT_FINANCIAL_PLAN"], {
        dataStatus: "CONFLICTING",
        evidenceSummary,
      });
    }
    const calculatedTotalDebit = addDecimalStrings(
      quote.facts.amountIn,
      quote.facts.feeAmount,
    );
    if (
      compareDecimalStrings(calculatedTotalDebit, quote.facts.totalDebit) !== 0 ||
      compareDecimalStrings(quote.facts.minimumAmountOut, quote.facts.expectedAmountOut) === 1
    ) {
      return incomplete("INSUFFICIENT_EVIDENCE", ["CONSISTENT_FINANCIAL_PLAN"], {
        dataStatus: "CONFLICTING",
        evidenceSummary,
      });
    }
  } catch {
    return incomplete("INSUFFICIENT_EVIDENCE", ["CONSISTENT_FINANCIAL_PLAN"], {
      dataStatus: "CONFLICTING",
      evidenceSummary,
    });
  }

  const maxDebitRule = input.policy.rules.find(
    (rule): rule is Extract<GuardRuleInput, { type: "MAX_TOTAL_DEBIT" }> =>
      rule.type === "MAX_TOTAL_DEBIT",
  );
  if (
    !maxDebitRule ||
    !DECIMAL_PATTERN.test(maxDebitRule.value) ||
    maxDebitRule.value.length > 128 ||
    maxDebitRule.currencyAssetRef !== input.intent.sellAssetRef ||
    compareDecimalStrings(quote.facts.totalDebit, maxDebitRule.value) === 1
  ) {
    return withIndependentAxes({
      outcome: "BLOCKED_BY_RULE",
      dataStatus: "COMPLETE",
      policyStatus: "BLOCK",
      authorizationStatus: "PENDING",
      executionStatus: "NOT_STARTED",
      blockers: [maxDebitRule?.id ?? "max-total-debit"],
      missingEvidence: [],
    });
  }

  const slippageRule = input.policy.rules.find(
    (rule): rule is Extract<GuardRuleInput, { type: "MAX_SLIPPAGE_BPS" }> =>
      rule.type === "MAX_SLIPPAGE_BPS",
  );
  const requiresAuthorization =
    input.policy.rules.find((rule) => rule.type === "HUMAN_AUTHORIZATION_REQUIRED")?.value === true;
  let derivedSlippageOverPolicy = true;
  if (
    slippageRule &&
    DECIMAL_PATTERN.test(slippageRule.value) &&
    slippageRule.value.length <= 128
  ) {
    try {
      derivedSlippageOverPolicy = derivedSlippageExceedsBps({
        expectedAmountOut: quote.facts.expectedAmountOut,
        minimumAmountOut: quote.facts.minimumAmountOut,
        maximumBps: slippageRule.value,
      });
    } catch {
      derivedSlippageOverPolicy = true;
    }
  }
  const review =
    !slippageRule ||
    !DECIMAL_PATTERN.test(slippageRule.value) ||
    slippageRule.value.length > 128 ||
    compareDecimalStrings(quote.facts.slippageBps, slippageRule.value) === 1 ||
    derivedSlippageOverPolicy;

  return withIndependentAxes({
    outcome: review ? "REVIEW_REQUIRED" : "ALLOWED_BY_POLICY",
    dataStatus: "COMPLETE",
    policyStatus: review ? "WARN" : "PASS",
    authorizationStatus: requiresAuthorization ? "PENDING" : "NOT_REQUIRED",
    executionStatus: "NOT_STARTED",
    blockers: [],
    missingEvidence: [],
    evidenceSummary,
  });
}
