export type RyntraGuardRequestOptions = {
  idempotencyKey?: string;
  correlationId?: string;
  signal?: AbortSignal;
};

export type RyntraGuardClientOptions = {
  baseUrl: string;
  apiKey?: string;
  /** Dedicated principal credential for `/v1/payout*`; never reused from apiKey. */
  payoutPrincipalToken?: string;
  fetch?: typeof globalThis.fetch;
  createCorrelationId?: () => string;
};

export type RyntraGuardActualOutcome = {
  amountIn: string;
  amountOut: string;
  feeAmount: string;
  explorerUrl: string;
};

export type RyntraPayoutCreateInput = {
  applicationId: string;
  businessKey: string;
  treasuryWalletAddress: string;
  beneficiaryId: string;
  amount: string;
  purposeCode: "INVOICE" | "PAYROLL" | "REFUND" | "TREASURY_TRANSFER";
  externalReferenceHash?: string | null;
  policyId: string;
};

export type RyntraPayoutPolicyVersionInput = {
  maxPerPayoutBaseUnits: string;
  dailyOutflowLimitBaseUnits: string;
  minimumPostPayoutReserveBaseUnits: string;
  maxFeeNativeUnits: string;
  evidenceMaxAgeSeconds: number;
  authorizationTtlSeconds: number;
  beneficiaryActivationDelaySeconds: number;
  secondApprovalThresholdBaseUnits: string;
  allowedPurposeCodes: Array<"INVOICE" | "PAYROLL" | "REFUND" | "TREASURY_TRANSFER">;
};

export type RyntraPayoutBeneficiaryVersionInput = {
  label: string;
  walletAddress: string;
  activationDelaySeconds: number;
};

type RyntraGuardReconcileBase = {
  intentId: string;
  transactionHash: string;
};

export type RyntraGuardReconcileInput =
  | (RyntraGuardReconcileBase & {
      observedState: "CONFIRMED";
      observedAt: string;
      actualOutcome: RyntraGuardActualOutcome;
    })
  | (RyntraGuardReconcileBase & {
      observedState: "RPC_UNCERTAIN_AFTER_BROADCAST";
      observedAt?: string;
      actualOutcome?: RyntraGuardActualOutcome;
    });

type GuardErrorBody = {
  error?: {
    code?: string;
    message?: string;
    retryable?: boolean;
    requiredAction?: string | null;
    correlationId?: string;
  };
};

export class RyntraGuardApiError extends Error {
  readonly code: string;
  readonly status: number;
  readonly retryable: boolean;
  readonly requiredAction: string | null;
  readonly correlationId: string | null;

  constructor(
    message: string,
    options: {
      code: string;
      status: number;
      retryable?: boolean;
      requiredAction?: string | null;
      correlationId?: string | null;
    },
  ) {
    super(message);
    this.name = "RyntraGuardApiError";
    this.code = options.code;
    this.status = options.status;
    this.retryable = options.retryable ?? false;
    this.requiredAction = options.requiredAction ?? null;
    this.correlationId = options.correlationId ?? null;
  }
}

function defaultCorrelationId(): string {
  return `corr_${globalThis.crypto.randomUUID().replaceAll("-", "")}`;
}

function legacyIdentifier(value: string): string {
  if (!/^[A-Za-z0-9_-]{3,128}$/.test(value)) {
    throw new TypeError("Invalid Guard identifier.");
  }
  return encodeURIComponent(value);
}

function payoutIdentifier(value: string): string {
  if (!/^[A-Za-z0-9._:-]{3,128}$/.test(value)) {
    throw new TypeError("Invalid Guard identifier.");
  }
  return encodeURIComponent(value);
}

function intentListPath(limit?: number): string {
  if (limit === undefined) return "/v1/intents";
  if (!Number.isInteger(limit) || limit < 1 || limit > 200) {
    throw new TypeError("Guard intent list limit must be an integer from 1 to 200.");
  }
  return `/v1/intents?${new URLSearchParams({ limit: String(limit) })}`;
}

function payoutListPath(query: { limit?: number; offset?: number } = {}): string {
  const search = new URLSearchParams();
  if (query.limit !== undefined) {
    if (!Number.isInteger(query.limit) || query.limit < 1 || query.limit > 200) {
      throw new TypeError("Guard payout list limit must be an integer from 1 to 200.");
    }
    search.set("limit", String(query.limit));
  }
  if (query.offset !== undefined) {
    if (!Number.isInteger(query.offset) || query.offset < 0 || query.offset > 1_000_000) {
      throw new TypeError("Guard payout list offset must be an integer from 0 to 1000000.");
    }
    search.set("offset", String(query.offset));
  }
  const value = search.toString();
  return value ? `/v1/payouts?${value}` : "/v1/payouts";
}

function payoutResourceListPath(
  path: "/v1/payout-policies" | "/v1/payout-beneficiaries",
  query: { limit?: number; offset?: number } = {},
): string {
  const payoutPath = payoutListPath(query);
  return `${path}${payoutPath.slice("/v1/payouts".length)}`;
}

function positiveVersion(value: number): string {
  if (!Number.isInteger(value) || value < 1 || value > 999_999_999) {
    throw new TypeError("Guard resource version must be a positive integer.");
  }
  return String(value);
}

export class RyntraGuardClient {
  private readonly baseUrl: string;
  private readonly apiKey: string | undefined;
  private readonly payoutPrincipalToken: string | undefined;
  private readonly fetcher: typeof globalThis.fetch;
  private readonly createCorrelationId: () => string;

  constructor(options: RyntraGuardClientOptions) {
    const parsed = new URL(options.baseUrl);
    if (parsed.protocol !== "https:" && parsed.hostname !== "localhost" && parsed.hostname !== "127.0.0.1") {
      throw new TypeError("Guard baseUrl must use HTTPS outside localhost.");
    }
    this.baseUrl = parsed.toString().replace(/\/$/, "");
    this.apiKey = options.apiKey;
    this.payoutPrincipalToken = options.payoutPrincipalToken;
    this.fetcher = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.createCorrelationId = options.createCorrelationId ?? defaultCorrelationId;
  }

  private async request<T>(
    path: string,
    init: {
      method?: "GET" | "POST";
      body?: unknown;
      options?: RyntraGuardRequestOptions;
      credential?: "LEGACY" | "PAYOUT";
    } = {},
  ): Promise<T> {
    const method = init.method ?? "GET";
    const headers: Record<string, string> = {
      accept: "application/json",
      "x-correlation-id": init.options?.correlationId ?? this.createCorrelationId(),
    };
    const credential = init.credential === "PAYOUT" ? this.payoutPrincipalToken : this.apiKey;
    if (credential) headers.authorization = `Bearer ${credential}`;
    if (method === "POST") {
      headers["content-type"] = "application/json";
      if (!init.options?.idempotencyKey) {
        throw new TypeError("A state-changing Guard request requires idempotencyKey.");
      }
      headers["idempotency-key"] = init.options.idempotencyKey;
    }
    const response = await this.fetcher(`${this.baseUrl}${path}`, {
      method,
      headers,
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
      signal: init.options?.signal,
    });
    let payload: unknown = null;
    try {
      payload = await response.json();
    } catch {
      payload = null;
    }
    if (!response.ok) {
      const error = (payload ?? {}) as GuardErrorBody;
      throw new RyntraGuardApiError(
        error.error?.message ?? "Ryntra Guard request failed.",
        {
          code: error.error?.code ?? "UNKNOWN_API_ERROR",
          status: response.status,
          retryable: error.error?.retryable,
          requiredAction: error.error?.requiredAction,
          correlationId:
            error.error?.correlationId ?? response.headers.get("x-correlation-id"),
        },
      );
    }
    if (!payload || typeof payload !== "object" || !("data" in payload)) {
      throw new RyntraGuardApiError("Ryntra Guard returned an invalid response envelope.", {
        code: "INVALID_RESPONSE",
        status: response.status,
        correlationId: response.headers.get("x-correlation-id"),
      });
    }
    return (payload as { data: T }).data;
  }

  readonly intents = {
    create: <T = Record<string, unknown>>(
      input: unknown,
      options: RyntraGuardRequestOptions,
    ) => this.request<T>("/v1/intents", { method: "POST", body: input, options }),
    get: <T = Record<string, unknown>>(intentId: string, options?: RyntraGuardRequestOptions) =>
      this.request<T>(`/v1/intents/${legacyIdentifier(intentId)}`, { options }),
    list: <T = Record<string, unknown>>(
      query: { limit?: number } = {},
      options?: RyntraGuardRequestOptions,
    ) => this.request<T>(intentListPath(query.limit), { options }),
  };

  readonly preflight = <T = Record<string, unknown>>(
    intentId: string,
    input: { evidence: unknown[] },
    options: RyntraGuardRequestOptions,
  ) =>
    this.request<T>(`/v1/intents/${legacyIdentifier(intentId)}/preflight`, {
      method: "POST",
      body: input,
      options,
    });

  readonly evaluations = {
    get: <T = Record<string, unknown>>(
      evaluationId: string,
      options?: RyntraGuardRequestOptions,
    ) => this.request<T>(`/v1/evaluations/${legacyIdentifier(evaluationId)}`, { options }),
  };

  readonly authorize = <T = Record<string, unknown>>(
    input: {
      intentId: string;
      evaluationId: string;
      fingerprint: unknown;
      subjectRef: string;
      method: "PARTNER_AUTHENTICATED";
    },
    options: RyntraGuardRequestOptions,
  ) => {
    const { intentId, ...body } = input;
    return this.request<T>(`/v1/intents/${legacyIdentifier(intentId)}/authorize`, {
      method: "POST",
      body,
      options,
    });
  };

  readonly executions = {
    record: <T = Record<string, unknown>>(
      input: {
        intentId: string;
        authorizationId: string;
        fingerprint: unknown;
        transactionHash: string;
      },
      options: RyntraGuardRequestOptions,
    ) => {
      const { intentId, ...record } = input;
      return this.request<T>(`/v1/intents/${legacyIdentifier(intentId)}/executions`, {
        method: "POST",
        body: { operation: "RECORD", ...record },
        options,
      });
    },
    reconcile: <T = Record<string, unknown>>(
      input: RyntraGuardReconcileInput,
      options: RyntraGuardRequestOptions,
    ) => {
      const { intentId, ...reconciliation } = input;
      return this.request<T>(`/v1/intents/${legacyIdentifier(intentId)}/executions`, {
        method: "POST",
        body: { operation: "RECONCILE", ...reconciliation },
        options,
      });
    },
  };

  readonly status = {
    getByIntent: <T = Record<string, unknown>>(
      intentId: string,
      options?: RyntraGuardRequestOptions,
    ) => this.request<T>(`/v1/intents/${legacyIdentifier(intentId)}/status`, { options }),
  };

  readonly receipts = {
    getByIntent: <T = Record<string, unknown>>(
      intentId: string,
      options?: RyntraGuardRequestOptions,
    ) => this.request<T>(`/v1/intents/${legacyIdentifier(intentId)}/receipt`, { options }),
  };

  readonly capabilities = {
    list: <T = Record<string, unknown>>(options?: RyntraGuardRequestOptions) =>
      this.request<T>("/v1/capabilities", { options }),
  };

  readonly payouts = {
    create: <T = Record<string, unknown>>(
      input: RyntraPayoutCreateInput,
      options: RyntraGuardRequestOptions,
    ) => this.request<T>("/v1/payouts", { method: "POST", body: input, options, credential: "PAYOUT" }),
    get: <T = Record<string, unknown>>(payoutId: string, options?: RyntraGuardRequestOptions) =>
      this.request<T>(`/v1/payouts/${payoutIdentifier(payoutId)}`, { options, credential: "PAYOUT" }),
    list: <T = Record<string, unknown>>(
      query: { limit?: number; offset?: number } = {},
      options?: RyntraGuardRequestOptions,
    ) => this.request<T>(payoutListPath(query), { options, credential: "PAYOUT" }),
    preflight: <T = Record<string, unknown>>(payoutId: string, options: RyntraGuardRequestOptions) =>
      this.request<T>(`/v1/payouts/${payoutIdentifier(payoutId)}/preflight`, {
        method: "POST", body: {}, options, credential: "PAYOUT",
      }),
    approve: <T = Record<string, unknown>>(
      payoutId: string,
      input: { decision: "APPROVED" | "REJECTED"; fingerprintHash: string },
      options: RyntraGuardRequestOptions,
    ) => this.request<T>(`/v1/payouts/${payoutIdentifier(payoutId)}/approvals`, {
      method: "POST", body: input, options, credential: "PAYOUT",
    }),
    executionPackage: <T = Record<string, unknown>>(payoutId: string, options?: RyntraGuardRequestOptions) =>
      this.request<T>(`/v1/payouts/${payoutIdentifier(payoutId)}/execution-package`, { options, credential: "PAYOUT" }),
    recordExecution: <T = Record<string, unknown>>(
      payoutId: string,
      transactionHash: string,
      options: RyntraGuardRequestOptions,
    ) => this.request<T>(`/v1/payouts/${payoutIdentifier(payoutId)}/executions`, {
      method: "POST", body: { transactionHash }, options, credential: "PAYOUT",
    }),
    status: <T = Record<string, unknown>>(payoutId: string, options?: RyntraGuardRequestOptions) =>
      this.request<T>(`/v1/payouts/${payoutIdentifier(payoutId)}/status`, { options, credential: "PAYOUT" }),
    receipt: <T = Record<string, unknown>>(payoutId: string, options?: RyntraGuardRequestOptions) =>
      this.request<T>(`/v1/payouts/${payoutIdentifier(payoutId)}/receipt`, { options, credential: "PAYOUT" }),
  };

  readonly payoutPolicies = {
    list: <T = Record<string, unknown>>(
      query: { limit?: number; offset?: number } = {},
      options?: RyntraGuardRequestOptions,
    ) => this.request<T>(payoutResourceListPath("/v1/payout-policies", query), { options, credential: "PAYOUT" }),
    createVersion: <T = Record<string, unknown>>(
      policyId: string,
      input: RyntraPayoutPolicyVersionInput,
      options: RyntraGuardRequestOptions,
    ) => this.request<T>(`/v1/payout-policies/${payoutIdentifier(policyId)}/versions`, {
      method: "POST", body: input, options, credential: "PAYOUT",
    }),
    activate: <T = Record<string, unknown>>(
      policyId: string,
      version: number,
      options: RyntraGuardRequestOptions,
    ) => this.request<T>(`/v1/payout-policies/${payoutIdentifier(policyId)}/versions/${positiveVersion(version)}/activate`, {
      method: "POST", body: {}, options, credential: "PAYOUT",
    }),
  };

  readonly payoutBeneficiaries = {
    list: <T = Record<string, unknown>>(
      query: { limit?: number; offset?: number } = {},
      options?: RyntraGuardRequestOptions,
    ) => this.request<T>(payoutResourceListPath("/v1/payout-beneficiaries", query), { options, credential: "PAYOUT" }),
    create: <T = Record<string, unknown>>(
      input: RyntraPayoutBeneficiaryVersionInput & { beneficiaryId: string },
      options: RyntraGuardRequestOptions,
    ) => this.request<T>("/v1/payout-beneficiaries", {
      method: "POST", body: input, options, credential: "PAYOUT",
    }),
    createVersion: <T = Record<string, unknown>>(
      beneficiaryId: string,
      input: RyntraPayoutBeneficiaryVersionInput,
      options: RyntraGuardRequestOptions,
    ) => this.request<T>(`/v1/payout-beneficiaries/${payoutIdentifier(beneficiaryId)}/versions`, {
      method: "POST", body: input, options, credential: "PAYOUT",
    }),
    activate: <T = Record<string, unknown>>(
      beneficiaryId: string,
      version: number,
      options: RyntraGuardRequestOptions,
    ) => this.request<T>(`/v1/payout-beneficiaries/${payoutIdentifier(beneficiaryId)}/versions/${positiveVersion(version)}/activate`, {
      method: "POST", body: {}, options, credential: "PAYOUT",
    }),
    disable: <T = Record<string, unknown>>(
      beneficiaryId: string,
      options: RyntraGuardRequestOptions,
    ) => this.request<T>(`/v1/payout-beneficiaries/${payoutIdentifier(beneficiaryId)}/disable`, {
      method: "POST", body: {}, options, credential: "PAYOUT",
    }),
  };
}
