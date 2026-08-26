import { verifyTypedData, type Address, type Hex } from "viem";
import type { z } from "zod";

import { hashCanonical } from "./canonical.ts";
import { ExecutionFingerprintSchema } from "./contracts.ts";

type ExecutionFingerprint = z.infer<typeof ExecutionFingerprintSchema>;

const AUTHORIZATION_PRIMARY_TYPE = "ArcTransferAuthorization" as const;

const DOMAIN_TYPES = [
  { name: "name", type: "string" },
  { name: "version", type: "string" },
  { name: "chainId", type: "uint256" },
] as const;

const AUTHORIZATION_TYPES = [
  { name: "wallet", type: "address" },
  { name: "audience", type: "string" },
  { name: "intentId", type: "string" },
  { name: "evaluationId", type: "string" },
  { name: "fingerprintHash", type: "bytes32" },
  { name: "expiresAt", type: "uint64" },
] as const;

const VERIFY_TYPES = {
  [AUTHORIZATION_PRIMARY_TYPE]: AUTHORIZATION_TYPES,
} as const;

export type ArcWalletAuthorizationChallenge = ReturnType<
  typeof buildArcWalletAuthorizationChallenge
>;

function chainIdFromRef(chainRef: string): number {
  const match = /^eip155:(\d+)$/.exec(chainRef);
  const chainId = match ? Number(match[1]) : Number.NaN;
  if (!Number.isSafeInteger(chainId) || chainId <= 0) {
    throw new Error("The authorization fingerprint does not name a valid EVM chain.");
  }
  return chainId;
}

function expirySeconds(expiresAt: string): string {
  const milliseconds = Date.parse(expiresAt);
  if (!Number.isFinite(milliseconds)) {
    throw new Error("The authorization fingerprint has an invalid expiry.");
  }
  return String(Math.floor(milliseconds / 1_000));
}

/**
 * The exact EIP-712 payload a connected EOA signs before Ryntra records human
 * authorization. It binds the session's intent and evaluation to the complete
 * execution fingerprint without asking the wallet to sign a transaction yet.
 */
export function buildArcWalletAuthorizationChallenge({
  intentId,
  evaluationId,
  fingerprint,
  audience,
}: {
  intentId: string;
  evaluationId: string;
  fingerprint: ExecutionFingerprint;
  audience: string;
}) {
  const parsed = ExecutionFingerprintSchema.parse(fingerprint);
  const normalizedAudience = new URL(audience).origin;
  return {
    domain: {
      name: "Ryntra Arc Guard",
      version: "1",
      chainId: chainIdFromRef(parsed.chainRef),
    },
    primaryType: AUTHORIZATION_PRIMARY_TYPE,
    types: {
      EIP712Domain: DOMAIN_TYPES,
      [AUTHORIZATION_PRIMARY_TYPE]: AUTHORIZATION_TYPES,
    },
    message: {
      wallet: parsed.walletAddress as Address,
      audience: normalizedAudience,
      intentId,
      evaluationId,
      fingerprintHash: hashCanonical(parsed) as Hex,
      expiresAt: expirySeconds(parsed.expiresAt),
    },
  } as const;
}

/** Verify an EOA's exact-intent authorization without storing its signature. */
export async function verifyArcWalletAuthorization({
  intentId,
  evaluationId,
  fingerprint,
  signature,
  audience,
}: {
  intentId: string;
  evaluationId: string;
  fingerprint: ExecutionFingerprint;
  signature: Hex;
  audience: string;
}): Promise<boolean> {
  const challenge = buildArcWalletAuthorizationChallenge({
    intentId,
    evaluationId,
    fingerprint,
    audience,
  });
  return verifyTypedData({
    address: challenge.message.wallet,
    domain: {
      ...challenge.domain,
      chainId: BigInt(challenge.domain.chainId),
    },
    primaryType: challenge.primaryType,
    types: VERIFY_TYPES,
    message: {
      ...challenge.message,
      expiresAt: BigInt(challenge.message.expiresAt),
    },
    signature,
  });
}

/** A non-secret proof reference for the receipt; the raw signature is omitted. */
export function arcWalletAuthorizationSignatureRef(signature: Hex): string {
  return `eip712:${hashCanonical({ signature: signature.toLowerCase() })}`;
}
