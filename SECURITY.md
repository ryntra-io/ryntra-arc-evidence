# Security policy

## Supported release

Security fixes are accepted for the latest tagged source release. This is a
read-only source distribution, not an npm package and not a hosted service.

## Reporting

Please use the repository's private GitHub Security Advisory flow. Do not open a
public issue containing an exploit, credential, private endpoint, user data,
wallet material or provider secret.

Include the affected commit, a minimal reproduction, the impact, and whether the
issue crosses any of these boundaries:

- **the custody boundary** — any path that could hold key material, produce a
  signature, or submit a transaction the operator did not authorize;
- **the authorization boundary** — any way a lifecycle could reach `AUTHORIZED`
  without a valid authorization, or an execution could bind to an authorization
  it does not match;
- **the evidence boundary** — a receipt that re-hashes as valid after
  tampering, an integrity check that passes on bytes it did not cover, or a
  fact rendered without the source it came from;
- **the reconciliation boundary** — an expected effect reported as `MATCHED`
  against actual effects that differ, or a settlement reported complete when a
  required leg has not settled;
- **tenant isolation** — any way one caller's intents, receipts or idempotency
  keys become visible or writable to another;
- request/response size, depth and string limits, and log or error redaction —
  including a rejected request echoing its own input.

Never send a seed phrase, private key, signing request or funds as part of a
report. Ryntra does not need them to reproduce an issue, and this repository has
no code path that would accept them.

## Security model

The service records evidence. It does not authorize, sign, fund or settle.

- **No key material.** Authorization arrives as a signature produced elsewhere.
  There is no signer, no keystore and no seed handling in this repository.
- **Separated concerns.** Evidence, policy, authorization, execution and
  reconciliation are distinct types and distinct transitions. A state cannot be
  reached by asserting it.
- **Fail closed.** With a store that cannot serve concurrent writers, every
  state-changing call returns `503 CAPABILITY_UNAVAILABLE` with the exact
  missing configuration named. Reads stay available so the reason is visible.
- **Nothing is inferred.** A receipt states what was recorded. It never asserts
  that an external fact inside it is true, that the document has legal or
  compliance standing, or that anything applies beyond Arc Public Testnet.

This code is not audited. Treat it as a reference implementation on a public
testnet, because that is what it is.
