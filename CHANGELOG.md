# Changelog

## [1.0.0] — 2026-08-26

### Included

- Typed evidence kernel for intents, evaluations, authorizations, executions
  and receipts, with explicit lifecycle transitions.
- Typed record contracts and validation.
- Canonical hashing, domain-separated payout hashing and offline receipt
  integrity verification.
- EIP-712 authorization verification.
- Validated OpenAPI contract, headless client and partner integration example.
- Network-free tests, type checking, lint and repository boundary checks.

### Scope

This version targets Arc Public Testnet. It is a library and API contract,
not a hosted HTTP service or mainnet integration. It does not hold keys or
sign transactions. The software is not independently audited and is not a
published npm package. Receipts do not establish legal or compliance status.

[1.0.0]: https://github.com/ryntra-io/ryntra-arc-evidence/releases/tag/v1.0.0
