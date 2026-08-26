# Ryntra Arc Evidence

[![verify](https://github.com/ryntra-io/ryntra-arc-evidence/actions/workflows/ci.yml/badge.svg)](https://github.com/ryntra-io/ryntra-arc-evidence/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Decision and settlement evidence for programmable money, as a typed kernel and
an HTTP contract.**

An intended payment becomes four separate, checkable facts — what was proposed,
what the evidence supported, what a human authorized, and what the network
actually did — instead of one confident summary. This repository is the kernel
that keeps them separate, the OpenAPI contract that exposes them, a headless
client, and offline receipt verification.

Apache-2.0. No key material, no signing path, no funds. Authorization arrives as
a signature produced somewhere else, and this code verifies it rather than
producing it.

## Quick start

```bash
npm ci
npm run verify
```

`verify` runs lint, typecheck, the tests, OpenAPI validation and the boundary
gate. Nothing in it reaches a network or a database — every test runs against
fixtures, so a bad afternoon at somebody's RPC provider cannot turn this
repository red. The whole install is two runtime dependencies, `viem` and `zod`.

Read the lifecycle end to end in
[`examples/partner-arc-app/server-flow.ts`](examples/partner-arc-app/server-flow.ts):
intent → preflight → authorization → execution → receipt, as a partner would
call it.

## What is here

| Piece | Where |
|---|---|
| Evidence kernel — the states and the transitions between them | `lib/guard/kernel.ts` |
| Typed contracts for every record | `lib/guard/contracts.ts` |
| Canonical hashing and receipt integrity | `lib/guard/canonical.ts`, `canonical-json.ts`, `payout-canonical.ts` |
| EIP-712 authorization **verification** | `lib/guard/arc-wallet-authorization.ts` |
| Lifecycle service over a pluggable store | `lib/guard/service.ts`, `store.ts` |
| HTTP contract | `openapi/ryntra-guard-v1.yaml` |
| Headless client | `packages/guard-sdk` |
| Worked partner integration | `examples/partner-arc-app` |

## What is verified

- **The state machine**, over every declared transition — including the ones
  that must not exist. A state is reached by its transition or not at all.
- **The record contracts**, in both directions: a malformed record is refused
  as malformed, and a well-formed one round-trips.
- **Receipt integrity**: a receipt re-hashes from its own bytes, and a tampered
  one reports as tampered rather than as invalid-for-some-reason.
- **Authorization verification**: a signature over the wrong fingerprint, the
  wrong domain or the wrong signer is rejected, each for its own reason.
- **The contract document**, against the OpenAPI schema rather than a copy of
  it.

## What it does not do

- **It holds no keys and signs nothing.** There is no signer, no keystore and
  no seed handling here, and no code path that would accept one.
- **It is not the Ryntra service.** The HTTP routes, deployment wiring, store
  adapters, provider registry and payout lifecycle are not in this repository.
  The contract is here; the operator's implementation of it is not.
- **It is not audited and not production-ready.**
- **It carries no compliance or legal standing.** A receipt states what was
  recorded. It never asserts that an external fact inside it is true, or that
  anyone was authorized to act.
- **It targets Arc Public Testnet.** Nothing here claims mainnet behaviour.
- **It is not published to npm.** The workspace here is source.

## Security boundary

Evidence, policy, authorization, signature, execution and reconciliation are
separate concerns and stay separate in the types. Report issues through the
private GitHub Security Advisory flow — [SECURITY.md](SECURITY.md) names the
exact boundaries a report should say whether it crosses. Never send a seed
phrase, private key or signing request.

## Licence and boundary

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

**Selected developer interfaces and evidence tooling are open source. The Ryntra
product remains proprietary.** The production application, its infrastructure,
its risk and policy logic, its strategies and its provider adapters are not in
this repository and are not published. Ryntra is not an open-source company, and
nothing here is a hosted service.
