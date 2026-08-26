# Changelog

Notable changes to Ryntra Arc Evidence. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — unreleased

**Initial public release.** A replacement rather than a continuation: its
predecessor, `ryntra-arc-demo`, carries content in its published history that a
later commit cannot remove, so it is retired and this repository starts from a
fresh history with a fresh first commit.

The version is `1.0.0` rather than `0.2.0` for the same reason. There is no
`0.1.0` in this repository to succeed, and a first tag that implies one sends a
reader looking for something that does not exist.

### Added

- Typed evidence kernel: intents, evaluations, authorizations, executions and
  receipts as separate states with earned transitions.
- Typed contracts for every record, refusing malformed input as malformed.
- Canonical hashing, domain-separated payout hashing, and offline receipt
  integrity verification.
- EIP-712 authorization **verification** — a signature over the wrong
  fingerprint, domain or signer is rejected, each for its own reason.
- `openapi/ryntra-guard-v1.yaml`, validated against the OpenAPI schema in CI.
- A headless client in `packages/guard-sdk`.
- A worked partner integration in `examples/partner-arc-app`.
- A boundary gate that fails the build on a file the publication list does not
  name, on any `.env` file, on a symlink, and on a credential-shaped string.

### Changed

- **This is a library, not an application, and that is the substantive change
  from `ryntra-arc-demo`.** The predecessor shipped Next.js routes and a
  lifecycle UI, which meant hand-writing stubs for everything they needed and
  could not have — and those stubs are what leaked: `lib/guard/arc-verification.ts`
  existed only to say, in a comment, where the real answer came from. Taking the
  real modules under those names pulls in 44 files including
  the security layer, the risk module, the capability registry and the whole
  payout service. So the surface is the set that closes on its own: the kernel,
  the contract, the SDK and an example. A contract and a kernel say the same
  thing about the design, and carry none of the product with them.
- Licence is **Apache-2.0**. `ryntra-arc-demo` was MIT; Apache-2.0 adds an
  explicit patent grant and matches the other two public Ryntra repositories.
  It is a superset of MIT's permissions, so nothing anyone could do with the
  earlier tree becomes disallowed.
- The OpenAPI document version is `1.0.0`. It previously carried a suffix
  naming the event the code was first written for, which described the occasion
  rather than the contract.
- The SDK describes itself as a headless client rather than a private one.
- Two runtime dependencies, `viem` and `zod`, where the predecessor had nine.

### Removed

- `docs/limitations.md` as published. It was an internal audit table: review
  verdicts and private commit SHAs, a competition track with the owner's
  remaining action, a deployment host, and a row stating that the public
  repository trailed the private source and still carried unsafe claims. The
  capability boundaries it also recorded are stated in `README.md` and
  `SECURITY.md`, which is where a reader looks for them.
- `docs/demo-script.md`, written for a competition audience.
- Every `app/` route, page and stylesheet, and the service wiring beneath them.
- `.env.example`. This surface has nothing to configure.

### Not in this release

- **No HTTP service.** The contract is published; an implementation of it is
  not. That is a deliberate narrowing and is stated rather than implied.
- No key material, no signer, no funds.
- No mainnet behaviour, and no claim of any.
- No audit. This code has not had one.
- No npm package. The workspace here is source.
