# Contributing

Thanks for looking. This repository is a bounded source distribution of an
evidence model, so the most useful contributions are usually corrections: a
state transition that should not exist, a receipt field whose meaning has drifted
from what it records, a claim that outruns its evidence.

## Before a pull request

```bash
npm ci
npm run verify
```

`verify` runs lint, typecheck, the network-free tests, the OpenAPI validation
and the boundary gate. All five must pass. Nothing in `verify` reaches a network
or a database, so a bad afternoon at somebody's RPC provider cannot turn this
repository red.

The Postgres tests skip without `DATABASE_URL`, and they skip visibly. If you
are changing the multi-writer adapter, run them against a throwaway database and
say so in the pull request — a claim about concurrent writers that no live test
covered is not a claim this repository accepts.

## What will not be merged

- Anything that holds key material, produces a signature, or submits a
  transaction. Authorization arrives from outside; that is the whole design.
- A path that reaches a lifecycle state without the transition that defines it.
  States are earned, never asserted.
- A sentence that says or implies this software is safe, endorsed, compliant,
  independently reviewed or ready for production. None of that is true of it,
  and it reports what it recorded rather than what it would like to be.
- A second copy of something that already exists here once. Canonical hashing
  and the evidence kernel are single-source on purpose.
- A store adapter that reports a durability it does not have. If it cannot
  serve concurrent writers, it must fail state changes closed and say why.

## Style

Match the surrounding code. Comments explain *why* something is the way it is,
particularly where the obvious implementation would be wrong — those comments
are load-bearing, and deleting one usually means the next person reintroduces
the defect it describes.

## Commit messages

Product-level and conventional: `feat:`, `fix:`, `docs:`, `test:`, `release:`.
A commit message is published permanently and is the one part of a repository a
later commit cannot correct, so it describes the change to this software and
nothing about how it came to be written.
