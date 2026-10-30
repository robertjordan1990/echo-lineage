# echo-lineage/v1 — public release candidate

Status: **Stage 2A read-only verifier + Stage 2B Core implementation candidate**.
The new bounded local profile is pending independent patch review and human
key/privilege review; this branch is not a release or an adopted installation.

Maintained under the project pseudonym **Robert Jordan**.
Developed through documented human–AI collaboration within **fAIR DecentrAIzation**.
The pseudonym does not identify a separate person or assign copyright ownership.
See [NOTICE.md](NOTICE.md) for attribution and scope.

## Run it

Use Python 3.10 or newer on a local POSIX filesystem. Stage 2A uses the Python
standard library. Stage 2B additionally requires the tested dependencies in
`requirements-2b.txt`; the public-pack check requires Bash, `sha256sum`, and `awk`.
No API key or network connection is required to run the local verifier.

For all Stage 2A and 2B checks, install dependencies in an isolated environment
outside the checkout and run:

```sh
python3 -B -m venv /path/to/private/venv
/path/to/private/venv/bin/python -B -m pip install -r requirements-2b.txt
/path/to/private/venv/bin/python -B scripts/verify_release.py
```

The checks cover the full file manifest, regression suite, public-pack hashes,
synthetic ledger fixtures, and the expected CLI exits **0 / 10 / 2**.
For the three individual commands, see [examples/README.md](examples/README.md).

A verified independent root can return 0. A continuation requiring an
acceptance whose attribution is not authenticated remains incomplete (10)
in Stage 2A, even when its document relationships are consistent.

The exact 151-test Stage 2A baseline has a separate CI job and can run in an
isolated environment without cryptography using
`python3 -B scripts/verify_release.py --profile stage2a`.

Stage 2B uses a separate [local state CLI](tools/spec/echo-lineage-state-v1/README.md).
It records four explicitly signed operator decisions about one existing,
independent root. It authenticates the scoped pinned key holder, not biological
identity, physical consent, a model session, or authorship of the unsigned root.
`runtime_activation` is always false. [Polish command guide](tools/STATE_COMMANDS.pl.md).

## What this is

`echo-lineage/v1` is a small protocol and verifier for **auditable continuity between agent installations and sessions without pretending that transport, shared context, or a successful hash check automatically creates identity, authority, or acceptance**.

It separates three questions that agent stacks often collapse:

1. **Verification** — are the documents, hashes, parent relations and responsibility heads internally consistent?
2. **Acceptance** — who, if anyone, explicitly accepted this lineage/handoff, and on what evidence?
3. **Activation** — should any verified/accepted state actually become active locally?

Stage 2A implements only read-only verification. It deliberately cannot accept a lineage, import state, mutate a head, create a trajectory, or publish a commitment.

## Core invariants

```text
VERIFY SUCCESS != ACCEPTED
HANDOFF VERIFIED != IMPORTED
TARGET MISSING != HASH MISMATCH
COMMUNICATION != LINEAGE
```

Trajectory identity is bound to:

```text
(trajectory_id, genesis_root_document_hash)
```

A UUID, session name, model family, filesystem location, shared channel, or access to the same artifacts is never sufficient by itself.

Origins are explicit:

- independent
- continuation
- explicit fork
- explicit merge

Forks and merges are never inferred from similarity or transport.

## What Stage 2A verifies

- strict canonical JSON (NFC normalization, duplicate/collision rejection, no non-finite numbers);
- domain-separated document hashes;
- responsibility-head continuity;
- trajectory identity and explicit origin rules;
- parent graph evidence;
- typed artifact references and declared hash scope;
- optional local target / ledger bindings;
- the distinction between unavailable evidence and integrity failure;
- decision-policy consistency for existing acceptance records;
- reproducible unbound-handoff expiry checks when an explicit verification time is supplied.

## What Stage 2A does **not** verify

- Ed25519 signatures or trusted-key resolution;
- model/human identity claims;
- semantic truth of a hashed document;
- durable replay/rollback protection across invocations;
- local state adoption or import;
- authority to act;
- cryptographic authenticity of an acceptance actor.

The separate 2B Core CLI adds scoped Ed25519 decision signatures and local
durable state only within its declared profile. It does not change Stage 2A's
verification behavior: a structurally valid acceptance with unauthenticated
attribution still remains incomplete in the Stage 2A verifier.

## Public demo goal

A clean clone should demonstrate three outcomes:

1. **0 — verified:** a synthetic root whose required evidence is present and consistent.
2. **10 — incomplete/unavailable:** structure is valid but required attribution/target/parent evidence is unavailable.
3. **2 — integrity failure:** a synthetic mutation, contradiction, expired handoff, or hash mismatch is detected.

The public examples must be fictional. No project memory, transcripts, private handoffs, credentials, keys, local paths, or current Echo state belong in this repository.

## Why this is not “another MCP”

MCP and A2A solve transport, tool/task execution, discovery, context and authorization problems. `echo-lineage/v1` is intended as a complementary **verification and governance layer** over agent continuity and handoff claims.

The protocol should remain transport-neutral. An MCP call, A2A task, filesystem exchange, message bus, or offline artifact transfer can carry a handoff; none of those transports alone establishes lineage or acceptance.

## Prior-art posture

This project does **not** claim to invent provenance, signed handoffs, agent identity, transparency logs, task continuity, or cryptographic attestations.

Before any stronger novelty claim, compare explicitly against at least:

- MCP authorization / Tasks / tool-risk annotations;
- A2A tasks, contexts, artifacts and Agent Cards;
- in-toto / SLSA-style supply-chain attestations;
- Sigstore / Rekor transparency;
- W3C PROV;
- Agent Identity Protocol (AIP);
- signed agent-handoff protocols;
- recent work on authorization succession across replacement/fork/rollback.

The candidate contribution is the specific composition and semantics of verification, explicit lineage origin, attributed acceptance and non-automatic activation.

## Release scope

This candidate contains the verifier, required runtime modules, complete
regression tests, protocol schemas, and fictional examples. It is a source
snapshot with a fresh publication history. Its publication date is not the
date of first invention, and the project makes no priority claim. Private
project archives and earlier commit history are outside this release.

`SHA256SUMS` covers every distributed file except the manifest itself.
Checksums detect a mismatch against that manifest; they do not authenticate
the publisher or provide a trusted external checkpoint.

The code is licensed under the [Apache License, Version 2.0](LICENSE). This is a research
demonstrator, not a production security or authenticated-identity system.
