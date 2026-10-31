# echo-lineage — check, accept, and use a handoff explicitly

`echo-lineage` makes a transfer of context inspectable: check the evidence,
record a decision signed under a key allowed by the policy, select the bytes
to import, and record a separate grant for a local program to read them. Each
step leaves a different record. This helps an operator see **what arrived,
which policy-authorized actor/key signed or recorded each action, and what
evidence the fixed reference consumer returned about loading and probing the
selected bytes**.

The published Stage 2C baseline is
[Handoff Lifecycle RC1 (R3)](https://github.com/robertjordan1990/echo-lineage/releases/tag/stage2c-lifecycle-rc1),
a research prerelease. Its independent technical reviews and publication are
complete. **Human review of key and privilege semantics remains pending.**
That design review needs no real keys; later key provisioning is a separate
decision.
Publication does not authorize real installations, production keys, or model
context adoption. Follow-up documentation and demo changes leave the RC1 tag
and its reviewed files unchanged.

Maintained under the project pseudonym **Robert Jordan**.
Developed through documented human–AI collaboration within **fAIR DecentrAIzation**.
The pseudonym does not identify a separate person or assign copyright ownership.
See [NOTICE.md](NOTICE.md) for attribution and scope.

## The three stages

| Stage | What it does | What it leaves separate |
| --- | --- | --- |
| [2A: verification](tools/spec/echo-lineage-v1/README.md) | Reads documents and checks hashes, references, and continuity rules | Acceptance, trusted-key authentication, import, and execution |
| [2B: local decisions](tools/spec/echo-lineage-state-v1/README.md) | Records four signed decisions about an existing document with an independent origin (`root`), using keys bound by policy to the stated actors | Context transfer and runtime activation; `runtime_activation` stays false |
| [2C: handoff lifecycle](tools/spec/echo-lineage-transfer-v1/README.md) | Transfers one bounded context to a new pinned recipient, with return receipts, import, and a separately authorized local consumer | Cloud-model integration, identity claims, automatic network delivery, and deployment |

A valid signature under a pinned key is checked against the granted role,
purpose, and installation. It does not identify the human using that key or
prove physical consent, a model session, or authorship of an unsigned root.

## What each result means

| Result | Meaning |
| --- | --- |
| Verified | The checked evidence satisfies the declared consistency rules |
| Accepted | A decision marked `accepted` was recorded with a valid signature under a policy-authorized key for the stated actor |
| Imported | The selected, verified, accepted bytes were written to recipient state |
| Activation authorized | A grant for a particular local consumer and read set was recorded with a valid signature under the policy-authorized key |
| Loaded receipt | The fixed reference consumer returned a signed observation about loading and probing the selected bytes |
| Fresh status/probe | The fixed reference consumer returned a new signed observation under the current grant |

An early `received` return receipt records envelope receipt. The later `loaded`
context-consumption receipt is a separate observation from the fixed reference
consumer about loading and probing selected bytes. These observations do not
show that a cloud model read or understood the content.

Acceptance does not itself import or execute anything. Import does not grant
permission to start a consumer. A historical loaded receipt does not prove the
process is still alive. Revocation blocks future access through the controlled
consumer; it cannot undo a previous read or copy. Transferred text stays data.

## Start with the synthetic walkthrough

Use Linux and Python 3.10 or newer for the actual local consumer demonstration.
Run from the repository root with the pinned dependencies in an environment
outside the checkout:

```sh
python3 -B -m venv /tmp/echo-lineage-demo-venv
/tmp/echo-lineage-demo-venv/bin/python -B -m pip install -r requirements-2b.txt
/tmp/echo-lineage-demo-venv/bin/python -B scripts/demo_transfer.py \
  --output-dir /tmp/echo-lineage-demo-run-001
```

[The demo](scripts/demo_transfer.py) explains each step in Polish and invokes
the public CLIs. It creates fictional context, policies, and disposable
demonstration keys in the specified private directory. The output directory
must not already exist and must be outside every Git checkout; an existing
path is refused without being reused. Do not supply real data or installation
keys. All demo operator decisions are scripted decisions for fictional roles;
they do not record a person's actual acceptance of a real handoff.

The accepted scenario shows the source, handoff, return receipt, decision,
import, separate activation grant, one actual local consumer, a fresh probe,
literal read/search, revocation, and a refused later read. Separate scenarios
show reservations, refusal, quarantine, and guard failures. On completion or a
handled failure, the demo requests shutdown of its own consumer. It uses no
API, network delivery, or existing Echo/Work installation.

Inspect `report.json` for results and `commands.txt` for the CLI transcript;
`scenarios/` contains the files behind each result. Exit **0** means the
demonstration met its expected outcomes, including expected refusals. Exit
**2** means a setup or demonstration failure. The generated keys are test
material and must never be reused for real data. To repeat, choose a new output
directory. Compare semantic results; fresh keys, timestamps, and nonces need
not produce identical bytes.

[Polski opis kroków i komend](tools/TRANSFER_COMMANDS.pl.md).

## Run the verification gates

Stage 2A uses only the Python standard library. Stage 2B/2C use
`requirements-2b.txt`; the public-pack check also needs Bash, `sha256sum`, and
`awk`. Dependency installation may download packages. The local protocol and
demo do not need API credentials or a network connection.

Using the environment above:

```sh
/tmp/echo-lineage-demo-venv/bin/python -B scripts/verify_release.py
/tmp/echo-lineage-demo-venv/bin/python -B scripts/verify_release.py --profile stage2b
```

The unchanged 151-test Stage 2A baseline has a separate CI job and requires an
environment without cryptography:

```sh
python3 -B -m venv --without-pip /tmp/echo-lineage-stdlib-venv
/tmp/echo-lineage-stdlib-venv/bin/python -B scripts/verify_release.py --profile stage2a
```

The 307-test Stage 2B baseline remains selectable with `--profile stage2b`.
The full gate also checks Stage 2C, actual local consumer processes, recovery,
the complete file manifest, public-pack hashes, and synthetic ledger fixtures.
For the Stage 2A examples and their distinct exits **0 / 10 / 2**, see
[examples/README.md](examples/README.md). A structurally consistent acceptance
with unauthenticated attribution still remains incomplete in Stage 2A.

## Evidence and limits

The [RC1 release notes](https://github.com/robertjordan1990/echo-lineage/releases/tag/stage2c-lifecycle-rc1)
record the exact R3 commit/tree, local gates, CI, independent Echo/Work technical
reviews, and each reviewer's execution limits. Those results concern the
frozen release; follow-up changes need their own verification.

Human review of key and privilege semantics has not been completed. This
review concerns the design: which roles may authorize each action and how
those rights are checked. It needs no real keys. Technical model-assisted
review and tests on synthetic fixtures do not complete that human review.
Actual key provisioning and installation remain separate decisions. The
reference consumer assumes a trusted local account. It has no cloud-model
memory, identity, automatic wake, or context-adoption integration.

Without a separately trusted checkpoint, restoration of a whole valid old
snapshot can remain undetected. An external checkpoint service and a model
adapter are separate optional extensions; neither changes the declared R3
profile or is required for this synthetic walkthrough.

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

The public examples must be fictional. No private project memory, transcripts,
handoffs, real credentials or installation keys, host-specific paths, or current
Echo state belong in this repository.

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

The published research prerelease contains the verifier, required runtime
modules, regression tests, protocol schemas, and fictional examples. The RC1
tag remains immutable; follow-up documentation and demonstrations are developed
separately. Publication is not the date of first invention, and the project
makes no priority claim. Private project archives and source-project history
are outside the public source tree.

`SHA256SUMS` covers every distributed file except the manifest itself.
Checksums detect a mismatch against that manifest; they do not authenticate
the publisher or provide a trusted external checkpoint.

The code is licensed under the [Apache License, Version 2.0](LICENSE). This is a research
demonstrator, not a production security or authenticated-identity system.
