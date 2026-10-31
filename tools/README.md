# Included verification tools

The public release includes the full Stage 2A read-only verifier and its
runtime dependencies, plus the Stage 1B ledger, hash-chain, H_t-validation,
and stack-privacy tools exercised by the regression suite. Separate Stage 2B
and Stage 2C CLIs provide signed local decisions and a bounded handoff lifecycle.

Run with Python 3.10 or newer. Stage 2A runtime and tests use only the standard library.
See [the protocol specification](spec/echo-lineage-v1/README.md) for CLI bindings
and [the runnable examples](../examples/README.md) for exit codes 0, 10, and 2.
Historical artifacts from the private source project are outside this release.
The synthetic examples describe no real installation or decision.

From the repository root, run `python3 -B tools/tools/echo_state.py --help`
for the separate Stage 2B Core profile. It requires the pinned
optional dependencies in the root `requirements-2b.txt`. Its local POSIX state
profile, signing boundary and commands are specified in
[echo-lineage-state-v1](spec/echo-lineage-state-v1/README.md).
See also the [Polish command guide](STATE_COMMANDS.pl.md).

For Stage 2C, run `python3 -B tools/tools/echo_transfer.py --help`.
Its [protocol specification](spec/echo-lineage-transfer-v1/README.md) and
[Polish command guide](TRANSFER_COMMANDS.pl.md) separate receipt, decision,
import, activation, historical loading, and fresh process status. Start with
the [synthetic demo](../scripts/demo_transfer.py), using the setup in the
[repository quickstart](../README.md#start-with-the-synthetic-walkthrough).
The published RC1 technical review is complete; human review of key and
privilege semantics remains pending. This design review needs no real keys;
actual key provisioning remains separate. The demo does not deploy an
existing installation or connect a cloud model.
