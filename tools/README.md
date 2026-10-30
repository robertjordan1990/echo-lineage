# Included verification tools

The public release includes the full Stage 2A read-only verifier and its
runtime dependencies, plus the Stage 1B ledger, hash-chain, H_t-validation,
and stack-privacy tools exercised by the regression suite.

Run with Python 3.10 or newer. Stage 2A runtime and tests use only the standard library.
See [the protocol specification](spec/echo-lineage-v1/README.md) for CLI bindings
and [the runnable examples](../examples/README.md) for exit codes 0, 10, and 2.
Other tools and historical artifacts from the source project are outside this
release. The synthetic examples describe no real installation or decision.

From the repository root, run `python3 -B tools/tools/echo_state.py --help`
for the separate Stage 2B Core candidate. It requires the pinned
optional dependencies in the root `requirements-2b.txt`. Its local POSIX state
profile, signing boundary and commands are specified in
[echo-lineage-state-v1](spec/echo-lineage-state-v1/README.md).
See also the [Polish command guide](STATE_COMMANDS.pl.md).
