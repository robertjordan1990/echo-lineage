# Stage 2B Core: local signed decision state

Implementation candidate, profile `2B-h1-local`. This is separate from the
unchanged Stage 2A verifier. Merge/release requires independent review of the
exact patch and human review of key and privilege semantics.

## Scope and trust

One state store binds one existing validated `trajectory_root`, one installation,
one root artifact ID, and an explicit pinned public-key registry. The first
profile requires `origin_kind=independent_no_lineage_claim`, no lineage parents,
null genesis reference, `signature_policy=optional`, and no root proofs.
Required/out-of-band root signature policies, continuation/fork/merge acceptance
closure, and roots already carrying proofs are refused as unsupported. A signed
acceptance never upgrades the root's author authentication.

Only `human_operator` decisions can be signed or applied. The actor equals
`recording_operator.operator_actor_id`; authenticated delegation is not included.
Other decision modes remain structurally parseable in Stage 2A but cannot be
newly authenticated or recorded here. The signature authenticates the explicitly
scoped pinned key holder, not a biological person, physical consent, a model
identity, or an opinion attributed to an agent.

There is no root/key creation command, import, handoff lifecycle, public
commitment, model wake-up, tool execution from text, or runtime activation.
`runtime_activation=false` is permanent for this profile. Approval of these
local decisions is separate from approval to publish code.

## Four signed decisions

| Decision | Recorded effect |
| --- | --- |
| `accepted` | Replaces the complete prior local accepted scope when evidence permits. |
| `accepted_with_reservations` | Replaces scope with explicitly verified targets; unavailable/excluded sources remain explicit reservations. |
| `declined` | Records refusal; preserves historical acceptance. Integrity-failure evidence also sets an integrity block. |
| `quarantined_integrity_failure` | Records the integrity failure and blocks local acceptance while retaining its historical pointer. |

The unchanged Stage 2A decision matrix controls which decisions the observed
targets permit. No signature means no decision write, including decline and
quarantine. Technical input errors are refusals, not automatically signed
quarantine records. An accepted replacement clears a block only when its fresh
report permits that decision. A later decline of valid evidence cannot clear an
earlier block. Scope is replaced rather than silently unioned with old scope.

Status separates `latest_decision`, historical `active`, `integrity_blocked`,
and `local_acceptance_active`. The last means a recorded acceptance without a
recorded block; it is not a live observation of external files. Status/verify
always expose `current_targets_rechecked=false` and `active_is_historical=true`.
Prepare and a new apply check current targets. An exact replay returns the
historical result without pretending that old evidence was freshly observed.

## Pinned policy and keys

The closed policy schema is:

```json
{"schema":"echo-lineage-trust/v1","keys":[{
  "key_id":"urn:echo:key:00000000-0000-4000-8000-000000000001",
  "public_key":"<canonical base64 of the reviewed 32-byte Ed25519 public key>",
  "decision_actor_id":"urn:echo:decision-actor:00000000-0000-4000-8000-000000000001",
  "installation_id":"urn:echo:installation:00000000-0000-4000-8000-000000000001",
  "decision_mode":"human_operator","purpose":"lineage_acceptance"
}]}
```

The placeholder is intentionally not an enrolled key. Keys must be explicitly
reviewed and pinned; labels, runtime IDs and transcript hashes are not credentials.
One to 256 keys are allowed, with unique key IDs and public keys. Every key must
match the bound installation and allowed mode/purpose. Public inputs reject
malformed/noncanonical curve encodings and pure small-order points before the
cryptography backend. This validation does not assert full prime-subgroup
membership for mixed-order encodings. Signing/verification uses cryptography's
Ed25519 implementation and the existing Stage 2A proof payload/domain.

`decision sign` accepts an explicitly provided unencrypted PKCS8 PEM file, owned
by the account, regular, single-link, mode 0600, at most 16 KiB. Only the file path
is an argument; key contents must never be put in argv, logs, fixtures or the
repository. There is no implicit key discovery or key generation. Tests use
published synthetic seeds in temporary directories only.

## Commands

All normal outputs are JSON. Paths below are placeholders. `S`, candidates,
signed decisions and private key files must be outside every Git checkout.
The state directory must not yet exist at initialization; its parent must exist.
The output parent for `--out` must already exist, be owned by the account and
have mode 0700; its ancestors must pass the same safety checks as the store.

```text
python3 -B tools/tools/echo_state.py state init --state-dir S --root ROOT --trust-policy POLICY --expected-root-hash H --root-artifact-id ARTIFACT_ID
python3 -B tools/tools/echo_state.py state status --state-dir S --json
python3 -B tools/tools/echo_state.py state verify --state-dir S --checkpoint TRUSTED_CHECKPOINT --json
python3 -B tools/tools/echo_state.py decision prepare --state-dir S --root ROOT --decision accepted --actor-id A --operator-id A --request-id ID --verification-time T --expected-state-digest OLD --out CANDIDATE
python3 -B tools/tools/echo_state.py decision sign --state-dir S --candidate CANDIDATE --key-file PRIVATE --out SIGNED
python3 -B tools/tools/echo_state.py decision apply --state-dir S --decision SIGNED --expected-state-digest OLD --request-id ID
```

`H` is the validated, domain-separated root `document_hash.value`, not the hash
of the JSON file. `ARTIFACT_ID` is an explicitly selected typed artifact UUID,
distinct from all source and ledger IDs. `OLD` is `snapshot_digest` from status.
`T` is an explicit UTC verification time (`Z` or `+00:00`); it is a declared
verification time, not a trusted-clock attestation. Receipt time is separate.
Request IDs contain 1–128 ASCII token characters `[A-Za-z0-9_.:-]`, starting
with an alphanumeric character. Decision nonce and typed acceptance ID are
generated during prepare. Preparing/signing records no decision.

Prepare/apply accept the existing explicit repeatable Stage 2A bindings:
`--target ID=PATH`, `--target-root ID=PATH`, `--ledger ID=PATH`,
`--ledger-root ID=PATH`, `--ledger-entry ID=ENTRY`. The root argument at prepare
must equal the root bound in the store. No paths are persisted into reports.
Sign validates the candidate's complete report/body/pre-state bindings before
reading the key. It does not claim current target verification; apply does that.

A candidate/signed file is one closed `echo-lineage-decision-bundle/v1` object:
`schema`, `request_id`, `report`, `document`. Apply accepts optional `--report`
only as an exact canonical copy of the embedded report, never as an alternate
authority. Candidate/signature outputs are new exclusive 0600 files; existing
files are never replaced. A crash may leave an incomplete new output that must
be inspected and cannot be blindly overwritten.

Exit 0 means the requested operation completed, not that every decision was an
acceptance. Exit 10 means an unsupported profile or unavailable authentication
capability. Exit 2 means invalid/conflicting/unsafe input, integrity refusal,
or an uncertain write. An uncertain state commit has `commit_uncertain=true`
and requires inspection of state/request before any retry. An uncertain auxiliary
output has `output_uncertain=true` and is not evidence of a state commit.

## Trusted report and journal

`echo-lineage-state-report/v1` is produced from the actual Stage 2A verifier and
a separate typed local adapter, not a supplied JSON `PASS` assertion. It binds
store/install/trajectory/root IDs, request ID, policy digest, verifier version,
canonicalization, exact target coverage, dependency evidence status/count,
verification time and pre-state generation/head/digest. It carries both:

- `root_document_hash`: the protocol's domain-separated document hash;
- `root_artifact_hash`: SHA-256 of canonical JSON for the full root document.

The acceptance signs the report hash through its finalized proof payload.
Observed hashes stay in the report; acceptance target results follow the existing
closed Stage 2A projection. Explicit exclusions are retained where that protocol
requires them. Human-readable errors, filesystem paths, transcripts and keys are
not report fields.

Apply holds the stable store lock, replays historical signatures and all derived
indexes, checks exact request replay before CAS, checks new-request CAS, verifies
policy/signature/identity/decision scope, and recomputes the complete report from
current bindings at the original fixed verification time. A fabricated or
rehashed report cannot bypass this recomputation. The lock serializes cooperating
writers; it does not freeze independently modified external source files.

State schema `echo-lineage-state/v1` is one bounded 8 MiB canonical snapshot with
at most 1024 decisions. It contains the fixed root/policy, generation, chained
records, request/acceptance/nonce/responsibility indexes, active scope and integrity
block. Full replay reconstructs and compares these fields. Domains (ASCII bytes
prepended to canonical JSON) are:

| Digest | Domain |
| --- | --- |
| Policy | `ECHO\|STATE\|v1\|POLICY\|` |
| Snapshot | `ECHO\|STATE\|v1\|SNAPSHOT\|` |
| Genesis journal head | `ECHO\|STATE\|v1\|GENESIS\|` |
| Journal event | `ECHO\|STATE\|v1\|EVENT\|` |

Genesis hashes `{store_id,root,root_artifact_id,policy}`; each event hashes its
closed record excluding `event_hash`. Report/bundle hashes are SHA-256 of
canonical JSON. Exact signed bundle/request replay returns its existing record,
even with the old CAS digest. Conflicting reuse of a request ID, acceptance ID,
nonce, chain slot or predecessor edge is refused.

## Filesystem and recovery limits

Only local POSIX filesystems and a non-attacker-controlled owning account are
in scope. Network filesystems, full malicious account/root control, key theft,
trusted-clock guarantees and continuous external-file monitoring are not covered.
The private state directory is 0700, state/lock files are owned single-link 0600
regular files, and symlinks, special files and writable/untrusted ancestors are
refused. Root-owned sticky temporary directories are an explicit allowed parent
case for tests; temporary storage is not a durability/backup recommendation.
If a home ancestor is group-writable, choose a separately reviewed private parent;
the CLI will not chmod the home or weaken its checks.

Initialization atomically claims a new directory; an interrupted partial
initialization is left for manual inspection and never silently reinitialized.
Writers use a stable lock inode, pinned directory descriptors, inode checks,
temporary snapshot fsync, rename and directory fsync. Errors after publication,
including cleanup errors, are classified as uncertain; there is no automatic
rollback or retry.

`state verify` verifies the stored historical chain, not current external targets.
Without an independently trusted checkpoint it reports
`rollback_protection=not_externally_anchored`: restoration of a whole older valid
snapshot cannot be detected. An optional checkpoint is the closed object
`{store_id,generation,journal_head}` supplied through an independently trusted
path. It must match an exact historical chain member, not only a generation.
Success proves that ancestor is present; it does not prove no later state was
lost. A local checkpoint created alongside the same snapshot is not an external
trust anchor.
