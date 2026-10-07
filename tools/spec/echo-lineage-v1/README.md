# echo-lineage/v1 — Stage 2A

Stage 2A is a public, read-only verification protocol. It verifies document
structure, hashes, responsibility-head continuity, trajectory identity, graph
shape, parent evidence, and optionally bound local targets. It does not accept
lineage, import a handoff, create local state, update a head, publish a
commitment, or create a new trajectory.

The implementation and its tests use the Python standard library only. The JSON
Schemas use JSON Schema 2020-12 and remain useful as standalone public
contracts; the verifier additionally enforces cross-document and cross-array
relations that JSON Schema cannot express.

The files under `tools/examples/echo-lineage-v1/` are fictional protocol
fixtures, not project claims or decisions. The acceptance example illustrates
the structure of a previously recorded human decision; Stage 2A did not create
or endorse it, and its synthetic `verification_report_hash` is not accompanied
by a report artifact. Even with its related root, verifying that example exits
10 with `status: "structure_valid_attribution_unverified"` and
`evidence_status: "incomplete"`. The handoff example deliberately names a fictional
memory head without a local target binding, so a full verification reports
`verification_not_attempted` and exits 10 until that private evidence is
supplied. Structural validity alone never establishes semantic truth.

## Channel first; no automatic genealogy

Communication is not lineage. Distinct sessions can first exchange attributed
messages and handoffs, review one another's claims, and preserve agreements,
contradictions, and unknowns. A channel, shared workshop, filesystem location,
name, model family, similar output, access to the same artifacts, or successful
verification does not create ancestry, identity, authority, acceptance, or a
third trajectory.

An explicit merge is considered only when cooperation reveals a concrete need
that a channel between distinct trajectories cannot meet. A merge:

- is declared explicitly with `origin_kind: "merge"`;
- names at least two verified `merge_input` parents;
- creates a new `(trajectory_id, genesis_root_document_hash)` identity;
- does not rewrite or absorb the parent trajectories; and
- still requires a separately attributed acceptance decision.

Designing or verifying a possible merge does not activate it. Cooperation and
testing do not require private conversations, personal data, keys, or local
state: use public-safe hashes, ciphertext commitments, redacted material, and
synthetic fixtures.

## Identity, origins, and graph

Trajectory identity is the pair:

```text
(trajectory_id, genesis_root_document_hash)
```

A matching UUID alone is not evidence of continuation. All typed identifiers
use a lowercase canonical UUID version 1–5 with an RFC variant. The following
identifiers are distinct and never interchangeable:

- `trajectory_id` identifies the lineage trajectory;
- `installation_id` identifies an installation declaration;
- `runtime_session_id` identifies a runtime session;
- `decision_actor_id` attributes a decision; and
- `key_id` is an opaque public `urn:echo:key:<uuid>` identifier, not key
  material or proof that the key is trusted.

`TRAJECTORY_ROOT.json` keeps its v1 name for compatibility. It is a local
declaration made by an installation participating in a trajectory; it is not
necessarily the historical genesis of that trajectory. Its origin contract is:

- `independent_no_lineage_claim`: no parents and a null
  `genesis_root_document_hash`; the effective genesis is its recomputed
  document hash;
- `continuation`: exactly one `predecessor`, with the established non-null
  genesis hash and the same trajectory identity;
- `explicit_fork`: exactly one `fork_origin`, a new trajectory UUID, and a null
  genesis field because this root establishes a new genesis; and
- `merge`: at least two distinct `merge_input` trajectory identities, a new
  trajectory UUID, and a null genesis field because this root establishes a new
  genesis.

`lineage_parents` contains installation relations only. Documents, memory
databases, governance material, runtimes, archives, and canon are instead
listed in `inheritance_sources`. Memory sources may be multiple. Forks are
`explicit_only`.

A `lineage_parent` entry is a claim until its evidence is checked. For every
parent, the verifier must bind and verify the related root identity,
installation, genesis, handoff document hash, and parent responsibility head.
Unavailable parent evidence is an unavailable verification result and can
never produce exit code 0. Contradictory, malformed, or hash-mismatched parent
evidence is an integrity/graph failure and produces exit code 2. The schemas
can constrain parent shape and origin cardinality; matching referenced
documents and semantic uniqueness of parent identities require the verifier.

## Canonical form, hashes, and responsibility heads

Canonical JSON is the ECHOHASH/v1 form: recursively NFC-normalized strings and
keys, UTF-8, sorted keys, compact separators, and no NaN or Infinity. Parsers
also reject duplicate keys and normalized-key collisions.

For document type `T`:

```text
document_hash = SHA256(
  UTF8("ECHO|LINEAGE|v1|DOCUMENT|" + UPPER(T) + "|")
  || canonical_json({
       "protocol": protocol,
       "document_type": document_type,
       "body": body,
       "responsibility": responsibility
     })
)

resulting_head = SHA256(
  UTF8("ECHO|LINEAGE|v1|RESPONSIBILITY|")
  || HEX(previous_head)
  || HEX(document_hash)
)
```

The verifier always recomputes both values. Responsibility event 0 uses the
all-zero previous head; every later event uses a non-zero previous head. Every
trajectory root begins its installation's responsibility chain at event 0;
acceptance and handoff documents use later events. This structural rule does
not replace comparison of chain ID, event index, and head with the expected
preceding document.

Every proof has a closed `signed_payload` containing exactly:

```text
protocol, proof_scope, document_type, trajectory_id, installation_id,
chain_id, event_index, previous_head, document_hash, resulting_head
```

The payload must equal the recomputed proof payload. For a handoff,
`installation_id` carries the issuer installation ID. The signature message is:

```text
UTF8("ECHO|LINEAGE|v1|PROOF|RESPONSIBILITY_HEAD|")
|| canonical_json(signed_payload)
```

Proof records declare `algorithm: "ed25519"`.
The `signature` field is the canonical padded base64 encoding of exactly 64
signature bytes; arbitrary text and path-like placeholders are invalid.
`signature_policy: "required"` requires at least one proof. Stage 2A validates
proof structure and coverage only. It does not implement Ed25519 signature
verification, key discovery, revocation, or semantic trust. A structurally
valid proof is reported as signature-unverified, never as cryptographically
trusted.

All timestamp fields have an RFC3339-like full date-time structure with an
explicit `Z` or numeric offset. They remain untrusted claims: schema validity
does not prove clock accuracy, calendar truth, ordering, freshness, or
authority.

## Artifact `hash_scope`

An artifact reference always states what its lowercase SHA-256 value means:

- `file_bytes`: SHA-256 of the exact file byte stream;
- `ciphertext`: SHA-256 of the exact ciphertext byte stream; this is
  mechanically a byte hash but explicitly declares the privacy boundary;
- `canonical_document`: SHA-256 of
  `canonical_json(parsed_json_value)` in ECHOHASH/v1 form; and
- `echohash_head`: the committed lowercase 64-hex ECHOHASH head read from a
  file containing exactly that value and, optionally, one trailing LF.

`canonical_document` is not the lineage `document_hash`. The former hashes the
canonical form of the complete parsed JSON value with no lineage domain prefix;
the latter uses the domain-separated formula above and covers only the
protocol, document type, body, and responsibility fields.

Accordingly, a handoff's `lineage_root_ref` and `latest_acceptance_ref` use
`canonical_document`, while `subject.*_document_hash`,
`parent.handoff_document_hash`, and the top-level `document_hash.value` use the
domain-separated lineage document hash. A verifier must dispatch by
`hash_scope`; it must not silently treat every commitment as raw file bytes.
A `ledger_ref` is valid only for the two raw-byte scopes, `file_bytes` and
`ciphertext`; canonical documents and ECHOHASH-head files are verified through
their explicit target bindings.

## Documents and privacy boundary

The public schemas and fictitious examples may be committed. Actual
`TRAJECTORY_ROOT.json`, `LINEAGE_ACCEPTANCE.json`, `HANDOFF.json`, targets,
private handoffs, decision evidence, local locators, keys, and current memory
head belong in private local state outside Git. Public documents refer to
artifacts only by typed `artifact_id`, SHA-256, declared hash scope, role, and
optional ledger commitment.

Absolute paths, traversal, locator fields, and private state directories are
forbidden in protocol documents. Local paths are supplied only as CLI bindings.
Any future operation that creates or changes private local state must require
an explicit `--state-dir`; it must not infer an ambient default.
Free-form decision path strings are not supported: `reason_code` and
reservation `code` use lowercase protocol codes without `/` or `\`.
Do not place plaintext transcripts, personal data, credentials, decryption
keys, or private filenames into public examples or lineage metadata.

## Acceptance attribution and decision policy

`LINEAGE_ACCEPTANCE.json` attributes a decision separately from the operator
who recorded it. Invoking a CLI never attributes a decision to a model.
Actor-mode requirements are:

- `model_session`: `runtime_session_id` and hashed
  `decision_evidence_ref`; it forbids human, policy, and historical-claim actor
  fields;
- `joint_human_model`: `runtime_session_id`, `human_actor_id`, and hashed
  `decision_evidence_ref`; it forbids policy and historical-claim actor fields;
- `human_operator`: the top-level `decision_actor_id` directly identifies the
  human actor; runtime, second-human, policy, and historical-claim actor fields
  are forbidden;
- `system_policy`: hashed `policy_artifact_ref`; runtime, human, and
  historical-claim actor fields are forbidden; and
- `imported_historical_claim`: hashed `historical_claim_artifact_ref` and a
  non-activating effect; runtime, human, and policy actor fields are forbidden.

`decision_evidence_ref` may additionally document any actor mode, but it is
mandatory for `model_session` and `joint_human_model`. These exclusions prevent
one record from silently blending attribution modes.

Stage 2A validates existing acceptance documents but cannot create them. Every
acceptance contains at least one target result, and every target result is bound
to an `expected_sha256`, including an unattempted or unavailable target.
Stage 2A has no trusted-key resolver and accepts no verification-report artifact
binding. It therefore cannot authenticate the claimed decision actor or verify
the artifact named only by `verification_report_hash`. Every otherwise valid
`LINEAGE_ACCEPTANCE` consequently exits 10 with
`status: "structure_valid_attribution_unverified"` and
`evidence_status: "incomplete"`. An unsigned acceptance and one carrying a
structurally valid but cryptographically unverified proof have the same
incomplete outcome; omitting the proof never produces a stronger result.
The acceptance subject identifies its root with both
`trajectory_root_artifact_id` and the domain-separated
`trajectory_root_document_hash`. A handoff subject is optional, but
`handoff_artifact_id` and `handoff_document_hash` must appear together or not
at all.

When that optional handoff subject is present, the verifier also requires the
handoff to be one of the subject root's declared parent handoffs and to match
the parent issuer, trajectory, genesis, responsibility head, and recursively
verified handoff evidence. A bound subject handoff must name the accepting
installation. An unbound subject handoff is also allowed, but it must carry
`expires_at`, and recursive verification must evaluate its expiry against an
explicit `verification_time`.

`target_results` contains exactly one entry for the subject root artifact. That
entry has `criticality: "critical_root"` and its `expected_sha256` equals the
subject root document hash. If the subject includes a handoff pair,
`target_results` also contains exactly one entry for that handoff artifact,
again with `criticality: "critical_root"` and an expected hash equal to the
subject handoff document hash. Once the related root is supplied, every
remaining target result maps one-to-one to an `inheritance_sources` artifact
with the same artifact ID, expected hash, and criticality; omissions and
unrelated extras are invalid. JSON Schema enforces the local shapes and minimum
critical-root cardinality. Equality with subject fields and exact
cross-document coverage are enforced by the verifier.

An otherwise valid trajectory-root or handoff verification report may have no
external artifact targets; its advisory future-decision set is then exactly
`accepted` and `declined`. This still does not create an acceptance.

The effect is `activating` only for `accepted` and
`accepted_with_reservations`; `declined` and
`quarantined_integrity_failure` are non-activating. `accepted` requires every
target to be verified. Any `verification_not_attempted` or
`target_missing_unanchored` forbids either accepting decision. A critical-root
or required-source `hash_mismatch` or `target_invalid` also forbids either
accepting decision. Quarantine additionally requires at least one actual
`hash_mismatch` or `target_invalid`.

A verified ledger whose target is missing can support
`accepted_with_reservations`. A supporting or optional integrity failure can be
reserved only when that artifact is explicitly excluded from active
inheritance.
`accepted_with_reservations` requires a reservation for every non-verified
target. Every other decision requires an empty reservations array. JSON Schema
can require non-empty, unique arrays and the broad policy matrix; matching
every reservation to its target and enforcing uniqueness by typed ID require
the verifier.

Target states are:

- `target_present_verified`;
- `ledger_known_target_missing`;
- `hash_mismatch`;
- `target_invalid`;
- `verification_not_attempted`; and
- `target_missing_unanchored`.

Missing data known from a verified ledger is not an integrity failure. It is
reported exactly as `ledger known, target missing` and the CLI exits 10. An
unbound handoff requires both a null recipient installation and `expires_at`;
a bound handoff requires a typed recipient installation ID different from the
issuer. The verifier requires expiry to be later than issuance. Handoff
sequence 0 uses the all-zero previous handoff hash, and every later sequence
uses a non-zero previous handoff hash. These structural constraints do not
prove freshness or prevent replay without durable private replay state.
Every handoff carries all three mandatory safety constraints:
`manual_acceptance_required`, `verify_before_use`, and
`no_public_commitment`. Stage 2A has no operation that can override them;
future public commitments remain an explicit opt-in action outside this stage.
Both document references (`lineage_root_ref` and `latest_acceptance_ref`) use
`canonical_document`. A handoff may name each H_t log only once; two heads for
one `log_id` are ambiguous and invalid.

Expiry of an unbound handoff is evaluated only against an explicit
`--verification-time` value; the verifier never substitutes its ambient clock.
Without that value, expiry remains unevaluated, the evidence is incomplete, and
the result is exit 10 unless an independent integrity failure requires exit 2.
A supplied verification time at or after `expires_at` makes the document
invalid and yields exit 2. The comparison is reproducible, but both timestamps
remain untrusted claims.

These distinctions are invariant:

```text
VERIFY SUCCESS != ACCEPTED
HANDOFF VERIFIED != IMPORTED
TARGET MISSING != HASH MISMATCH
```

## Verification reports and CLI

A non-invalid report contains the verified document type, recomputed document
hash and resulting head, target results, allowed future decisions, proof status,
`evidence_status`, a strict `evidence_errors` array, and—only
for a trajectory root—the effective trajectory identity. `evidence_status:
"complete"` requires an empty evidence-error array. `evidence_status:
"incomplete"` requires at least one error identifying unavailable parent or
related-document evidence, an unevaluated out-of-band proof policy, or a
structurally valid but cryptographically unverified proof. It prevents
`verified`; absent a stronger target integrity failure it forces
`verified_with_unavailable_targets`. Incomplete evidence also removes
`accepted` and `accepted_with_reservations` from the advisory future-decision
set. For a structurally valid acceptance with unverified attribution or report
artifact, the more precise status is
`structure_valid_attribution_unverified`; it also has incomplete evidence and
exit code 10. A handoff or parent graph that relies on such an acceptance
inherits incomplete evidence.

Within the supplied verification set, one typed acceptance/handoff ID or nonce,
one responsibility `(chain_id, event_index)` slot, and one
`(chain_id, previous_head)` edge cannot map to different document hashes.
Conflicts are reported as responsibility forks. Durable detection across
separate invocations remains private-state work for Stage 2B/2C.

An invalid report contains at least one non-empty error. Contradictory parent
evidence is reported this way rather than as incomplete evidence. Report status
must agree with target and external-evidence status: `verified` has complete
external evidence and only verified targets,
`verified_with_unavailable_targets` has incomplete external evidence or at
least one unavailable target and no integrity failure,
`structure_valid_attribution_unverified` is restricted to a structurally valid
`LINEAGE_ACCEPTANCE` whose decision attribution and verification-report
artifact were not authenticated, and `integrity_failure` has at least one
mismatched or invalid target.

```text
python3 tools/tools/echo_lineage.py lineage verify --document FILE [bindings]
python3 tools/tools/echo_lineage.py handoff verify --document FILE [bindings]
python3 -B -m tools.tools.echo_lineage lineage verify --document FILE [bindings]
python3 -B -m tools.tools.echo_lineage handoff verify --document FILE [bindings]
```

The no-write guarantee applies to the documented direct-script invocations
above. The supported no-write module form includes `-B`, as shown. Plain
`python3 -m tools.tools.echo_lineage` may create interpreter-managed
`__pycache__` files before the module disables bytecode writes and is not a
supported no-write invocation.

Useful read-only bindings are repeatable `ARTIFACT_ID=VALUE` options.
`--target`, `--target-root`, `--ledger-root`, and `--ledger-entry` are keyed by
the target artifact ID. `--ledger` is keyed by the distinct
`ledger_artifact_id` named in that target's `ledger_ref`; this lets one
committed ledger serve more than one target without conflating the ledger with
its members. `--related-root`, `--related-acceptance`, and
`--related-handoff` supply graph and document evidence.
`--known-trajectory TRAJECTORY_ID=GENESIS_SHA256` binds an externally known
trajectory identity. `--expected-previous-head`, `--expected-chain-id`, and
`--expected-event-index` check responsibility continuity.
`--verification-time RFC3339` explicitly evaluates unbound-handoff expiry.

Exit codes:

- `0`: a non-acceptance document, every parent, and all attempted/required
  targets and evidence verified; Stage 2A never returns 0 for
  `LINEAGE_ACCEPTANCE`;
- `2`: malformed document, contradictory graph or parent evidence, unsafe
  target, hash mismatch, expired unbound handoff, or other integrity failure;
  and
- `10`: the document is structurally valid but at least one target or required
  evidence item is unavailable, missing, not attempted, an unbound expiry was
  not evaluated, or acceptance attribution/report evidence remains
  unauthenticated.

Under either supported invocation above, the verifier opens inputs read-only
and creates no files. There is deliberately no `accept`, `decline`, `import`,
`export`, `--state-dir`, head update, merge activation, lineage inference, or
commitment command in Stage 2A.

## Ledger reuse and residual risks

Target bindings reuse Stage 1B's hardened relative-path normalization, root
containment, ledger parsing, and hashing. Symlinks are rejected. Ledger
commitments establish membership and the scope-specific expected value but do
not imply semantic truth, identity, authority, or acceptance.

Residual risks include TOCTOU between path checks and reads, membership leakage
from hashes of guessable private plaintext, untrusted timestamps, absent or
unverified signatures, key loss, replay without persistent private replay
state, and valid hashes over malicious or semantically false content. Stage 2A
also does not authenticate the optional proof envelope: proofs cover the
responsibility head, but optional proofs are outside `document_hash` and can be
stripped until a future key/signature policy makes authentication mandatory.
Stage 2B/2C must address durable replay/rollback state, atomic import, key policy, and
controlled state mutation; none is implemented here.
