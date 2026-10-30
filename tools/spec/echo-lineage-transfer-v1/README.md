# Stage 2C: explicit local transfer and context consumption

Status: **implementation test candidate; independent patch review and release pending**.

The first profile, `2C-h1-bound`, extends the separate local Stage 2B state
workflow. It leaves the existing Stage 2A verifier, schemas, exits, and Stage 2B
CLI unchanged. Existing documents and prior decisions retain their exact
meaning. This is a bounded research demonstrator, not general agent identity
authentication or a production security boundary against an account owner.

## Complete declared scope

One source installation with an existing independent `2B-h1-local` root can
issue one bound handoff to one new recipient installation. The recipient can
receive, decide, import a selected verified scope, and separately authorize a
fixed local UTF-8 context consumer. Explicit files carry the envelope and return
receipts; the protocol opens no network connection.

The consumer is a real separate local process. It loads selected imported
documents into memory and provides bounded literal read/search operations. Its
signed response to a fresh probe attests to this local use within the trusted
account. It does not establish that a cloud model read, remembers, adopted, or
consciously consented to anything. Transferred text never becomes executable
code, a command, a trust policy, or a grant of tool access.

The reference consumer requires Linux procfs and `SO_PEERCRED` for its anchored
private Unix socket. The POSIX filesystem contract for state storage remains
separate; another runtime platform needs its own reviewed adapter.

This profile excludes fork/merge, key rotation, a second transfer from the same
source epoch, automatic model startup, cloud model integration, automatic
network delivery, and exclusive continuation. It does not require the source
runtime to stop.

## Distinct evidence layers

| Observation | What it establishes |
| --- | --- |
| Policy provisioning | Local keys, installations, purposes and consumer are pinned |
| Signed candidate | A scoped key authorized these exact proposed bytes |
| Migration committed | This local store has changed writer/profile |
| Handoff issued | One source responsibility slot was consumed and the epoch sealed |
| File exported | Local output was observed; remote receipt is still unknown |
| Receive committed | Recipient state holds the envelope and actual staged bytes |
| Return receipt verified | The registered recipient key attests to that milestone |
| Decision recorded | A particular operator decision was recorded |
| Lineage acceptance | The separately signed v1 acceptance covers the continuation |
| Import committed | Exactly the allowed selected bytes are locally published |
| Activation authorized | An operator granted a particular consumer/read set |
| Launch intent committed | One attempt may start; completion is not yet known |
| Loaded receipt verified | The pinned adapter attests to loading and probing context |
| Fresh signed status | This consumer responded now; old receipt alone is insufficient |

Receipt, acceptance, import, authorization, launch, historical consumption, and
current liveness are separate. No return receipt means **UNKNOWN**, rather than
proof that delivery failed. An acknowledgment is not consent or canon.

## Trust policy

The closed `echo-lineage-transfer-trust/v1` policy is provisioned independently
at both endpoints. Migration and recipient initialization require its expected
digest explicitly. A policy carried in an envelope cannot install itself.

The policy pins the transfer ID; source store, installation, exact legacy
snapshot digest and old acceptance policy digest; a different recipient store
and installation; an explicit recipient v1 lineage-acceptance registry; scoped
operator keys; and a distinct local consumer key/identity/version/code digest
with `read` and `search` capabilities.

Control purposes are separate: migration, issuance, export, receive, receiver
decision, context import, context activation, deactivation, return receipt, and
receipt ingestion. The consumer role can only attest to consumption. A previous
`lineage_acceptance` grant does not authorize source migration. A control
decision grant does not imply v1 lineage-acceptance authority. Operators sign as
their own recording actor; this authenticates a pinned key holder, not
biological identity, physical consent, or an unsigned root's author.

The separately signed packet has closed fields `schema`, `policy_digest`,
`purpose`, `actor_id`, `installation_id`, `role`, `payload`, and an Ed25519
`proof`. Its signature domain includes the purpose. Model-specific payloads
have their own closed validation. Canonical transfer digests use
`ECHO|TRANSFER|v1|<DOMAIN>|` and canonical JSON. Protocol document hashes, full
canonical artifact hashes, raw transport byte hashes, and transfer hashes
remain distinct.

Legacy metadata preserves JSON objects and their protocol/full canonical
hashes. It does not preserve or attest to the original root file's whitespace
or raw file bytes. Newly exported metadata uses reproducible canonical JSON
plus one LF; that output's raw byte hash is a separate derived observation.
Captured payload base64, in contrast, preserves its exact original bytes.

## Source ownership and independent recipient

Migration uses the original store's stable lock and one atomic snapshot
replacement. It preserves the complete signed legacy history and adds a
separate lifecycle journal. The changed closed profile causes the old Stage 2B
CLI to refuse subsequent writes. Migration does not consume a responsibility
slot. Preparation and signing do not reserve one either.

Issuance requires the latest source decision itself to be the exact current
activating acceptance, with no integrity block. An older active acceptance
surviving a later decline is insufficient. Atomic issuance consumes the next
responsibility slot and permanently seals this profile's epoch. A refusal or
expiry does not make that slot reusable. The same immutable transfer can be
exported again; an alternative transfer requires a later protocol profile.

Before migration or issuance, the profile also checks the deterministic
recipient chain and reserved metadata artifact IDs. The recipient chain must
differ from the source chain; the source-acceptance, recipient-root, and handoff
artifact IDs must not alias source root, inherited artifact, or ledger IDs.
A collision is refused before source ownership or sealing, allowing a different
transfer ID to be provisioned while the existing source remains unchanged.

The envelope binds the complete pre-issuance source proof, signed issuance and
export authority, actual captured bytes, independent policy digest, both
installations, nonces, state heads, and explicit times. It does not include its
own digest recursively. Embedded policy/history/flags are verified against
local pins and replayed rather than treated as authentication.

The recipient creates a new `continuation` root: a new installation and chain,
the same trajectory/genesis, and exactly one predecessor pointing at the
actual handoff. It cannot relabel an existing independent root. The producer
runtime-session ID is only a local producer claim. No model identity is
inferred. Full required closure and target coverage are checked by a new typed
adapter; old verifier errors are never removed by string matching.

## Decisions, bytes, and reservations

The four control decisions are `accepted`, `accepted_with_reservations`,
`declined`, and `quarantined_integrity_failure`. Acceptance requires consistent
closure and a real separately authorized v1 lineage acceptance. A refusal can
be recorded without fabricating acceptance of invalid lineage.

Payload bytes are bounded, captured explicitly, and held inside the atomic
snapshot as base64. Paths used locally to capture data never become commands
or filesystem destinations inside a packet. Missing ledger-bound data and
explicit exclusions remain distinct from corruption. Import may only select
verified, accepted, non-excluded artifacts. Binary evidence can remain staged;
the first context consumer interprets only selected UTF-8 documents.

## Process activation and recovery

The operator activation grant binds the exact import and acceptance, selected
manifest, consumer identity/version/code digest, installation/store, activation
ID, capabilities, nonce, and a fresh probe. A durable consumer launch intent
precedes process creation. A fixed installed module is launched directly,
without a shell or any packet-derived executable. Private anchored Unix IPC
and a stable instance lock prevent a duplicate live consumer.

Journal capacity is reserved for the entire activation and revocation path:
four slots before a grant, three before launch intent, and two before a loaded
receipt. The last remaining slot can therefore record deactivation. A new grant
that would exhaust this reserve is refused without changing state; exact
idempotent replay still works after the journal reaches its limit.

After loading, the consumer answers a probe from its in-memory context and
signs an observation bound to the grant, actual loaded hashes, instance, and
time. The commit rechecks that the grant is still current. Every subsequent
read/search checks current authorization. Revocation denies future reads;
it cannot undo past access. A receipt remains historical after a process dies.

Canonical JSON normalizes display strings to NFC. Exact read/search text is
also returned as `text_utf8_b64`; literal search queries are encoded internally
as UTF-8 bytes before canonical transport. The loaded probe receipt binds
`probe_result_sha256` of the exact original substring bytes. Display text alone
must not be used as proof of byte identity. Fresh status returns the probe hash
rather than exposing document text. IPC verification also requires an explicit
independent state directory; a policy carried by control metadata is compared
with that state and cannot authenticate itself.

An uncertain start or receipt outcome requires explicit inspection and
reconciliation. It never triggers automatic relaunch. State snapshots, file
output, another computer, and process startup are separate atomicity domains.
`commit_uncertain` and `output_uncertain` require inspection before retry.
An identical signed request is deduplicated before CAS; conflicting request
reuse, nonce reuse, or a stale new action fails closed.

## Filesystem, rollback, and release gates

The profile assumes a non-attacker-controlled POSIX account. State and control
directories are private and outside Git checkouts; stable inode locks and
anchored directory descriptors protect local transitions. Symlinks, hardlinks,
special files, unsafe parents, and unbounded input are refused. No protection
against a malicious account owner or root is claimed.

Limits: 8 MiB state, 4 MiB complete envelope, 1 MiB legacy proof, 1 MiB decoded
payload total, 16 payload artifacts, 64 lifecycle records, depth 64. Capacity is
checked before irreversible changes, with space reserved for later phases.
An oversized valid legacy history is refused rather than pruned.

These are individual upper bounds, not a promise that every combination fits.
Capacity preflight includes full policy registries, duplicated continuation
metadata in the receiving signed action, base64 overhead, and future control
records. A valid source that cannot complete this bounded profile is refused
before migration/issuance rather than sealed into an unusable transfer.

Without an independently trusted checkpoint, restoring a whole valid old
snapshot remains undetectable: `rollback_protection=not_externally_anchored`.
A checkpoint must verify actual history membership, not just generation.
UTC values are explicit clock claims, not a trusted-time service.

Publication requires unchanged 151-test stdlib Stage 2A and 307-test Stage 2B
profiles, full 2C negative/concurrency/crash/process gates, an updated exact
manifest/test count, independent review of the exact patch, and human
key/privilege review. Implementation, review, publication, installation, and
adoption remain distinct decisions. No real keys or private context belong
in this public tree.
