# Three runnable outcomes

All records are fictional. Run from the repository root using Python 3.10+.
The second and third commands intentionally return nonzero process exit codes.

Verified independent root, exit **0**:

```sh
python3 -B tools/tools/echo_lineage.py lineage verify --document tools/examples/echo-lineage-v1/TRAJECTORY_ROOT.example.json --json
```

Structurally valid acceptance with unauthenticated attribution, exit **10**:

```sh
python3 -B tools/tools/echo_lineage.py lineage verify --document tools/examples/echo-lineage-v1/LINEAGE_ACCEPTANCE.example.json --related-root tools/examples/echo-lineage-v1/TRAJECTORY_ROOT.example.json --json
```

Mutated root whose saved digest no longer matches, exit **2**:

```sh
python3 -B tools/tools/echo_lineage.py lineage verify --document examples/MUTATED_ROOT.json --json
```

Exit 0 does not authorize activation. A continuation requires parent handoff
and acceptance evidence; acceptance attribution is not authenticated in Stage
2A, so even a structurally valid continuation remains incomplete (exit 10).
The successful example is therefore an independent root, not a continuation.

`Ht_pair.jsonl` and the H_t seed fixture are generated fictional records.
The date retained in the seed filename is a compatibility filename, not evidence
of a real event. `MUTATED_ROOT.json` changes only `body.created_at` in the root
example while retaining its original hashes; the mismatch is deliberate.
