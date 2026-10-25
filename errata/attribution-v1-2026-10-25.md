# Attribution clarification — erratum v1 withdrawn (2026-10-25)

The attribution correction published at
`e0131fabfd5309da08b305aac5d5f819bc37a4fc` has been **withdrawn by Echo**.
It followed an earlier working-group message that Echo subsequently superseded.
His final clarification: "Keep your original wording. It's accurate."

The original publication's statement that Echo independently confirmed the
two-fixture PASS with his own verifier is accurate. He independently checked
both signed records (BIP-340, event IDs and bindings), the ledger-16 bind and
ledger-17 withholding fix. This does not mean he repeated Pavlo's live reveal
request sequence or all 16 local controls.

## Subsequent independent public replay

Echo also reported a cold replay of the public evidence at original commit
`58be70b420aaa223611d92702b4624b751d4f08d`:

- Release ZIP hash, 552,285-byte size and byte identity with the committed pack.
- 141/141 integrity hashes and exact inventory.
- 13/13 public adversarial controls and 19/19 BIP-340 vectors.
- Two signed records matching his earlier live API observations.
- Normal and Python `-O` offline replay, JCS and event-ID checks.
- A flipped signature bit in a local copy rejected by integrity and independently
  by replay at `ORIGINAL_RECORD`.

These are Echo's reported independent executions, directly read in the
Trustless AI working-group discussion on 2026-10-25. His raw replay logs are not
bundled. The earlier statements that he had not run the public replay or
verified the 141-entry manifest are superseded by this later execution.

Pavlo Tvardovskyi (`pipavlo82`) remains author and executor of the full historical
live replay and 16 local controls. **Three private-input controls remain
author-only.** They are `NOT_REPLAYED` without the excluded private content.

## Evidence unchanged

This clarification changes publication documentation only. It is not a new
evidence release. The original 142 evidence files, `SHA256SUMS`, commit,
tag `v1.0.0` and ZIP asset are unchanged. The intermediate correction remains
in ordinary Git history; no history or tag is rewritten.

Original ZIP SHA-256:

```text
b3544b46e8fce3c1015150ecd49557c355d37469f358d7fef281cb9c050d7f4e
```

Fixture states are historical observations, not frozen conformance vectors.
Production-wide security, all customer records, OTS/PQ anchoring, external
execution, general agent authorization and full certification remain NOT_COVERED.
No new DEILS service requests or private-input publication accompanies this update.
