# Attribution erratum v1 — 2026-10-25

Applies to the editable publication documentation and release description for
DEILS independent replay evidence **v1.0.0**, originally published at
`58be70b420aaa223611d92702b4624b751d4f08d`.

Author of the replay: **Pavlo Tvardovskyi (`pipavlo82`)**.

## Correction

The original root README, `PUBLICATION.json` and release description summarized
Echo's work too broadly as confirmation of the two-fixture PASS. That wording
must not be read as an independent execution of Pavlo's entire replay.

Echo independently checked selected cryptographic and withholding properties of the same two live fixtures using his own implementation, and reviewed Pavlo's reported results. Echo did not independently execute Pavlo's full live replay or the 16 local adversarial controls.

Echo did not verify the 141-entry hash manifest or run the public offline replay.
His selected-property checks and review of Pavlo's report do not independently
establish execution of Pavlo's full procedure, all 16 controls, or its 13-control
public subset.

Pavlo executed the two-fixture live replay and the 16 local adversarial controls.
The public package reproduces 13 controls. Three content-dependent controls need
separately authorized private inputs and remain `NOT_REPLAYED` in public mode.
No such private inputs are published.

This correction follows Echo's clarification in the Trustless AI working-group
discussion on 2026-10-25. His earlier descriptions of separately implemented
cryptographic and withholding checks are distinguished from his review of the
complete report. Neither is presented as a rerun of Pavlo's complete replay.

## Immutable evidence boundary

This is **attribution erratum v1**, not a new evidence release. The original
142 evidence files, their `SHA256SUMS`, the original commit, tag `v1.0.0`, and
the release ZIP remain unchanged. Historical tagged publication wording remains
readable; this erratum supersedes its broad attribution. No correction to the
frozen evidence files is needed: those files do not claim Echo replayed the
complete fixtures or controls.

Original ZIP SHA-256:

```text
b3544b46e8fce3c1015150ecd49557c355d37469f358d7fef281cb9c050d7f4e
```

The fixture states remain historical observations, not immutable conformance
vectors. Production-wide security, all customer records, OTS/PQ anchoring,
external execution, general agent authorization and full security certification
remain NOT_COVERED. No new DEILS service requests were made for this correction.
