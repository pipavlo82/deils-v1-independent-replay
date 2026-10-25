# Independent DEILS reveal v1 live replay

Author: **Pavlo Tvardovskyi (`pipavlo82`)**. Published evidence version: **v1.0.0**.

Scope: **Two authorized DEILS v1 live fixtures and 16 local adversarial controls.**

| Fixture | Ledger position | Observed result |
|---|---|---|
| `proof_d7aea6052737f4335eb8` | 16 | `content_bound` |
| `proof_f0c2bd0e9bd475f872fd` | 17 | `content_commitment_mismatch` |

The negative fixture exposed a terminal-mismatch withholding bug. A subsequent read-only replay confirmed that the original stored proof and signature were no longer exposed through the tested GET and verification-only `/verify-proof` endpoints. The positive reveal was independently bound to its original signed commitment record using NIP-01 event-ID recomputation, BIP-340 signature verification and matching Python/Node JCS bytes and SHA-256.

These fixture states are **historical replay observations, not immutable conformance vectors**. Publication did not repeat live reveal requests or contact the DEILS service.

## Evidence and reproduction

The [original 142-file evidence pack](deils-v1-independent-live-replay-2026-10-25/README.md) is preserved byte-for-byte, with its [141-entry SHA-256 manifest](deils-v1-independent-live-replay-2026-10-25/SHA256SUMS), [complete inventory](deils-v1-independent-live-replay-2026-10-25/INVENTORY.txt), [results](deils-v1-independent-live-replay-2026-10-25/RESULTS.md), [privacy finding](deils-v1-independent-live-replay-2026-10-25/PRIVACY_FINDING.md), [controls](deils-v1-independent-live-replay-2026-10-25/ADVERSARIAL_CONTROLS.md) and [redaction manifest](deils-v1-independent-live-replay-2026-10-25/REDACTION_MANIFEST.json).

The original sanitized ZIP is attached to the [v1.0.0 release](https://github.com/pipavlo82/deils-v1-independent-replay/releases/tag/v1.0.0).

```text
ZIP SHA-256: b3544b46e8fce3c1015150ecd49557c355d37469f358d7fef281cb9c050d7f4e
```

From the repository root, using Python 3.12 and Node 22.15.0:

```sh
python -B deils-v1-independent-live-replay-2026-10-25/verify_integrity.py
python -B deils-v1-independent-live-replay-2026-10-25/replay/offline_replay.py --out ../deils-public-replay-output
```

The public offline replay needs no confidential inputs or network access. It verifies both public signed records, 19 official BIP-340 verification vectors and **13 of the 16 local controls**. The remaining three content-dependent controls explicitly require separately authorized private inputs and are reported as **NOT_REPLAYED** by public-only mode. Their historical results are retained; the actual revealed content, true blinding and pre-fix leaked payload are excluded.

## Publication and review attribution

Tiago authorized this public destination through Pavlo's publication instructions. Statements such as “LOCAL ONLY / UNPUBLISHED” and “awaiting Tiago” inside the pinned pack describe its earlier packaging state. They remain unchanged as historical evidence; this separate wrapper records the authorized publication.

**Echo independently confirmed the two-fixture PASS using his own verifier.**
He checked both signed records, their NIP-01 IDs/BIP-340 signatures and bindings,
the ledger-16 commitment bind, and the ledger-17 withholding fix. This is distinct
from repeating Pavlo's live reveal request sequence.

Echo subsequently cold-replayed the public pack at
`58be70b420aaa223611d92702b4624b751d4f08d`: the ZIP hash and byte identity,
141/141 integrity entries, 13/13 public controls, 19/19 BIP-340 vectors, both
signed records, and normal/Python `-O` offline replay. He also reported that a
flipped signature bit fails both integrity and replay (at `ORIGINAL_RECORD`).
These are Echo's independently executed results, as reported in his working-group
clarification; his raw replay logs are not included here.

**The three private-input controls remain author-only.** Echo did not rerun all
16 local controls. Their original execution is Pavlo's work; the public pack
reproduces 13 and explicitly reports three as `NOT_REPLAYED` without private inputs.

Echo withdrew his earlier attribution correction request: "Keep your original
wording. It's accurate." The [attribution clarification](errata/attribution-v1-2026-10-25.md)
marks the briefly published erratum as withdrawn. Ordinary commits retain that
publication history; the original v1.0.0 evidence and tag have not changed.

| Evidence activity | Attribution and reproducibility |
|---|---|
| Two-fixture live replay and 16 local controls | Authored and executed by Pavlo Tvardovskyi. |
| Signed records, ledger-16 bind and ledger-17 withholding | Independently checked by Echo using his own implementation. |
| Public pack at `58be70b4` | Cold-replayed by Echo: 141 hashes, 13 public controls, 19 BIP-340 vectors, two signed records, normal and `-O`. |
| Three content-dependent controls | Author-only historical results; require private inputs and are `NOT_REPLAYED` in public mode. |

The original review transcript and Echo's private replay environment are not part
of this package. No broader independent acceptance is inferred.

## Public contract pin

**Snapshot of deployed descriptions, mapping per invinoveritas.**

- Repository: `babyblueviper1/invinoveritas`.
- Commit: `992f36b2661299557fe6c05e91fa089e05021cef`.
- File: [`deils/reveal-contract-2026-10-25.json`](https://github.com/babyblueviper1/invinoveritas/blob/992f36b2661299557fe6c05e91fa089e05021cef/deils/reveal-contract-2026-10-25.json).
- Size: 4,752 bytes; `api_version: 1.13.0`.
- SHA-256: `e4629dec96ae78844515234d202eda560fd0734eaf4a67c04c494985170fde4c`.

Private deployment commits `6f8c80be` and `95e066cb` are **upstream-reported**, not independently verifiable from this public snapshot. The snapshot is not retroactive proof of a deployed process revision.

## NOT_COVERED

- Production-wide security.
- All customer records.
- OTS/PQ anchoring.
- External execution.
- General agent authorization.
- Full security or privacy certification.

The [limitations](deils-v1-independent-live-replay-2026-10-25/LIMITATIONS.md) also distinguish unavailable source messages, absent private inputs, the actual observed refusal classes and the limits of before/after HTTP stability.

This repository is an attributed evidence record, not a new DEILS implementation. It does not assume access to the private `trustless-ai/deils` repository. When that repository becomes public, this versioned record can be incorporated by reference while retaining its attribution and pins. No third-party dependency is relicensed; included licenses remain intact.

`PUBLICATION.json` and `PUBLICATION_SHA256SUMS` cover this wrapper separately from the immutable evidence pack.
