# Public contract pin

Repository: `babyblueviper1/invinoveritas`.

Exact commit: `992f36b2661299557fe6c05e91fa089e05021cef`.

Path: `deils/reveal-contract-2026-10-25.json`.

Raw length: **4752 bytes**. SHA-256: **`e4629dec96ae78844515234d202eda560fd0734eaf4a67c04c494985170fde4c`**.

Git blob: `614e9edf23b595bbf3c345455dbb03f9d422cd61`. The abbreviated revision was resolved through GitHub. A separate anonymous raw-content GET returned HTTP200 and identical bytes. See `evidence/public-contract-access.json`.

`api_version` is `1.13.0`. The snapshot contains GET `/attestations/{proof_id}` and POST `/prove/{proof_id}/reveal`; its GET description explicitly extends withholding to POST `/verify-proof` by proof ID. It does **not** contain the full `/verify-proof` schema or its referenced components. The exact recorded OpenAPI excerpt supplies `VerifyProofRequest` and `consume:false` semantics; the snapshot is not presented as a complete standalone OpenAPI document.

## Documented refusal order

First failure wins:

1. `commitment_record_mismatch`: terminal=true, hash_evaluated=false; internal integrity check with no public injection seam.
2. `input_refused`: integer-lane/type/range rejection, terminal=false, hash_evaluated=false.
3. `blinding_missing` / `blinding_malformed`: exactly 64 lowercase hex characters required; non-terminal, pre-hash.
4. `input_refused`: outside RFC8785 JCS domain, including lone surrogate; non-terminal, pre-hash.
5. `content_bound` or terminal `content_commitment_mismatch` after comparison.

Documented valid-shape outcomes use HTTP200. Other documented statuses:404 unknown proof,422 invalid outer body,429 rate limit. This order is a source contract, **not a claim that every branch was live-tested by Pavlo**.

## Withholding boundary and provenance

Stored `proof` and `signature` are served only at `content_bound`. Withheld state returns an existence tuple and signed commitment record. Mismatch returns that information plus caller-submitted mismatch evidence, never the stored original payload. A public commitment-record signature is not the stored proof signature.

The snapshot maps refusal semantics to private deployment commit `6f8c80be`, withholding repair to `95e066cb`, and boundary-description work to `e8149678`. These are **Invinoveritas-reported mappings**, not independently authenticated production revisions. The public snapshot was created after the live observations; it is not backdated deployment evidence. `evidence/CONTRACT_COMPARISON.json` compares its actual paths to the saved observed OpenAPI bytes.

Actual comparison: the reveal operation is structurally identical to the recorded OpenAPI operation. GET differs only at `/get/description`, where the later public snapshot adds explicit withholding prose. The historical GET behavior was measured directly; the later prose is not substituted for that observation.
