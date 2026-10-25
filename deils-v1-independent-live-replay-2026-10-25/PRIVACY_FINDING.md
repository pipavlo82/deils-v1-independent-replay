# Terminal-mismatch privacy finding and repair

The authorized wrong-content reveal itself behaved as expected: terminal mismatch. The defect appeared in the subsequent public GET, which returned stored-proof fields despite the lack of a matching reveal. Commitment integrity alone did not enforce the withholding boundary.

## Preserved observation

Original terminal GET:6043wirebytes; SHA256 `852eb3842d55797b5b01bc0b9d8dd178766d462206c78dbaed8ddb1621f68aee`. `/proof` and `/signature` were present and absent in the earlier withheld GET. The final sanitized artifact is `evidence/terminal/http/terminal-after.body`, SHA256 `c00d1d2b4651721342c0ba41f3e527ac2ddda747bd305b118dbd4b58100aba25`.

`PRIVACY_REDACTION.json` preserves the original-wire and intermediate/final sanitized hashes. Leaked bytes were deliberately not retained in shareable evidence. We cannot reproduce their raw original-wire hash from redacted bytes, and do not pretend otherwise. Their equality to the original commitment was not recomputed in the earlier replay. The initial report therefore recorded a disclosure observation pending maintainer interpretation.

Invinoveritas now explicitly documents the intended boundary in the pinned public contract, with `terminal_mismatch_withholding_fix:95e066cb`. Federico's direct acknowledgement/fix was conveyed upstream; an original acknowledgement message is unavailable locally. The source file substantiates the operator's reported repair mapping, not which private commit a running process actually used.

## Verified repair observation

Saved later GET and consume:false verify-proof responses omit original stored proof/signature. Nested field inventories and source attribution exhaust the returned structures. The only returned blinding belongs to the earlier caller-controlled synthetic mismatch request. Public commitment-record signatures remain present, as required, and are not mislabeled as proof disclosure.

Two later GETs are byte-identical. Verification-only POST returns valid:false/status:content_commitment_mismatch/state:not_evaluated. The specific regression is no longer observable on those tested response paths.

## Failed attempts preserved

- The earlier live harness expected terminal GET `status`; the actual response used `reveal_state`. Its exit1/STOP remains recorded. Saved evidence was reconciled offline; no terminal retry. A red harness assertion was not relabelled as a green live invocation.
- The first sanitizer missed the top-level proof material in tool output. It was corrected before the old shareable archive; this new pack contains no unredacted material and does not republish that tool output.
- This packaging pass initially selected an extensionless import in a library comment, then used `reveal_state` for the earlier withheld schema (which actually used `status`). Both packaging failures were local, corrected without new live calls, and recorded in `evidence/PACKAGING_ATTEMPTS.json`.

This is not evidence of complete confidentiality, database erasure, revocation of previously disclosed information, or protection of every customer record. The earlier exposure cannot be undone by a later withholding fix.
