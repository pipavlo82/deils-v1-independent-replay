# Fixture histories

## Negative fixture — ledger17

ID: `proof_f0c2bd0e9bd475f872fd`. Authenticated profile: `deils-reveal-v1`.

1. Original GET: `content_withheld`, existence tuple plus signed record. Saved raw response SHA256 `9dfa7e8ec202c3de17f247bd522dbb1423c84f20e09cf67adc67bfe328d6a4f8`.
2. At approximately14:58:00UTC, authorized content `{}` returned `blinding_missing`, HTTP200, terminal:false, hash_evaluated:false. GET remained byte-identical. Other pre-hash classes were reported by Federico and were not independently rerun in this live phase.
3. At approximately14:58:15UTC, exactly one authorized well-formed synthetic wrong-content request produced terminal `content_commitment_mismatch`. The caller-chosen64-zero blinding is a public synthetic control, not the withheld secret. No terminal retry occurred.
4. Immediate GET at14:58:15UTC retained mismatch state but disclosed `/proof` and `/signature` fields absent before. Their content was redacted. The exact original-wire digest survives; leaked bytes are not distributed or reconstructed.
5. Invinoveritas subsequently reported the withholding repair as95e066cb. The public pinned snapshot calls it `terminal_mismatch_withholding_fix`. An original standalone acknowledgement message is not retained in this evidence set; do not fabricate a quotation or timestamp.
6. On the later read-only replay, GET at15:56:32..33UTC and16:02:43..44UTC returned byte-identical1882bytes, SHA256 `189301d511dbe38023f43435ee0cfc3764e5b436afafe39935fb3a5f1d83ead0`. Only caller-owned mismatch content was present, plus public commitment evidence.
7. At15:56:33..34UTC, `/verify-proof` with proof_id and consume:false returned HTTP200, valid:false, content_commitment_mismatch, not_evaluated; raw263-byte digest `48734452214b51d3f552e329c25dc81f18cc1c90d386cd5e706ee0af7f98104a`. No stored original proof or signature was present.

The original negative secret content/blinding is not known to this packaging task. Source attribution of the returned mismatch content is established by equality to the saved caller request, not by guessing the original.

## Positive fixture — ledger16

ID: `proof_d7aea6052737f4335eb8`. Signed profile: `deils-reveal-v1`.

1. The original signed commitment was captured before reveal, including the earlier12:29UTC preparation observation (`evidence/initial-positive/`). Withheld response raw SHA256 `44776426807fba35c1b5afc3b6dde6c10b8fba30e5b222575bce789df9cb9860`.
2. Original event ID: `3b40439b3b741752035fe38fc698f6884aa670ed5b8abf7c454155b17ae7b968`.
3. Later GET at15:56:33UTC observed `content_bound`. The audit did not issue this positive reveal; the transition happened upstream between observations. The exact successful reveal request/time is unavailable here.
4. The entire commitment record matches the pre-reveal record. Event ID, active-key BIP340 signature, exact signed JCS, proof_id/ledger16/profile/commitment bindings pass.
5. Python/Node produced identical1744 JCS bytes. SHA256 `d3a134d0227c4ff1b30ec13a4a3b6145d2a059ee2b612c274c7bb59b5de844ef` matches the original signed commitment. Blinding is64lowercasehex; integer-only safe-number lane holds. Actual bytes and blinding stay private.
6. An added content profile=v0 does not select policy: verification retains the authenticated v1 profile and rejects the altered commitment preimage.
7. Final GET at16:02:44..45UTC matched the first bound GET byte-for-byte:6022bytes, raw SHA256 `d6dcea1c3552852cabcbc7a3ffb2d9cb3d8e6c0ef3ee6c57c5f9ea3a8e60f624`.

These times and states are historical HTTP observations. They are not frozen/live conformance guarantees. No fixture has been contacted again during packaging.
