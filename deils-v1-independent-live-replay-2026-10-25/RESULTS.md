# Exact observed results

These statements are traced to saved HTTP bytes, sanitized observations and executed local logs, not rebuilt from narrative summaries.

| Surface | Observation | Evidence |
|---|---|---|
| Negative original state | content_withheld; ledger17; authenticated deils-reveal-v1 | terminal/http/negative-before.body |
| Pre-hash refusal | HTTP200, blinding_missing, terminal=false, hash_evaluated=false; before/after bytes equal | terminal/http/prehash-*.body |
| Terminal wrong content | HTTP200, content_commitment_mismatch, matches=false, terminal=true | terminal/http/terminal-post.body |
| Terminal hash evaluation | no hash_evaluated field exposed; recomputed_hash equals independently hashed known synthetic submission | terminal-post.body; original Python logs/reconciliation |
| Initial privacy regression | terminal GET carried /proof and /signature, absent before; both redacted | terminal-after.body/meta; PRIVACY_REDACTION.json |
| Fixed negative GET | mismatch persists; no stored proof/signature; caller submission attributed exactly | fixed/http/negative-before.sanitized.json; PYTHON_RESULTS.json |
| Fixed verification-only POST | HTTP200; valid=false; status=content_commitment_mismatch; state=not_evaluated; no stored payload | fixed/http/verify-negative.* |
| Positive later state | content_bound; ledger16; signed record unchanged from pre-reveal | fixed/http/positive-before.sanitized.json; original-positive-record.json |
| Positive content binding | Python/Node exact 1744-byte JCS preimage; commitment matches original | recorded/PYTHON_RESULTS.json; NODE_RESULTS.json |
| Both signed records | NIP-01 ID and BIP-340 valid; active pinned key, profile and row bindings pass | replay/sources/original-*-record.json; recorded logs |
| Local controls |16/16 rejected;0 unexpected acceptances,0 crashes | ADVERSARIAL_CONTROL_MATRIX.json |

Paths in the table are relative to `evidence/`, except `replay/` paths.

Positive canonical SHA-256: `d3a134d0227c4ff1b30ec13a4a3b6145d2a059ee2b612c274c7bb59b5de844ef`.

Active key: `6786e18a864893a900bd9858e650f67ccc3513f248fed374b591e2ff6922fbb7`. Both live key manifests were fully JSON-equal to GitHub key manifest at `06d34d75db6888fb6ebee54e6ce5facb783140d2`, including active/validity/revocation fields.

Negative original signed commitment: `sha256:da9d73871cc0084ea3d2f5a2534becdc688349e7c2106ca3bd6e525d1ceed06e`.

Caller-owned synthetic mismatch digest: `sha256:ab6fdff392ee0fd84fe49e80b55879b8b11d84423073e4a99c00a251a9037f56`.

The terminal replay phase recorded13 service requests (11GET,2revealPOST: one refusal and exactly one terminal mismatch). The later privacy/positive phase recorded8 (7GET,1verify-proof POST with consume:false,0reveal). Earlier preparation/HOLD requests are separate historical work; these21 requests are not claimed as the entire lifetime request count. Packaging performed **zero DEILS service requests**. Only the new public contract was retrieved from GitHub.

Historical normal/repeat and Python-O complete outputs matched within their respective runtime. Packaging re-executed the saved-input checks offline and matched their semantic results. No byte-identical future live HTTP replay claim is made; recorded before/after equality is a historical observation, not an immutability promise.
