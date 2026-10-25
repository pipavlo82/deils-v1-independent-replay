# DEILS v1 independent live replay — 2026-10-25

Author: **Pavlo Tvardovskyi (`pipavlo82`)**. Evidence-pack version: **1.0.0**.

Package verdict: **READY_FOR_PUBLICATION_REVIEW**. Historical replay verdict: **PASS, bounded to two authorized fixtures and the tested endpoints**.

**LOCAL ONLY / UNPUBLISHED.** Repository placement and visibility await Tiago's decision. No private DEILS repository access is assumed for reviewers. This is preservation of executed evidence, not a new security audit or an adopted normative specification.

## Scope

Two authorized live fixtures plus 16 local adversarial input controls: signed commitment records, NIP-01/BIP-340, record/row and authenticated profile binding, observed pre-hash refusal and terminal behavior, positive commitment binding, and the tested withheld-content boundary.

The negative fixture is `proof_f0c2bd0e9bd475f872fd`, ledger 17. The positive fixture is `proof_d7aea6052737f4335eb8`, ledger 16. Their historical observations are **not sealed or immutable conformance vectors**. No fixture was contacted or changed during this packaging task.

## Read and reproduce

1. `SOURCE_PINS.json` and `sources/` pin the public contract and key reference.
2. `FIXTURE_REPLAY.md`, `RESULTS.md` and `PRIVACY_FINDING.md` map conclusions to saved observations.
3. `ADVERSARIAL_CONTROLS.md` covers all 16 local controls, including old-ID signature versus event-ID recomputation.
4. `REPLAY.md` gives offline commands. The public-only replay verifies both records, 19 official BIP-340 verification tuples and 13 controls. Three content-dependent controls require authorized private inputs and are never silently counted as public replay successes.
5. `REDACTION_MANIFEST.json`, `PRIVACY_SCAN.json`, `PROVENANCE.json`, `INVENTORY.txt` and `SHA256SUMS` describe exact contents and redactions.

Python and Node independently reproduced 1744 JCS bytes with SHA-256 `d3a134d0227c4ff1b30ec13a4a3b6145d2a059ee2b612c274c7bb59b5de844ef`, equal to the original pre-reveal signed commitment. The raw positive content and real blinding are deliberately absent here.

No independent acceptance by Echo is claimed. The runtime algorithms are independently checked; this evidence package and its offline checks remain Pavlo's replay. No production-wide privacy/security, OTS/PQ anchoring, customer-record coverage, external execution or general authorization claim is made.
