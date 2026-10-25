# Limitations and evidence gaps

## Explicitly NOT_COVERED

- Production-wide security, all customer records, complete privacy/security certification.
- OTS/PQ anchoring, independently authenticated public publication or external timestamp validation.
- External execution, payments, general agent authorization or recipient-only access.
- Entropy/freshness of the true blinding; its observed format does not prove CSPRNG generation.
- Private deployment commit authenticity;6f8c80be/95e066cb/e8149678 are upstream-reported mappings.
- Every refusal branch or concurrent-consumption/internal-database behavior. Only the documented live missing-blinding refusal was independently executed in the terminal phase.

## Unavailable or intentionally excluded

- The original Federico acknowledgement message is not retained. Public contract evidence documents the reported repair without an invented quotation.
- The exact successful positive reveal request and its execution timestamp are unavailable. The positive state and cryptographic bind were independently observed later by GET.
- The original pre-fix leaked bytes are excluded and not reconstructed. Their preserved original-wire digest is an observation commitment, not a rehashable public blob.
- Positive revealed content, true blinding and its full raw response are excluded. Public-only replay covers13/16 local controls; three require separately authorized private inputs. Recorded16-control outputs remain available and were privately rerun offline during packaging.
- The initial source authority and fixture authorization came from Pavlo's instructions conveying Federico's permission. No additional signed authorization record is fabricated.
- Node JSON.parse is not an independent duplicate-member detector. The accompanying Python parser rejects duplicates; the independent byte comparison is limited to the admitted integer lane, not all RFC8785 values.

Historical fixture state is not immutable. Before/after byte equality belongs to the recorded window, not future live responses. No new DEILS HTTP requests were made while packaging. No claim is made that Echo replayed these16controls or both fixtures.

Publication placement/visibility awaits Tiago; the private trustless-ai/deils repository is not assumed accessible. No repository or new repository was created. Upstream dependency licenses are preserved; this package does not relicense them or establish an organizational certification.
