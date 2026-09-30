# Generic assessment and report contract

The generic investigation command sends one compact evidence packet to the
assessment model. The model does the writing and reasoning; Python only
collects evidence, validates citations/schema, applies safety limits, and
renders an accepted response.

## Required model output

The model must return strict JSON with:

1. `verdict` and integer `confidence`.
2. `what_happened`: one or two evidence-cited observed statements.
3. `alert_claim_assessment`: an evidence-cited assessment of the Wazuh title,
   which is treated as a detection claim rather than proof.
4. `hypotheses`: zero to two evidence-cited items, with at most one each of:
   - `possible_legitimate_context`
   - `possible_concern`
5. `unknowns`, constrained response options, and one bounded analyst question.

Hypotheses must use bounded language such as “consistent with,” “could
indicate,” or “may warrant review.” A hypothesis may refer to a clue such as a
test marker, but it cannot silently turn that clue into authorization or fact.
When it uses unverified operational context (for example, “controlled,”
“expected,” “known,” “user-installed,” “bundled,” or “documented”), the assessment is accepted with an explicit caution
and its confidence is capped at 65.

`same_hash` is a weak identity-only relationship: it shows that records refer
to the same file hash, not that they share a process chain or caused one
another. A hypothesis that relies only on same-hash evidence is accepted with
a correlation caution. Likewise, product-looking registry/path labels are not
software provenance; claims of ownership, installation, signer validation, or
an unmodified binary are accepted with a software-identity caution.

Parent/target-process-origin evidence gives process identity context only; it
does not prove that other parent/target activity caused the seed event. A
hypothesis combining cited events more than ten minutes apart receives a
temporal-link caution.

## Three assessment outcomes

- **Rejected:** invalid JSON, invalid/unknown citations, missing required
  sections, unsafe action selection, or a verdict that fails its evidence and
  confidence requirements. The report contains evidence only.
- **Accepted:** cited, bounded assessment with no operational-context caution.
- **Accepted with flags:** useful cited reasoning that includes a clearly
  labelled but unverified operational-context hypothesis. The report shows the
  exact caution and does not present that hypothesis as fact.

## Required report sections

Every accepted report contains:

1. Case metadata and alert overview from Wazuh.
2. Observed evidence, with readable fields and evidence references.
3. LLM assessment: verdict and confidence.
4. What happened.
5. Alert-claim assessment.
6. Possible legitimate context and possible concern.
7. Evidence limits.
8. Recommended analyst actions.
9. Analyst question.

The renderer does not invent prose. An absent hypothesis is rendered as no
evidence-backed statement selected; it is never replaced with a deterministic
benign or malicious conclusion.
