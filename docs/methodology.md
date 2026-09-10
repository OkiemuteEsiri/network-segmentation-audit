# Assessment Methodology

## Objective

Determine whether observed network communication is consistent with an approved segmentation model and whether material exceptions are sufficiently constrained and governed.

## Procedure

1. Validate the zone taxonomy and approved communication matrix.
2. Ingest representative flow records from authorised exports or synthetic fixtures.
3. Reject malformed records before control evaluation.
4. Evaluate every flow against explicit source-zone, destination-zone, and port policy.
5. Apply contextual controls for sensitive services and internet reachability.
6. Rank findings using bounded contextual risk scoring.
7. Triage each finding with the accountable service/application owner.
8. Record whether access is removed, narrowed, formally excepted, or policy documentation is corrected.
9. Re-run the same dataset format after remediation and compare deterministic finding IDs.

## Risk interpretation

- **Critical (85-100):** direct or highly sensitive trust-boundary exposure requiring immediate review.
- **High (70-84):** significant segmentation failure or sensitive service exposure.
- **Medium (40-69):** meaningful control weakness that should enter remediation planning.
- **Low (<40):** lower-impact hygiene or governance issue.

Scores are prioritisation aids, not probability estimates.

## Validation evidence

A remediation is considered technically validated when representative post-change flow records no longer reproduce the violating path, or the path conforms to a revised least-privilege policy that has documented ownership and approval. Governance closure alone does not prove that packet-level enforcement changed.

## ATT&CK usage

ATT&CK techniques are included only to explain the defensive threat scenarios affected by poor segmentation. The tool does not infer adversary presence from a policy violation.
