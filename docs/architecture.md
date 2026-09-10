# Architecture

## Components

1. **Input adapters** load declared segmentation policy and observed flow metadata from JSON.
2. **Domain validation** rejects unsupported zones, protocols, and invalid ports before analysis.
3. **Policy resolver** evaluates each observed flow against explicit source-zone, destination-zone, and port rules.
4. **Control engine** evaluates policy violations, internet reachability to sensitive tiers, sensitive cross-boundary services, and missing ownership.
5. **Risk layer** calculates a bounded contextual score using policy status, trust zone, service sensitivity, internet exposure, and governance context.
6. **Reporting layer** renders evidence, remediation, validation criteria, and ATT&CK context to Markdown.
7. **CLI/CI layer** supports repeatable local execution and pipeline validation.

## Trust model

The project assumes input datasets are authorised exports or synthetic fixtures. It never attempts live discovery. Policy is authoritative for this lab; where business intent differs from policy, the governance process must reconcile the discrepancy rather than silently suppress the finding.

## Data flow

`policy.json + flows.json -> validation -> policy evaluation -> controls -> risk scoring -> deterministic findings -> Markdown report`

## Security engineering properties

- fail-fast input validation
- immutable domain records
- deterministic finding identifiers
- explicit evidence and revalidation instructions
- no hidden network I/O
- no credentials or secrets required
- bounded risk scoring to keep output interpretable
