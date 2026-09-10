# Network Segmentation Audit

Defensive security-engineering project for evaluating whether observed network flows conform to an approved segmentation policy. It is designed for offline analysis of synthetic or exported flow records; it does not scan, probe, or connect to live systems.

## Problem statement

Network segmentation controls often exist as diagrams and firewall rules, while actual traffic evolves independently. Security teams need a repeatable way to compare observed east-west and north-south communication against a declared zone policy, identify overly permissive paths, prioritise violations by business risk, and prove that remediation was validated.

## Architecture

```text
Synthetic / exported flow records
          |
          v
   JSON ingestion + validation
          |
          v
    Zone policy resolution
          |
          v
  Segmentation analysis engine
   |        |        |       |
 denied   risky    missing  unknown
 paths    service  owners   assets
   \        |        |       /
          v
   risk scoring + findings
          |
          v
 Markdown report + CLI output
```

## Implemented controls

- Detect flows that violate explicit zone-to-zone policy.
- Identify internet-to-sensitive-zone communication.
- Flag administrative services crossing trust boundaries.
- Flag database and directory services exposed beyond approved source zones.
- Detect unknown or unmapped source/destination assets.
- Detect missing application/service ownership for material exceptions.
- Produce deterministic finding IDs for revalidation and workflow tracking.
- Assign bounded 0–100 contextual risk scores and Critical/High/Medium/Low severity.
- Preserve evidence, remediation guidance, and validation criteria per finding.

## Usage

```bash
python -m segmentation_audit.cli --policy config/zones.json --flows data/synthetic_flows.json --output report.md
```

The CLI exits with code `2` when Critical or High findings exist, allowing use as a defensive CI quality gate for controlled datasets and policy-as-code changes.

## Design decisions

The engine is deliberately deterministic and vendor-neutral. It evaluates declared policy plus observed metadata rather than attempting packet capture, firewall exploitation, bypass testing, or active discovery. Risk combines policy violation severity, trust-boundary distance, service sensitivity, internet exposure, and ownership/governance context.

## MITRE ATT&CK context

Mappings are defensive threat-model context, not evidence of compromise:

- **T1021 – Remote Services:** administrative protocols crossing poorly controlled trust boundaries can facilitate lateral movement.
- **T1210 – Exploitation of Remote Services:** unnecessary service exposure increases exploitable attack surface.
- **T1190 – Exploit Public-Facing Application:** direct internet reachability to sensitive tiers increases exposure risk.

## Remediation and validation workflow

1. Confirm the observed flow and owning application.
2. Determine whether the path is explicitly required by architecture.
3. Remove unnecessary access or constrain protocol/port/source/destination.
4. Document approved exceptions with accountable ownership.
5. Re-export representative flow data after the change.
6. Re-run the analyzer and verify that the original finding ID is absent or downgraded for a justified reason.

## Limitations

- Offline analyzer only; no live firewall, router, cloud, or packet-capture integration.
- Does not infer application intent from payload contents.
- Synthetic examples are illustrative and contain no employer or client data.
- A clean report demonstrates policy conformity for the supplied dataset, not proof that a network is secure.

## Skills demonstrated

Network security architecture, segmentation assurance, policy-as-code, risk scoring, Python engineering, defensive detection logic, evidence-driven remediation, unit testing, reporting, and CI security quality gates.

## Roadmap

- CSV/NetFlow adapters.
- CIDR-aware asset inventory mapping.
- Policy-diff mode for firewall change review.
- Exception expiry and compensating-control handling.
- SARIF/JSON output for pipeline integrations.
- Coverage metrics showing observed versus permitted communication paths.

## Safety

This repository contains no exploit payloads, credential attacks, evasion techniques, production targets, or confidential data. Use only with data and environments you are authorised to assess.
