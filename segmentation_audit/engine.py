from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Iterable

from .models import Finding, FlowRecord, Policy

ADMIN_PORTS = {22, 23, 3389, 5985, 5986}
DIRECTORY_PORTS = {389, 636, 88, 464}
DATABASE_PORTS = {1433, 1521, 3306, 5432, 27017}
SENSITIVE_ZONES = {"database", "identity", "management"}


class SegmentationAnalyzer:
    """Evaluate observed flows against an explicit segmentation policy."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    @staticmethod
    def _id(control: str, flow: FlowRecord) -> str:
        raw = f"{control}|{flow.source_asset}|{flow.destination_asset}|{flow.protocol}|{flow.port}"
        return f"NSA-{hashlib.sha256(raw.encode()).hexdigest()[:10].upper()}"

    @staticmethod
    def _severity(score: int) -> str:
        if score >= 85:
            return "Critical"
        if score >= 70:
            return "High"
        if score >= 40:
            return "Medium"
        return "Low"

    @staticmethod
    def _score(flow: FlowRecord, *, denied: bool = False, sensitive_service: bool = False, owner_missing: bool = False) -> int:
        score = 20
        if denied:
            score += 35
        if flow.source_zone == "internet":
            score += 25
        if flow.destination_zone in SENSITIVE_ZONES:
            score += 15
        if sensitive_service:
            score += 15
        if owner_missing:
            score += 10
        if flow.internet_exposed:
            score += 10
        return min(100, score)

    def analyze(self, flows: Iterable[FlowRecord]) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        flow_list = list(flows)

        for flow in flow_list:
            denied = not self.policy.allows(flow)
            sensitive_service = flow.port in ADMIN_PORTS | DIRECTORY_PORTS | DATABASE_PORTS

            if denied:
                score = self._score(flow, denied=True, sensitive_service=sensitive_service, owner_missing=not bool(flow.owner))
                finding = Finding(
                    self._id("policy-violation", flow),
                    "Observed flow violates declared segmentation policy",
                    self._severity(score), score,
                    flow.source_asset, flow.destination_asset,
                    f"{flow.source_zone}->{flow.destination_zone} {flow.protocol.upper()}/{flow.port} is not permitted by policy.",
                    "Remove the path or add only a formally approved least-privilege rule with documented business justification.",
                    "Re-run the audit with post-change flow data and confirm this deterministic finding ID no longer appears.",
                    ("T1021", "T1210"),
                )
                findings.append(finding); seen.add(finding.finding_id)

            if flow.source_zone == "internet" and flow.destination_zone in SENSITIVE_ZONES:
                score = self._score(flow, denied=denied, sensitive_service=sensitive_service) + 5
                score = min(100, score)
                finding = Finding(
                    self._id("internet-sensitive", flow),
                    "Internet path reaches a sensitive trust zone",
                    self._severity(score), score,
                    flow.source_asset, flow.destination_asset,
                    f"Internet-originated flow reaches {flow.destination_zone} on {flow.protocol.upper()}/{flow.port}.",
                    "Terminate internet-facing traffic in an appropriate edge/DMZ tier and prevent direct reachability to sensitive internal zones.",
                    "Verify representative internet-originated flows can no longer reach the sensitive destination directly.",
                    ("T1190",),
                )
                if finding.finding_id not in seen:
                    findings.append(finding); seen.add(finding.finding_id)

            if sensitive_service and flow.source_zone != flow.destination_zone and flow.source_zone not in {"management", "server"}:
                score = self._score(flow, denied=denied, sensitive_service=True)
                finding = Finding(
                    self._id("sensitive-service", flow),
                    "Sensitive service crosses an unexpected trust boundary",
                    self._severity(score), score,
                    flow.source_asset, flow.destination_asset,
                    f"Port {flow.port} crosses {flow.source_zone}->{flow.destination_zone} outside a management/server source zone.",
                    "Restrict administrative, directory, and database services to approved management or application tiers and named sources.",
                    "Confirm the service is reachable only from approved source zones and assets after remediation.",
                    ("T1021", "T1210"),
                )
                if finding.finding_id not in seen:
                    findings.append(finding); seen.add(finding.finding_id)

            if denied and not flow.owner:
                score = self._score(flow, denied=True, sensitive_service=sensitive_service, owner_missing=True)
                finding = Finding(
                    self._id("missing-owner", flow),
                    "Unapproved flow lacks accountable ownership",
                    self._severity(score), score,
                    flow.source_asset, flow.destination_asset,
                    "A policy-violating flow has no application or service owner recorded.",
                    "Assign an accountable owner before any exception is considered; undocumented access should be removed by default.",
                    "Re-run after ownership and disposition are recorded; verify the flow is removed or explicitly governed.",
                    tuple(),
                )
                if finding.finding_id not in seen:
                    findings.append(finding); seen.add(finding.finding_id)

        findings.sort(key=lambda item: (-item.score, item.finding_id))
        return findings

    @staticmethod
    def summarize(findings: Iterable[Finding]) -> dict[str, int]:
        summary: dict[str, int] = defaultdict(int)
        for finding in findings:
            summary[finding.severity] += 1
        return dict(summary)
