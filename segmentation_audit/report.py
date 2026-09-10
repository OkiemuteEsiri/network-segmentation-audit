from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Iterable

from .models import Finding


def render_markdown(findings: Iterable[Finding]) -> str:
    items = list(findings)
    counts = Counter(item.severity for item in items)
    lines = [
        "# Network Segmentation Audit Report",
        "",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Executive summary",
        "",
        f"Total findings: **{len(items)}**",
        "",
        f"- Critical: {counts.get('Critical', 0)}",
        f"- High: {counts.get('High', 0)}",
        f"- Medium: {counts.get('Medium', 0)}",
        f"- Low: {counts.get('Low', 0)}",
        "",
        "## Findings",
        "",
    ]
    if not items:
        lines.append("No segmentation findings were identified in the supplied dataset and policy.")
        return "\n".join(lines) + "\n"

    for item in items:
        lines.extend([
            f"### {item.finding_id} — {item.title}",
            "",
            f"**Severity:** {item.severity}  ",
            f"**Risk score:** {item.score}/100  ",
            f"**Path:** `{item.source_asset}` → `{item.destination_asset}`  ",
            f"**MITRE ATT&CK context:** {', '.join(item.mitre) if item.mitre else 'N/A'}",
            "",
            f"**Evidence:** {item.evidence}",
            "",
            f"**Remediation:** {item.remediation}",
            "",
            f"**Validation:** {item.validation}",
            "",
        ])
    return "\n".join(lines)
