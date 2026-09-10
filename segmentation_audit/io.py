from __future__ import annotations

import json
from pathlib import Path

from .models import FlowRecord, Policy, PolicyRule


def load_policy(path: str | Path) -> Policy:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    rules = []
    for item in payload.get("rules", []):
        rules.append(PolicyRule(
            source_zone=item["source_zone"],
            destination_zone=item["destination_zone"],
            allowed_ports=frozenset(int(port) for port in item.get("allowed_ports", [])),
        ))
    if not rules:
        raise ValueError("policy must contain at least one rule")
    return Policy(tuple(rules))


def load_flows(path: str | Path) -> list[FlowRecord]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    flows = []
    for item in payload.get("flows", []):
        flows.append(FlowRecord(
            source_asset=item["source_asset"],
            source_zone=item["source_zone"],
            destination_asset=item["destination_asset"],
            destination_zone=item["destination_zone"],
            protocol=item["protocol"],
            port=int(item["port"]),
            owner=item.get("owner"),
            internet_exposed=bool(item.get("internet_exposed", False)),
        ))
    if not flows:
        raise ValueError("flow dataset must contain at least one record")
    return flows
