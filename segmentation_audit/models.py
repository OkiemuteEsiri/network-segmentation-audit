from __future__ import annotations

from dataclasses import dataclass
from typing import FrozenSet, Tuple

VALID_ZONES = frozenset({"internet", "dmz", "user", "server", "database", "identity", "management"})


@dataclass(frozen=True)
class FlowRecord:
    source_asset: str
    source_zone: str
    destination_asset: str
    destination_zone: str
    protocol: str
    port: int
    owner: str | None = None
    internet_exposed: bool = False

    def __post_init__(self) -> None:
        if not self.source_asset or not self.destination_asset:
            raise ValueError("source_asset and destination_asset are required")
        if self.source_zone not in VALID_ZONES or self.destination_zone not in VALID_ZONES:
            raise ValueError("flow contains an unsupported zone")
        if self.protocol.lower() not in {"tcp", "udp"}:
            raise ValueError("protocol must be tcp or udp")
        if not 1 <= self.port <= 65535:
            raise ValueError("port must be between 1 and 65535")


@dataclass(frozen=True)
class PolicyRule:
    source_zone: str
    destination_zone: str
    allowed_ports: FrozenSet[int]

    def __post_init__(self) -> None:
        if self.source_zone not in VALID_ZONES or self.destination_zone not in VALID_ZONES:
            raise ValueError("policy rule contains an unsupported zone")
        if any(port < 1 or port > 65535 for port in self.allowed_ports):
            raise ValueError("policy contains invalid port")


@dataclass(frozen=True)
class Policy:
    rules: Tuple[PolicyRule, ...]

    def allows(self, flow: FlowRecord) -> bool:
        return any(
            rule.source_zone == flow.source_zone
            and rule.destination_zone == flow.destination_zone
            and flow.port in rule.allowed_ports
            for rule in self.rules
        )


@dataclass(frozen=True)
class Finding:
    finding_id: str
    title: str
    severity: str
    score: int
    source_asset: str
    destination_asset: str
    evidence: str
    remediation: str
    validation: str
    mitre: Tuple[str, ...]
