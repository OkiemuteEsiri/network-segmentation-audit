from __future__ import annotations

import argparse
from pathlib import Path

from .engine import SegmentationAnalyzer
from .io import load_flows, load_policy
from .report import render_markdown


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Audit observed network flows against an approved segmentation policy.")
    parser.add_argument("--policy", required=True, help="Path to segmentation policy JSON")
    parser.add_argument("--flows", required=True, help="Path to observed flow JSON")
    parser.add_argument("--output", required=True, help="Path for Markdown report")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    policy = load_policy(args.policy)
    flows = load_flows(args.flows)
    findings = SegmentationAnalyzer(policy).analyze(flows)
    Path(args.output).write_text(render_markdown(findings), encoding="utf-8")
    print(f"Assessed {len(flows)} flows; generated {len(findings)} findings -> {args.output}")
    return 2 if any(item.severity in {"Critical", "High"} for item in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
