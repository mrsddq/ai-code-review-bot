from __future__ import annotations

import argparse
from pathlib import Path

from .reporters import json_report, sarif_report, text_report
from .reviewer import SEVERITY_ORDER, review_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Review Python code for risky patterns")
    parser.add_argument("path", nargs="?", type=Path, default=Path("."))
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    parser.add_argument("--output", "-o", type=Path)
    parser.add_argument("--fail-on", choices=("none", "low", "medium", "high"), default="high")
    args = parser.parse_args()

    findings = review_path(args.path)
    renderers = {"text": text_report, "json": json_report, "sarif": sarif_report}
    report = renderers[args.format](findings)
    if args.output:
        args.output.write_text(report + "\n", encoding="utf-8")
    else:
        print(report)
    if args.fail_on != "none" and any(
        SEVERITY_ORDER[item.severity] >= SEVERITY_ORDER[args.fail_on] for item in findings
    ):
        raise SystemExit(1)


if __name__ == "__main__":
    main()

