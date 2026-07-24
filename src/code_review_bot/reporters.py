from __future__ import annotations

import json

from .reviewer import Finding


def text_report(findings: list[Finding]) -> str:
    if not findings:
        return "No findings."
    return "\n".join(
        f"{item.path}:{item.line}:{item.column} [{item.severity.upper()} {item.rule}] "
        f"{item.message} {item.suggestion}"
        for item in findings
    )


def json_report(findings: list[Finding]) -> str:
    return json.dumps({"findings": [item.to_dict() for item in findings]}, indent=2)


def sarif_report(findings: list[Finding]) -> str:
    levels = {"low": "note", "medium": "warning", "high": "error"}
    rules = {
        item.rule: {
            "id": item.rule,
            "shortDescription": {"text": item.message},
            "help": {"text": item.suggestion},
        }
        for item in findings
    }
    results = [
        {
            "ruleId": item.rule,
            "level": levels[item.severity],
            "message": {"text": item.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": item.path.replace("\\", "/")},
                    "region": {"startLine": item.line, "startColumn": item.column},
                }
            }],
        }
        for item in findings
    ]
    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "AI Code Review Bot", "rules": list(rules.values())}},
            "results": results,
        }],
    }
    return json.dumps(document, indent=2)

