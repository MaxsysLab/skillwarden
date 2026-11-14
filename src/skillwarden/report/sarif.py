"""SARIF 2.1.0 output so SkillWarden results drop straight into CI / code
scanning dashboards."""

from __future__ import annotations

import json
from typing import Any

from skillwarden.models import Finding, ScanResult

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def to_sarif(result: ScanResult, version: str = "0.1.0") -> str:
    rules: dict[str, dict[str, Any]] = {}
    sarif_results: list[dict[str, Any]] = []

    for f in result.findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": f.description},
                "properties": {"category": f.category.value},
            }
        sarif_results.append(
            {
                "ruleId": f.rule_id,
                "level": f.severity.sarif_level,
                "message": {"text": f.description},
                "properties": {
                    "category": f.category.value,
                    "severity": f.severity.value,
                    "confidence": f.confidence,
                    "source": f.source.value,
                },
                "locations": _locations(f),
            }
        )

    doc = {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SkillWarden",
                        "informationUri": "https://github.com/MaxsysLab/skillwarden",
                        "version": version,
                        "rules": list(rules.values()),
                    }
                },
                "results": sarif_results,
                "invocations": [
                    {
                        "executionSuccessful": result.status == "complete",
                        "toolExecutionNotifications": [
                            {"level": "error", "message": {"text": error}}
                            for error in result.errors
                        ],
                    }
                ],
                "properties": {
                    "riskScore": result.risk_score,
                    "severityLabel": result.severity_label.value,
                    "status": result.status,
                    "errors": result.errors,
                    "warnings": result.warnings,
                    "skipped": [s.model_dump() for s in result.skipped],
                    "recommendation": result.recommendation,
                },
            }
        ],
    }
    return json.dumps(doc, indent=2)


def _locations(f: Finding) -> list[dict[str, Any]]:
    if not f.file:
        return []
    region = {"startLine": f.line} if f.line else {}
    return [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": f.file},
                **({"region": region} if region else {}),
            }
        }
    ]
