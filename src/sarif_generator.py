#!/usr/bin/env python3
"""
SARIF Generator Module
----------------------
Handles the generation of SARIF (Static Analysis Results Interchange Format)
output for vulnerability findings.
"""
from datetime import datetime

# Mapping from internal severity levels to SARIF levels
SEVERITY_TO_SARIF = {
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note"
}

def build_sarif(findings, rules, tool_name="VB Vulnerability Scanner"):
    """
    Construct a SARIF v2.1.0 object from findings.

    Args:
        findings: List of finding dictionaries containing vulnerability information
        rules: List of rule dictionaries used to detect vulnerabilities
        tool_name: Name of the scanning tool (default: "VB Vulnerability Scanner")

    Returns:
        Dictionary representing a SARIF v2.1.0 document
    """
    # Build rules list for SARIF 'tool'
    sarif_rules = []
    rule_by_id = {r["id"]: r for r in rules}
    for rid, r in rule_by_id.items():
        sarif_rules.append({
            "id": rid,
            "name": r["name"],
            "shortDescription": {"text": r["name"]},
            "fullDescription": {"text": r.get("description", "")},
            "defaultConfiguration": {"level": SEVERITY_TO_SARIF.get(r.get("severity", "info"), "note")}
        })

    # Build results list from findings
    sarif_results = []
    for f in findings:
        level = SEVERITY_TO_SARIF.get(f["severity"], "note")
        message_text = f"{f['rule_name']} — {f['match']}"
        # create result entry
        sarif_results.append({
            "ruleId": f["rule_id"],
            "ruleIndex": next((i for i, rr in enumerate(sarif_rules) if rr["id"] == f["rule_id"]), 0),
            "level": level,
            "message": {"text": message_text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f["file"]},
                        "region": {
                            "startLine": f["line"],
                            # optionally include snippet or char offsets
                            "snippet": {"text": f["snippet"]}
                        }
                    }
                }
            ]
        })

    # Construct the complete SARIF document
    sarif = {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "informationUri": "https://example.local/vb-scanner",
                        "rules": sarif_rules
                    }
                },
                "results": sarif_results,
                "invocation": {
                    "timestamp": datetime.utcnow().isoformat() + "Z"
                }
            }
        ]
    }
    return sarif
