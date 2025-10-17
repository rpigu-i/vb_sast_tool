#!/usr/bin/env python3
"""
VB Vulnerability Scanner with SARIF output
-----------------------------------------
Scans Visual Basic / Access DB code files using signatures loaded from a YAML rule file.

Usage:
    python3 src/scan_vb_vulnerabilities.py <VB_folder> <rules.yaml> [--sarif results.sarif.json]

Examples:
    python3 src/scan_vb_vulnerabilities.py ./vb_exports rules.yaml
    python3 src/scan_vb_vulnerabilities.py ./vb_exports rules.yaml --sarif vb_findings.sarif.json
"""
import re
import yaml
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

# -------------------- Helpers --------------------

SEVERITY_TO_SARIF = {
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note"
}

def load_rules(yaml_path):
    """Load vulnerability detection rules from a YAML file."""
    with open(yaml_path, "r", encoding="utf-8") as f:
        rules = yaml.safe_load(f)
    if not isinstance(rules, list):
        raise ValueError("Rules YAML must contain a list of rules.")
    # Normalize minimal rule fields and compile regex
    normalized = []
    for i, r in enumerate(rules):
        if not r.get("pattern"):
            continue
        entry = {
            "id": r.get("id", f"RULE_{i+1}"),
            "name": r.get("name", r.get("id", f"RULE_{i+1}")),
            "pattern": r["pattern"],
            "severity": r.get("severity", "info"),
            "description": r.get("description", "")
        }
        try:
            entry["regex"] = re.compile(entry["pattern"], re.IGNORECASE | re.MULTILINE)
        except re.error as ex:
            raise ValueError(f"Invalid regex for rule {entry['id']}: {ex}")
        normalized.append(entry)
    return normalized

def find_line_and_snippet(text, start, end, context_lines=2):
    """Given start/end indexes, return 1-based line number and a small snippet (with context)."""
    # line number
    start_line = text.count("\n", 0, start) + 1
    # extract snippet by lines
    lines = text.splitlines()
    line_idx = start_line - 1
    start_ctx = max(0, line_idx - context_lines)
    end_ctx = min(len(lines)-1, line_idx + context_lines)
    snippet = "\n".join(lines[start_ctx:end_ctx+1])
    # relative line in snippet:
    relative_line = line_idx - start_ctx + 1
    return start_line, snippet, relative_line

def scan_file(file_path, rules):
    """Scan a single VB file for vulnerabilities based on the rules."""
    findings = []
    text = Path(file_path).read_text(errors="ignore")
    for rule in rules:
        for m in rule["regex"].finditer(text):
            match_text = m.group(0)
            start, end = m.span()
            line_num, snippet, relative_line = find_line_and_snippet(text, start, end)
            findings.append({
                "file": str(file_path),
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "severity": rule["severity"],
                "description": rule["description"],
                "match": match_text,
                "start": start,
                "end": end,
                "line": line_num,
                "snippet": snippet,
                "snippet_line": relative_line
            })
    return findings

def scan_directory(directory, rules):
    """Recursively scan .bas, .vb, .frm, .cls files in a directory."""
    exts = ("*.vb", "*.bas", "*.frm", "*.cls", "*.txt")  # common exports
    all_findings = []
    p = Path(directory)
    for ext in exts:
        for file_path in p.rglob(ext):
            all_findings.extend(scan_file(file_path, rules))
    return all_findings

def report_console(findings):
    """Print human-friendly report to console."""
    if not findings:
        print("No vulnerabilities found.")
        return
    print("Potential Vulnerabilities Found:\n")
    for f in findings:
        print(f"File: {f['file']}")
        print(f"  Line: {f['line']}")
        print(f"  Rule: {f['rule_name']} [{f['rule_id']}] ({f['severity']})")
        if f['description']:
            print(f"  Description: {f['description']}")
        print("  Match snippet:")
        # show the snippet with an indicator arrow at the matched line inside snippet
        snippet_lines = f['snippet'].splitlines()
        for i, ln in enumerate(snippet_lines, start=1):
            prefix = " -> " if i == f['snippet_line'] else "    "
            print(f"{prefix}{ln}")
        print("-" * 72)

def build_sarif(findings, rules, tool_name="VB Vulnerability Scanner"):
    """Construct a SARIF v2.1.0 object from findings."""
    # Build rules list for sarif 'tool'
    sarif_rules = []
    rule_by_id = {r["id"]: r for r in rules}
    for rid, r in rule_by_id.items():
        sarif_rules.append({
            "id": rid,
            "name": r["name"],
            "shortDescription": {"text": r["name"]},
            "fullDescription": {"text": r.get("description", "")},
            "defaultConfiguration": {"level": SEVERITY_TO_SARIF.get(r.get("severity","info"), "note")}
        })

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

# -------------------- CLI / Main --------------------

def main():
    parser = argparse.ArgumentParser(description="VB Vulnerability scanner with SARIF output")
    parser.add_argument("vb_folder", help="Folder containing VB/Access flat files to scan")
    parser.add_argument("rules_yaml", help="YAML file with detection rules")
    parser.add_argument("--sarif", help="Write results to SARIF JSON file", default=None)
    args = parser.parse_args()

    rules = load_rules(args.rules_yaml)
    findings = scan_directory(args.vb_folder, rules)
    report_console(findings)

    if args.sarif:
        sarif_obj = build_sarif(findings, rules, tool_name="VB Vulnerability Scanner")
        with open(args.sarif, "w", encoding="utf-8") as fh:
            json.dump(sarif_obj, fh, indent=2)
        print(f"\n SARIF output written to: {args.sarif}")

if __name__ == "__main__":
    main()
