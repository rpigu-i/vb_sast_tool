#!/usr/bin/env python3
"""
VB Vulnerability Scanner
------------------------
Scans Visual Basic / Access DB code files using signatures loaded from a YAML rule file.

Usage:
    python3 src/scan_vb_vulnerabilities.py path/to/vb_files/ rules.yaml
"""

import re
import yaml
import sys
from pathlib import Path

# -------------------- Core Functions --------------------

def load_rules(yaml_path):
    """Load vulnerability detection rules from a YAML file."""
    with open(yaml_path, "r", encoding="utf-8") as f:
        rules = yaml.safe_load(f)
    if not isinstance(rules, list):
        raise ValueError("Rules YAML must contain a list of rules.")
    return rules


def scan_file(file_path, rules):
    """Scan a single VB file for vulnerabilities based on the rules."""
    findings = []
    text = Path(file_path).read_text(errors="ignore")

    for rule in rules:
        name = rule.get("name", "Unnamed Rule")
        pattern = rule.get("pattern")
        severity = rule.get("severity", "info")
        description = rule.get("description", "")

        if not pattern:
            continue

        regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
        matches = regex.findall(text)

        if matches:
            findings.append({
                "file": str(file_path),
                "rule": name,
                "severity": severity,
                "description": description,
                "matches": matches
            })

    return findings


def scan_directory(directory, rules):
    """Recursively scan all .vb files in a directory."""
    all_findings = []
    for file_path in Path(directory).rglob("*.vb"):
        file_findings = scan_file(file_path, rules)
        all_findings.extend(file_findings)
    return all_findings


def report_findings(findings):
    """Print results in a readable format."""
    if not findings:
        print("No vulnerabilities found.")
        return

    print("Potential Vulnerabilities Found:\n")
    for f in findings:
        print(f"File: {f['file']}")
        print(f"  Rule: {f['rule']} ({f['severity']})")
        if f['description']:
            print(f"  Description: {f['description']}")
        print("  Matches:")
        for m in f['matches']:
            print(f"    → {m.strip()}")
        print("-" * 60)


# -------------------- Main --------------------

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 src/scan_vb_vulnerabilities.py <VB folder> <rules.yaml>")
        sys.exit(1)

    vb_dir = sys.argv[1]
    rules_file = sys.argv[2]

    rules = load_rules(rules_file)
    findings = scan_directory(vb_dir, rules)
    report_findings(findings)


if __name__ == "__main__":
    main()
