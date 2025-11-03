# VB SAST Tool - Scan for VB Vulnerabilities 
Example Python tool for scanning flat files containing VB for vulnerabilities.

1. Clone the repository. The script is located in src/scan_vb_vulnerabilities.py.

2. Under the `rules` directory you can find the `rules.yaml`. This contains basic vulnerability sigantures. More can be added as needed.

3. In the `examples/vb_export`s directory you can find an example VB project. Or you can execute this against your own.

Run:

```bash

# console-only report
python3 src/scan_vb_vulnerabilities.py ./examples/vb_exports rules/rules.yaml

# console + SARIF file
python3 src/scan_vb_vulnerabilities.py ./examples/vb_exports rules/rules.yaml --sarif vb_findings.sarif.json

```

After the SARIF file is written you can open it with tools that understand SARIF (e.g., GitHub Code Scanning, VS Code SARIF viewer extensions, or other CI tools).

# Approach

This example uses a purely regex approach currently. Here signatures in the YAML rules file are scanned against the flat files, and a SARIF output is generated.

Future examples in this repository will include an approach that leverages:

1. Taints
2. Sinks
3. Taint flow/Control Flow Analysis
4. Abstract Syntax Trees

# Adding a Rule

To add a rule to the YAML file, use the following format:

```yaml
- id: VB_EVAL_USAGE
  name: Unsafe Eval Usage
  pattern: |
    \bEval\s*\(
  severity: high
  description: "Eval can execute arbitrary code."
```
