# VB SAST Tool - Scan for VB Vulnerabilities 
Example Python tool for scanning flat files containing VB for vulnerabilities.

1. Clone the repository. The script is located in src/scan_vb_vulnerabilities.py.

2. Under the `rules` directory you can find the `rules.yaml`. This contains basic vulnerability sigantures. More can be added as needed.

3. In the `examples/vb_export`s directory you can find an example VB project. Or you can execute this against your own.

Run:

```bash

# console-only report
python3 src/scan_vb_vulnerabilities.py ./examples/vb_exports rules.yaml

# console + SARIF file
python3 src/scan_vb_vulnerabilities.py ./examples/vb_exports rules.yaml --sarif vb_findings.sarif.json

```

After the SARIF file is written you can open it with tools that understand SARIF (e.g., GitHub Code Scanning, VS Code SARIF viewer extensions, or other CI tools).
