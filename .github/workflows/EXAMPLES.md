# Example Workflow for Using QaD VB SAST Scanner

This directory contains example workflows demonstrating how to use the QaD VB SAST Scanner action.

## Version Reference

The examples use `@main` to reference the latest version of the action. Once stable releases are published, you can use semantic versioning tags like:
- `@v1` - Latest v1.x.x release (recommended for automatic updates)
- `@v1.0.0` - Specific version (recommended for stability)
- `@main` - Latest development version (use for testing)

## Basic Workflow

Create a file `.github/workflows/vb-security-scan.yml` in your repository:

```yaml
name: VB Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

permissions:
  contents: read
  security-events: write  # Required for uploading SARIF to Code Scanning

jobs:
  vb-sast-scan:
    runs-on: ubuntu-latest
    name: Scan VB/VBA Code for Security Issues
    
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
      
      - name: Run QaD VB SAST Scanner
        uses: rpigu-i/QaD_vb_sast_tool@main
        with:
          scan-path: './src'
```

## Advanced Workflow with Custom Rules

```yaml
name: VB Security Scan (Custom Rules)

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 0 * * 0'  # Weekly scan on Sunday at midnight

permissions:
  contents: read
  security-events: write

jobs:
  vb-sast-scan:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
      
      - name: Run QaD VB SAST Scanner
        uses: rpigu-i/QaD_vb_sast_tool@main
        with:
          scan-path: './legacy/vb_code'
          rules-path: './security/custom_vb_rules.yaml'
          sarif-output: 'custom-vb-results.sarif.json'
      
      - name: Upload SARIF as artifact
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: vb-sarif-results
          path: custom-vb-results.sarif.json
          retention-days: 30
```

## Workflow with Multiple Scans

```yaml
name: Multi-Directory VB Security Scan

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

permissions:
  contents: read
  security-events: write

jobs:
  scan-legacy-code:
    runs-on: ubuntu-latest
    name: Scan Legacy VB Code
    
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
      
      - name: Scan Legacy VB6 Code
        uses: rpigu-i/QaD_vb_sast_tool@main
        with:
          scan-path: './legacy/vb6'
          sarif-output: 'legacy-vb6-results.sarif.json'
  
  scan-vba-macros:
    runs-on: ubuntu-latest
    name: Scan VBA Macros
    
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
      
      - name: Scan Excel VBA Macros
        uses: rpigu-i/QaD_vb_sast_tool@main
        with:
          scan-path: './excel/exported_macros'
          sarif-output: 'vba-macros-results.sarif.json'
```

## Workflow Without Auto-Upload

If you want to review results before uploading to Code Scanning:

```yaml
name: VB Security Scan (Manual Upload)

on:
  push:
    branches: [ main ]

permissions:
  contents: read
  security-events: write

jobs:
  vb-sast-scan:
    runs-on: ubuntu-latest
    
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4
      
      - name: Run QaD VB SAST Scanner
        id: scan
        uses: rpigu-i/QaD_vb_sast_tool@main
        with:
          scan-path: './src'
          upload-sarif: 'false'  # Don't auto-upload
      
      - name: Check findings count
        run: |
          echo "Found ${{ steps.scan.outputs.findings-count }} potential issues"
          if [ "${{ steps.scan.outputs.findings-count }}" -gt "50" ]; then
            echo "Too many findings, needs review before uploading"
            exit 1
          fi
      
      - name: Manual upload to Code Scanning
        if: success()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.scan.outputs.sarif-file }}
          category: vb-sast-scanner
```

## Notes

- The `security-events: write` permission is required to upload SARIF files to GitHub Code Scanning
- Results will appear in the Security tab under Code Scanning
- PR annotations will automatically appear for findings in changed files
- You can customize the rules by providing your own `rules.yaml` file
