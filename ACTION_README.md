# QaD VB SAST Scanner - GitHub Action

A Quick and Dirty (QaD) Static Application Security Testing (SAST) scanner for Visual Basic 6 and VBA code that integrates seamlessly with GitHub Advanced Security Code Scanning.

## 🎯 Purpose

This action helps you identify security vulnerabilities and code quality issues in legacy VB6 and VBA codebases. It's designed for organizations that need quick security scans of Visual Basic code without expensive commercial tools.

## 🚀 Features

- **Pattern-based vulnerability detection** using configurable YAML rules
- **SARIF output** compatible with GitHub Code Scanning and other SAST tools
- **Automatic upload** to GitHub Security tab for easy vulnerability management
- **Pull request annotations** for immediate feedback on security issues
- **Customizable rules** to fit your organization's security policies
- **Zero configuration** - works out of the box with sensible defaults

## 🔍 Detected Issues

The scanner includes built-in rules for detecting:

- **High Severity**:
  - Hardcoded passwords and credentials
  - Use of `Eval()` function (arbitrary code execution)
  - Shell command execution (`Shell`, `WScript.Shell`)

- **Medium Severity**:
  - SQL injection vulnerabilities (string concatenation in queries)
  - Unsafe file system access

- **Low/Info Severity**:
  - Insecure HTTP URLs (should use HTTPS)
  - Hardcoded IP addresses
  - Code smells (GoTo/GoSub statements)

## 📋 Quick Start

Add this to your workflow file (e.g., `.github/workflows/vb-security.yml`):

```yaml
name: VB Security Scan

on: [push, pull_request]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: rpigu-i/QaD_vb_sast_tool@main
        with:
          scan-path: './src'
```

## 📖 Documentation

See [EXAMPLES.md](.github/workflows/EXAMPLES.md) for comprehensive usage examples including:
- Basic scans
- Custom rules
- Multiple directory scanning
- Manual upload control

## 🛠️ Customization

Create your own `rules.yaml` file to customize detection patterns:

```yaml
- id: CUSTOM_RULE
  name: Custom Security Rule
  pattern: >-
    \bDangerousFunction\s*\(
  severity: high
  description: "Detects use of dangerous functions"
```

Then reference it in your workflow:

```yaml
- uses: rpigu-i/QaD_vb_sast_tool@main
  with:
    scan-path: './src'
    rules-path: './security/custom_rules.yaml'
```

## 📊 Viewing Results

After the action runs:
1. **Security Tab**: Navigate to your repository's "Security" tab → "Code scanning"
2. **Pull Requests**: See annotations directly on changed lines
3. **Artifacts**: Download SARIF files for offline analysis

## 🤝 Contributing

Contributions are welcome! This is an open-source project designed to help the community scan legacy VB code.

## 📄 License

See [LICENSE](LICENSE) for details.

## ⚠️ Limitations

- This is a pattern-based (regex) scanner, not a full semantic analyzer
- May produce false positives that require manual review
- Best used as part of a defense-in-depth security strategy
- Not a replacement for comprehensive security audits

## 🔗 Links

- [Repository](https://github.com/rpigu-i/QaD_vb_sast_tool)
- [Issue Tracker](https://github.com/rpigu-i/QaD_vb_sast_tool/issues)
- [Example Workflows](.github/workflows/EXAMPLES.md)
