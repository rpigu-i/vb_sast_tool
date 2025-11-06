```
________        .__        __                        .___ ________  .__         __          
\_____  \  __ __|__| ____ |  | __ _____    ____    __| _/ \______ \ |__|_______/  |_ ___.__.
 /  / \  \|  |  \  |/ ___\|  |/ / \__  \  /    \  / __ |   |    |  \|  \_  __ \   __<   |  |
/   \_/.  \  |  /  \  \___|    <   / __ \|   |  \/ /_/ |   |    `   \  ||  | \/|  |  \___  |
\_____\ \_/____/|__|\___  >__|_ \ (____  /___|  /\____ |  /_______  /__||__|   |__|  / ____|
       \__>             \/     \/      \/     \/      \/          \/                 \/
```
                                                                                                                                              
# Quick and Dirty (QaD) 
### VB SAST Tool - Scan for VB Vulnerabilities 
A Python based SAST tool that scans flat files containing VBA and VB6 code for vulnerability and code smell patterns. 

There's plenty of legacy VB6 and VBA code out there. Sometimes you need a quick and dirty pass of the files for compliance 
and security reasons but don't have an expensive commerical tool that supports the language.

 Well in such a case, this is the tool for you. It's not sophisticated, it might be a little noisy, but it gets the job 
 done in a pinch. You also get a SARIF file export you can pump into GitHub Advanced Security and other SARIF compatible platforms. 


## Installation

This tool is packaged with Poetry and can be installed as a Python package.

### Prerequisites
- Python 3.8 or higher
- Poetry (install from https://python-poetry.org/docs/#installation)

### Install the Package

1. Clone the repository:
```bash
git clone https://github.com/rpigu-i/vb_sast_tool.git
cd vb_sast_tool
```

2. Install with Poetry:
```bash
poetry install
```

## Usage

After installation, you can run the tool using the `vb-scan` command:

```bash
# Console-only report
poetry run vb-scan ./examples/vb_exports rules/rules.yaml

# Console + SARIF file
poetry run vb-scan ./examples/vb_exports rules/rules.yaml --sarif vb_findings.sarif.json
```

### Alternative: Direct Python Execution

You can also run the script directly without installing:

```bash
# Install dependencies first
poetry install --no-root

# Run directly
poetry run python src/vb_sast_tool/scan_vb_vulnerabilities.py ./examples/vb_exports rules/rules.yaml
```

## About

The `rules` directory contains `rules.yaml` with basic vulnerability signatures. More can be added as needed.

The `examples/vb_exports` directory contains an example VB project, or you can execute this against your own.

After the SARIF file is written, you can open it with tools that understand SARIF (e.g., GitHub Code Scanning, VS Code SARIF viewer extensions, or other CI tools).

## Testing

The project includes a comprehensive test suite that validates each pattern in the rules YAML file:

```bash
# Run all tests
poetry run pytest tests/

# Run tests with verbose output
poetry run pytest tests/ -v

# Run a specific test class
poetry run pytest tests/test_rules.py::TestEvalUsage -v
```

The test suite includes:
- Unit tests for each rule pattern (VB_HARDCODED_PASSWORD, VB_EVAL_USAGE, VB_SQL_CONCAT, VB_SHELL_EXEC, VB_FILESYSTEM, VB_HTTP_URL, VB_GOTO_STATEMENT)
- Integration tests using the example VB files
- Tests to verify all rules are properly loaded and configured

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
  pattern: >-
    \bEval\s*\(
  severity: high
  description: "Eval can execute arbitrary code."
```

**Note:** Use `>-` for the pattern field to ensure the pattern string doesn't include trailing newlines that could cause regex matching issues.
