# mcp-semclone - Model Context Protocol Server for SEMCL.ONE

[![Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![MCP 1.0+](https://img.shields.io/badge/MCP-1.0+-purple.svg)](https://modelcontextprotocol.io/)

MCP (Model Context Protocol) server that provides LLMs with comprehensive OSS compliance and vulnerability analysis capabilities through the SEMCL.ONE toolchain.

## Overview

mcp-semclone integrates the complete SEMCL.ONE toolchain to provide LLMs with powerful software composition analysis capabilities:

- **License Detection & Compliance**: Scan codebases for licenses and validate against policies
- **Vulnerability Assessment**: Query multiple vulnerability databases for security issues
- **Package Discovery**: Identify packages from source code and generate PURLs
- **SBOM Generation**: Create Software Bill of Materials in SPDX/CycloneDX formats
- **Policy Validation**: Check license compatibility and organizational compliance

## Features

### Tools
- `scan_directory` - Comprehensive directory scanning for packages, licenses, and vulnerabilities
- `check_package` - Check specific packages for licenses and vulnerabilities
- `validate_policy` - Validate licenses against organizational policies
- `generate_sbom` - Generate SBOM for projects

### Resources
- `license_database` - Access license compatibility information
- `policy_templates` - Get pre-configured policy templates

### Prompts
- `compliance_check` - Guided workflow for license compliance checking
- `vulnerability_assessment` - Guided workflow for security assessment

## Installation

### Prerequisites

First, install all SEMCL.ONE tools:

```bash
# Install individual tools
pip install osslili     # License detection
pip install src2purl     # Package discovery
pip install purl2notices # License notices extraction
pip install ospac        # Policy validation
pip install vulnq        # Vulnerability queries
pip install upmex        # Package metadata extraction

# Or install all at once
pip install osslili src2purl purl2notices ospac vulnq upmex
```

### Install MCP Server

```bash
pip install mcp-semclone
```

For development:

```bash
git clone https://github.com/scanoss/mcp-semclone.git
cd mcp-semclone
pip install -e .
```

## Configuration

### MCP Client Integration

Add to your MCP client configuration file:

```json
{
  "mcpServers": {
    "semclone": {
      "command": "python",
      "args": ["-m", "mcp_semclone.server"],
      "env": {
        "GITHUB_TOKEN": "your_github_token_optional",
        "NVD_API_KEY": "your_nvd_api_key_optional"
      }
    }
  }
}
```

### Environment Variables

Optional environment variables for enhanced functionality:

```bash
# API Keys (optional, for higher rate limits)
export GITHUB_TOKEN="your_github_token"
export NVD_API_KEY="your_nvd_api_key"

# Tool paths (if not in PATH)
export OSSLILI_PATH="/path/to/osslili"
export SRC2PURL_PATH="/path/to/src2purl"
export VULNQ_PATH="/path/to/vulnq"
export OSPAC_PATH="/path/to/ospac"
```

## Usage Examples

### With MCP Clients

Once configured, you can ask your LLM:

- "Scan /path/to/project for license compliance issues"
- "Check if this project has any critical vulnerabilities"
- "Generate an SBOM for my project"
- "Validate these licenses against our commercial distribution policy"
- "Find all GPL-licensed dependencies in this codebase"

### Direct MCP Client Usage

```python
from mcp import Client
import asyncio

async def main():
    async with Client("mcp-semclone") as client:
        # Scan a directory
        result = await client.call_tool(
            "scan_directory",
            {
                "path": "/path/to/project",
                "check_vulnerabilities": True,
                "check_licenses": True
            }
        )
        print(f"Found {result['metadata']['total_packages']} packages")
        print(f"Found {result['metadata']['total_vulnerabilities']} vulnerabilities")

        # Check a specific package
        package_result = await client.call_tool(
            "check_package",
            {"identifier": "pkg:npm/express@4.17.1"}
        )
        print(f"Vulnerabilities: {package_result['vulnerabilities']}")

asyncio.run(main())
```

## Workflows

### License Compliance Check

1. **Scan the project** to identify all packages and licenses
2. **Load or create a policy** defining allowed/denied licenses
3. **Validate licenses** against the policy
4. **Generate compliance report** with violations and recommendations

### Vulnerability Assessment

1. **Discover packages** in the codebase
2. **Query vulnerability databases** for each package
3. **Prioritize by severity** (CRITICAL > HIGH > MEDIUM > LOW)
4. **Identify available fixes** and upgrade paths
5. **Generate security report** with remediation steps

### SBOM Generation

1. **Scan project structure** to identify components
2. **Extract metadata** for each component
3. **Detect licenses** and copyright information
4. **Format as SBOM** (SPDX or CycloneDX)
5. **Validate completeness** of the SBOM

## Architecture

```
┌─────────────┐
│   LLM Client    │
│  (MCP Client)    │
└────────┬────────┘
         │ MCP Protocol
┌────────▼────────┐
│  mcp-semclone   │
│   MCP Server    │
└────────┬────────┘
         │ Subprocess calls
┌────────▼────────────────────┐
│     SEMCL.ONE Toolchain     │
├──────────────────────────────┤
│ osslili  │ License detection │
│ src2purl │ Package discovery │
│ vulnq    │ Vulnerability DB  │
│ ospac    │ Policy engine     │
│ upmex    │ Metadata extract  │
└──────────────────────────────┘
```

## Tool Integration

The MCP server orchestrates multiple SEMCL.ONE tools:

1. **src2purl**: Identifies packages from source files
2. **osslili**: Detects licenses in code and documentation
3. **vulnq**: Queries vulnerability databases (OSV, GitHub, NVD)
4. **ospac**: Validates licenses against policies
5. **purl2notices**: Extracts license notices and copyright
6. **upmex**: Extracts package metadata from manifests

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=mcp_semclone tests/

# Run specific test
pytest tests/test_server.py -v
```

### Building

```bash
# Build package
python -m build

# Install locally for testing
pip install -e .
```

## Troubleshooting

### Common Issues

1. **Tools not found**: Ensure all SEMCL.ONE tools are installed and in PATH
2. **API rate limits**: Add API keys to environment variables
3. **Permission errors**: Check file/directory permissions
4. **Large codebases**: Use recursive=False or limit scan depth

### Debug Mode

Enable debug logging:

```bash
export MCP_LOG_LEVEL=DEBUG
python -m mcp_semclone.server
```

## Security Considerations

- API keys are optional but recommended for production use
- The server runs tools via subprocess with user permissions
- Vulnerability data is fetched from public APIs
- No data is sent to external services without explicit tool calls

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

mcp-semclone is released under the Apache License 2.0. See [LICENSE](LICENSE) for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/scanoss/mcp-semclone/issues)
- **Discussions**: [GitHub Discussions](https://github.com/scanoss/mcp-semclone/discussions)
- **Security**: Report vulnerabilities to security@scanoss.com

---

*Part of the [SEMCL.ONE](https://github.com/scanoss/semcl.one) Software Composition Analysis toolchain*