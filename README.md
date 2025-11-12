# mcp-semclone - Model Context Protocol Server for SEMCL.ONE

[![Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![MCP 1.0+](https://img.shields.io/badge/MCP-1.0+-purple.svg)](https://modelcontextprotocol.io/)

MCP (Model Context Protocol) server that provides LLMs with comprehensive OSS compliance and vulnerability analysis capabilities through the SEMCL.ONE toolchain.

## Overview

mcp-semclone integrates the complete SEMCL.ONE toolchain to provide LLMs with powerful software composition analysis capabilities:

- **License Detection & Compliance**: Scan codebases for licenses and validate against policies
- **Binary Analysis**: Analyze compiled binaries (APK, EXE, DLL, SO, JAR) for OSS components and licenses
- **Vulnerability Assessment**: Query multiple vulnerability databases for security issues
- **Package Discovery**: Identify packages from source code and generate PURLs
- **SBOM Generation**: Create Software Bill of Materials in SPDX/CycloneDX formats
- **Policy Validation**: Check license compatibility and organizational compliance

## Features

### Tools
- `scan_directory` - Comprehensive directory scanning for packages, licenses, and vulnerabilities
- `scan_binary` - Analyze compiled binaries (APK, EXE, DLL, SO, JAR) for OSS components
- `check_package` - Check specific packages for licenses and vulnerabilities
- `validate_policy` - Validate licenses against organizational policies
- `validate_license_list` - Quick license safety validation for distribution types
- `get_license_obligations` - Get detailed compliance requirements for licenses
- `check_license_compatibility` - Check if two licenses can be mixed
- `get_license_details` - Get comprehensive license information including full text
- `analyze_commercial_risk` - Assess commercial distribution risks
- `run_compliance_check` - Universal one-shot compliance workflow for any project type
- `generate_sbom` - Generate SBOM for projects

### Resources
- `license_database` - Access license compatibility information
- `policy_templates` - Get pre-configured policy templates

### Prompts
- `compliance_check` - Guided workflow for license compliance checking
- `vulnerability_assessment` - Guided workflow for security assessment

## Installation

### Single Command Installation

```bash
pip install mcp-semclone
```

This automatically installs all required SEMCL.ONE tools:
- **purl2notices** - Comprehensive package detection and license extraction
- **osslili** - License detection from archives (used by check_package)
- **binarysniffer** - Binary analysis for OSS components
- **ospac** - Policy validation engine
- **vulnq** - Vulnerability database queries
- **upmex** - Package metadata extraction (used by check_package)

### Pipx Installation (Recommended for Global Access)

[pipx](https://pipx.pypa.io/) installs the package in an isolated environment while making the CLI tools globally available. This is ideal for avoiding dependency conflicts with other Python packages on your system.

```bash
# Install pipx if you don't have it
pip install pipx
pipx ensurepath

# Install mcp-semclone
pipx install mcp-semclone

# IMPORTANT: Inject all SEMCL.ONE tool dependencies into the same isolated environment
# This ensures all tools are available both as libraries and CLI commands
# Required by some agents that need direct CLI tool access
pipx inject mcp-semclone purl2notices osslili binarysniffer ospac vulnq upmex
```

**Benefits of pipx:**
- ✅ Isolated environment prevents dependency conflicts
- ✅ All tools globally accessible in PATH
- ✅ Easy to update: `pipx upgrade mcp-semclone`
- ✅ Clean uninstall: `pipx uninstall mcp-semclone`

### Development Installation

```bash
git clone https://github.com/SemClone/mcp-semclone.git
cd mcp-semclone
pip install -e .[dev]
```

## Configuration

### MCP Client Integration

**Quick Start - Basic Configuration:**

Add to your MCP client configuration file (e.g., `.cursor/mcp.json`, Cline settings, `.kiro/settings/mcp.json`):

```json
{
  "mcpServers": {
    "semclone": {
      "command": "/path/to/your/.local/pipx/venvs/mcp-semclone/bin/python3",
      "args": ["-m", "mcp_semclone.server"],
      "env": {}
    }
  }
}
```

**Find your pipx Python path:**
```bash
# macOS/Linux
echo "$HOME/.local/pipx/venvs/mcp-semclone/bin/python3"

# Or locate automatically
pipx list --include-injected | grep mcp-semclone -A 3
```

**📖 For detailed setup instructions including:**
- IDE-specific configurations (Cursor, Cline, Kiro, VS Code, JetBrains)
- Auto-approve settings
- pip vs pipx configurations
- Configuration templates
- Troubleshooting

**See the [IDE Integration Guide](guides/IDE_INTEGRATION_GUIDE.md)**

### Environment Variables

Optional environment variables for enhanced functionality:

```bash
# API Keys (optional, for higher rate limits)
export GITHUB_TOKEN="your_github_token"
export NVD_API_KEY="your_nvd_api_key"

# Tool paths (optional, only if tools are not in PATH)
# Tools are auto-detected by default using shutil.which()
export PURL2NOTICES_PATH="/custom/path/to/purl2notices"
export OSSLILI_PATH="/custom/path/to/osslili"
export BINARYSNIFFER_PATH="/custom/path/to/binarysniffer"
export VULNQ_PATH="/custom/path/to/vulnq"
export OSPAC_PATH="/custom/path/to/ospac"
export UPMEX_PATH="/custom/path/to/upmex"
```

**Note:** Tools are automatically detected in your PATH. Environment variables are only needed for custom installation locations.

## Usage Examples

### With MCP Clients

Once configured, you can ask your LLM:

- "Scan /path/to/project for license compliance issues"
- "Analyze this Android APK file for OSS components and licenses"
- "Check if this project has any critical vulnerabilities"
- "Generate an SBOM for my project"
- "What licenses are in this compiled binary?"
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

        # Scan a binary file
        binary_result = await client.call_tool(
            "scan_binary",
            {
                "path": "/path/to/app.apk",
                "analysis_mode": "deep",
                "check_compatibility": True
            }
        )
        print(f"Found {binary_result['metadata']['component_count']} components")
        print(f"Licenses: {binary_result['licenses']}")

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
┌─────────────────┐
│   LLM Client    │
│  (MCP Client)   │
└────────┬────────┘
         │ MCP Protocol
┌────────▼────────┐
│  mcp-semclone   │
│   MCP Server    │
└────────┬────────┘
         │ Subprocess calls
┌────────▼──────────────────────────┐
│      SEMCL.ONE Toolchain          │
├────────────────────────────────────┤
│ purl2notices │ Package + License  │
│ osslili      │ Archive scanning   │
│ binarysniffer│ Binary analysis    │
│ vulnq        │ Vulnerability DB   │
│ ospac        │ Policy engine      │
│ upmex        │ Metadata extract   │
└────────────────────────────────────┘
```

## Server Instructions for LLMs

The MCP server includes comprehensive instructions that help LLMs understand how to use the tools effectively. These instructions are automatically injected into the LLM's context when using the server, providing:

### Workflow Patterns
- **License-first approach**: The server prioritizes license detection before package identification or vulnerability scanning
- **Efficient execution order**: Tools are orchestrated in an optimal sequence (licenses → packages → vulnerabilities → policy validation)
- **Smart dependency handling**: Package identification is only performed when needed for vulnerability checks or detailed SBOMs

### Tool Selection Guidance
- When to use `scan_directory` (comprehensive analysis) vs `check_package` (single package lookup)
- How tools interact (e.g., `generate_sbom` automatically calls `scan_directory` internally)
- Specialized tools for specific scenarios (e.g., `analyze_commercial_risk` for mobile/commercial distribution)

### Performance Optimization
- Vulnerability scanning is limited to the first 10 packages to avoid timeouts
- Recursive scanning depth limits: 10 for licenses, 5 for package identification
- 120-second timeout per tool invocation
- Guidance for handling large codebases

### Common Usage Patterns
The server provides ready-to-use workflow examples:
1. **Basic compliance check**: License inventory without package identification
2. **Full security assessment**: Complete vulnerability analysis with package discovery
3. **Policy validation**: Automated license compliance checking
4. **Commercial risk analysis**: Copyleft detection for mobile/commercial use
5. **SBOM generation**: Supply chain transparency documentation

This enables LLMs to automatically choose the right tool combination, optimize performance, and follow best practices without requiring user expertise in OSS compliance workflows.

## Tool Integration

The MCP server orchestrates multiple SEMCL.ONE tools:

1. **purl2notices**: Comprehensive package detection, license scanning, and copyright extraction (primary scanning tool)
2. **osslili**: License detection in archives and compressed files (used by check_package)
3. **binarysniffer**: Binary analysis for compiled artifacts (APK, EXE, DLL, SO, JAR)
4. **vulnq**: Queries vulnerability databases (OSV, GitHub, NVD)
5. **ospac**: Validates licenses against policies
6. **upmex**: Extracts package metadata from manifests (used by check_package)

## Examples

### Basic MCP Client Usage

See [`examples/basic_usage.py`](examples/basic_usage.py) for simple examples of calling MCP tools directly.

### Strands Agent with Ollama

A complete autonomous agent example demonstrating OSS compliance analysis using local LLM (Ollama) with MCP integration.

**Location**: `examples/strands-agent-ollama/`

**Features:**
- Autonomous decision-making (plan → execute → interpret → report)
- Local LLM inference via Ollama (llama3, gemma3, deepseek-r1)
- Interactive and batch analysis modes
- Custom policy enforcement
- Complete privacy (no external API calls)

**Quick Start:**
```bash
cd examples/strands-agent-ollama
./quickstart.sh
python agent.py interactive
```

**Documentation:**
- [README.md](examples/strands-agent-ollama/README.md) - Complete usage guide
- [TUNING.md](examples/strands-agent-ollama/TUNING.md) - Optimization guide
- [OVERVIEW.md](examples/strands-agent-ollama/OVERVIEW.md) - Architecture reference

**Use Cases:**
- Mobile app compliance (APK/IPA analysis)
- Embedded/IoT firmware scanning
- CI/CD integration
- Interactive compliance queries

See the [example directory](examples/strands-agent-ollama/) for full details.

## IDE Integration

Use SEMCL.ONE tools directly within your AI-powered IDE for seamless OSS compliance analysis during development.

### Supported IDEs

- **Cursor IDE** - AI-first code editor
- **Cline** - AI coding extension for VS Code
- **Kiro IDE** - Amazon's agentic AI IDE
- **VS Code** - With MCP extension
- **JetBrains IDEs** - With AI plugin

### Quick Setup

1. **Install mcp-semclone** with pipx (recommended):
   ```bash
   pipx install mcp-semclone
   pipx inject mcp-semclone purl2notices osslili binarysniffer ospac vulnq upmex
   ```

2. **Configure your IDE** - Add MCP server configuration (see guide for IDE-specific paths)

3. **Restart your IDE**

### Use Cases in IDEs

Once integrated, ask your IDE's AI:
- "Check this project for license compliance issues"
- "What licenses are used in my dependencies?"
- "Is this package safe for commercial distribution?"
- "Generate SBOM for this release"
- "Create NOTICE file for mobile app"

**📖 Complete documentation**: See [IDE Integration Guide](guides/IDE_INTEGRATION_GUIDE.md)

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

- **Issues**: [GitHub Issues](https://github.com/SemClone/mcp-semclone/issues)
- **Discussions**: [GitHub Discussions](https://github.com/SemClone/mcp-semclone/discussions)
- **Security**: Report vulnerabilities to security@semcl.one

---

*Part of the [SEMCL.ONE](https://github.com/SemClone/semcl.one) Software Composition Analysis toolchain*