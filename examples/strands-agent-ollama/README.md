# Strands Agent with Ollama - OSS Compliance Example

This example demonstrates how to build an autonomous agent using **Ollama** (local LLM) that performs OSS compliance analysis using the **mcp-semclone** MCP server.

## Overview

The example shows how to:
- Connect to a local MCP server (mcp-semclone)
- Use Ollama with granite3-dense:8b for local, private LLM inference
- Execute OSS compliance workflows autonomously
- Analyze binaries, source code, and dependencies
- Generate compliance reports without sending data to external services

## Architecture

```
┌─────────────────────┐
│  Strands Agent      │  ← Autonomous agent loop
│  (Python app)       │
└──────────┬──────────┘
           │
           ├─► Ollama (granite3-dense:8b)  ← Local LLM inference
           │
           └─► MCP Server                   ← mcp-semclone tools
               (stdio transport)
                   │
                   ├─► scan_directory()
                   ├─► scan_binary()
                   ├─► validate_policy()
                   ├─► get_license_obligations()
                   └─► ... (12 tools total)
```

## Prerequisites

1. **Ollama installed** with recommended model:
   ```bash
   # Install Ollama: https://ollama.ai
   brew install ollama  # macOS

   # Pull granite3-dense:8b model (RECOMMENDED)
   ollama pull granite3-dense:8b

   # Alternative: llama3 (may produce less accurate results)
   # ollama pull llama3
   ```

   **⚠️ Model Recommendation:** Use `granite3-dense:8b` for best results. Testing shows it provides accurate, grounded analysis without hallucinations. The `llama3` model may invent non-existent packages in compliance reports.

2. **mcp-semclone installed**:
   ```bash
   pip install mcp-semclone
   ```

3. **SEMCL.ONE tools** available in PATH:
   ```bash
   # Verify tools are installed
   which purl2notices osslili binarysniffer ospac vulnq upmex
   ```

## Installation

```bash
cd examples/strands-agent-ollama

# Install dependencies
pip install -r requirements.txt

# Verify Ollama is running
ollama list
```

## Usage

### Basic Compliance Analysis

```bash
# Analyze a directory (uses granite3-dense:8b by default)
python agent.py /path/to/project

# Analyze a binary file
python agent.py /path/to/app.apk

# Use verbose output
python agent.py /path/to/project --verbose

# Explicitly specify granite3 model (recommended)
python agent.py /path/to/project --model granite3-dense:8b

# Use alternative model (not recommended - may hallucinate)
python agent.py /path/to/project --model llama3
```

## How It Works

### 1. Agent Initialization

The agent connects to the mcp-semclone server using stdio transport:

```python
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

server_params = StdioServerParameters(
    command="mcp-semclone",
    args=[],
    env=None
)

async with stdio_client(server_params) as (read, write):
    async with ClientSession(read, write) as session:
        # Agent loop runs here
        pass
```

### 2. LLM Decision Making

The agent uses Ollama's granite3-dense:8b to:
- Understand user queries
- Select appropriate MCP tools
- Interpret tool results
- Generate human-readable reports

```python
import ollama

response = ollama.chat(
    model='llama3',
    messages=[{
        'role': 'user',
        'content': f'Analyze compliance for: {path}'
    }]
)
```

### 3. Tool Execution

Based on LLM decisions, the agent calls MCP tools:

```python
# Example: Binary scan
result = await session.call_tool(
    "scan_binary",
    arguments={
        "path": "/path/to/app.apk",
        "analysis_mode": "standard",
        "check_licenses": True
    }
)
```

### 4. Result Interpretation

The LLM interprets results and provides actionable insights:

```python
# Feed results back to LLM
analysis = ollama.chat(
    model='llama3',
    messages=[{
        'role': 'system',
        'content': 'You are an OSS compliance expert.'
    }, {
        'role': 'user',
        'content': f'Interpret these results: {result}'
    }]
)
```

## Example Workflows

### Workflow 1: Mobile App Compliance

```python
# The agent will:
# 1. Detect file type (APK) → use scan_binary
# 2. Extract licenses and components
# 3. Check App Store compatibility
# 4. Identify copyleft licenses
# 5. Generate legal notice
# 6. Provide compliance recommendations

python agent.py mobile-compliance myapp.apk
```

Output:
```
🔍 Analyzing: myapp.apk
📦 Type: Android APK (binary analysis)
⚙️  Mode: standard (balanced speed/accuracy)

📊 Analysis Results:
   - Components: 42 detected
   - Licenses: MIT (15), Apache-2.0 (20), BSD-3-Clause (5), GPL-3.0 (2)

⚠️  Compliance Issues:
   - GPL-3.0 detected: Requires source disclosure
   - App Store incompatible: GPL-3.0, AGPL-3.0

✅ Recommendations:
   1. Remove GPL-3.0 component (found in: libexample.so)
   2. Replace with MIT/Apache-2.0 alternative
   3. Review NOTICE file requirements
   4. Generate legal attribution text

📄 Legal Notice: Generated → legal_notice.txt
```

### Workflow 2: Source Code Audit

```python
# The agent will:
# 1. Scan directory for licenses
# 2. Identify package dependencies
# 3. Check vulnerabilities
# 4. Validate against policy
# 5. Generate SBOM
# 6. Provide remediation steps

python agent.py audit /path/to/project --policy enterprise.yaml
```

### Workflow 3: Batch Analysis

```python
# Analyze multiple projects in parallel
python agent.py batch /projects/* --workers 4
```

## Configuration

### Agent Configuration (`agent_config.yaml`)

```yaml
# LLM Settings
llm:
  model: llama3
  temperature: 0.1  # Low for deterministic compliance decisions
  max_tokens: 2000

# MCP Server Settings
mcp:
  server_command: mcp-semclone
  timeout: 300  # 5 minutes

# Analysis Settings
analysis:
  default_mode: standard
  confidence_threshold: 0.5
  max_depth: 10

# Reporting
reports:
  format: markdown
  include_sbom: true
  include_notices: true
```

### Policy Configuration (`policy.yaml`)

```yaml
policy_name: "Enterprise OSS Policy"
version: "1.0"

allowed_licenses:
  - MIT
  - Apache-2.0
  - BSD-3-Clause
  - ISC

blocked_licenses:
  - GPL-3.0
  - AGPL-3.0
  - SSPL-1.0

require_attribution: true
require_source_disclosure: false
```

## Architecture Details

### Agent Loop

```python
async def agent_loop(session, query):
    """Main agent decision loop."""

    # 1. Plan: LLM decides strategy
    plan = await llm_plan(query)

    # 2. Act: Execute MCP tools
    results = []
    for action in plan.actions:
        result = await session.call_tool(
            action.tool,
            arguments=action.args
        )
        results.append(result)

    # 3. Analyze: LLM interprets results
    analysis = await llm_analyze(results)

    # 4. Report: Generate output
    report = await llm_report(analysis)

    return report
```

### Error Handling

The agent handles:
- MCP server connection failures
- Tool execution errors
- Ollama inference failures
- Invalid file paths
- Policy validation errors

### Performance Optimization

- **Parallel Tool Calls**: Independent tools run concurrently
- **Caching**: Results cached for repeated queries
- **Streaming**: Large results streamed to prevent memory issues
- **Timeouts**: Configurable timeouts for long-running operations

## Example Output

### Mobile App Analysis

```markdown
# OSS Compliance Report: myapp.apk

**Generated**: 2025-11-08 09:45:00
**Analyzer**: Strands Agent v1.0 (llama3 + mcp-semclone)

## Executive Summary

- **Risk Level**: MEDIUM
- **Compliance Status**: ⚠️ Action Required
- **Components Detected**: 42
- **License Issues**: 2 critical, 3 warnings

## License Distribution

| License | Count | Risk | Status |
|---------|-------|------|--------|
| Apache-2.0 | 20 | ✅ Low | Compliant |
| MIT | 15 | ✅ Low | Compliant |
| BSD-3-Clause | 5 | ✅ Low | Compliant |
| **GPL-3.0** | **2** | **❌ High** | **BLOCKED** |

## Critical Issues

### Issue 1: GPL-3.0 License Detected
- **Component**: libexample.so
- **Impact**: Requires source code disclosure for entire app
- **App Store**: ❌ Incompatible
- **Recommendation**: Remove or replace with MIT/Apache alternative

### Issue 2: Missing Legal Notices
- **Required**: 40 components need attribution
- **Status**: Not included in APK
- **Recommendation**: Add NOTICE.txt to assets/

## Recommendations

1. **Immediate Actions**:
   - Remove GPL-3.0 component (libexample.so)
   - Add legal notice file to app resources
   - Review third-party SDK licenses

2. **Policy Updates**:
   - Block GPL-3.0 in CI/CD pipeline
   - Automate license scanning on builds
   - Require pre-approval for new dependencies

3. **Next Steps**:
   - Scan updated build after GPL removal
   - Generate final legal notice
   - Document compliance in release notes

## Appendices

### A. Full Component List
[See attached SBOM: sbom.json]

### B. Legal Notice Text
[See attached: NOTICE.txt]

### C. License Obligations
[Detailed obligations for each license]
```

## Advanced Features

### Custom Tools

Add custom compliance checks:

```python
from agent import StrandsAgent

agent = StrandsAgent()

@agent.register_tool
async def custom_license_check(license_id):
    """Custom license validation logic."""
    # Your custom logic here
    pass
```

### Multi-Model Support

Use different models for different tasks:

```python
config = {
    'planning_model': 'llama3',      # Strategic decisions
    'analysis_model': 'deepseek-r1',  # Technical analysis
    'reporting_model': 'gemma3',      # Report generation
}
```

### Integration with CI/CD

```yaml
# .github/workflows/compliance.yml
name: OSS Compliance Check

on: [pull_request]

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2

      - name: Setup Ollama
        run: |
          curl -fsSL https://ollama.ai/install.sh | sh
          ollama pull llama3

      - name: Install mcp-semclone
        run: pip install mcp-semclone

      - name: Run Compliance Agent
        run: |
          cd examples/strands-agent-ollama
          python agent.py audit . --policy policy.yaml

      - name: Upload Report
        uses: actions/upload-artifact@v2
        with:
          name: compliance-report
          path: compliance_report.md
```

## Troubleshooting

### Ollama Connection Issues

```bash
# Check Ollama is running
ollama list

# Restart Ollama
killall ollama
ollama serve &

# Test llama3
ollama run llama3 "Hello"
```

### MCP Server Issues

```bash
# Test MCP server directly
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | mcp-semclone

# Check tool availability
which osslili binarysniffer ospac
```

### Performance Issues

```yaml
# Reduce LLM context size
llm:
  max_tokens: 1000  # Smaller responses

# Faster analysis mode
analysis:
  default_mode: fast
  max_depth: 5
```

## License

This example is part of mcp-semclone and is licensed under Apache-2.0.

## Documentation

- **README.md** (this file) - Getting started and usage examples
- **[TUNING.md](TUNING.md)** - Complete guide to tuning and optimization
  - Model selection (llama3, gemma3, deepseek-r1)
  - Temperature and sampling configuration
  - Performance optimization techniques
  - Accuracy tuning strategies
  - Custom prompts and policies
  - Resource management
  - Advanced scenarios

## Support

- **Documentation**: https://github.com/SemClone/mcp-semclone
- **Issues**: https://github.com/SemClone/mcp-semclone/issues
- **Ollama**: https://ollama.ai/docs
