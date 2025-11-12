# IDE Integration Guide

This guide explains how to integrate the SEMCL.ONE MCP server with popular AI-powered IDEs for seamless OSS compliance analysis directly within your development environment.

## Supported IDEs

The SEMCL.ONE MCP server works with any IDE that supports the Model Context Protocol (MCP):

- **Cursor IDE** - AI-first code editor
- **Cline** - AI coding extension for VS Code
- **Kiro IDE** - Amazon's agentic AI IDE (launched July 2025)
- **VS Code** (with MCP extensions)
- **JetBrains IDEs** (with AI plugin + MCP support)

## Prerequisites

1. **Install mcp-semclone** (choose one method):

   **Option A: Using pipx (recommended)**:
   ```bash
   # Install pipx if you don't have it
   pip install pipx
   pipx ensurepath

   # Install mcp-semclone
   pipx install mcp-semclone

   # IMPORTANT: Install all CLI dependencies - required by some agents
   pipx inject mcp-semclone purl2notices osslili binarysniffer ospac vulnq upmex
   ```

   **Option B: Using pip**:
   ```bash
   pip install mcp-semclone
   ```

2. **Verify installation**:
   ```bash
   python -m mcp_semclone.server --version
   ```

## Cursor IDE Integration

### Quick Setup

1. **Locate your Cursor configuration directory**:
   - macOS/Linux: `~/.cursor/`
   - Windows: `%USERPROFILE%\.cursor\`

2. **Create or edit `mcp.json`**:

   **For project-specific configuration** (recommended):
   ```bash
   mkdir -p .cursor
   ```

   Create `.cursor/mcp.json`:

   **If installed with pipx**:
   ```json
   {
     "mcpServers": {
       "semclone": {
         "command": "/path/to/your/.local/pipx/venvs/mcp-semclone/bin/python3",
         "args": ["-m", "mcp_semclone.server"],
         "env": {},
         "disabled": false,
         "autoApprove": [
           "scan_directory",
           "check_package",
           "validate_policy",
           "get_license_obligations",
           "check_license_compatibility",
           "get_license_details",
           "analyze_commercial_risk",
           "validate_license_list",
           "run_compliance_check",
           "generate_legal_notices",
           "generate_sbom",
           "scan_binary"
         ]
       }
     }
   }
   ```

   **If installed with pip**:
   ```json
   {
     "mcpServers": {
       "semclone": {
         "command": "/path/to/your/python",
         "args": ["-m", "mcp_semclone.server"],
         "env": {},
         "disabled": false,
         "autoApprove": [
           "scan_directory",
           "check_package",
           "validate_policy",
           "get_license_obligations",
           "check_license_compatibility",
           "get_license_details",
           "analyze_commercial_risk",
           "validate_license_list",
           "run_compliance_check",
           "generate_legal_notices",
           "generate_sbom",
           "scan_binary"
         ]
       }
     }
   }
   ```

   **For global configuration** (all projects):
   Create `~/.cursor/mcp.json` with the same content.

   **Find your pipx Python path**:
   ```bash
   # macOS/Linux
   echo "$HOME/.local/pipx/venvs/mcp-semclone/bin/python3"

   # Or locate it automatically
   pipx list --include-injected | grep mcp-semclone -A 3
   ```

3. **Restart Cursor IDE**

4. **Verify connection**:
   - Open Cursor
   - The AI should now have access to SEMCL.ONE tools
   - Try asking: "Scan this project for license compliance issues"

### Advanced Configuration

#### With Environment Variables

```json
{
  "mcpServers": {
    "semclone": {
      "command": "python",
      "args": ["-m", "mcp_semclone.server"],
      "env": {
        "CUSTOM_VAR": "value"
      }
    }
  }
}
```

#### Using Variable Interpolation

```json
{
  "mcpServers": {
    "semclone": {
      "command": "${env:PYTHON_PATH}",
      "args": ["-m", "mcp_semclone.server"],
      "env": {
        "WORKSPACE_ROOT": "${workspaceFolder}"
      }
    }
  }
}
```

**Available variables**:
- `${env:NAME}` - Environment variable
- `${workspaceFolder}` - Project root directory
- `${userHome}` - User home directory
- `${workspaceFolderBasename}` - Project folder name

## Kiro IDE Integration

Kiro is Amazon's new agentic AI IDE with native MCP support.

### Quick Setup

1. **Locate your Kiro configuration directory**:
   - macOS/Linux: `~/.kiro/settings/`
   - Windows: `%USERPROFILE%\.kiro\settings\`

2. **Create or edit `mcp.json`**:

   **For workspace-specific configuration**:
   ```bash
   mkdir -p .kiro/settings
   ```

   Create `.kiro/settings/mcp.json`:

   **If installed with pipx**:
   ```json
   {
     "mcpServers": {
       "semclone": {
         "command": "/path/to/your/.local/pipx/venvs/mcp-semclone/bin/python3",
         "args": ["-m", "mcp_semclone.server"],
         "env": {},
         "disabled": false,
         "autoApprove": [
           "scan_directory",
           "check_package",
           "validate_policy",
           "get_license_obligations",
           "check_license_compatibility",
           "get_license_details",
           "analyze_commercial_risk",
           "validate_license_list",
           "run_compliance_check",
           "generate_legal_notices",
           "generate_sbom",
           "scan_binary"
         ]
       }
     }
   }
   ```

   **If installed with pip**:
   ```json
   {
     "mcpServers": {
       "semclone": {
         "command": "/path/to/your/python",
         "args": ["-m", "mcp_semclone.server"],
         "env": {},
         "disabled": false,
         "autoApprove": [
           "scan_directory",
           "check_package",
           "validate_policy",
           "get_license_obligations",
           "check_license_compatibility",
           "get_license_details",
           "analyze_commercial_risk",
           "validate_license_list",
           "run_compliance_check",
           "generate_legal_notices",
           "generate_sbom",
           "scan_binary"
         ]
       }
     }
   }
   ```

   **Find your pipx Python path**:
   ```bash
   # macOS/Linux
   echo "$HOME/.local/pipx/venvs/mcp-semclone/bin/python3"

   # Windows
   echo "%USERPROFILE%\.local\pipx\venvs\mcp-semclone\Scripts\python.exe"

   # Or locate it automatically
   pipx list --include-injected | grep mcp-semclone -A 3
   ```

   **For user-wide configuration**:
   Create `~/.kiro/settings/mcp.json` with the same content.

3. **Restart Kiro IDE**

4. **Enable MCP in Settings**:
   - Open Kiro Settings
   - Navigate to MCP section
   - Verify "semclone" server is listed and connected

### Configuration Fields Explained

| Field | Required | Description |
|-------|----------|-------------|
| `command` | Yes | Executable command (must be in PATH or use full path) |
| `args` | Yes | Array of command arguments |
| `env` | Yes | Environment variables (can be empty object) |
| `disabled` | Yes | Set to `false` to enable the server |
| `autoApprove` | Yes | List of tools that don't require user confirmation |

### Auto-Approve Tool List

The `autoApprove` field allows these tools to run without prompting the user:

- **License Analysis**: `get_license_details`, `get_license_obligations`, `check_license_compatibility`
- **Package Scanning**: `scan_directory`, `check_package`, `scan_binary`
- **Policy & Risk**: `validate_policy`, `analyze_commercial_risk`, `validate_license_list`
- **Documentation**: `generate_legal_notices`, `generate_sbom`
- **Complete Workflow**: `run_compliance_check` (one-shot compliance check for any project type)

**Note**: Only include tools you trust to run automatically. You can remove sensitive tools if needed.

## Cline Integration

Cline is a popular AI coding extension for VS Code with native MCP support.

### Quick Setup

1. **Install Cline extension** in VS Code from the marketplace

2. **Locate your Cline configuration**:
   - Open Cline settings in VS Code
   - Look for "MCP Settings" or configuration file path
   - Typically stored in VS Code settings or a separate config file

3. **Create or edit MCP configuration**:

   **If installed with pipx**:
   ```json
   {
     "mcpServers": {
       "semclone": {
         "command": "/path/to/your/.local/pipx/venvs/mcp-semclone/bin/python3",
         "args": ["-m", "mcp_semclone.server"],
         "env": {},
         "disabled": false,
         "autoApprove": [
           "scan_directory",
           "check_package",
           "validate_policy",
           "get_license_obligations",
           "check_license_compatibility",
           "get_license_details",
           "analyze_commercial_risk",
           "validate_license_list",
           "run_compliance_check",
           "generate_legal_notices",
           "generate_sbom",
           "scan_binary"
         ]
       }
     }
   }
   ```

   **If installed with pip**:
   ```json
   {
     "mcpServers": {
       "semclone": {
         "command": "/path/to/your/python",
         "args": ["-m", "mcp_semclone.server"],
         "env": {},
         "disabled": false,
         "autoApprove": [
           "scan_directory",
           "check_package",
           "validate_policy",
           "get_license_obligations",
           "check_license_compatibility",
           "get_license_details",
           "analyze_commercial_risk",
           "validate_license_list",
           "run_compliance_check",
           "generate_legal_notices",
           "generate_sbom",
           "scan_binary"
         ]
       }
     }
   }
   ```

   **Find your pipx Python path**:
   ```bash
   # macOS/Linux
   echo "$HOME/.local/pipx/venvs/mcp-semclone/bin/python3"

   # Windows
   echo "%USERPROFILE%\.local\pipx\venvs\mcp-semclone\Scripts\python.exe"

   # Or locate it automatically
   pipx list --include-injected | grep mcp-semclone -A 3
   ```

   **Find your Python path (for pip installation)**:
   ```bash
   # macOS/Linux
   which python3

   # Windows
   where python
   ```

4. **Restart VS Code** or reload Cline

5. **Verify connection**:
   - Open Cline panel in VS Code
   - Check that MCP tools are available
   - Try asking: "Scan this project for license compliance issues"

### Configuration Fields

| Field | Required | Description |
|-------|----------|-------------|
| `command` | Yes | Full path to Python executable |
| `args` | Yes | Arguments to run the MCP server |
| `env` | Yes | Environment variables (can be empty object) |
| `disabled` | Yes | Set to `false` to enable the server |
| `autoApprove` | Yes | List of tools that don't require user confirmation |

**Important Notes**:
- **Use full paths** for the `command` field (not just "python" or "python3")
- **Install all dependencies** with `pipx inject` if using pipx - some agents require CLI tool access
- The `autoApprove` list allows tools to run without prompting for each execution

## VS Code Integration

VS Code requires an MCP extension to support the Model Context Protocol.

1. **Install MCP extension** (check VS Code marketplace for latest)

2. **Configure in `settings.json`**:
   ```json
   {
     "mcp.servers": {
       "semclone": {
         "command": "python",
         "args": ["-m", "mcp_semclone.server"]
       }
     }
   }
   ```

## JetBrains IDEs Integration

JetBrains IDEs (IntelliJ IDEA, PyCharm, WebStorm, etc.) support MCP through the AI plugin plugin.

1. **Install AI plugin plugin**
2. **Enable MCP support** in AI plugin settings
3. **Configure MCP servers** following IDE-specific instructions


## Common Use Cases

### During Development

Ask your AI:
- "Check this file for license compliance"
- "What licenses are used in this project?"
- "Is this package safe for commercial use?"
- "What are my obligations for the MIT license?"

### Before Commits

Ask your AI:
- "Scan changed files for new dependencies"
- "Validate project against our compliance policy"
- "Check if any new licenses were introduced"

### Pre-Release

Ask your AI:
- "Generate SBOM for this release"
- "Create NOTICE file for distribution"
- "Generate legal notices for mobile app"
- "Analyze commercial distribution risks"

## Troubleshooting

### Server Not Connecting

**Check installation**:
```bash
python -m mcp_semclone.server --version
```

**Verify Python in PATH**:
```bash
which python  # macOS/Linux
where python  # Windows
```

**Check logs**:
- **Cursor**: Developer Tools → Console
- **Kiro**: View → Kiro - MCP Logs
- **VS Code**: Output → MCP Server Logs

### Tools Not Appearing

1. **Restart the IDE** after configuration changes
2. **Verify JSON syntax** - Use a JSON validator
3. **Check file location** - Ensure `mcp.json` is in correct directory
4. **Review logs** for connection errors

### Permission Issues

If you see permission errors:

**macOS/Linux**:
```bash
chmod +x $(which python)
```

**Windows**: Run IDE as Administrator (first time only)

### Python Not Found

**Specify full path to Python**:

```json
{
  "mcpServers": {
    "semclone": {
      "command": "/usr/bin/python3",
      "args": ["-m", "mcp_semclone.server"]
    }
  }
}
```

**Or use virtual environment**:

```json
{
  "mcpServers": {
    "semclone": {
      "command": "/path/to/venv/bin/python",
      "args": ["-m", "mcp_semclone.server"]
    }
  }
}
```

## Available Tools

Once integrated, your IDE's AI will have access to these 12 tools:

| Tool | Purpose |
|------|---------|
| `scan_directory` | Scan source code directories for licenses |
| `check_package` | Analyze individual package archives |
| `scan_binary` | Scan compiled binaries for OSS components |
| `validate_policy` | Validate licenses against compliance policy |
| `get_license_obligations` | Get obligations for specific licenses |
| `check_license_compatibility` | Check if licenses are compatible |
| `get_license_details` | Get comprehensive license information |
| `analyze_commercial_risk` | Analyze commercial licensing risks |
| `validate_license_list` | Validate license list for distribution type |
| `run_compliance_check` | Universal compliance workflow for any project type |
| `generate_legal_notices` | Generate comprehensive attribution docs |
| `generate_sbom` | Generate Software Bill of Materials |

## Example Workflows

### Mobile App Compliance

1. Developer asks: "Check if this project is safe for App Store distribution"
2. AI uses `scan_directory` to analyze the project
3. AI uses `validate_license_list` with distribution type "mobile"
4. AI uses `analyze_commercial_risk` to assess risks
5. AI provides comprehensive compliance report

### SBOM Generation

1. Developer asks: "Generate SBOM for this release"
2. AI uses `scan_directory` to identify packages
3. AI uses `generate_sbom` with CycloneDX format
4. SBOM saved to `sbom.json` in project root

### Legal Notice Creation

1. Developer asks: "Create NOTICE file for distribution"
2. AI uses `scan_directory` to find packages
3. AI uses `generate_legal_notices` with all PURLs
4. Legal notices saved to `NOTICE.txt`

## Best Practices

### Security

- ✅ Use project-specific configuration for sensitive projects
- ✅ Review `autoApprove` lists carefully
- ✅ Keep mcp-semclone updated: `pip install -U mcp-semclone`
- ❌ Don't commit `.cursor/mcp.json` or `.kiro/settings/mcp.json` with secrets

### Performance

- ✅ Use global configuration for consistent tooling across projects
- ✅ Enable auto-approve for read-only tools
- ✅ Cache scan results when possible
- ❌ Avoid scanning very large directories repeatedly

### Team Collaboration

- ✅ Document IDE setup in project README
- ✅ Share configuration templates via `.cursor/mcp.json.example`
- ✅ Use environment variables for flexible paths
- ✅ Standardize compliance policies across team

## Configuration Templates

### Minimal Configuration (Cursor with pipx)

`.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "semclone": {
      "command": "/path/to/your/.local/pipx/venvs/mcp-semclone/bin/python3",
      "args": ["-m", "mcp_semclone.server"],
      "env": {},
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

### Minimal Configuration (Cline with pipx)

Cline MCP configuration:
```json
{
  "mcpServers": {
    "semclone": {
      "command": "/path/to/your/.local/pipx/venvs/mcp-semclone/bin/python3",
      "args": ["-m", "mcp_semclone.server"],
      "env": {},
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

### Minimal Configuration (Kiro with pipx)

`.kiro/settings/mcp.json`:
```json
{
  "mcpServers": {
    "semclone": {
      "command": "/path/to/your/.local/pipx/venvs/mcp-semclone/bin/python3",
      "args": ["-m", "mcp_semclone.server"],
      "env": {},
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

### Production Configuration (Full auto-approve)

For any IDE (replace path with your actual Python path):
```json
{
  "mcpServers": {
    "semclone": {
      "command": "/path/to/your/.local/pipx/venvs/mcp-semclone/bin/python3",
      "args": ["-m", "mcp_semclone.server"],
      "env": {},
      "disabled": false,
      "autoApprove": [
        "scan_directory",
        "check_package",
        "validate_policy",
        "get_license_obligations",
        "check_license_compatibility",
        "get_license_details",
        "analyze_commercial_risk",
        "validate_license_list",
        "run_compliance_check",
        "generate_legal_notices",
        "generate_sbom",
        "scan_binary"
      ]
    }
  }
}
```

### Selective Auto-Approve Configuration

For read-only operations (safe for most use cases):
```json
{
  "mcpServers": {
    "semclone": {
      "command": "/path/to/your/.local/pipx/venvs/mcp-semclone/bin/python3",
      "args": ["-m", "mcp_semclone.server"],
      "env": {},
      "disabled": false,
      "autoApprove": [
        "get_license_details",
        "get_license_obligations",
        "check_license_compatibility",
        "validate_license_list",
        "check_package"
      ]
    }
  }
}
```

## Next Steps

- Read the [Mobile App Compliance Guide](./MOBILE_APP_COMPLIANCE_GUIDE.md)
- Explore [SEMCL.ONE toolchain](https://github.com/SemClone)
- Check [MCP specification](https://modelcontextprotocol.io)
- Join discussions at [GitHub Issues](https://github.com/SemClone/mcp-semclone/issues)

## Support

For IDE integration issues:
- Check [SUPPORT.md](../SUPPORT.md)
- Review [GitHub Issues](https://github.com/SemClone/mcp-semclone/issues)
- Consult IDE-specific MCP documentation

## Contributing

Found an issue or have an improvement? See [CONTRIBUTING.md](../CONTRIBUTING.md).

---

*Part of the [SEMCL.ONE](https://semcl.one) ecosystem for comprehensive OSS compliance and code analysis.*
