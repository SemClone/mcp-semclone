# Mobile App Compliance Guide - SEMCL.ONE MCP Server

## Overview

This guide demonstrates how to use the SEMCL.ONE MCP (Model Context Protocol) server to assess commercial licensing risks for mobile app development. The MCP server provides comprehensive tools for license analysis, commercial risk assessment, SBOM generation, and legal notice creation.

## Key Use Cases

### 1. Commercial Mobile App Safety Assessment

**Question**: "Can I use this Python package in my commercial mobile app?"

**MCP Tools Used**:
- `run_compliance_check` - Universal compliance workflow (recommended)
- `analyze_commercial_risk` - Risk assessment tool
- `scan_directory` - License inventory
- `generate_legal_notices` - Complete legal documentation with purl2notices

**Example Results**:

#### ✅ SAFE: mcp-semclone
```json
{
  "project": "mcp-semclone",
  "primary_license": "Apache-2.0",
  "mobile_app_safe": true,
  "risk_level": "LOW",
  "wheel_available": true,
  "data_files_count": 0,
  "compliance_status": "APPROVED"
}
```

**Action Required**: Include Apache-2.0 license notice in app settings.

#### ⚠️ CAUTION: ospac
```json
{
  "project": "ospac",
  "primary_license": "Apache-2.0",
  "mobile_app_safe": false,
  "risk_level": "MEDIUM",
  "data_files_count": 728,
  "risk_factors": [
    "Wheel contains data files that may have mixed licensing",
    "Data files contain copyleft license references"
  ],
  "compliance_status": "REQUIRES_REVIEW"
}
```

**Action Required**: Legal review before commercial use due to mixed licensing in bundled data files.

### 2. License Inventory and SBOM Generation

**MCP Workflow**:
1. `scan_directory` - Comprehensive package detection and license scanning using purl2notices
2. `generate_sbom` - Create Software Bill of Materials with identified packages

**Output**: SPDX-compatible SBOM with package URLs (PURLs) and license information.

### 3. Legal Notice Generation

**MCP Tool**: `generate_legal_notices` (uses purl2notices for complete documentation)

**Purpose**: Generate production-ready NOTICE files with copyright extraction

**Generated Notice**: Complete legal notices including:
- All copyright holders (auto-extracted from package metadata)
- Full license texts from SPDX
- Proper attribution for all dependencies
- Ready for inclusion in mobile app distribution

**Recommended**: Use `run_compliance_check` for one-shot workflow that generates NOTICE.txt automatically.

## MCP Tool Reference

### Core Tools

#### `analyze_commercial_risk(path, include_data_files=True)`
**Purpose**: Comprehensive commercial licensing risk assessment
**Returns**:
- `primary_license`: Main project license (Apache-2.0, MIT, GPL, etc.)
- `mobile_app_safe`: Boolean indicating safety for mobile apps
- `risk_level`: LOW/MEDIUM/HIGH risk assessment
- `risk_factors`: List of identified licensing risks
- `wheel_analysis`: Distribution package analysis
- `recommendations`: Actionable next steps

#### `scan_directory(path, check_licenses=True, check_vulnerabilities=False)`
**Purpose**: Comprehensive compliance scanning using purl2notices for package detection, license scanning, and copyright extraction
**Returns**:
- `licenses`: Detected license evidence with confidence scores
- `packages`: All discovered packages including transitive dependencies (PURLs)
- `copyrights`: Extracted copyright statements from source
- `metadata`: Summary statistics

#### `generate_sbom(path, format="spdx")`
**Purpose**: Generate Software Bill of Materials
**Returns**:
- `sbom`: SPDX-compatible SBOM with packages and licenses

#### `run_compliance_check(path, distribution_type="mobile", check_vulnerabilities=True)`
**Purpose**: Universal one-shot compliance workflow for ANY project type
**Returns**:
- `decision`: "APPROVED" or "REJECTED"
- `risk_level`: "LOW", "MEDIUM", or "HIGH"
- `artifacts_created`: ["NOTICE.txt", "sbom.json"]
- `recommendations`: Actionable next steps
- Complete summary with policy violations and vulnerability counts

#### `generate_legal_notices(purls, output_file="NOTICE.txt")`
**Purpose**: Generate complete legal documentation using purl2notices
**Returns**:
- `notice`: Formatted legal text for app inclusion
- `recommended_location`: Suggested placement in app

### Supporting Tools

#### `check_package(identifier)`
**Purpose**: Analyze specific packages by PURL/CPE
**Use**: Verify upstream package licensing

#### `validate_policy(licenses, distribution="binary")`
**Purpose**: Policy compliance checking using ospac
**Use**: Validate against organizational license policies

## License-First Methodology

The SEMCL.ONE approach performs comprehensive scanning in a single pass:

1. **Comprehensive Scanning** (purl2notices) - Detect packages, licenses, and copyrights in one pass
2. **Risk Assessment** - Evaluate commercial compatibility using ospac
3. **Cross-Reference** - Correlate licenses with package metadata
4. **Documentation** - Generate compliance artifacts (SBOM, legal notices)

## Risk Assessment Matrix

| Primary License | Data Files | Mixed Licensing | Risk Level | Mobile Safe |
|----------------|------------|-----------------|------------|-------------|
| Apache-2.0/MIT | None | No | LOW | ✅ YES |
| Apache-2.0/MIT | Present | No | LOW | ✅ YES |
| Apache-2.0/MIT | Present | Yes | MEDIUM | ⚠️ REVIEW |
| GPL/AGPL | Any | Any | HIGH | ❌ NO |
| Unknown | Any | Any | MEDIUM | ⚠️ REVIEW |

## Integration Examples

### MCP Client Configuration
```json
{
  "mcpServers": {
    "semclone": {
      "command": "/path/to/python",
      "args": ["-m", "mcp_semclone.server"],
      "env": {
        "MCP_LOG_LEVEL": "INFO"
      }
    }
  }
}
```

### Programmatic Usage
```python
from mcp_semclone.server import analyze_commercial_risk

async def check_mobile_safety(project_path):
    result = await analyze_commercial_risk(project_path)

    if result["mobile_app_safe"]:
        print(f"✅ Safe for mobile app: {result['primary_license']}")
        return True
    else:
        print(f"⚠️ Review required: {result['risk_factors']}")
        return False
```

## Common Scenarios

### Scenario 1: Pure Apache-2.0 Library
- **Result**: LOW risk, mobile app safe
- **Action**: Include license notice
- **Example**: mcp-semclone

### Scenario 2: Apache-2.0 with Data Files
- **Result**: MEDIUM risk if data contains copyleft references
- **Action**: Legal review of bundled data
- **Example**: ospac

### Scenario 3: GPL/LGPL Library
- **Result**: HIGH risk, not mobile app safe
- **Action**: Avoid or seek alternative
- **Example**: N/A in SEMCL.ONE suite

### Scenario 4: Mixed Dependencies
- **Result**: Depends on most restrictive license
- **Action**: Review dependency tree
- **Example**: Projects with complex dependency chains

## Best Practices

### For Mobile App Developers
1. **Early Assessment**: Check licensing before integration
2. **Continuous Monitoring**: Re-assess when updating dependencies
3. **Documentation**: Maintain compliance artifacts
4. **Legal Review**: Consult legal counsel for MEDIUM+ risk projects

### For Library Authors
1. **Clear Licensing**: Use standard licenses (Apache-2.0, MIT)
2. **Avoid Mixed Licensing**: Keep data files under same license as code
3. **Distribution Analysis**: Check what gets packaged in wheels
4. **Documentation**: Provide clear licensing guidance

## Troubleshooting

### Common Issues

#### "Tool not found" Errors
- Ensure all SEMCL.ONE tools are installed: `pip install purl2notices osslili ospac vulnq binarysniffer upmex`
- Check PATH configuration

#### "No licenses detected"
- Verify project has LICENSE file or license declarations
- Check file permissions
- Use `--max-depth` to control scan depth

#### "Mixed licensing detected"
- Review data directory contents
- Consider separating code from reference data
- Evaluate if data files are essential for mobile app use

### Debug Mode
```bash
export MCP_LOG_LEVEL=DEBUG
python -m mcp_semclone.server
```

## Generated Artifacts

The MCP server generates several compliance artifacts:

### Compliance Reports
- `{project}_enhanced_compliance.json` - Risk assessment summary
- `{project}_sbom.json` - Software Bill of Materials

### Legal Documentation
- `{project}_mobile_notice.txt` - Mobile app legal notice
- `{project}_legal_notice.txt` - General legal notice

### Analysis Logs
- License detection evidence
- Package identification results
- Risk factor analysis

## Conclusion

The SEMCL.ONE MCP server provides comprehensive mobile app compliance capabilities through:

- **Automated Risk Assessment**: License-first analysis with commercial focus
- **SBOM Generation**: Industry-standard software bill of materials
- **Legal Documentation**: Ready-to-use compliance notices
- **Mixed Licensing Detection**: Identifies hidden copyleft risks
- **Mobile-Specific Guidance**: Tailored recommendations for app developers

For questions or support, see the [GitHub repository](https://github.com/SemClone/mcp-semclone).