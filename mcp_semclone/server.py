#!/usr/bin/env python3
"""MCP Server for SEMCL.ONE OSS Compliance Toolchain."""

import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field

# Configure logging
log_level = os.environ.get("MCP_LOG_LEVEL", "INFO")
logging.basicConfig(
    level=getattr(logging, log_level.upper()),
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


class ScanResult(BaseModel):
    """Result from a package scan."""

    packages: List[Dict[str, Any]] = Field(default_factory=list)
    licenses: List[Dict[str, Any]] = Field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = Field(default_factory=list)
    policy_violations: List[Dict[str, Any]] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


# Initialize FastMCP server
mcp = FastMCP(
    name="mcp-semclone",
    instructions="""Open source compliance and software supply chain security server using SEMCL.ONE toolchain.

WORKFLOW PATTERNS:
1. License-first approach: Always scan for licenses before identifying packages or vulnerabilities
2. Tool execution order: licenses (osslili) → packages (src2purl) → vulnerabilities (vulnq) → policy validation (ospac)
3. Package identification is optional and only required when checking vulnerabilities or generating detailed SBOMs
4. Vulnerability checks automatically trigger package identification if not already performed

TOOL SELECTION GUIDE:
- scan_directory: Primary tool for analyzing projects/codebases. Use for comprehensive license inventory, optional package identification, and vulnerability assessment
- check_package: Use when you have a specific package identifier (PURL, CPE, or file) to analyze. Checks both vulnerabilities and licenses for individual packages
- validate_policy: Standalone license policy validation. Use when you already have license data and need to check compliance
- analyze_commercial_risk: Specialized tool for commercial distribution risk assessment. Detects copyleft licenses and mixed licensing in data files
- generate_mobile_legal_notice: Creates legal notices for mobile app distribution. Use after identifying licenses in dependencies
- generate_sbom: Automatically calls scan_directory internally to generate Software Bill of Materials

PERFORMANCE CONSTRAINTS:
1. Vulnerability scanning limited to first 10 packages to avoid timeouts
2. Tool execution timeout: 120 seconds per tool invocation
3. Recursive scanning depth limits: max-depth 10 for license scans, max-depth 5 for package identification
4. Large codebases: Consider scanning specific subdirectories rather than entire repository

INPUT FORMAT REQUIREMENTS:
- Package identifiers: Accepts PURLs (pkg:npm/package@1.0), CPEs (cpe:2.3:a:vendor:product), or file paths
- Paths: Absolute or relative paths to files or directories
- License lists: Array of SPDX license identifiers (e.g., ["Apache-2.0", "MIT"])
- Policy files: JSON or YAML format policy definitions for ospac tool

COMMON WORKFLOWS:
1. Basic compliance check: scan_directory(path, check_licenses=True, identify_packages=False)
2. Full security assessment: scan_directory(path, check_vulnerabilities=True) - automatically enables package identification
3. Policy validation: scan_directory(path, policy_file="policy.json") → validate_policy(licenses, policy_file)
4. Commercial risk analysis: analyze_commercial_risk(path) for mobile/commercial distribution decisions
5. SBOM generation: generate_sbom(path, format="spdx") for supply chain transparency

RESOURCE ACCESS:
- semcl://license_database: Retrieves comprehensive license compatibility database from ospac
- semcl://policy_templates: Returns pre-configured policy templates (commercial, open_source, internal)

ERROR HANDLING:
- Tools return {"error": "message"} on failures
- Non-zero exit codes are logged but don't always indicate failure (check returned data)
- Missing CLI tools (src2purl, osslili, vulnq, ospac) will raise FileNotFoundError"""
)

# Global tool paths configuration
tool_paths = {
    "src2purl": os.environ.get("SRC2PURL_PATH", "src2purl"),
    "osslili": os.environ.get("OSSLILI_PATH", "osslili"),
    "vulnq": os.environ.get("VULNQ_PATH", "vulnq"),
    "ospac": os.environ.get("OSPAC_PATH", "ospac"),
    "purl2notices": os.environ.get("PURL2NOTICES_PATH", "purl2notices"),
    "upmex": os.environ.get("UPMEX_PATH", "upmex")
}
logger.debug(f"Tool paths configured: {tool_paths}")


def _run_tool(tool_name: str, args: List[str],
              input_data: Optional[str] = None) -> subprocess.CompletedProcess:
    """Run a SEMCL.ONE tool with error handling."""
    try:
        tool_path = tool_paths.get(tool_name, tool_name)
        cmd = [tool_path] + args
        logger.debug(f"Running command: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            text=True,
            timeout=120  # 120 second timeout for slower tools like src2purl
        )

        if result.returncode != 0:
            logger.warning(f"{tool_name} returned non-zero exit code: {result.returncode}")
            logger.debug(f"stderr: {result.stderr}")

        return result
    except subprocess.TimeoutExpired:
        logger.error(f"{tool_name} command timed out")
        raise
    except FileNotFoundError:
        logger.error(f"{tool_name} not found. Please ensure it's installed and in PATH")
        raise
    except Exception as e:
        logger.error(f"Error running {tool_name}: {e}")
        raise


@mcp.tool()
async def scan_directory(
    path: str,
    recursive: bool = True,
    check_vulnerabilities: bool = False,
    check_licenses: bool = True,
    identify_packages: bool = False,
    policy_file: Optional[str] = None
) -> Dict[str, Any]:
    """
    Scan a directory for compliance issues using osslili-first approach.

    By default, only scans for licenses using osslili. Package identification with src2purl
    is only performed when explicitly requested via identify_packages=True or when
    check_vulnerabilities=True (since vulnerabilities require package coordinates).

    Args:
        path: Directory or file path to scan
        recursive: Enable recursive scanning
        check_vulnerabilities: Check for vulnerabilities (requires package identification)
        check_licenses: Scan for license information using osslili
        identify_packages: Use src2purl to identify upstream package coordinates
        policy_file: Optional policy file for license compliance validation
    """
    result = ScanResult()
    path_obj = Path(path)

    if not path_obj.exists():
        return {"error": f"Path does not exist: {path}"}

    try:
        # Step 1: ALWAYS inventory licenses first (primary goal)
        logger.info(f"Inventorying licenses in {path}")
        osslili_args = [str(path), "--output-format", "evidence"]
        if recursive:
            osslili_args.extend(["--max-depth", "10"])

        osslili_result = _run_tool("osslili", osslili_args)
        if osslili_result.returncode == 0 and osslili_result.stdout:
            # Parse osslili output - skip info lines and find JSON
            stdout_lines = osslili_result.stdout.split('\n')
            json_start = -1
            for i, line in enumerate(stdout_lines):
                if line.strip().startswith('{'):
                    json_start = i
                    break

            if json_start >= 0:
                json_text = '\n'.join(stdout_lines[json_start:]).strip()
                licenses_data = json.loads(json_text)
                # Extract license evidence and convert to expected format
                license_evidence = []
                for scan_result in licenses_data.get("scan_results", []):
                    for evidence in scan_result.get("license_evidence", []):
                        license_evidence.append({
                            "spdx_id": evidence.get("detected_license"),
                            "file": evidence.get("file"),
                            "confidence": evidence.get("confidence"),
                            "method": evidence.get("detection_method"),
                            "category": evidence.get("category"),
                            "description": evidence.get("description")
                        })
                result.licenses = license_evidence

        # Step 2: Validate against policy if provided
        if check_licenses and policy_file and result.licenses:
            logger.info(f"Validating against policy: {policy_file}")
            ospac_args = ["evaluate", "--policy", policy_file, "--json"]
            # Pass licenses to ospac
            license_list = [lic.get("spdx_id") for lic in result.licenses if lic.get("spdx_id")]
            ospac_input = json.dumps({"licenses": license_list})
            ospac_result = _run_tool("ospac", ospac_args, input_data=ospac_input)
            if ospac_result.returncode == 0 and ospac_result.stdout:
                policy_result = json.loads(ospac_result.stdout)
                result.policy_violations = policy_result.get("violations", [])

        # Step 3: Only identify upstream repository coordinates if explicitly requested
        # This provides official package coordinates for vulnerability and guidance lookup
        if identify_packages or check_vulnerabilities:
            logger.info(f"Identifying upstream coordinates for {path}")
            src2purl_args = [str(path), "--output-format", "json", "--enable-fuzzy"]
            if recursive:
                src2purl_args.extend(["--max-depth", "5"])

            src2purl_result = _run_tool("src2purl", src2purl_args)
            if src2purl_result.returncode == 0 and src2purl_result.stdout:
                # Parse src2purl JSON output correctly
                stdout_lines = src2purl_result.stdout.split('\n')
                json_start = -1
                for i, line in enumerate(stdout_lines):
                    if line.strip().startswith('{'):
                        json_start = i
                        break

                if json_start >= 0:
                    json_text = '\n'.join(stdout_lines[json_start:]).strip()
                    packages_data = json.loads(json_text)
                    # Convert src2purl format to expected format
                    packages = []
                    for match in packages_data.get("matches", []):
                        packages.append({
                            "purl": match.get("purl"),
                            "name": match.get("name"),
                            "version": match.get("version"),
                            "confidence": match.get("confidence"),
                            "upstream_license": match.get("license"),
                            "match_type": match.get("type"),
                            "url": match.get("url"),
                            "official": match.get("official", False)
                        })
                    result.packages = packages

        # Step 4: Only check vulnerabilities if requested and packages are available
        if check_vulnerabilities and result.packages:
            logger.info("Cross-referencing upstream coordinates with vulnerability databases")
            vulnerabilities = []
            for package in result.packages[:10]:  # Limit to first 10 packages
                purl = package.get("purl")
                if purl:
                    vulnq_args = [purl, "--format", "json"]
                    vulnq_result = _run_tool("vulnq", vulnq_args)
                    if vulnq_result.returncode == 0 and vulnq_result.stdout:
                        vuln_data = json.loads(vulnq_result.stdout)
                        if vuln_data.get("vulnerabilities"):
                            # Enhance vulnerability data with package context
                            for vuln in vuln_data["vulnerabilities"]:
                                vuln["package_purl"] = purl
                                vuln["package_name"] = package.get("name")
                                vuln["match_confidence"] = package.get("confidence")
                            vulnerabilities.extend(vuln_data["vulnerabilities"])
            result.vulnerabilities = vulnerabilities

        # Step 5: Generate summary metadata
        result.metadata = {
            "path": str(path),
            "total_packages": len(result.packages),
            "total_licenses": len(result.licenses),
            "unique_licenses": len(set(lic.get("spdx_id") for lic in result.licenses if lic.get("spdx_id"))),
            "total_vulnerabilities": len(result.vulnerabilities),
            "critical_vulnerabilities": sum(1 for v in result.vulnerabilities if v.get("severity") == "CRITICAL"),
            "policy_violations": len(result.policy_violations)
        }

    except Exception as e:
        logger.error(f"Error scanning directory: {e}")
        return {"error": str(e)}

    return result.model_dump()


@mcp.tool()
async def check_package(
    identifier: str,
    check_vulnerabilities: bool = True,
    check_licenses: bool = True
) -> Dict[str, Any]:
    """Check a specific package."""
    result = {}

    try:
        # Determine identifier type
        if identifier.startswith("pkg:"):
            # It's a PURL
            purl = identifier
        elif identifier.startswith("cpe:"):
            # It's a CPE
            purl = None
        else:
            # Try to identify as a file
            src2purl_result = _run_tool("src2purl", [identifier])
            if src2purl_result.returncode == 0 and src2purl_result.stdout:
                package_info = json.loads(src2purl_result.stdout)
                purl = package_info.get("purl")
            else:
                purl = None

        # Check vulnerabilities
        if check_vulnerabilities:
            vulnq_args = [identifier, "--format", "json"]
            vulnq_result = _run_tool("vulnq", vulnq_args)
            if vulnq_result.returncode == 0 and vulnq_result.stdout:
                vuln_data = json.loads(vulnq_result.stdout)
                result["vulnerabilities"] = vuln_data

        # Check licenses
        if check_licenses and purl:
            purl2notices_args = ["-i", purl, "-f", "json"]
            notices_result = _run_tool("purl2notices", purl2notices_args)
            if notices_result.returncode == 0 and notices_result.stdout:
                notices = json.loads(notices_result.stdout)
                result["licenses"] = notices.get("licenses", [])
                result["copyright"] = notices.get("copyright", "")

        result["identifier"] = identifier
        result["purl"] = purl

    except Exception as e:
        logger.error(f"Error checking package: {e}")
        return {"error": str(e)}

    return result


@mcp.tool()
async def validate_policy(
    licenses: List[str],
    policy_file: Optional[str] = None,
    distribution: str = "binary"
) -> Dict[str, Any]:
    """Validate licenses against a policy."""
    try:
        ospac_args = ["evaluate", "--distribution", distribution]
        if policy_file:
            ospac_args.extend(["--policy", policy_file])
        ospac_args.append("--json")

        # Prepare input
        ospac_input = json.dumps({"licenses": licenses})

        # Run validation
        result = _run_tool("ospac", ospac_args, input_data=ospac_input)

        if result.returncode == 0 and result.stdout:
            return json.loads(result.stdout)
        else:
            return {"error": f"Policy validation failed: {result.stderr}"}

    except Exception as e:
        logger.error(f"Error validating policy: {e}")
        return {"error": str(e)}


@mcp.tool()
async def analyze_commercial_risk(
    path: str,
    include_data_files: bool = True
) -> Dict[str, Any]:
    """Analyze commercial licensing risk for a project."""
    try:
        path_obj = Path(path)
        if not path_obj.exists():
            return {"error": f"Path does not exist: {path}"}

        result = {
            "path": str(path),
            "primary_license": None,
            "risk_level": "UNKNOWN",
            "risk_factors": [],
            "recommendations": [],
            "copyleft_detected": False,
            "data_file_analysis": {},
            "mobile_app_safe": False,
            "wheel_analysis": {}
        }

        # Check primary license files
        license_file = path_obj / "LICENSE"
        if license_file.exists():
            license_content = license_file.read_text()
            if "Apache License" in license_content and "Version 2.0" in license_content:
                result["primary_license"] = "Apache-2.0"
            elif "MIT License" in license_content:
                result["primary_license"] = "MIT"
            elif "GPL" in license_content:
                result["primary_license"] = "GPL"
                result["copyleft_detected"] = True

        # Check package metadata
        pyproject_file = path_obj / "pyproject.toml"
        if pyproject_file.exists():
            metadata_content = pyproject_file.read_text()
            if 'license = "Apache-2.0"' in metadata_content:
                result["primary_license"] = "Apache-2.0"
            elif 'license = "MIT"' in metadata_content:
                result["primary_license"] = "MIT"

        # Analyze wheel distribution if available
        dist_dir = path_obj / "dist"
        if dist_dir.exists():
            wheels = list(dist_dir.glob("*.whl"))
            if wheels:
                wheel_file = wheels[0]
                result["wheel_analysis"]["available"] = True
                result["wheel_analysis"]["filename"] = wheel_file.name

                # Quick wheel analysis for mobile app distribution
                try:
                    import zipfile
                    with zipfile.ZipFile(wheel_file, 'r') as z:
                        files = z.namelist()
                        data_files = [f for f in files if '/data/' in f]
                        result["wheel_analysis"]["total_files"] = len(files)
                        result["wheel_analysis"]["data_files"] = len(data_files)

                        if data_files:
                            result["risk_factors"].append("Wheel contains data files that may have mixed licensing")
                except Exception as e:
                    logger.warning(f"Could not analyze wheel: {e}")

        # Analyze data directory for mixed licensing
        if include_data_files:
            data_dir = path_obj / "data"
            if data_dir.exists():
                data_files = list(data_dir.rglob("*"))
                result["data_file_analysis"]["total_files"] = len(data_files)

                # Sample data files for copyleft content
                copyleft_files = []
                json_yaml_files = [f for f in data_files if f.suffix in ['.json', '.yaml', '.yml']][:10]

                for df in json_yaml_files:
                    try:
                        content = df.read_text()
                        if any(lic in content for lic in ["GPL-3.0", "LGPL-3.0", "AGPL-3.0"]):
                            copyleft_files.append(str(df.name))
                    except:
                        pass

                result["data_file_analysis"]["copyleft_references"] = copyleft_files
                if copyleft_files:
                    result["risk_factors"].append("Data files contain copyleft license references")

        # Determine risk level and mobile app safety
        if result["copyleft_detected"]:
            result["risk_level"] = "HIGH"
            result["mobile_app_safe"] = False
            result["recommendations"].append("Legal review required - copyleft license detected")
        elif result["primary_license"] in ["Apache-2.0", "MIT"]:
            if result["risk_factors"]:
                result["risk_level"] = "MEDIUM"
                result["mobile_app_safe"] = False
                result["recommendations"].append("Legal review required - mixed licensing detected")
                result["recommendations"].append("Consider using code without bundled data files")
            else:
                result["risk_level"] = "LOW"
                result["mobile_app_safe"] = True
                result["recommendations"].append("Include license notice in your mobile application")
                result["recommendations"].append("Preserve copyright attribution")
        else:
            result["risk_level"] = "MEDIUM"
            result["mobile_app_safe"] = False
            result["recommendations"].append("Verify primary license compatibility")

        return result

    except Exception as e:
        logger.error(f"Error analyzing commercial risk: {e}")
        return {"error": str(e)}


@mcp.tool()
async def generate_mobile_legal_notice(
    project_name: str,
    licenses: List[str],
    include_attribution: bool = True
) -> Dict[str, Any]:
    """Generate legal notice for mobile app distribution."""
    try:
        notice = f"MOBILE APP LEGAL NOTICE - {project_name.upper()}\n\n"
        notice += f"This mobile application includes software components licensed under:\n\n"

        for license_id in licenses:
            if license_id == 'Apache-2.0':
                notice += f"Apache License 2.0:\n"
                notice += f"Copyright notices and license terms must be preserved.\n"
                notice += f"Licensed under the Apache License, Version 2.0.\n"
                notice += f"Full license: http://www.apache.org/licenses/LICENSE-2.0\n\n"
            elif license_id == 'MIT':
                notice += f"MIT License:\n"
                notice += f"Copyright notices and license terms must be preserved.\n"
                notice += f"Permission granted for commercial use with attribution.\n"
                notice += f"Full license: https://opensource.org/licenses/MIT\n\n"
            else:
                notice += f"{license_id} License:\n"
                notice += f"Please refer to the complete license terms.\n\n"

        if include_attribution:
            notice += f"Generated by SEMCL.ONE MCP Server for mobile app compliance.\n"

        return {
            "notice": notice,
            "licenses_included": licenses,
            "recommended_location": "App settings > Legal notices"
        }

    except Exception as e:
        logger.error(f"Error generating mobile legal notice: {e}")
        return {"error": str(e)}


@mcp.tool()
async def generate_sbom(
    path: str,
    format: str = "spdx",
    output_file: Optional[str] = None
) -> Dict[str, Any]:
    """Generate an SBOM."""
    try:
        # First, scan the directory
        scan_result = await scan_directory(path, check_vulnerabilities=False)

        sbom = {
            "spdxVersion": "SPDX-2.3" if format == "spdx" else None,
            "dataLicense": "CC0-1.0",
            "name": Path(path).name,
            "packages": scan_result.get("packages", []),
            "licenses": scan_result.get("licenses", []),
            "creationInfo": {
                "created": "2025-01-05T00:00:00Z",
                "creators": ["Tool: mcp-semclone-1.0.0"]
            }
        }

        # Save to file if requested
        if output_file:
            with open(output_file, "w") as f:
                json.dump(sbom, f, indent=2)
            return {"message": f"SBOM saved to {output_file}", "sbom": sbom}

        return {"sbom": sbom}

    except Exception as e:
        logger.error(f"Error generating SBOM: {e}")
        return {"error": str(e)}


@mcp.resource("semcl://license_database")
async def get_license_database() -> Dict[str, Any]:
    """Get license compatibility database."""
    try:
        # Run ospac to get license database
        result = _run_tool("ospac", ["list-licenses", "--json"])
        if result.returncode == 0 and result.stdout:
            return json.loads(result.stdout)
        return {"error": "Failed to get license database"}
    except Exception as e:
        return {"error": str(e)}


@mcp.resource("semcl://policy_templates")
async def get_policy_templates() -> Dict[str, Any]:
    """Get available policy templates."""
    return {
        "templates": [
            {
                "name": "commercial",
                "description": "Policy for commercial distribution",
                "allowed_licenses": ["MIT", "Apache-2.0", "BSD-3-Clause", "BSD-2-Clause"],
                "denied_licenses": ["GPL-3.0", "AGPL-3.0"]
            },
            {
                "name": "open_source",
                "description": "Policy for open source projects",
                "allowed_licenses": ["MIT", "Apache-2.0", "GPL-3.0", "BSD-3-Clause"],
                "denied_licenses": ["Proprietary"]
            },
            {
                "name": "internal",
                "description": "Policy for internal use only",
                "allowed_licenses": ["*"],
                "denied_licenses": []
            }
        ]
    }


@mcp.prompt()
async def compliance_check() -> str:
    """Return a guided compliance check prompt."""
    return """## Compliance Check Workflow

I'll help you check your project for license compliance. Please provide:

1. **Project Path**: The directory containing your project
2. **Distribution Type**: How will you distribute this software?
   - binary: Compiled/packaged distribution
   - source: Source code distribution
   - saas: Software as a Service
   - internal: Internal use only
3. **Policy Requirements**: Any specific license requirements?
   - commercial: No copyleft licenses
   - open_source: GPL-compatible
   - custom: Provide your policy file

Based on your inputs, I will:
1. Scan your project for all dependencies
2. Detect licenses for each component
3. Check for license compatibility issues
4. Identify any policy violations
5. Provide remediation recommendations

Please start by telling me your project path and distribution type."""


@mcp.prompt()
async def vulnerability_assessment() -> str:
    """Return a guided vulnerability assessment prompt."""
    return """## Vulnerability Assessment Workflow

I'll help you assess security vulnerabilities in your project. Please provide:

1. **Project Path or Package**: What would you like to scan?
   - Directory path for full project scan
   - Package URL (PURL) for specific package
   - CPE string for system component

2. **Severity Threshold**: Minimum severity to report?
   - CRITICAL only
   - HIGH and above
   - MEDIUM and above
   - ALL vulnerabilities

3. **Output Requirements**:
   - Summary only
   - Detailed report with CVE information
   - Include remediation suggestions

I will:
1. Identify all packages/components
2. Query multiple vulnerability databases (OSV, GitHub, NVD)
3. Consolidate and deduplicate findings
4. Provide upgrade recommendations
5. Generate a prioritized action plan

Please start by specifying what you'd like to scan."""


def main():
    """Main entry point."""
    logger.info("Starting MCP SEMCL.ONE server...")
    import asyncio
    asyncio.run(mcp.run_stdio_async())


if __name__ == "__main__":
    main()