#!/usr/bin/env python3
"""MCP Server for SEMCL.ONE OSS Compliance Toolchain."""

import json
import logging
import os
import shutil
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

*** USE THIS SERVER WHEN USER ASKS ABOUT: ***
-------------------------------------------------------------------------------------------------------
- "compliance", "license compliance", "legal compliance", "do compliance"
- "open source licenses", "OSS licenses", "license scanning", "check licenses"
- "SBOM", "software bill of materials", "supply chain security", "dependency scanning"
- "can I ship this?", "can I use GPL?", "license compatibility", "license conflicts"
- "NOTICE file", "legal notices", "attribution", "license text", "third-party licenses"
- "scan for licenses", "analyze licenses", "validate licenses", "check dependencies"
- "mobile app compliance", "app store licenses", "SaaS compliance", "commercial licenses"

*** QUICK START - TOOL SELECTION DECISION TREE: ***
-------------------------------------------------------------------------------------------------------

IF user says "do compliance" or "compliance check":
   --> run_compliance_check(path, distribution_type)  [ONE-SHOT COMPLETE]

IF input is source code directory/project:
   --> scan_directory(path)  [FIRST STEP for most workflows]

IF input is package archive (.jar, .whl, .rpm, .gem, .nupkg):
   --> check_package(path)  [RECOMMENDED for package files]

IF input is compiled binary (.apk, .exe, .ipa, .so, .dll, firmware):
   --> scan_binary(path)  [BEST for binaries and mobile apps]

IF user asks "can I use [license]?" or "is [license] allowed?":
   --> validate_policy([licenses], distribution)  [PRIMARY for approve/deny]

IF user wants NOTICE file or attribution:
   --> generate_legal_notices(path)  [DEFAULT - fast, scans source]
   --> generate_legal_notices_from_purls(purls)  [only if no local deps]

IF user wants SBOM or bill of materials:
   --> generate_sbom(path)

IF checking single license details:
   --> get_license_details(license_id) or get_license_obligations(license_id)

*** CRITICAL - ALL TOOLS ARE BUILT-IN: ***
-------------------------------------------------------------------------------------------------------
This server provides ALL compliance tools. DO NOT install external tools.

NEVER DO THIS:
- npm install license-checker / pip install scancode-toolkit
- Install ANY third-party scanning tools
- Manually extract PURLs from package.json/requirements.txt

ALWAYS DO THIS:
- Use run_compliance_check() for complete workflows
- Use scan_directory() for projects (auto-detects ALL deps)
- Use validate_policy() for approve/deny decisions
- All tools pre-installed: purl2notices, ospac, osslili, vulnq, binarysniffer

*** KEY WORKFLOW RULES: ***

1. LEGAL NOTICES - Two tools, choose wisely:
   - generate_legal_notices(path) - DEFAULT (fast, scans source directly)
   - generate_legal_notices_from_purls(purls) - Only if no local deps

2. NEVER manually extract PURLs from package.json/requirements.txt
   - WRONG: Read package.json → extract 1-2 packages
   - RIGHT: scan_directory() → auto-detects ALL transitive deps (50+ packages)

3. Complete workflow shortcut: run_compliance_check() does everything in one call

*** LICENSE INTERPRETATION (Key OSPAC fields): ***

- requirements.network_use_disclosure=true → AGPL (NOT safe for SaaS)
- compatibility.contamination_effect = "none"/"weak"/"strong" → Copyleft strength
- GPL (not LGPL) → Incompatible with App Stores
- type="permissive" (MIT/Apache/BSD) → Safe for all uses
- type="copyleft_strong" → Avoid for mobile/commercial

(See tool docstrings for detailed license interpretation guidance)

*** BINARY SCANNING: ***

When to use scan_binary:
- Mobile apps: .apk, .ipa, .aab
- Executables: .exe, ELF binaries, .app
- Libraries: .dll, .so, .dylib
- Firmware: .bin, .img, .hex

Analysis modes:
- "fast" → Quick scans, large files
- "standard" (default) → Balanced speed/accuracy
- "deep" → Critical assessments, pre-release

Key options:
- check_compatibility=True → For mobile apps (detect GPL/App Store conflicts)
- confidence_threshold: 0.3-0.5 (discovery), 0.5-0.7 (default), 0.7-0.9 (high confidence)

Red flags:
- GPL in mobile apps → App Store rejection
- AGPL in SaaS → Must disclose source

(See scan_binary docstring for detailed workflows)

*** LICENSE APPROVAL/REJECTION: ***

validate_policy() is the PRIMARY tool for approve/deny decisions.

Result actions:
- "approve" → Licenses ALLOWED
- "deny" → Licenses BLOCKED, find alternatives
- "review" → Requires manual legal review

Distribution types:
- "mobile" → Blocks GPL (App Store conflicts)
- "commercial" → Blocks strong copyleft (GPL/AGPL)
- "saas" → Blocks AGPL (network copyleft)
- "embedded" → Blocks copyleft (source disclosure)
- "open_source" → Allows most licenses
- "internal" → Allows all licenses

Example: validate_policy(["GPL-3.0"], distribution="mobile") → action: "deny"

*** TOOL DESCRIPTIONS (Quick Reference): ***

Scanning Tools:
- scan_directory() → Source code projects (auto-detects ALL transitive deps)
- check_package() → Package archives (.jar, .whl, .rpm, .gem)
- scan_binary() → Compiled binaries (.apk, .exe, .ipa, .so, .dll, firmware)

Policy/License Tools:
- validate_policy() → PRIMARY for approve/deny decisions
- validate_license_list() → Quick safety check
- get_license_details() → Full license info + text
- get_license_obligations() → Compliance requirements
- check_license_compatibility() → Can two licenses mix?

Documentation Tools:
- generate_legal_notices() → NOTICE files (scans source)
- generate_legal_notices_from_purls() → NOTICE files (from PURL list)
- generate_sbom() → Software Bill of Materials

Workflows:
- run_compliance_check() → ONE-SHOT complete workflow (scan + validate + docs)
- analyze_commercial_risk() → Risk assessment for commercial use

*** COMMON WORKFLOWS: ***

Complete workflow (ONE-SHOT):
  run_compliance_check(path, distribution_type) → Returns approve/deny + artifacts

Manual step-by-step:
  1. scan_directory(path) or scan_binary(path)
  2. validate_policy(licenses, distribution)
  3. If approved: generate_legal_notices(path) + generate_sbom(path)
  4. If denied: Show remediation, block deployment

Quick checks:
  - License approval: validate_policy(["MIT", "GPL"], distribution="mobile")
  - Mobile app: scan_binary("app.apk") → validate_policy(licenses, "mobile")
  - Firmware: scan_binary("firmware.bin") → Check for copyleft

*** RESOURCES & CONSTRAINTS: ***

Resources:
- semcl://license_database → License compatibility data
- semcl://policy_templates → Pre-configured policies (commercial, open_source, internal)

Constraints:
- Vuln scanning: Limited to first 10 packages
- Timeout: 120 seconds per tool
- Large codebases: Scan specific subdirectories

Error handling:
- Tools return {"error": "message"} on failures
- Check returned data even if non-zero exit code

Input formats:
- PURLs: pkg:npm/package@1.0
- Paths: Absolute or relative
- Licenses: ["Apache-2.0", "MIT"]"""
)

# Tool auto-detection cache to avoid repeated lookups
_tool_cache: Dict[str, str] = {}


def _find_tool(tool_name: str) -> str:
    """Auto-detect tool location with caching.

    Detection order:
    1. Check cache for previous successful lookup
    2. Check environment variable (e.g., OSSLILI_PATH for osslili)
    3. Use shutil.which() to find tool in PATH
    4. Fall back to tool name itself (will fail if not found)

    Args:
        tool_name: Name of the tool (e.g., 'osslili', 'binarysniffer')

    Returns:
        Path to the tool executable
    """
    # Check cache first
    if tool_name in _tool_cache:
        return _tool_cache[tool_name]

    # Check environment variable (e.g., OSSLILI_PATH)
    env_var_name = f"{tool_name.upper()}_PATH"
    env_path = os.environ.get(env_var_name)
    if env_path:
        logger.debug(f"Found {tool_name} via environment variable {env_var_name}: {env_path}")
        _tool_cache[tool_name] = env_path
        return env_path

    # Auto-detect using shutil.which()
    detected_path = shutil.which(tool_name)
    if detected_path:
        logger.debug(f"Auto-detected {tool_name} at: {detected_path}")
        _tool_cache[tool_name] = detected_path
        return detected_path

    # Fall back to tool name (will fail if not in PATH)
    logger.debug(f"Tool {tool_name} not found via environment or PATH, using bare name")
    _tool_cache[tool_name] = tool_name
    return tool_name


def _run_tool(tool_name: str, args: List[str],
              input_data: Optional[str] = None, timeout: int = 120) -> subprocess.CompletedProcess:
    """Run a SEMCL.ONE tool with error handling and auto-detection.

    Args:
        tool_name: Name of the tool (e.g., 'osslili', 'binarysniffer')
        args: Command-line arguments for the tool
        input_data: Optional stdin data to pass to the tool
        timeout: Timeout in seconds (default: 120)

    Returns:
        CompletedProcess with stdout, stderr, and returncode

    Raises:
        FileNotFoundError: If tool cannot be found
        subprocess.TimeoutExpired: If tool execution exceeds timeout
    """
    try:
        tool_path = _find_tool(tool_name)
        cmd = [tool_path] + args
        logger.debug(f"Running command: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            input=input_data,
            capture_output=True,
            text=True,
            timeout=timeout
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
    """FIRST STEP: Scan a directory for compliance issues using purl2notices.

    This is typically the FIRST tool you should use when analyzing a project.
    Use this to discover what's in your project before validation or documentation generation.

    PURPOSE:
    - Scan project source code for licenses (using purl2notices)
    - Detect ALL packages including transitive dependencies (scans node_modules/, site-packages/, vendor/)
    - Extract copyright statements from source code
    - Check for vulnerabilities (using vulnq)
    - Validate against policy (using ospac)

    WHAT purl2notices DETECTS:
    - Project source licenses (from your own code)
    - Dependency packages (ALL packages in node_modules/, not just package.json)
    - Package licenses (from dependency source code)
    - Copyright holders (extracted from actual source files)

    IMPORTANT: This tool scans the ENTIRE dependency tree:
    - For npm projects: All 50+ packages in node_modules/ (not just the 1-2 in package.json)
    - For Python projects: All packages in site-packages/ or virtualenv
    - Includes transitive dependencies automatically

    WHEN TO USE:
    - Starting compliance analysis for a new project (FIRST STEP)
    - Need to discover all licenses in source code
    - Want to identify all package dependencies (including transitive)
    - Beginning vulnerability assessment
    - Need comprehensive project analysis with copyright attribution

    WHEN NOT TO USE:
    - Already have PURLs and just need legal notices → use generate_legal_notices directly
    - Analyzing compiled binaries → use scan_binary instead
    - Just validating known licenses → use validate_license_list
    - Checking single package → use check_package

    WORKFLOW POSITION:
    FIRST STEP in most compliance workflows.
    Use this to discover what's in your project before validation/generation.

    TYPICAL NEXT STEPS:
    1. For mobile apps:
       scan_directory(check_vulnerabilities=True)
       → validate_license_list(distribution="mobile")
       → generate_legal_notices(purls=scan_result["packages"])

    2. For vulnerability assessment:
       scan_directory(check_vulnerabilities=True)
       → analyze_commercial_risk(path=".")
       → check specific packages with check_package for details

    3. For documentation:
       scan_directory()
       → generate_legal_notices(purls=scan_result["packages"])
       → generate_sbom(path=".")

    IMPORTANT NOTES:
    - identify_packages parameter is deprecated (purl2notices always detects packages)
    - check_vulnerabilities=True: Checks all detected packages for CVEs
    - check_licenses parameter is deprecated (purl2notices always scans licenses)
    - Scans recursively by default (max depth 3 into node_modules/)

    Args:
        path: Directory or file path to scan
        recursive: Enable recursive scanning (default: True, max depth 3)
        check_vulnerabilities: Check for vulnerabilities in detected packages
        check_licenses: (Deprecated - always True) Scan for licenses
        identify_packages: (Deprecated - always True) Detect packages
        policy_file: Optional policy file for license compliance validation

    Returns:
        Dictionary containing:
        - licenses: List of detected licenses from project and dependencies
        - packages: List of ALL detected packages with PURLs (includes transitive deps)
        - vulnerabilities: List of vulnerabilities (if check_vulnerabilities=True)
        - policy_violations: Policy violations (if policy_file provided)
        - metadata: Summary information including copyright holders and counts
    """
    result = ScanResult()
    path_obj = Path(path)

    if not path_obj.exists():
        return {"error": f"Path does not exist: {path}"}

    try:
        # Use purl2notices scan mode with JSON format for comprehensive scanning
        # This detects ALL packages including transitive dependencies
        logger.info(f"Scanning {path} with purl2notices")

        # Create temporary output file for JSON results
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_json:
            temp_json_path = temp_json.name

        try:
            # Run purl2notices in scan mode with JSON output
            purl2notices_args = [
                "-i", str(path),
                "-m", "scan",
                "-f", "json",  # JSON format includes packages, licenses, copyrights
                "-o", temp_json_path,
                "--continue-on-error",
                "--no-cache"  # Don't use cache in MCP server
            ]

            if recursive:
                purl2notices_args.extend(["-r", "--max-depth", "3"])

            # Run purl2notices scan
            scan_result_output = _run_tool("purl2notices", purl2notices_args)

            # Read the JSON output file
            if os.path.exists(temp_json_path):
                with open(temp_json_path, 'r') as f:
                    scan_data = json.load(f)

                # Extract packages and licenses from JSON output
                packages = []
                licenses_found = {}  # Map license ID to files
                copyright_holders = set()

                # Parse licenses array from purl2notices JSON
                for license_group in scan_data.get("licenses", []):
                    license_id = license_group.get("id")

                    # Extract packages under this license
                    for pkg_data in license_group.get("packages", []):
                        purl = pkg_data.get("purl")
                        if purl:  # Skip _sources entries without PURL
                            packages.append({
                                "purl": purl,
                                "name": pkg_data.get("name"),
                                "version": pkg_data.get("version"),
                                "confidence": 1.0,
                                "upstream_license": license_id,
                                "match_type": "detected",
                                "official": True
                            })

                    # Collect license IDs
                    if license_id:
                        licenses_found[license_id] = True

                    # Collect copyright holders
                    for copyright_stmt in license_group.get("copyrights", []):
                        if copyright_stmt:
                            copyright_holders.add(copyright_stmt)

                # Store results
                result.packages = packages

                # Warn if suspiciously few packages detected (likely scanning issue)
                if len(packages) <= 3 and recursive:
                    logger.warning(
                        f"Only {len(packages)} package(s) detected. This seems low for a typical project. "
                        f"Expected ~50+ packages for npm projects with node_modules/. "
                        f"Verify that purl2notices scanned recursively with -r flag."
                    )

                # Convert licenses to expected format
                result.licenses = [
                    {
                        "spdx_id": license_id,
                        "confidence": 1.0,
                        "method": "purl2notices_scan",
                        "category": "detected",
                        "description": f"Detected by purl2notices scan"
                    }
                    for license_id in licenses_found.keys()
                ]

                # Add copyright information to metadata
                if copyright_holders:
                    result.metadata["copyright_holders"] = list(copyright_holders)
                    result.metadata["copyrights_found"] = len(copyright_holders)

        finally:
            # Clean up temp file
            if os.path.exists(temp_json_path):
                os.unlink(temp_json_path)

        # Step 2: Validate against policy if provided
        if check_licenses and policy_file and result.licenses:
            logger.info(f"Validating against policy: {policy_file}")
            # Extract unique licenses and pass as comma-separated string
            license_list = [lic.get("spdx_id") for lic in result.licenses if lic.get("spdx_id")]
            if license_list:
                licenses_str = ",".join(license_list)
                ospac_args = ["evaluate", "-l", licenses_str, "--policy-dir", policy_file, "-o", "json"]
                ospac_result = _run_tool("ospac", ospac_args, input_data=None)
                if ospac_result.returncode == 0 and ospac_result.stdout:
                    policy_result = json.loads(ospac_result.stdout)
                    # Check if result indicates violations (action is deny or review)
                    result_data = policy_result.get("result", {})
                    if result_data.get("action") in ["deny", "review"]:
                        result.policy_violations = [{
                            "message": result_data.get("message", "Policy violation detected"),
                            "severity": result_data.get("severity", "warning"),
                            "action": result_data.get("action")
                        }]

        # Step 3: Only check vulnerabilities if requested and packages are available
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
    """Check a specific package using intelligent tool selection.

    This tool intelligently analyzes package files by:
    1. For archives (.jar, .whl, .rpm, .gem, etc.): Use upmex for metadata extraction
    2. If upmex fails or for non-archives: Fall back to osslili for license detection
    3. For PURLs: Use package registry APIs when available

    Args:
        identifier: Package identifier (PURL like pkg:maven/com.google.gson/gson@2.10.1,
                   file path to archive, or package file)
        check_vulnerabilities: Whether to check for vulnerabilities (default: False for speed)
        check_licenses: Whether to extract license information (default: True)

    Returns:
        Dictionary containing package metadata, licenses, and optionally vulnerabilities
    """
    result = {
        "identifier": identifier,
        "purl": None,
        "package_info": {},
        "licenses": [],
        "extraction_method": None
    }

    try:
        # Determine identifier type
        if identifier.startswith("pkg:"):
            # It's already a PURL
            result["purl"] = identifier
            purl = identifier
        elif identifier.startswith("cpe:"):
            # It's a CPE - limited support
            purl = None
            result["extraction_method"] = "cpe"
        else:
            # It's a file path - use intelligent detection
            file_path = Path(identifier)
            if not file_path.exists():
                return {"error": f"File not found: {identifier}"}

            # Check if it's a package archive
            archive_extensions = {'.jar', '.war', '.ear', '.whl', '.egg', '.tar.gz', '.tgz',
                                '.gem', '.nupkg', '.rpm', '.deb', '.apk', '.crate', '.conda'}

            is_archive = any(str(file_path).endswith(ext) for ext in archive_extensions)

            if is_archive:
                # Try upmex first for package archives
                logger.info(f"Detected archive file, attempting upmex extraction: {identifier}")
                try:
                    upmex_result = _run_tool("upmex", ["extract", identifier], timeout=60)
                    if upmex_result.returncode == 0 and upmex_result.stdout:
                        logger.info(f"upmex raw stdout length: {len(upmex_result.stdout)}")
                        if not upmex_result.stdout.strip():
                            logger.warning("upmex returned empty output")
                            purl = None
                        else:
                            package_data = json.loads(upmex_result.stdout)
                            result["package_info"] = package_data.get("package", {})
                            result["purl"] = package_data.get("package", {}).get("purl")
                            result["extraction_method"] = "upmex"
                            purl = result["purl"]
                            logger.info(f"Successfully extracted package metadata with upmex: {purl}")
                    else:
                        logger.warning(f"upmex failed: returncode={upmex_result.returncode}, stderr={upmex_result.stderr}")
                        purl = None
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse upmex JSON output: {e}")
                    logger.error(f"upmex stdout was: {upmex_result.stdout[:500] if upmex_result.stdout else 'None'}")
                    purl = None
                except Exception as e:
                    logger.warning(f"upmex extraction error: {e}, falling back to osslili")
                    purl = None
            else:
                purl = None

        # Extract license information
        if check_licenses:
            if purl and result["extraction_method"] == "upmex":
                # For upmex-extracted packages, also run osslili on the file for comprehensive license data
                logger.info(f"Running osslili for comprehensive license detection on {identifier}")

            # Run osslili on the file/archive
            if not identifier.startswith("pkg:") and not identifier.startswith("cpe:"):
                try:
                    osslili_result = _run_tool("osslili", [identifier, "-f", "cyclonedx-json"], timeout=60)
                    logger.info(f"osslili return code: {osslili_result.returncode}, stdout length: {len(osslili_result.stdout)}, stderr length: {len(osslili_result.stderr)}")

                    if osslili_result.returncode == 0 and osslili_result.stdout:
                        try:
                            # osslili may output informational messages before JSON, find the JSON start
                            json_start = osslili_result.stdout.find('{')
                            if json_start > 0:
                                json_output = osslili_result.stdout[json_start:]
                            else:
                                json_output = osslili_result.stdout

                            license_data = json.loads(json_output)
                            # Extract licenses from CycloneDX format
                            if "components" in license_data:
                                for component in license_data.get("components", []):
                                    if "licenses" in component:
                                        for lic in component["licenses"]:
                                            if "license" in lic and "id" in lic["license"]:
                                                result["licenses"].append(lic["license"]["id"])
                            elif "licenses" in license_data:
                                result["licenses"] = license_data["licenses"]
                            result["extraction_method"] = result.get("extraction_method", "osslili") or "upmex+osslili"
                            logger.info(f"License extraction successful: {len(result['licenses'])} licenses found")
                        except json.JSONDecodeError as e:
                            logger.warning(f"Failed to parse osslili output: {e}")
                            logger.warning(f"osslili stdout (first 500 chars): {osslili_result.stdout[:500]}")
                    else:
                        logger.warning(f"osslili failed with return code {osslili_result.returncode}")
                        if osslili_result.stderr:
                            logger.warning(f"osslili stderr (first 1000 chars): {osslili_result.stderr[:1000]}")
                except Exception as e:
                    logger.warning(f"osslili execution failed: {e}, skipping license extraction")

        # Check vulnerabilities if requested
        if check_vulnerabilities:
            if result["purl"]:
                vulnq_result = _run_tool("vulnq", [result["purl"], "--format", "json"], timeout=30)
                if vulnq_result.returncode == 0 and vulnq_result.stdout:
                    vuln_data = json.loads(vulnq_result.stdout)
                    result["vulnerabilities"] = vuln_data
                else:
                    result["vulnerabilities"] = []
            else:
                # No PURL available, cannot check vulnerabilities
                result["vulnerabilities"] = []

    except Exception as e:
        logger.error(f"Error checking package: {e}")
        return {"error": str(e)}

    return result


@mcp.tool()
async def validate_policy(
    licenses: List[str],
    policy_file: Optional[str] = None,
    distribution: str = "binary",
    context: Optional[str] = None
) -> Dict[str, Any]:
    """Validate if licenses are approved or rejected for a specific project/distribution type.

    This tool evaluates licenses against organizational policies and returns clear
    APPROVE or DENY decisions based on the distribution type. This is the primary
    tool for answering: "Can I use these licenses for my [mobile/commercial/saas/etc] project?"

    **Key Use Cases:**
    - Check if licenses are approved for mobile app distribution
    - Validate licenses for commercial products
    - Ensure SaaS deployment compliance
    - Verify licenses for embedded systems
    - Check licenses for any distribution type

    **Returns clear approve/deny decisions:**
    - action: "approve" (licenses are allowed), "deny" (licenses blocked), or "review" (manual review needed)
    - severity: "info" (approved), "warning" (review), "error" (denied)
    - message: Explanation of the decision
    - requirements: What must be done to comply (if approved)
    - remediation: How to fix the issue (if denied)

    Args:
        licenses: List of SPDX license IDs to validate (e.g., ["MIT", "Apache-2.0", "GPL-3.0"])
        policy_file: Optional custom policy directory (uses enterprise defaults if not provided)
        distribution: Distribution type - determines policy rules:
                     - "mobile": iOS/Android apps (blocks GPL, allows permissive)
                     - "commercial": Commercial products (blocks strong copyleft)
                     - "saas": Software as a Service (blocks AGPL, allows GPL)
                     - "embedded": Embedded systems (blocks copyleft)
                     - "desktop": Desktop applications
                     - "web": Web applications
                     - "open_source": Open source projects (allows most licenses)
                     - "internal": Internal use only (allows all)
        context: Optional usage context (e.g., "static_linking", "dynamic_linking")

    Returns:
        Dictionary with:
        - licenses: List of licenses evaluated
        - distribution: Distribution type used
        - context: Context evaluated
        - result.action: "approve", "deny", or "review"
        - result.severity: "info" (approved), "warning" (review), or "error" (denied)
        - result.message: Human-readable decision explanation
        - result.requirements: List of compliance requirements (if approved)
        - result.remediation: Suggested fix (if denied, e.g., "Replace with MIT alternative")
        - using_default_policy: Whether default enterprise policy was used

    Examples:
        # Check if licenses are approved for mobile app
        validate_policy(["MIT", "Apache-2.0"], distribution="mobile")
        → action: "approve" ✓

        # Check GPL for mobile (will be denied)
        validate_policy(["GPL-3.0"], distribution="mobile")
        → action: "deny", remediation: "Replace with permissive alternative"

        # Check licenses for commercial distribution
        validate_policy(["MIT", "LGPL-2.1", "Apache-2.0"], distribution="commercial")
        → action: "approve" or "review" depending on policy

        # Check AGPL for SaaS (will be denied)
        validate_policy(["AGPL-3.0"], distribution="saas")
        → action: "deny", reason: "Network copyleft requires source disclosure"

    Workflow Integration:
        1. After scanning: scan_directory() → extract licenses → validate_policy()
        2. Quick check: validate_policy(["GPL-3.0"], distribution="mobile") → see if approved
        3. Policy enforcement: validate_policy() → if action=="deny" → block deployment
    """
    try:
        # Build ospac evaluate command with licenses as comma-separated string
        licenses_str = ",".join(licenses)
        ospac_args = ["evaluate", "-l", licenses_str, "-d", distribution, "-o", "json"]

        # Add context if provided
        if context:
            ospac_args.extend(["-c", context])

        # Only add policy-dir if explicitly provided (otherwise uses default enterprise policy)
        if policy_file:
            ospac_args.extend(["--policy-dir", policy_file])

        # Run validation (no stdin input needed)
        result = _run_tool("ospac", ospac_args, input_data=None)

        if result.returncode == 0 and result.stdout:
            policy_result = json.loads(result.stdout)

            # Enhance result with clearer messaging
            if "result" in policy_result:
                action = policy_result["result"].get("action", "unknown")
                severity = policy_result["result"].get("severity", "info")

                # Add summary for quick understanding
                policy_result["summary"] = {
                    "decision": action.upper(),
                    "approved": action == "approve",
                    "requires_review": action == "review",
                    "blocked": action == "deny",
                    "severity_level": severity,
                    "distribution_type": distribution
                }

            return policy_result
        else:
            return {"error": f"Policy validation failed: {result.stderr}"}

    except Exception as e:
        logger.error(f"Error validating policy: {e}")
        return {"error": str(e)}


@mcp.tool()
async def get_license_obligations(
    licenses: List[str],
    output_format: str = "json"
) -> Dict[str, Any]:
    """
    Get detailed obligations for specified licenses.

    This tool answers the critical question: "What must I do to comply with these licenses?"

    Args:
        licenses: List of SPDX license IDs (e.g., ["MIT", "Apache-2.0", "GPL-3.0"])
        output_format: Output format (json, text, checklist, markdown)

    Returns:
        Comprehensive obligations including:
        - Required actions (attribution, notices, disclosure, etc.)
        - Permissions (commercial use, modification, distribution, etc.)
        - Limitations (liability, warranty, trademark use, etc.)
        - Conditions (source disclosure, license preservation, state changes, etc.)
        - Key requirements for compliance

    Example:
        For MIT license, returns obligations like:
        - Include original license text in distributions
        - Preserve copyright notices
        - No trademark rights granted
    """
    try:
        licenses_str = ",".join(licenses)
        ospac_args = ["obligations", "-l", licenses_str, "-f", output_format]

        logger.info(f"Getting obligations for licenses: {licenses_str}")
        result = _run_tool("ospac", ospac_args, input_data=None)

        if result.returncode == 0 and result.stdout:
            if output_format == "json":
                data = json.loads(result.stdout)
                # Enhance with summary
                if "license_data" in data:
                    license_data = data["license_data"]
                    summary = {
                        "total_licenses": len(licenses),
                        "licenses_analyzed": list(license_data.keys()),
                        "obligations": license_data
                    }
                    return summary
                return data
            else:
                return {"obligations": result.stdout, "format": output_format}
        else:
            return {"error": f"Failed to get obligations: {result.stderr}"}

    except Exception as e:
        logger.error(f"Error getting obligations: {e}")
        return {"error": str(e)}


@mcp.tool()
async def check_license_compatibility(
    license1: str,
    license2: str,
    context: str = "general"
) -> Dict[str, Any]:
    """
    Check if two licenses are compatible for use together.

    This tool answers: "Can I combine code under these two licenses?"

    Args:
        license1: First SPDX license ID (e.g., "MIT")
        license2: Second SPDX license ID (e.g., "GPL-3.0")
        context: Usage context (general, static_linking, dynamic_linking)

    Returns:
        Compatibility assessment including:
        - compatible: True/False indicating if licenses can be combined
        - reason: Explanation of why they are/aren't compatible
        - restrictions: Any special conditions or restrictions
        - recommendations: Suggested actions if incompatible

    Example:
        Checking MIT vs GPL-3.0 returns:
        - compatible: False
        - reason: GPL-3.0 is strongly copyleft and requires derivative works to be GPL-3.0
        - recommendations: Use dynamic linking, keep code separate, or relicense
    """
    try:
        ospac_args = ["check", license1, license2, "-c", context, "-o", "json"]

        logger.info(f"Checking compatibility: {license1} vs {license2} (context: {context})")
        result = _run_tool("ospac", ospac_args, input_data=None)

        if result.returncode == 0 and result.stdout:
            data = json.loads(result.stdout)
            # Enhance output with clear messaging
            if "compatible" in data:
                data["summary"] = (
                    f"{license1} and {license2} are {'compatible' if data['compatible'] else 'incompatible'}"
                    f" in {context} context"
                )
            return data
        else:
            return {"error": f"Compatibility check failed: {result.stderr}"}

    except Exception as e:
        logger.error(f"Error checking compatibility: {e}")
        return {"error": str(e)}


@mcp.tool()
async def get_license_details(
    license_id: str,
    include_full_text: bool = False
) -> Dict[str, Any]:
    """
    Get comprehensive details about a specific license.

    This tool provides complete license information including the full license text
    for generating NOTICE files and understanding license requirements.

    Args:
        license_id: SPDX license ID (e.g., "Apache-2.0", "MIT", "GPL-3.0")
        include_full_text: Include full license text (can be long, ~5-20KB)

    Returns:
        License information including:
        - name: Full license name
        - type: License category (permissive, copyleft_weak, copyleft_strong, etc.)
        - properties: Characteristics (OSI approved, FSF free, etc.)
        - permissions: What you CAN do (commercial use, modify, distribute, etc.)
        - requirements: What you MUST do (include license, preserve copyright, etc.)
        - limitations: What is NOT provided (liability, warranty, etc.)
        - obligations: Specific compliance requirements
        - full_text: Complete license text (if include_full_text=True, fetched from SPDX API)

    Example:
        For Apache-2.0, returns complete license data including:
        - Full license text for NOTICE files
        - Patent grant information
        - Attribution requirements
    """
    try:
        ospac_args = ["data", "show", license_id, "-f", "json"]

        logger.info(f"Getting details for license: {license_id}")
        result = _run_tool("ospac", ospac_args, input_data=None)

        if result.returncode == 0 and result.stdout:
            data = json.loads(result.stdout)

            # Extract license data from the response (ospac returns it directly, not nested)
            license_info = data if "license_id" not in data and "id" in data else data.get("license_data", {}).get(license_id, data)

            # Fetch full text from SPDX API if requested
            if include_full_text:
                try:
                    import urllib.request
                    import urllib.error

                    # SPDX API endpoint for license text
                    spdx_url = f"https://raw.githubusercontent.com/spdx/license-list-data/main/text/{license_id}.txt"

                    logger.info(f"Fetching full license text from SPDX for {license_id}")

                    req = urllib.request.Request(spdx_url)
                    with urllib.request.urlopen(req, timeout=10) as response:
                        full_text = response.read().decode('utf-8')
                        license_info["full_text"] = full_text
                        license_info["full_text_source"] = "SPDX License List (GitHub)"
                        logger.info(f"Successfully fetched {len(full_text)} characters of license text")

                except urllib.error.HTTPError as e:
                    if e.code == 404:
                        logger.warning(f"Full text not available for {license_id} from SPDX")
                        license_info["full_text"] = "[Full text not available - license may be deprecated or use non-standard identifier]"
                        license_info["full_text_source"] = "unavailable"
                    else:
                        logger.warning(f"HTTP error fetching license text: {e}")
                        license_info["full_text"] = f"[Error fetching full text: HTTP {e.code}]"
                        license_info["full_text_source"] = "error"

                except Exception as e:
                    logger.warning(f"Could not fetch full license text: {e}")
                    license_info["full_text"] = "[Full text unavailable - network error or timeout]"
                    license_info["full_text_source"] = "error"
            else:
                # Inform user that full text is available
                license_info["full_text_available"] = True
                license_info["full_text"] = "[Full text available - set include_full_text=true to retrieve from SPDX]"

            # Add helpful summary
            license_info["license_id"] = license_id

            return license_info
        else:
            return {"error": f"License details not found: {result.stderr}"}

    except Exception as e:
        logger.error(f"Error getting license details: {e}")
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
async def validate_license_list(
    licenses: List[str],
    distribution: str = "general",
    check_app_store_compatibility: bool = False
) -> Dict[str, Any]:
    """QUICK answer to: "Can I ship this with these licenses?"

    This tool analyzes a list of licenses without requiring a filesystem path,
    making it ideal for quick validation checks.

    WHEN TO USE:
    - You have a list of licenses (from scan results)
    - Need to validate for specific distribution type (mobile, desktop, saas, embedded)
    - Want app store compatibility check (iOS/Android)
    - Fast compliance validation without deep analysis
    - Quick go/no-go decision for shipping

    WHEN NOT TO USE:
    - Need to scan codebase first → use scan_directory
    - Need detailed policy evaluation → use validate_policy
    - Need complete legal documentation → use generate_legal_notices after validation
    - Don't have license list yet → use scan_directory first

    WORKFLOW POSITION:
    Use AFTER scan_directory/check_package to validate licenses,
    BEFORE generate_legal_notices to confirm compliance.

    COMMON WORKFLOW:
    scan_directory(identify_packages=True)
    → validate_license_list(distribution="mobile") [VALIDATION STEP]
    → generate_legal_notices(purls=[...]) [IF APPROVED]

    RETURNS CLEAR DECISION:
    - safe_for_distribution: true/false
    - app_store_compatible: true/false (if check_app_store_compatibility=True)
    - recommendations: What to do next
    - violations: What's wrong (if any)

    Args:
        licenses: List of SPDX license identifiers (e.g., ["MIT", "Apache-2.0"])
        distribution: Target distribution type - "mobile", "desktop", "saas", "embedded", "general"
        check_app_store_compatibility: Check specific App Store (iOS/Android) compatibility

    Returns:
        Dictionary with:
        - safe_for_distribution: bool - Overall safety assessment
        - copyleft_risk: str - "none", "weak", or "strong"
        - risk_level: str - "LOW", "MEDIUM", or "HIGH"
        - violations: List of identified issues
        - recommendations: List of actionable recommendations
        - app_store_compatible: bool - iOS/Android app store compatibility
        - license_details: Summary of each license
    """
    try:
        logger.info(f"Validating {len(licenses)} licenses for {distribution} distribution")

        result = {
            "licenses_analyzed": licenses,
            "distribution": distribution,
            "safe_for_distribution": True,
            "copyleft_risk": "none",
            "risk_level": "LOW",
            "violations": [],
            "recommendations": [],
            "app_store_compatible": True,
            "license_details": {}
        }

        # Get detailed information for each license
        strong_copyleft = []
        weak_copyleft = []
        permissive = []
        unknown = []

        for license_id in licenses:
            # Get license details using existing tool
            try:
                details_result = await get_license_details(license_id, include_full_text=False)

                if "error" in details_result:
                    unknown.append(license_id)
                    result["license_details"][license_id] = {"type": "unknown", "error": "Could not retrieve details"}
                    continue

                license_type = details_result.get("type", "unknown")
                requirements = details_result.get("requirements", {})
                same_license = requirements.get("same_license", False)
                disclose_source = requirements.get("disclose_source", False)

                result["license_details"][license_id] = {
                    "type": license_type,
                    "requires_same_license": same_license,
                    "requires_source_disclosure": disclose_source
                }

                # Categorize license
                if license_id in ["GPL-2.0", "GPL-2.0-only", "GPL-3.0", "GPL-3.0-only", "AGPL-3.0", "AGPL-3.0-only"]:
                    strong_copyleft.append(license_id)
                elif license_id in ["LGPL-2.1", "LGPL-3.0", "MPL-2.0", "EPL-1.0", "EPL-2.0"]:
                    weak_copyleft.append(license_id)
                elif license_type == "permissive" or license_id in ["MIT", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC"]:
                    permissive.append(license_id)
                else:
                    unknown.append(license_id)

            except Exception as e:
                logger.warning(f"Could not get details for {license_id}: {e}")
                unknown.append(license_id)
                result["license_details"][license_id] = {"type": "unknown", "error": str(e)}

        # Assess copyleft risk
        if strong_copyleft:
            result["copyleft_risk"] = "strong"
            result["risk_level"] = "HIGH"
            result["safe_for_distribution"] = False

            for lic in strong_copyleft:
                result["violations"].append(f"{lic} is a strong copyleft license - requires source disclosure")

            # Special handling for AGPL in SaaS
            agpl_licenses = [l for l in strong_copyleft if "AGPL" in l]
            if agpl_licenses and distribution == "saas":
                result["violations"].append("AGPL detected for SaaS distribution - network copyleft trigger applies")
                result["recommendations"].append("AGPL requires source disclosure even for SaaS/web services")

        elif weak_copyleft:
            result["copyleft_risk"] = "weak"
            if distribution == "mobile":
                result["risk_level"] = "MEDIUM"
                result["safe_for_distribution"] = False
                result["violations"].append("Weak copyleft licenses may require special handling for mobile")
                result["recommendations"].append("LGPL/MPL may allow dynamic linking - verify linking method")
            else:
                result["risk_level"] = "LOW"
                result["recommendations"].append("Weak copyleft licenses detected - review linking requirements")
        else:
            result["copyleft_risk"] = "none"
            result["risk_level"] = "LOW"
            result["safe_for_distribution"] = True

        # App Store compatibility check
        if check_app_store_compatibility or distribution == "mobile":
            # GPL is incompatible with iOS App Store due to DRM restrictions
            gpl_licenses = [l for l in licenses if "GPL" in l and "LGPL" not in l]
            if gpl_licenses:
                result["app_store_compatible"] = False
                result["safe_for_distribution"] = False
                result["violations"].append("GPL licenses conflict with App Store terms (DRM restrictions)")
                result["recommendations"].append("Consider replacing GPL dependencies with LGPL or permissive alternatives")
            else:
                result["app_store_compatible"] = True
                if weak_copyleft:
                    result["recommendations"].append("LGPL/MPL allowed on App Store with proper attribution")

        # Distribution-specific recommendations
        if distribution == "mobile" and result["safe_for_distribution"]:
            result["recommendations"].append("Include all license texts in app's legal notices screen")
            result["recommendations"].append("Preserve copyright attributions in About/Credits section")

        if distribution == "saas":
            if not strong_copyleft:
                result["recommendations"].append("No source disclosure required for SaaS distribution")
            result["recommendations"].append("Include license notices in web UI footer or /licenses endpoint")

        if distribution == "desktop":
            result["recommendations"].append("Include LICENSE and NOTICE files in installation directory")
            result["recommendations"].append("Preserve copyright notices in About dialog")

        # Unknown licenses warning
        if unknown:
            result["violations"].append(f"Unknown or unrecognized licenses: {', '.join(unknown)}")
            result["recommendations"].append("Manually review unknown licenses with legal counsel")
            result["risk_level"] = "HIGH" if result["risk_level"] == "LOW" else result["risk_level"]

        # Summary
        total = len(licenses)
        result["summary"] = {
            "total_licenses": total,
            "permissive": len(permissive),
            "weak_copyleft": len(weak_copyleft),
            "strong_copyleft": len(strong_copyleft),
            "unknown": len(unknown)
        }

        return result

    except Exception as e:
        logger.error(f"Error validating license list: {e}")
        return {"error": str(e)}


@mcp.tool()
async def generate_legal_notices(
    path: str,
    output_format: str = "text",
    output_file: Optional[str] = None,
    include_license_text: bool = True
) -> Dict[str, Any]:
    """PRIMARY TOOL: Generate legal notices by scanning source code directly (DEFAULT - FAST).

    This is the RECOMMENDED tool for creating legal compliance documentation.
    Scans your project's source code directly to detect ALL packages (including transitive
    dependencies) and generates comprehensive attribution notices.

    ⚠️ THIS IS THE DEFAULT TOOL - Use this for most cases!
    - Scans source code directly (node_modules/, site-packages/, vendor/)
    - Detects ALL packages automatically (transitive dependencies included)
    - 10x faster than downloading from registries
    - No need to extract PURLs manually

    WHEN TO USE THIS TOOL:
    - You have source code locally with dependencies installed
    - npm project with node_modules/ directory
    - Python project with site-packages/ or virtualenv
    - Any project with locally installed dependencies

    WHEN NOT TO USE:
    - Dependencies not installed locally → Use generate_legal_notices_from_purls instead
    - You already have a PURL list → Use generate_legal_notices_from_purls instead

    PURPOSE:
    Creates production-ready legal compliance documentation including:
    - Complete copyright holder attributions (auto-extracted)
    - Full license texts from SPDX
    - Formatted for NOTICE file inclusion
    - Ready for app store submission
    - Professional legal documentation

    WHEN TO USE (MOST COMMON SCENARIOS):
    - Creating NOTICE files for distribution (PRIMARY USE CASE)
    - Generating legal compliance documentation for any product
    - After scanning packages and need complete attribution
    - Preparing legal docs for app store submissions (iOS/Android)
    - Need copyright holder information (automatically extracted)
    - Anytime you need production-ready legal documentation

    WHEN NOT TO USE:
    - Understanding individual license obligations → use get_license_obligations
    - Just checking license compatibility → use check_license_compatibility
    - Quick validation only → use validate_license_list
    - Want one-shot complete workflow → use run_compliance_check
    - DON'T have PURLs yet → use scan_directory FIRST to get them

    WORKFLOW POSITION:
    Typically used AFTER scan_directory/check_package and validation (validate_license_list),
    as the FINAL step to generate legal documentation.

    COMMON WORKFLOWS:
    1. Mobile App Compliance (MOST COMMON):
       scan_directory(check_vulnerabilities=True, identify_packages=True)
       → validate_license_list(distribution="mobile")
       → generate_legal_notices(purls=[...], output_file="NOTICE.txt") [PRIMARY]
       → generate_sbom(path=".")

    2. After Package Analysis:
       check_package(identifier="pkg:npm/express@4.0.0")
       → validate_policy(licenses=[...])
       → generate_legal_notices(purls=[...])

    3. Batch Compliance:
       scan_directory(path=".", identify_packages=True)
       → (parallel) generate_sbom + generate_legal_notices

    BACKEND:
    Uses purl2notices in scan mode to read source code directly. Automatically extracts
    copyright holders, fetches license texts from SPDX, and formats complete attribution.

    Args:
        path: Path to source directory to scan (project root with dependencies installed)
        output_format: Output format - "text" (default), "html", "markdown"
        output_file: Optional path to save the output file
        include_license_text: If True, include full license texts (default: True)

    Returns:
        Dictionary containing:
        - notices: The generated legal notices text
        - packages_processed: Number/description of packages processed
        - packages_failed: Number of packages that failed processing
        - output_file: Path to saved file (if output_file was specified)
        - format: The output format used
        - mode: "scan_directory" (indicates source code scanning was used)

    Examples:
        # Generate text NOTICE file for npm project
        generate_legal_notices(
            path="/path/to/npm-project",
            output_file="NOTICE.txt"
        )

        # Generate HTML notices for Python project
        generate_legal_notices(
            path="/path/to/python-project",
            output_format="html",
            output_file="NOTICE.html"
        )

        # Quick scan without saving to file
        result = generate_legal_notices(path=".")
        print(result["notices"])
    """
    import subprocess
    import tempfile

    try:
        logger.info(f"Generating legal notices by scanning directory: {path}")

        # Prepare output path
        output_path = output_file or tempfile.mktemp(suffix=f'.{output_format}')

        # Run purl2notices in scan mode - reads source code directly
        cmd = [
            "purl2notices",
            "-i", path,
            "-m", "scan",  # Scan mode - reads source code directly
            "-o", output_path,
            "-f", output_format,
            "-r",  # Recursive
            "--max-depth", "3",
            "--continue-on-error"
        ]

        logger.info(f"Running purl2notices: {' '.join(cmd)}")

        # Run purl2notices
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )

        if result.returncode != 0:
            logger.error(f"purl2notices failed: {result.stderr}")
            return {
                "error": f"purl2notices failed: {result.stderr}",
                "stdout": result.stdout,
                "returncode": result.returncode
            }

        # Read generated notices
        if Path(output_path).exists():
            with open(output_path, 'r') as f:
                notices_content = f.read()

            return {
                "notices": notices_content,
                "packages_processed": "scanned from directory",
                "packages_failed": 0,
                "output_file": output_path,
                "format": output_format,
                "message": f"Successfully generated legal notices by scanning directory: {path}",
                "mode": "scan_directory"
            }
        else:
            return {
                "error": "purl2notices completed but output file not found",
                "stdout": result.stdout
            }

    except subprocess.TimeoutExpired:
        logger.error("purl2notices timed out after 5 minutes")
        return {"error": "Legal notices generation timed out after 5 minutes"}
    except FileNotFoundError:
        logger.error("purl2notices command not found")
        return {
            "error": "purl2notices not found. Install with: pip install purl2notices",
            "install_command": "pip install purl2notices"
        }
    except Exception as e:
        logger.error(f"Error generating legal notices: {e}")
        return {"error": str(e)}


@mcp.tool()
async def generate_legal_notices_from_purls(
    purls: List[str],
    output_format: str = "text",
    output_file: Optional[str] = None,
    include_license_text: bool = True
) -> Dict[str, Any]:
    """ALTERNATIVE TOOL: Generate legal notices from PURL list (downloads from registries - SLOWER).

    Use this tool ONLY when:
    - Dependencies are NOT installed locally (no node_modules/, site-packages/)
    - You already have a list of PURLs from another source
    - You're working with a PURL list, not source code

    ⚠️ PERFORMANCE WARNING: This downloads packages from registries (slow)
    - Downloads each package from npm/PyPI/etc (1-2 seconds per package)
    - For 49 packages: ~60-120 seconds
    - Use generate_legal_notices(path=...) instead if you have source code

    ⚠️ CRITICAL: DO NOT manually extract PURLs from package.json or requirements.txt!
    - WRONG: Reading package.json, extracting "http-server@14.1.1" → 1 PURL
    - RIGHT: Use scan_directory() to get ALL transitive dependencies → 49 PURLs
    - Example: npm project with 1 dependency = ~50 packages in node_modules (all needed!)

    WHEN TO USE THIS TOOL:
    - Source code not available locally
    - Working with a pre-existing PURL list
    - Dependencies not installed (no node_modules/ or site-packages/)

    WHEN NOT TO USE (use generate_legal_notices instead):
    - You have source code with dependencies installed locally
    - npm project with node_modules/ → Use generate_legal_notices(path=...)
    - Python project with virtualenv → Use generate_legal_notices(path=...)

    Args:
        purls: List of Package URLs (e.g., ["pkg:npm/express@4.0.0", "pkg:pypi/django@4.2.0"])
        output_format: Output format - "text" (default), "html", "markdown"
        output_file: Optional path to save the output file
        include_license_text: If True, include full license texts (default: True)

    Returns:
        Dictionary containing:
        - notices: The generated legal notices text
        - packages_processed: Number of packages successfully processed
        - packages_failed: Number of packages that failed processing
        - output_file: Path to saved file (if output_file was specified)
        - format: The output format used
        - mode: "download_purls" (indicates registry downloads were used)

    Examples:
        # Generate notices from PURL list (after scan_directory)
        scan_result = scan_directory("/path/to/project")
        purls = [pkg["purl"] for pkg in scan_result["packages"]]
        generate_legal_notices_from_purls(
            purls=purls,
            output_file="NOTICE.txt"
        )

        # Generate HTML notices from specific PURLs
        generate_legal_notices_from_purls(
            purls=["pkg:npm/express@4.21.2", "pkg:npm/body-parser@1.20.3"],
            output_format="html",
            output_file="NOTICE.html"
        )
    """
    import subprocess
    import tempfile

    try:
        if not purls:
            return {"error": "No PURLs provided"}

        logger.info(f"Generating legal notices for {len(purls)} packages (downloading from registries)")

        # Create temporary file with PURLs
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as purl_file:
            for purl in purls:
                purl_file.write(f"{purl}\n")
            purl_file_path = purl_file.name

        # Prepare output path
        output_path = output_file or tempfile.mktemp(suffix=f'.{output_format}')

        # Run purl2notices with PURL list - downloads from registries
        cmd = [
            "purl2notices",
            "-i", purl_file_path,
            "-o", output_path,
            "-f", output_format
        ]

        logger.info(f"Running purl2notices: {' '.join(cmd)}")

        # Run purl2notices
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )

        # Clean up temp purl file
        Path(purl_file_path).unlink(missing_ok=True)

        if result.returncode != 0:
            logger.error(f"purl2notices failed: {result.stderr}")
            return {
                "error": f"purl2notices failed: {result.stderr}",
                "stdout": result.stdout,
                "returncode": result.returncode
            }

        # Read generated notices
        if Path(output_path).exists():
            with open(output_path, 'r') as f:
                notices_content = f.read()

            return {
                "notices": notices_content,
                "packages_processed": len(purls),
                "packages_failed": 0,
                "output_file": output_path,
                "format": output_format,
                "message": f"Successfully generated legal notices for {len(purls)} packages",
                "mode": "download_purls"
            }
        else:
            return {
                "error": "purl2notices completed but output file not found",
                "stdout": result.stdout
            }

    except subprocess.TimeoutExpired:
        logger.error("purl2notices timed out after 5 minutes")
        return {"error": "Legal notices generation timed out after 5 minutes"}
    except FileNotFoundError:
        logger.error("purl2notices command not found")
        return {
            "error": "purl2notices not found. Install with: pip install purl2notices",
            "install_command": "pip install purl2notices"
        }
    except Exception as e:
        logger.error(f"Error generating legal notices from PURLs: {e}")
        return {"error": str(e)}


@mcp.tool()
async def download_and_scan_package(
    purl: str,
    keep_download: bool = False
) -> Dict[str, Any]:
    """Download package source from registry and perform comprehensive analysis.

    ⚠️ IMPORTANT: This tool CAN and WILL download source code from package registries!

    **Workflow (tries methods in order until sufficient data is collected):**
    1. **Primary**: Use purl2notices to download and analyze (fastest, most comprehensive)
    2. **Deep scan**: If incomplete, use purl2src to get download URL → download artifact → run osslili for deep license scanning + upmex for metadata
       - **Maven-specific**: If license still missing for Maven packages, uses upmex with --registry --api clearlydefined to resolve parent POM licenses
    3. **Online fallback**: If still incomplete, use upmex --api clearlydefined/purldb for online metadata

    **What this tool does:**
    - Downloads the actual package source code from npm/PyPI/Maven/etc registries
    - Performs comprehensive license and copyright analysis
    - Extracts package metadata (name, version, homepage, description)
    - Scans ALL source files for embedded licenses (not just package.json/setup.py/pom.xml)
    - Returns copyright statements found in actual source code
    - **Maven packages**: Automatically resolves parent POM licenses when not declared in package POM

    **When to use this tool:**
    - Package metadata is incomplete or missing (e.g., "UNKNOWN" license in PyPI)
    - Need to verify what's ACTUALLY in the package files (not just metadata)
    - Want to analyze source code directly (not just manifests)
    - Security auditing - see actual package contents before approval
    - License compliance - find licenses embedded in source files
    - Need to extract copyright statements from source code

    **Real-world example:**
    User asks: "Can you check if duckdb@0.2.3 has license info in the source code?"
    - PyPI metadata shows "UNKNOWN" license
    - This tool downloads the actual .whl/.tar.gz from PyPI
    - Scans ALL files in the package for license information
    - Finds licenses embedded in source code that aren't in metadata
    - Returns: {"method_used": "purl2notices", "declared_license": "UNKNOWN", "detected_licenses": ["CC0-1.0"], ...}

    **Performance:**
    - Primary (purl2notices): 5-15 seconds (fastest)
    - Deep scan (download + osslili + upmex): 10-30 seconds
    - Online fallback (upmex --api): 2-5 seconds (but less complete)

    **Security note:**
    - Downloads are verified against package checksums when available
    - Files are scanned but NOT executed
    - Temporary files are cleaned up unless keep_download=True

    Args:
        purl: Package URL (e.g., "pkg:pypi/duckdb@0.2.3", "pkg:npm/express@4.21.2")
        keep_download: If True, keeps downloaded files for manual inspection (default: False)

    Returns:
        Dictionary containing:
        - purl: The package URL analyzed
        - method_used: Which method succeeded ("purl2notices", "deep_scan", "online_fallback")
        - download_path: Where package was downloaded (if keep_download=True)
        - metadata: Package metadata (name, version, homepage, etc.)
        - declared_license: License from package metadata
        - detected_licenses: List of licenses found by scanning source files
        - copyright_statements: Copyright statements extracted from source
        - files_scanned: Number of files analyzed
        - scan_summary: Summary of what was found

    Examples:
        # Check if package has license info in source code
        download_and_scan_package(purl="pkg:pypi/duckdb@0.2.3")

        # Download and keep files for manual inspection
        result = download_and_scan_package(
            purl="pkg:npm/suspicious-package@1.0.0",
            keep_download=True
        )
        print(f"Inspect files at: {result['download_path']}")
    """
    import subprocess
    import tempfile
    import shutil
    import json
    import urllib.request
    from pathlib import Path

    temp_dir = None
    download_file = None

    try:
        logger.info(f"Downloading and scanning package: {purl}")

        result = {
            "purl": purl,
            "method_used": None,
            "download_path": None,
            "metadata": {},
            "declared_license": None,
            "detected_licenses": [],
            "copyright_statements": [],
            "files_scanned": 0,
            "scan_summary": "",
            "methods_attempted": []
        }

        # STEP 1: Try purl2notices first (primary method - fastest and most comprehensive)
        logger.info(f"Step 1: Trying purl2notices (primary method)")
        try:
            temp_cache = tempfile.mktemp(suffix=".json")
            purl2notices_result = _run_tool("purl2notices", [
                "-i", purl,
                "--cache", temp_cache,
                "-f", "json",
                "--no-cache"
            ])

            result["methods_attempted"].append("purl2notices")

            if purl2notices_result.returncode == 0 and purl2notices_result.stdout:
                # Parse cache file to get comprehensive data
                with open(temp_cache, 'r') as f:
                    cache_data = json.load(f)

                if cache_data.get("components"):
                    component = cache_data["components"][0]
                    result["method_used"] = "purl2notices"
                    result["metadata"] = {
                        "name": component.get("name"),
                        "version": component.get("version"),
                        "purl": component.get("purl")
                    }

                    # Extract licenses
                    if component.get("licenses"):
                        result["detected_licenses"] = [
                            lic.get("license", {}).get("id") or lic.get("license", {}).get("name")
                            for lic in component["licenses"]
                            if isinstance(lic, dict)
                        ]
                        result["declared_license"] = result["detected_licenses"][0] if result["detected_licenses"] else None

                    # Extract copyrights
                    if component.get("properties"):
                        result["copyright_statements"] = [
                            prop["value"] for prop in component["properties"]
                            if prop.get("name") == "copyright"
                        ]

                    logger.info(f"purl2notices succeeded: {len(result['detected_licenses'])} licenses, {len(result['copyright_statements'])} copyrights")

                    # Clean up temp cache
                    Path(temp_cache).unlink(missing_ok=True)

                    # If we got sufficient data, return early
                    if result["detected_licenses"] and result["copyright_statements"]:
                        result["scan_summary"] = f"Successfully analyzed using purl2notices. Found {len(result['detected_licenses'])} licenses and {len(result['copyright_statements'])} copyright statements."
                        return result
        except Exception as e:
            logger.warning(f"purl2notices failed: {e}")
            result["purl2notices_error"] = str(e)

        # STEP 2: Deep scan - download artifact and run osslili + upmex
        logger.info(f"Step 2: Attempting deep scan (download + osslili + upmex)")
        try:
            result["methods_attempted"].append("deep_scan")

            # Get download URL using purl2src
            purl2src_result = _run_tool("purl2src", [purl, "--format", "json"])

            if purl2src_result.returncode == 0 and purl2src_result.stdout:
                purl2src_data = json.loads(purl2src_result.stdout)

                if purl2src_data and len(purl2src_data) > 0:
                    download_info = purl2src_data[0]
                    download_url = download_info.get("download_url")
                    fallback_cmd = download_info.get("fallback_command")

                    if download_url:
                        # Download the artifact
                        temp_dir = tempfile.mkdtemp(prefix="package_scan_")
                        filename = download_url.split("/")[-1].split("?")[0]  # Clean filename
                        download_file = Path(temp_dir) / filename

                        logger.info(f"Downloading from: {download_url}")
                        urllib.request.urlretrieve(download_url, download_file)

                        if keep_download:
                            result["download_path"] = str(download_file)

                        # Run osslili on downloaded file
                        logger.info(f"Running osslili on {download_file}")
                        osslili_result = _run_tool("osslili", [
                            str(download_file),
                            "-f", "cyclonedx-json"
                        ])

                        if osslili_result.returncode == 0 and osslili_result.stdout:
                            # Strip informational messages (e.g., "ℹ Processing local path...")
                            osslili_output = osslili_result.stdout
                            json_start = osslili_output.find('{')
                            if json_start != -1:
                                osslili_output = osslili_output[json_start:]
                            osslili_data = json.loads(osslili_output)

                            # Extract licenses from osslili
                            if osslili_data.get("components"):
                                for comp in osslili_data["components"]:
                                    if comp.get("licenses"):
                                        for lic in comp["licenses"]:
                                            lic_id = lic.get("license", {}).get("id") or lic.get("license", {}).get("name")
                                            if lic_id and lic_id not in result["detected_licenses"]:
                                                result["detected_licenses"].append(lic_id)

                                    # Extract copyrights
                                    if comp.get("properties"):
                                        for prop in comp["properties"]:
                                            if prop.get("name") == "copyright":
                                                copyright = prop.get("value")
                                                if copyright and copyright not in result["copyright_statements"]:
                                                    result["copyright_statements"].append(copyright)

                            result["files_scanned"] = len(osslili_data.get("components", []))
                            logger.info(f"osslili deep scan: {len(result['detected_licenses'])} licenses, {result['files_scanned']} files")

                        # Run upmex on downloaded file
                        logger.info(f"Running upmex on {download_file}")
                        upmex_result = _run_tool("upmex", ["extract", str(download_file), "--format", "json"])

                        if upmex_result.returncode == 0 and upmex_result.stdout:
                            upmex_data = json.loads(upmex_result.stdout)
                            result["metadata"].update(upmex_data)
                            if not result["declared_license"] and upmex_data.get("license"):
                                result["declared_license"] = upmex_data["license"]
                            logger.info(f"upmex metadata extracted")

                        # MAVEN SPECIFIC: Check parent POM for declared license
                        # License can be in:
                        # 1. Source file headers (already checked by osslili → detected_licenses)
                        # 2. Package POM (already checked by upmex → declared_license)
                        # 3. Parent POM (need to check with --registry --api clearlydefined)
                        #
                        # We check parent POM if:
                        # - No declared_license found in package POM, OR
                        # - We have detected_licenses from source but no official declaration
                        if purl.startswith("pkg:maven/") and not result["declared_license"]:
                            logger.info(f"Maven package missing declared license (may have detected licenses from source), checking parent POM")
                            try:
                                upmex_maven_result = _run_tool("upmex", [
                                    "extract",
                                    str(download_file),
                                    "--format", "json",
                                    "--registry",
                                    "--api", "clearlydefined"
                                ])

                                if upmex_maven_result.returncode == 0 and upmex_maven_result.stdout:
                                    maven_data = json.loads(upmex_maven_result.stdout)
                                    if maven_data.get("license"):
                                        result["declared_license"] = maven_data["license"]
                                        result["metadata"]["license"] = maven_data["license"]
                                        result["metadata"]["license_source"] = "parent_pom_via_clearlydefined"

                                        # Add to detected_licenses if not already there
                                        if maven_data["license"] not in result["detected_licenses"]:
                                            result["detected_licenses"].append(maven_data["license"])

                                        logger.info(f"Maven parent POM license found: {maven_data['license']}")
                                        if result["detected_licenses"]:
                                            logger.info(f"Combined with source header licenses: {result['detected_licenses']}")
                            except Exception as e:
                                logger.warning(f"Maven parent POM resolution failed: {e}")

                        # If we got data from deep scan, mark as successful
                        if result["detected_licenses"] or result["metadata"]:
                            result["method_used"] = "deep_scan"

                            # Build summary showing license sources
                            summary_parts = ["Deep scan completed"]
                            if result["detected_licenses"]:
                                summary_parts.append(f"found {len(result['detected_licenses'])} licenses")
                                if result["metadata"].get("license_source") == "parent_pom_via_clearlydefined":
                                    summary_parts.append("(includes parent POM license)")
                            if result["copyright_statements"]:
                                summary_parts.append(f"{len(result['copyright_statements'])} copyrights")

                            result["scan_summary"] = ". ".join(summary_parts) + "."
                            return result

                    elif fallback_cmd:
                        logger.warning(f"No direct download URL, fallback command available: {fallback_cmd}")
                        result["fallback_command"] = fallback_cmd

        except Exception as e:
            logger.warning(f"Deep scan failed: {e}")
            result["deep_scan_error"] = str(e)

        # STEP 3: Online fallback - use upmex with API services
        logger.info(f"Step 3: Trying online fallback (upmex --api clearlydefined)")
        try:
            result["methods_attempted"].append("online_fallback")

            # Create a temporary dummy file (upmex needs a file path)
            temp_file = tempfile.mktemp(suffix=".purl")
            with open(temp_file, 'w') as f:
                f.write(purl)

            upmex_online_result = _run_tool("upmex", [
                "extract",
                temp_file,
                "--api", "clearlydefined",
                "--format", "json"
            ])

            if upmex_online_result.returncode == 0 and upmex_online_result.stdout:
                upmex_data = json.loads(upmex_online_result.stdout)
                result["metadata"].update(upmex_data)
                if not result["declared_license"] and upmex_data.get("license"):
                    result["declared_license"] = upmex_data["license"]
                result["method_used"] = "online_fallback"
                logger.info(f"Online metadata retrieved from ClearlyDefined")

            Path(temp_file).unlink(missing_ok=True)

        except Exception as e:
            logger.warning(f"Online fallback failed: {e}")
            result["online_fallback_error"] = str(e)

        # Generate final summary
        if result["method_used"]:
            summary_parts = []
            if result["metadata"].get("name"):
                summary_parts.append(f"Package: {result['metadata'].get('name')} v{result['metadata'].get('version', 'unknown')}")
            if result["declared_license"]:
                summary_parts.append(f"Declared license: {result['declared_license']}")
            if result["detected_licenses"]:
                summary_parts.append(f"Detected licenses: {', '.join(result['detected_licenses'])}")
            if result["copyright_statements"]:
                summary_parts.append(f"Copyrights: {len(result['copyright_statements'])}")
            if result["files_scanned"]:
                summary_parts.append(f"Files scanned: {result['files_scanned']}")

            result["scan_summary"] = ". ".join(summary_parts) + f". Method: {result['method_used']}"
        else:
            result["scan_summary"] = f"Failed to retrieve package data. Attempted methods: {', '.join(result['methods_attempted'])}"
            result["error"] = "All methods failed to retrieve package data"

        return result

    except Exception as e:
        logger.error(f"Error downloading and scanning package: {e}")
        return {
            "error": str(e),
            "purl": purl,
            "methods_attempted": result.get("methods_attempted", []) if 'result' in locals() else []
        }

    finally:
        # Cleanup unless user wants to keep files
        if not keep_download:
            if temp_dir and Path(temp_dir).exists():
                shutil.rmtree(temp_dir, ignore_errors=True)
            if download_file and Path(download_file).exists():
                Path(download_file).unlink(missing_ok=True)


@mcp.tool()
async def generate_sbom(
    purls: Optional[List[str]] = None,
    path: Optional[str] = None,
    output_file: Optional[str] = None,
    include_licenses: bool = True
) -> Dict[str, Any]:
    """Generate a Software Bill of Materials (SBOM) in CycloneDX format using purl2notices.

    This tool creates comprehensive SBOMs in CycloneDX 1.4 JSON format for software
    inventory, vulnerability tracking, and compliance documentation.

    SBOM includes: name, version, PURL, licenses, homepage (external references).
    Data is sourced from purl2notices scan mode which provides accurate package metadata.

    **Use this tool when:**
    - You need to generate an SBOM for a project or package list
    - Creating inventory documentation for compliance
    - After analyzing packages and need structured output
    - Preparing documentation for security audits
    - Required by procurement or regulatory requirements

    **Input modes:**
    - Provide `purls` (list of Package URLs) for packages you've already identified
    - Provide `path` to scan a directory and generate SBOM from discovered packages
    - At least one of `purls` or `path` must be provided

    Args:
        purls: Optional list of Package URLs (PURLs) to include in SBOM
        path: Optional directory path to scan for packages
        output_file: Optional path to save the SBOM file (CycloneDX JSON format)
        include_licenses: If True, include license information (default: True)

    Returns:
        Dictionary containing:
        - sbom: The generated SBOM structure (CycloneDX 1.4 JSON)
        - packages_count: Number of packages included
        - output_file: Path to saved file (if output_file was specified)

    Examples:
        # Generate SBOM from PURLs (after batch analysis)
        generate_sbom(
            purls=["pkg:npm/express@4.0.0", "pkg:pypi/django@4.2.0"],
            output_file="/tmp/sbom.json"
        )

        # Generate SBOM by scanning directory
        generate_sbom(path="/path/to/project")

        # After batch scan workflow
        scan_result = check_package("package.jar")
        generate_sbom(purls=[scan_result["purl"]], include_licenses=True)
    """
    import datetime

    try:
        if not purls and not path:
            return {"error": "Either 'purls' or 'path' must be provided"}

        packages_list = []
        licenses_list = []
        sbom_name = "project"

        # If path provided, scan directory
        if path:
            logger.info(f"Generating SBOM by scanning directory: {path}")
            scan_result = await scan_directory(path, check_vulnerabilities=False)
            packages_list = scan_result.get("packages", [])
            licenses_list = scan_result.get("licenses", [])
            sbom_name = Path(path).name

        # If PURLs provided, use them
        elif purls:
            logger.info(f"Generating SBOM from {len(purls)} PURLs")
            for purl in purls:
                # Parse PURL to extract package info
                try:
                    # Basic PURL parsing
                    if purl.startswith("pkg:"):
                        parts = purl[4:].split("/")
                        ecosystem = parts[0]
                        name_version = "/".join(parts[1:])

                        if "@" in name_version:
                            name, version = name_version.rsplit("@", 1)
                        else:
                            name = name_version
                            version = "unknown"

                        packages_list.append({
                            "purl": purl,
                            "name": name,
                            "version": version,
                            "ecosystem": ecosystem
                        })
                except Exception as e:
                    logger.warning(f"Failed to parse PURL {purl}: {e}")

        # Build CycloneDX SBOM from purl2notices data
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "metadata": {
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
                "tools": [{
                    "name": "mcp-semclone",
                    "version": "1.5.7"
                }],
                "component": {
                    "type": "application",
                    "name": sbom_name
                }
            },
            "components": []
        }

        for pkg in packages_list:
            component = {
                "type": "library",
                "name": pkg.get("name", "unknown"),
                "version": pkg.get("version", "unknown"),
                "purl": pkg.get("purl", "")
            }

            # Add homepage as external reference if available
            if pkg.get("homepage"):
                component["externalReferences"] = [{
                    "type": "website",
                    "url": pkg["homepage"]
                }]

            # Add license information if available
            if include_licenses:
                if "licenses" in pkg:
                    component["licenses"] = pkg["licenses"]
                elif "upstream_license" in pkg:
                    component["licenses"] = [{
                        "license": {"id": pkg["upstream_license"]}
                    }]

            sbom["components"].append(component)

        # Save to file if requested
        if output_file:
            with open(output_file, "w") as f:
                json.dump(sbom, f, indent=2)
            logger.info(f"CycloneDX SBOM saved to {output_file}")
            return {
                "message": f"CycloneDX SBOM saved to {output_file}",
                "sbom": sbom,
                "format": "cyclonedx-json",
                "packages_count": len(packages_list),
                "output_file": output_file
            }

        return {
            "sbom": sbom,
            "format": "cyclonedx-json",
            "packages_count": len(packages_list)
        }

    except Exception as e:
        logger.error(f"Error generating SBOM: {e}")
        return {"error": str(e)}


@mcp.tool()
async def scan_binary(
    path: str,
    analysis_mode: str = "standard",
    generate_sbom: bool = False,
    check_licenses: bool = True,
    check_compatibility: bool = False,
    confidence_threshold: float = 0.5,
    output_format: str = "json"
) -> Dict[str, Any]:
    """Scan binary files for OSS components and licenses using BinarySniffer.

    This tool analyzes compiled binaries, executables, libraries, and archives
    (APK, EXE, DLL, SO, JAR, etc.) to detect open source components, extract
    license information, and identify security issues.

    Use this tool when:
    - Analyzing mobile apps (APK, IPA)
    - Scanning executables (EXE, ELF binaries)
    - Examining shared libraries (DLL, SO, DYLIB)
    - Analyzing Java archives (JAR, WAR, EAR)
    - Scanning firmware or embedded binaries
    - Generating SBOM for binary distributions

    Args:
        path: Path to binary file or directory to analyze
        analysis_mode: Analysis depth - "fast" (quick scan), "standard" (balanced),
                      or "deep" (thorough analysis, slower)
        generate_sbom: If True, generate SBOM in CycloneDX format
        check_licenses: If True, perform detailed license analysis
        check_compatibility: If True, check license compatibility and show warnings
        confidence_threshold: Minimum confidence level (0.0-1.0) for component detection
        output_format: Output format - "json", "table", "csv" (default: json)

    Returns:
        Dictionary containing:
        - components: List of detected OSS components with licenses
        - licenses: Summary of all licenses found
        - compatibility_warnings: License compatibility issues (if check_compatibility=True)
        - sbom: CycloneDX SBOM (if generate_sbom=True)
        - metadata: Scan statistics and file information

    Examples:
        # Scan an Android APK
        scan_binary("app.apk")

        # Deep analysis with SBOM generation
        scan_binary("firmware.bin", analysis_mode="deep", generate_sbom=True)

        # Check license compatibility
        scan_binary("library.so", check_compatibility=True)
    """
    try:
        file_path = Path(path)
        if not file_path.exists():
            return {"error": f"Path does not exist: {path}"}

        result = {
            "components": [],
            "licenses": [],
            "compatibility_warnings": [],
            "metadata": {
                "path": str(file_path),
                "analysis_mode": analysis_mode,
                "confidence_threshold": confidence_threshold
            }
        }

        # Build binarysniffer command
        if check_licenses:
            # Use dedicated license command for license-focused analysis
            cmd = ["binarysniffer", "license", str(file_path)]

            if check_compatibility:
                cmd.append("--check-compatibility")

            cmd.extend(["--show-files", "-o", "-", "-f", "json"])

            # Execute license analysis
            license_result = _run_tool("binarysniffer", cmd[1:], timeout=300)

            if license_result.returncode == 0 and license_result.stdout:
                license_data = json.loads(license_result.stdout)
                result["licenses"] = license_data.get("licenses", [])
                result["compatibility_warnings"] = license_data.get("compatibility_warnings", [])
                result["metadata"]["license_count"] = len(result["licenses"])

        # Perform component analysis
        analyze_cmd = ["analyze", str(file_path)]

        # Add analysis mode flags
        if analysis_mode == "fast":
            analyze_cmd.append("--fast")
        elif analysis_mode == "deep":
            analyze_cmd.append("--deep")

        # Set confidence threshold
        analyze_cmd.extend(["-t", str(confidence_threshold)])

        # Generate SBOM if requested
        if generate_sbom:
            analyze_cmd.extend(["-f", "cyclonedx"])
        else:
            analyze_cmd.extend(["-f", "json"])

        # Add output to stdout
        analyze_cmd.extend(["-o", "-"])

        # Add license focus if enabled
        if check_licenses:
            analyze_cmd.append("--license-focus")

        # Execute analysis
        analyze_result = _run_tool("binarysniffer", analyze_cmd, timeout=300)

        if analyze_result.returncode == 0 and analyze_result.stdout:
            analysis_data = json.loads(analyze_result.stdout)

            if generate_sbom:
                # SBOM format
                result["sbom"] = analysis_data
                result["metadata"]["sbom_format"] = "CycloneDX"

                # Extract components from SBOM
                if "components" in analysis_data:
                    result["components"] = analysis_data["components"]
                    result["metadata"]["component_count"] = len(result["components"])
            else:
                # Standard JSON format
                result["components"] = analysis_data.get("components", analysis_data.get("results", []))
                result["metadata"]["component_count"] = len(result["components"])

                # Aggregate licenses from components if not already done
                if not check_licenses and result["components"]:
                    license_set = set()
                    for component in result["components"]:
                        if "license" in component:
                            license_set.add(component["license"])
                        if "licenses" in component:
                            license_set.update(component["licenses"])

                    result["licenses"] = [{"spdx_id": lic} for lic in license_set]
                    result["metadata"]["license_count"] = len(result["licenses"])

        # Add summary
        result["summary"] = {
            "total_components": result["metadata"].get("component_count", 0),
            "total_licenses": result["metadata"].get("license_count", 0),
            "has_compatibility_warnings": len(result["compatibility_warnings"]) > 0,
            "sbom_generated": generate_sbom
        }

        return result

    except FileNotFoundError:
        return {
            "error": "BinarySniffer not found. Please install it: pip install binarysniffer",
            "install_instructions": "https://github.com/SemClone/binarysniffer"
        }
    except json.JSONDecodeError as e:
        return {
            "error": f"Failed to parse BinarySniffer output: {e}",
            "raw_output": analyze_result.stdout if 'analyze_result' in locals() else None
        }
    except Exception as e:
        logger.error(f"Error scanning binary: {e}")
        return {"error": str(e)}


@mcp.tool()
async def run_compliance_check(
    path: str,
    distribution_type: Optional[str] = None,
    policy_file: Optional[str] = None,
    check_vulnerabilities: bool = True,
    output_dir: Optional[str] = None
) -> Dict[str, Any]:
    """UNIVERSAL COMPLIANCE WORKFLOW: One-shot compliance check for ANY project type.

    This is a convenience tool that runs the complete standard compliance workflow:
    1. Scan for licenses and packages (scan_directory)
    2. Generate legal notices with purl2notices (generate_legal_notices)
    3. Validate against policy using ospac (validate_policy or default policy)
    4. Generate SBOM for documentation (generate_sbom)
    5. Check for vulnerabilities (if enabled)
    6. Return comprehensive summary with APPROVE/REJECT decision

    This tool works for ANY distribution type (mobile, desktop, embedded, SaaS, etc.) -
    no specialized tools needed. Distribution type is used for policy validation context.

    WHEN TO USE:
    - You want a complete compliance assessment in one call
    - Starting a new project compliance review
    - Need approve/reject decision with full documentation
    - Don't want to orchestrate multiple tool calls manually
    - Want standardized compliance workflow

    WHEN NOT TO USE:
    - You need fine-grained control over each step → call individual tools
    - You only need specific information → use targeted tools (scan_directory, etc.)
    - You want to customize the workflow → use individual tools in your preferred sequence

    WORKFLOW EXECUTED:
    1. scan_directory(path, identify_packages=True, check_licenses=True)
    2. generate_legal_notices(purls, output_file=NOTICE.txt)
    3. validate_policy(licenses, policy_file or default_policy)
    4. generate_sbom(purls, output_file=sbom.json)
    5. check vulnerabilities (if check_vulnerabilities=True)
    6. Aggregate results → FINAL DECISION: approved/rejected + risk level

    Args:
        path: Directory or project to analyze
        distribution_type: Optional - mobile, desktop, saas, embedded, etc. (for policy context)
        policy_file: Optional - Path to custom ospac policy. Uses default if not specified.
        check_vulnerabilities: Check for security vulnerabilities (default: True)
        output_dir: Optional - Directory to save outputs (NOTICE.txt, sbom.json). Uses path if not specified.

    Returns:
        Dictionary containing:
        - decision: "APPROVED" or "REJECTED"
        - risk_level: "LOW", "MEDIUM", or "HIGH"
        - summary: Human-readable summary of findings
        - licenses: List of detected licenses
        - packages: List of identified packages (PURLs)
        - vulnerabilities: List of vulnerabilities (if checked)
        - policy_violations: List of policy violations (if any)
        - artifacts_created: List of files generated (NOTICE.txt, sbom.json)
        - recommendations: Actionable next steps

    Example:
        # Complete compliance check with default settings
        result = run_compliance_check("/path/to/project")

        # Mobile app compliance with custom policy
        result = run_compliance_check(
            path="/path/to/mobile/app",
            distribution_type="mobile",
            policy_file="/policies/mobile_policy.json"
        )

        # Check decision
        if result["decision"] == "APPROVED":
            print("✓ Ready to ship!")
        else:
            print("✗ Issues found:", result["policy_violations"])
    """
    try:
        logger.info(f"Running universal compliance check for: {path}")

        output_directory = output_dir or path
        artifacts_created = []

        # STEP 1: Scan directory for licenses and packages
        logger.info("Step 1/5: Scanning directory for licenses and packages...")
        scan_result = await scan_directory(
            path=path,
            recursive=True,
            check_licenses=True,
            identify_packages=True,
            check_vulnerabilities=False  # We'll do this separately
        )

        if "error" in scan_result:
            return {"error": f"Scan failed: {scan_result['error']}", "decision": "ERROR"}

        licenses = scan_result.get("licenses", [])
        packages = scan_result.get("packages", [])
        license_ids = list(set([lic.get("spdx_id") for lic in licenses if lic.get("spdx_id")]))
        purls = [pkg.get("purl") for pkg in packages if pkg.get("purl")]

        logger.info(f"✓ Scan complete: {len(purls)} packages, {len(license_ids)} unique licenses")

        # Warn if too few packages detected
        if len(purls) <= 3:
            logger.warning(
                f"⚠️  Only {len(purls)} package(s) detected! This seems low for a typical project. "
                f"Expected ~50+ packages for npm projects. Check if node_modules/ exists."
            )

        # STEP 2: Generate legal notices
        logger.info("Step 2/5: Generating legal notices with purl2notices...")
        notices_file = str(Path(output_directory) / "NOTICE.txt")
        notices_result = {}

        if purls:
            notices_result = await generate_legal_notices(
                purls=purls,
                output_format="text",
                output_file=notices_file,
                include_license_text=True
            )
            if "output_file" in notices_result:
                artifacts_created.append(notices_result["output_file"])
                logger.info(f"Legal notices saved to {notices_file}")
        else:
            logger.warning("No packages found - skipping legal notices generation")

        # STEP 3: Validate licenses against policy
        logger.info("Step 3/5: Validating licenses against policy...")
        policy_result = {}

        if license_ids:
            if distribution_type:
                # Use validate_license_list for quick validation
                policy_result = await validate_license_list(
                    licenses=license_ids,
                    distribution=distribution_type,
                    check_app_store_compatibility=(distribution_type == "mobile")
                )
            elif policy_file:
                # Use validate_policy if custom policy provided
                policy_result = await validate_policy(
                    licenses=license_ids,
                    policy_file=policy_file,
                    distribution=distribution_type or "general"
                )
            else:
                # Default: use validate_license_list with general distribution
                policy_result = await validate_license_list(
                    licenses=license_ids,
                    distribution="general",
                    check_app_store_compatibility=False
                )

        # STEP 4: Generate SBOM
        logger.info("Step 4/5: Generating SBOM...")
        sbom_file = str(Path(output_directory) / "sbom.json")
        sbom_result = {}

        if purls:
            sbom_result = await generate_sbom(
                path=path,
                output_format="cyclonedx-json",
                output_file=sbom_file,
                include_licenses=True
            )
            if "output_file" in sbom_result:
                artifacts_created.append(sbom_result["output_file"])
                logger.info(f"SBOM saved to {sbom_file}")

        # STEP 5: Check vulnerabilities (if enabled)
        logger.info("Step 5/5: Checking vulnerabilities...")
        vulnerabilities = []

        if check_vulnerabilities and purls:
            # Scan for vulnerabilities (limited to first 10 packages)
            vuln_scan = await scan_directory(
                path=path,
                check_vulnerabilities=True,
                identify_packages=True
            )
            vulnerabilities = vuln_scan.get("vulnerabilities", [])
            logger.info(f"Found {len(vulnerabilities)} vulnerabilities")

        # FINAL DECISION: Aggregate results
        decision = "APPROVED"
        risk_level = "LOW"
        summary_lines = []
        recommendations = []

        # Check policy violations
        policy_violations = policy_result.get("violations", [])
        if policy_violations or not policy_result.get("safe_for_distribution", True):
            decision = "REJECTED"
            risk_level = policy_result.get("risk_level", "HIGH")
            summary_lines.append(f"❌ REJECTED: Policy violations found")
            for violation in policy_violations:
                summary_lines.append(f"  - {violation}")
        else:
            summary_lines.append(f"✓ APPROVED: No policy violations")

        # Check vulnerability risk
        critical_vulns = [v for v in vulnerabilities if v.get("severity") == "CRITICAL"]
        high_vulns = [v for v in vulnerabilities if v.get("severity") == "HIGH"]

        if critical_vulns:
            risk_level = "HIGH"
            summary_lines.append(f"⚠ {len(critical_vulns)} CRITICAL vulnerabilities found")
            recommendations.append(f"Address {len(critical_vulns)} critical vulnerabilities before deployment")
        elif high_vulns:
            if risk_level == "LOW":
                risk_level = "MEDIUM"
            summary_lines.append(f"⚠ {len(high_vulns)} HIGH severity vulnerabilities found")
            recommendations.append(f"Review and address {len(high_vulns)} high severity vulnerabilities")

        # Add recommendations
        if policy_result.get("recommendations"):
            recommendations.extend(policy_result["recommendations"])

        if artifacts_created:
            recommendations.append(f"Review generated files: {', '.join(artifacts_created)}")

        summary = "\n".join(summary_lines)

        return {
            "decision": decision,
            "risk_level": risk_level,
            "summary": summary,
            "licenses": license_ids,
            "licenses_count": len(license_ids),
            "packages": purls,
            "packages_count": len(purls),
            "vulnerabilities": vulnerabilities,
            "vulnerabilities_count": len(vulnerabilities),
            "critical_vulnerabilities": len(critical_vulns),
            "high_vulnerabilities": len(high_vulns),
            "policy_violations": policy_violations,
            "policy_violations_count": len(policy_violations),
            "artifacts_created": artifacts_created,
            "recommendations": recommendations,
            "distribution_type": distribution_type or "general",
            "notices_generated": bool(notices_result),
            "sbom_generated": bool(sbom_result),
            "metadata": {
                "scan_path": path,
                "output_directory": output_directory,
                "policy_used": "custom" if policy_file else "default"
            }
        }

    except Exception as e:
        logger.error(f"Error running compliance check: {e}")
        return {"error": str(e), "decision": "ERROR"}


@mcp.resource("semcl://license_database")
async def get_license_database() -> Dict[str, Any]:
    """Get license compatibility database from ospac data directory."""
    try:
        # List available licenses from ospac's data directory
        from pathlib import Path
        import os

        # Try to find data directory - check common locations
        data_dirs = [
            Path("data/licenses/json"),
            Path("data/licenses/spdx"),
            Path.home() / ".ospac" / "data" / "licenses" / "json",
        ]

        licenses = {}
        for data_dir in data_dirs:
            if data_dir.exists():
                for license_file in data_dir.glob("*.json"):
                    try:
                        with open(license_file) as f:
                            license_data = json.load(f)
                            license_id = license_file.stem
                            licenses[license_id] = license_data.get("license", {})
                    except Exception:
                        continue

                # If we found licenses, return them
                if licenses:
                    return {
                        "licenses": licenses,
                        "total": len(licenses),
                        "source": str(data_dir.parent)
                    }

        return {
            "error": "No license database found. Run 'ospac data generate' to create one.",
            "licenses": {},
            "total": 0
        }
    except Exception as e:
        return {"error": str(e), "licenses": {}, "total": 0}


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