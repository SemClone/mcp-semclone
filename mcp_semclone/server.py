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

WORKFLOW PATTERNS:
1. License-first approach: Always scan for licenses before identifying packages or vulnerabilities
2. Tool execution order: licenses (osslili) → packages (src2purl) → vulnerabilities (vulnq) → policy validation (ospac)
3. Package identification is optional and only required when checking vulnerabilities or generating detailed SBOMs
4. Vulnerability checks automatically trigger package identification if not already performed

INTERPRETING LICENSE DATA FROM OSPAC:
When analyzing license obligations and requirements, use these OSPAC fields to derive implications:

1. NETWORK COPYLEFT (Critical for SaaS/Cloud):
   - Field: requirements.network_use_disclosure
   - If TRUE: License requires source disclosure even for SaaS/network use (AGPL-3.0)
   - If FALSE: License only requires disclosure on distribution (GPL-3.0)
   - Calculate: saas_safe = NOT network_use_disclosure
   - Example: AGPL has network_use_disclosure=true → NOT safe for SaaS without disclosure

2. COPYLEFT STRENGTH:
   - Field: compatibility.contamination_effect
   - Values: "none" (permissive), "weak" (LGPL/MPL), "strong" (GPL/AGPL)
   - Strong copyleft + network_use_disclosure=true = AGPL (most restrictive)
   - Strong copyleft + network_use_disclosure=false = GPL (distribution only)
   - Use this to determine viral effects on derivative works

3. DISCLOSURE TRIGGERS:
   - Calculate from requirements.disclose_source + network_use_disclosure:
     * Both TRUE → "distribution_or_network" (AGPL)
     * Only disclose_source TRUE → "distribution" (GPL)
     * Both FALSE → "none" (permissive licenses)

4. MOBILE APP COMPATIBILITY:
   - GPL licenses (GPL-2.0, GPL-3.0) are incompatible with App Stores due to DRM restrictions
   - Check: If "GPL" in license_id AND "LGPL" NOT in license_id → app_store_compatible = false
   - LGPL, MIT, Apache, BSD are all compatible with mobile app stores
   - Combine with policy validation for definitive answer

5. COMMON PITFALLS (Derive from requirements):
   - requirements.include_license=true → Pitfall: "Forgetting LICENSE file in distribution"
   - requirements.include_copyright=true → Pitfall: "Removing copyright notices"
   - requirements.disclose_source=true → Pitfall: "Not providing source code"
   - requirements.state_changes=true → Pitfall: "Not documenting modifications"

6. COMPLIANCE CHECKLISTS (Generate from obligations + requirements):
   - Use obligations[] for narrative requirements
   - Use requirements.* for specific checklist items
   - Format as actionable steps for users

7. LICENSE TYPE IMPLICATIONS:
   - type="permissive" → Ideal for: mobile, saas, commercial, all uses
   - type="copyleft_weak" → Review: linking requirements, LGPL static linking needs care
   - type="copyleft_strong" + network_use_disclosure=false → Avoid: mobile apps; OK: SaaS if no distribution
   - type="copyleft_strong" + network_use_disclosure=true → Avoid: SaaS, mobile; Requires: source publication

BINARY SCANNING GUIDANCE (scan_binary tool):

When to use scan_binary vs scan_directory:
- Use scan_binary for: APK, IPA, EXE, DLL, SO, DYLIB, JAR, WAR, EAR, firmware images, compiled binaries
- Use scan_directory for: Source code repositories, projects with build files, uncompiled code
- Use BOTH when: You have both source and compiled artifacts (scan separately, compare results)

File type recognition (when to use scan_binary):
- Mobile apps: .apk (Android), .ipa (iOS), .aab (Android App Bundle)
- Desktop executables: .exe (Windows), ELF binaries (Linux, no extension), .app bundles (macOS)
- Libraries: .dll (Windows), .so (Linux), .dylib (macOS), .a (static libs)
- Java/JVM: .jar, .war, .ear, .class files
- Firmware: .bin, .img, .hex, embedded system images
- Archives containing binaries: .zip, .tar.gz with binaries inside
- When user mentions: "compiled", "binary", "executable", "firmware", "APK", "mobile app binary"

Analysis mode selection:
- analysis_mode="fast": Use for initial scans, large files (>100MB), time-sensitive queries
  * Skips fuzzy matching, faster but may miss some components
  * Good for: Quick checks, CI/CD pipelines, preliminary assessments
- analysis_mode="standard" (default): Use for most cases, balanced speed/accuracy
  * Comprehensive signature matching, reasonable performance
  * Good for: General compliance checks, regular assessments
- analysis_mode="deep": Use for critical assessments, detailed analysis, legal compliance
  * Thorough analysis, slower but most accurate
  * Good for: Pre-release compliance, legal reviews, embedded systems

Confidence threshold guidance:
- confidence_threshold=0.3-0.5: Use for discovery mode (find all possible components)
- confidence_threshold=0.5-0.7 (default 0.5): Balanced, good for most use cases
- confidence_threshold=0.7-0.9: High confidence only, reduce false positives
- Lower threshold for firmware/embedded (components may be modified)
- Higher threshold for well-known libraries (expect exact matches)

When to enable specific options:
- check_licenses=True (default): Always use unless only interested in components
- check_compatibility=True: Use for commercial products, mobile apps, mixed licensing scenarios
- generate_sbom=True: Use for compliance documentation, supply chain requirements, distribution

Interpreting binary scan results:
1. Check result["summary"]["total_components"] - number of OSS components detected
2. Review result["licenses"] - all licenses found in the binary
3. If check_compatibility=True: Review result["compatibility_warnings"] for conflicts
4. Examine result["components"] for details on each detected component
5. Compare with source code scan if available (should match or be subset)

Common binary scanning workflows:

1. Mobile app pre-release check:
   scan_binary(
       path="app.apk",
       analysis_mode="deep",
       check_compatibility=True  # Detect GPL/App Store conflicts
   )
   → Review licenses for App Store compatibility
   → Use validate_license_list() with distribution="mobile" for verification
   → Generate legal notices with licenses found

2. Firmware compliance assessment:
   scan_binary(
       path="firmware.bin",
       analysis_mode="deep",
       confidence_threshold=0.4,  # Firmware components may be modified
       generate_sbom=True
   )
   → Extract all component licenses
   → Check for copyleft licenses (GPL in firmware = must provide source)
   → Generate NOTICE file for distribution

3. Desktop application check:
   scan_binary(
       path="application.exe",
       analysis_mode="standard",
       check_licenses=True,
       check_compatibility=True
   )
   → Identify all bundled libraries
   → Check for license conflicts
   → Validate against commercial distribution policy

4. Java/JVM application:
   scan_binary(
       path="application.jar",
       analysis_mode="standard",
       generate_sbom=True
   )
   → Detect bundled dependencies (even if not in manifest)
   → Generate SBOM for supply chain
   → Check for known vulnerabilities in detected components

5. Third-party library verification:
   scan_binary(
       path="vendor_library.so",
       analysis_mode="deep",
       confidence_threshold=0.7  # High confidence for verification
   )
   → Verify vendor license claims
   → Detect undisclosed OSS components
   → Check for license compliance issues

Red flags in binary scan results:
- GPL licenses in mobile apps → App Store rejection risk
- AGPL licenses in SaaS binaries → Must disclose source for network use
- Multiple incompatible copyleft licenses → Legal conflict
- Undisclosed components (not in vendor docs) → Compliance risk
- High component count with low confidence → Needs deeper analysis

TOOL SELECTION GUIDE:

**For Package Archives (.jar, .whl, .rpm, .gem, .nupkg, .crate, etc.):**
- check_package: RECOMMENDED for package archives. Intelligently uses upmex for metadata extraction + osslili for licenses. Fastest and most accurate for packages with structured metadata.

**For Compiled Binaries (.so, .dll, .dylib, .exe, .bin, .apk, .ipa):**
- scan_binary: Use for truly compiled binaries, firmware, and mobile apps. Uses BinarySniffer for signature-based component detection. Best for executables and native libraries.

**For Source Code Directories:**
- scan_directory: Primary tool for analyzing projects/codebases. Performs comprehensive license inventory with osslili, optional package identification, and vulnerability assessment.

**Detailed Tool Descriptions:**
- check_package: Intelligent package analyzer that automatically selects the best extraction method:
  * For archives: Tries upmex first (fast, accurate metadata), falls back to osslili
  * For PURLs: Direct package registry lookups
  * Returns: Package metadata (name, version, PURL), licenses, optional vulnerabilities
  * Use when: You have a package file (.jar, .whl, etc.) or PURL to analyze

- scan_binary: Binary signature detection for compiled files using BinarySniffer:
  * Detects OSS components embedded in binaries through signature matching
  * Use for: Mobile apps (APK/IPA), executables (EXE), native libraries (SO/DLL/DYLIB), firmware
  * Returns: Detected components, licenses, compatibility warnings, optional SBOM
  * Note: Slower than check_package for archives; prefer check_package for .jar, .whl, etc.

- scan_directory: Comprehensive source code analysis:
  * License inventory via osslili (fast, thorough)
  * Optional package identification via src2purl
  * Optional vulnerability scanning (first 10 packages)
  * Use for: Git repositories, source directories, projects with build files

- validate_policy: Standalone license policy validation without filesystem access
- validate_license_list: Quick distribution safety check (e.g., "Can I ship to App Store?")
- get_license_obligations: Detailed compliance requirements for specific licenses
- check_license_compatibility: Check if two licenses can be combined
- get_license_details: Comprehensive license information including full text
- analyze_commercial_risk: Commercial distribution risk assessment for copyleft detection
- generate_mobile_legal_notice: Creates legal notices for mobile app compliance
- generate_sbom: Generates Software Bill of Materials (calls scan_directory internally)

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

Source Code Workflows:
1. Basic compliance check: scan_directory(path, check_licenses=True, identify_packages=False)
2. Full security assessment: scan_directory(path, check_vulnerabilities=True) - automatically enables package identification
3. Policy validation: scan_directory(path, policy_file="policy.json") → validate_policy(licenses, policy_file)
4. Commercial risk analysis: analyze_commercial_risk(path) for mobile/commercial distribution decisions
5. SBOM generation: generate_sbom(path, format="spdx") for supply chain transparency

Binary Workflows:
6. Mobile app compliance: scan_binary("app.apk", analysis_mode="deep", check_compatibility=True) → validate_license_list(licenses, distribution="mobile")
7. Firmware assessment: scan_binary("firmware.bin", analysis_mode="deep", generate_sbom=True) → check copyleft presence
8. Desktop app check: scan_binary("app.exe") → get_license_obligations(licenses) → generate_mobile_legal_notice(licenses)
9. Library verification: scan_binary("library.so", confidence_threshold=0.7) → compare with vendor claims
10. Combined analysis: scan_directory("src/") + scan_binary("build/app.apk") → compare results, ensure completeness

Complete Mobile App Compliance Workflow:
Step 1: scan_binary("app.apk", analysis_mode="deep", check_compatibility=True)
Step 2: Extract licenses from result["licenses"]
Step 3: validate_license_list(licenses, distribution="mobile", check_app_store_compatibility=True)
Step 4: If violations: get_license_obligations(problematic_licenses) to understand requirements
Step 5: If compatible: generate_mobile_legal_notice(licenses) for in-app display
Step 6: generate_sbom=True to document components for compliance records

RESOURCE ACCESS:
- semcl://license_database: Retrieves comprehensive license compatibility database from ospac
- semcl://policy_templates: Returns pre-configured policy templates (commercial, open_source, internal)

ERROR HANDLING:
- Tools return {"error": "message"} on failures
- Non-zero exit codes are logged but don't always indicate failure (check returned data)
- Missing CLI tools (src2purl, osslili, vulnq, ospac) will raise FileNotFoundError"""
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
                copyright_info = []

                for scan_result in licenses_data.get("scan_results", []):
                    # Extract license evidence
                    for evidence in scan_result.get("license_evidence", []):
                        license_evidence.append({
                            "spdx_id": evidence.get("detected_license"),
                            "file": evidence.get("file"),
                            "confidence": evidence.get("confidence"),
                            "method": evidence.get("detection_method"),
                            "category": evidence.get("category"),
                            "description": evidence.get("description")
                        })

                    # Extract copyright information
                    for copyright_evidence in scan_result.get("copyright_evidence", []):
                        copyright_info.append({
                            "holder": copyright_evidence.get("holder"),
                            "year": copyright_evidence.get("year"),
                            "statement": copyright_evidence.get("statement"),
                            "file": copyright_evidence.get("file"),
                            "confidence": copyright_evidence.get("confidence", "high")
                        })

                result.licenses = license_evidence

                # Add copyright information to metadata if found
                if copyright_info:
                    result.metadata["copyright_holders"] = list(set([c["holder"] for c in copyright_info if c.get("holder")]))
                    result.metadata["copyright_info"] = copyright_info
                    result.metadata["copyrights_found"] = len(copyright_info)

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
    distribution: str = "binary"
) -> Dict[str, Any]:
    """Validate licenses against a policy."""
    try:
        # Build ospac evaluate command with licenses as comma-separated string
        licenses_str = ",".join(licenses)
        ospac_args = ["evaluate", "-l", licenses_str, "-d", distribution, "-o", "json"]

        # Only add policy-dir if explicitly provided (otherwise uses default)
        if policy_file:
            ospac_args.extend(["--policy-dir", policy_file])

        # Run validation (no stdin input needed)
        result = _run_tool("ospac", ospac_args, input_data=None)

        if result.returncode == 0 and result.stdout:
            return json.loads(result.stdout)
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
    """Validate if a list of licenses is safe for a specific distribution type.

    This tool analyzes a list of licenses without requiring a filesystem path,
    making it ideal for quick "Can I ship this?" questions.

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
                "creators": ["Tool: mcp-semclone-1.3.0"]
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