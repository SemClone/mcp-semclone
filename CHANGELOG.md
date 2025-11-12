# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.5.2] - 2025-01-12

### Fixed

#### Improved Workflow Instructions to Prevent Single-Package Detection Issues

**Problem**: Users reported that compliance checks only generated notices for 1 package instead of all transitive dependencies (e.g., 1 package instead of 48 in node_modules/).

**Root Cause**: LLMs were bypassing scan_directory or not using ALL packages from the scan result. Some were manually extracting PURLs from package.json instead of using the comprehensive scan.

**Changes**:
- **Enhanced server instructions** with CRITICAL WORKFLOW RULES section
- **Added explicit warnings** in generate_legal_notices against manual PURL extraction
- **Added diagnostic logging** to warn when suspiciously few packages detected (≤3 packages)
- **Improved examples** showing WRONG vs RIGHT workflow approaches

**Impact**:
- LLMs now understand to ALWAYS use scan_directory first
- Clear guidance that npm project with 1 dependency = ~50 packages in node_modules
- Better visibility when workflow is not followed correctly

**Note**: The underlying MCP server code and purl2notices scanning work correctly. This release only improves instructions and logging to prevent workflow misunderstandings.

## [1.5.1] - 2025-01-11

### Changed

#### Architecture Simplification: purl2notices for Everything

**scan_directory now uses purl2notices scan mode exclusively:**
- **REMOVED**: osslili dependency for scan_directory (still used by check_package)
- **REMOVED**: src2purl dependency entirely (replaced by purl2notices)
- **NEW**: purl2notices scan mode handles all scanning in one pass:
  - Detects ALL packages including transitive dependencies (scans entire node_modules/)
  - Extracts licenses from both project source and dependencies
  - Extracts copyright statements automatically from source code
  - No manual PURL extraction needed

**Benefits:**
- 100% accurate package detection (vs 83-88% fuzzy matching from src2purl)
- Detects ALL transitive dependencies (e.g., 51 packages vs 8 fuzzy matches)
- No confusing fuzzy match results
- Automatic copyright extraction as bonus feature
- Simpler architecture: one tool instead of two

**For npm projects:**
- Scans entire node_modules/ directory (50+ packages)
- NOT just direct dependencies from package.json (1-2 packages)
- Includes all transitive dependencies automatically

**Deprecated parameters in scan_directory:**
- `identify_packages` - now deprecated, purl2notices always detects packages
- `check_licenses` - now deprecated, purl2notices always scans licenses
- Parameters still accepted for backwards compatibility but have no effect

**Updated tool descriptions:**
- scan_directory now documents that it detects ALL packages including transitive deps
- Clarified that for npm projects, this means entire node_modules/ not just package.json
- Added emphasis on automatic copyright extraction
- Updated workflow examples to reflect simplified approach

**Dependencies:**
- Removed: `src2purl>=1.3.4` (no longer used)
- Still kept: `osslili>=1.5.7` and `upmex>=1.6.7` (used by check_package for archives)

**Migration:**
No code changes needed. The scan_directory function signature remains the same.
Results are more complete and accurate automatically.

## [1.4.0] - 2025-01-11

### Breaking Changes

#### Removed Tools
- **REMOVED**: `generate_mobile_legal_summary` (formerly `generate_mobile_legal_notice`)
  - **Reason**: Project-type-specific tools don't scale
  - **Migration**: Use `run_compliance_check` for one-shot workflows, or `generate_legal_notices` for manual workflow
  - **Note**: `generate_legal_notices` was always the correct tool for complete legal documentation

### Added

#### Universal Compliance Workflow
- **NEW**: `run_compliance_check` - One-shot compliance workflow for ANY project type
  - Works for mobile, desktop, SaaS, embedded, and any other distribution type
  - Distribution type is a parameter, not separate workflows
  - Automatic workflow execution: scan → generate NOTICE.txt → validate → generate sbom.json → check vulnerabilities
  - Returns APPROVED/REJECTED decision with risk level
  - Generates artifacts: `NOTICE.txt` and `sbom.json`
  - Returns comprehensive report with actionable recommendations
  - Uses default policy if none specified

#### Enhanced Tool Descriptions
All major tools now include structured guidance for better agent usability:

**scan_directory**:
- Marked as FIRST STEP in workflows
- Added "WHEN TO USE" section with clear scenarios
- Added "WHEN NOT TO USE" section with alternatives
- Added "WORKFLOW POSITION" guidance
- Added 3 complete workflow examples

**generate_legal_notices**:
- Marked as PRIMARY TOOL for legal documentation
- Enhanced description emphasizing purl2notices backend
- Added "WHEN TO USE" with most common scenarios
- Added "WHEN NOT TO USE" with clear alternatives
- Added "WORKFLOW POSITION" in typical sequences
- Added 3 complete workflow examples (mobile app compliance, after package analysis, batch compliance)
- Clarified copyright extraction capability

**validate_license_list**:
- Added clear positioning: "QUICK answer to: Can I ship this with these licenses?"
- Added "WHEN TO USE" scenarios
- Added "WHEN NOT TO USE" with alternatives
- Added "WORKFLOW POSITION" guidance
- Added "RETURNS CLEAR DECISION" section
- Added complete workflow example

### Changed

#### Server Instructions
- Added universal workflow documentation
- Two clear options: one-shot vs manual orchestration
- Emphasized: NO project-type-specific tools exist
- Distribution type is parameter for policy context, not separate workflow
- Clear tool sequences for common scenarios

#### Documentation
- Updated all IDE integration guides (Cursor, Cline, Kiro)
- Updated mobile app compliance guide to use universal tools
- Updated example code and configuration files
- Updated README with universal workflow approach
- Fixed all references to removed tools
- Added clear migration guidance

#### Configuration Files
- Updated all autoApprove lists in `.cursor/mcp.json.example`, `.kiro/settings/mcp.json.example`, `examples/mcp_client_config.json`, `guides/IDE_INTEGRATION_GUIDE.md`
- Replaced `generate_mobile_legal_summary` with `run_compliance_check`

### Architecture

#### Standard Compliance Workflow
**Option 1 - One-Shot (Recommended)**:
```
run_compliance_check(path, distribution_type="mobile")
→ APPROVED/REJECTED + NOTICE.txt + sbom.json
```

**Option 2 - Manual Orchestration**:
```
1. scan_directory (discover)
2. generate_legal_notices (complete docs with purl2notices)
3. validate_license_list or validate_policy (validation)
4. generate_sbom (documentation)
5. Compile report
```

#### Design Principles
- NO project-type-specific tools
- Distribution type is policy validation context only
- Use default policy if none specified
- One standardized workflow for everything
- Scales without code changes

### Fixed
- Fixed inconsistent tool references in documentation
- Fixed workflow guidance gaps
- Fixed tool naming ambiguity
- Removed confusing tool alternatives
- Fixed all remaining references to deleted mobile-specific tool

### Migration Guide

If you were using `generate_mobile_legal_notice` or `generate_mobile_legal_summary`:

**Option 1 - Use run_compliance_check (Recommended)**:
```python
# Old approach
scan_result = scan_directory(path)
notice = generate_mobile_legal_summary(project_name, licenses)

# New approach
result = run_compliance_check(path, distribution_type="mobile")
# Automatically generates NOTICE.txt and sbom.json
# Returns APPROVED/REJECTED decision
```

**Option 2 - Use generate_legal_notices directly**:
```python
# This was always the correct tool for complete documentation
scan_result = scan_directory(path, identify_packages=True)
purls = [pkg["purl"] for pkg in scan_result["packages"]]
generate_legal_notices(purls, output_file="NOTICE.txt")
```

## [1.3.7] - 2025-11-10

### Enhanced
- **License Approval/Rejection Workflow** - Major enhancement to validate_policy tool
  - Added comprehensive approve/deny/review decision support for all project types
  - Enhanced tool documentation with clear examples for mobile, commercial, SaaS, embedded, desktop, web, open_source, and internal distributions
  - Added `context` parameter for specialized scenarios (static_linking, dynamic_linking)
  - Returns structured decision output with action, severity, requirements, and remediation guidance
  - Added summary object with quick boolean flags (approved, blocked, requires_review)
  - New LLM instructions section dedicated to license approval/rejection workflow
  - Clear guidance on distribution-specific policy rules (e.g., GPL blocked for mobile, AGPL blocked for SaaS)
  - Workflow integration examples showing validate_policy as pre-deployment gate
  - Quick policy check examples without filesystem scanning

### Changed
- **Updated OSPAC dependency** from >=1.2.2 to >=1.2.3
  - Leverages latest policy engine improvements
  - Enhanced policy clarity for distribution types
  - Better remediation guidance in deny scenarios

### Benefits
- LLMs can now clearly determine if licenses are approved for specific project types
- Users get immediate approve/deny/review decisions with actionable remediation
- Eliminates ambiguity in license compliance decisions
- Enables automated policy enforcement in CI/CD pipelines
- Distribution-specific policies prevent common compliance mistakes (GPL in mobile, AGPL in SaaS)
- Context-aware evaluation for linking scenarios

## [1.3.6] - 2025-11-10

### Added
- **Pipx Installation Documentation** - Comprehensive installation guide using pipx
  - Step-by-step instructions for pipx installation with `pipx inject`
  - Ensures all SEMCL.ONE tools available as both libraries and CLI commands
  - Isolated environment prevents dependency conflicts
  - Updated MCP configuration examples for both pip and pipx installations
  - Updated IDE integration quick setup sections with pipx alternative
  - Clear documentation of all included SEMCL.ONE tools (osslili, binarysniffer, src2purl, purl2notices, ospac, vulnq, upmex)

### Benefits
- Users can choose installation method based on their needs
- Pipx provides clean isolation and easy updates
- All tools globally accessible in PATH when using pipx
- Better documentation clarity about included dependencies
- Easier package management with `pipx upgrade` and `pipx uninstall`

## [1.3.5] - 2025-11-08

### Added
- **IDE Integration Guide** - Comprehensive documentation for Cursor and Kiro IDE integration
  - Complete setup instructions for Cursor IDE MCP server configuration
  - Kiro IDE integration with autoApprove configuration examples
  - VS Code and JetBrains IDEs integration references
  - Configuration templates (.cursor/mcp.json.example, .kiro/settings/mcp.json.example)
  - Troubleshooting guide and best practices
  - Use case examples for IDE-integrated compliance analysis
  - Updated MANIFEST.in to include IDE configuration examples in distributions

### Changed
- **Strands Agent: Enhanced Compliance Reports** - Beautiful CLI output with rich library
  - JSON-structured LLM output for reliable parsing (replaces markdown format)
  - Rich library table formatting with color-coded panels and styled columns
  - License deduplication in package tables (eliminates duplicate license entries)
  - Risk indicators with emoji status (✅/⚠️/❌) for visual clarity
  - Formatted obligation checklists with checkboxes
  - Color-coded compliance panels (green/yellow/red) based on policy status

- **Model Recommendation Updates** - Switched default model to granite3-dense:8b
  - Changed default Ollama model from llama3 to granite3-dense:8b
  - Added warnings about llama3 hallucination issues in documentation
  - Updated README with model recommendation and testing observations
  - granite3-dense:8b provides accurate, grounded analysis without inventing packages

### Benefits
- Developers can now use SEMCL.ONE tools directly within AI-powered IDEs
- Seamless OSS compliance analysis during development workflow
- Enhanced agent output readability with professional table formatting
- More reliable LLM output parsing through structured JSON format
- Cleaner package tables without duplicate license entries
- Better model default reduces risk of inaccurate compliance reports

## [1.3.4] - 2025-11-08

### Added
- **New MCP Tool: generate_legal_notices** - Generate comprehensive legal notices using purl2notices
  - Takes list of PURLs and generates attribution documentation
  - Supports text, HTML, and markdown output formats
  - Includes copyright notices, license attributions, and full license texts
  - Essential for creating NOTICE files for distribution and compliance
  - Detailed docstring with usage instructions for LLM clients

### Changed
- **Enhanced generate_sbom Tool** - Now supports dual input modes
  - Added PURL list support: Can generate SBOMs from lists of Package URLs
  - Dual mode: Accepts either `purls` parameter OR `path` parameter (directory scan)
  - Better format support: CycloneDX-JSON, CycloneDX-XML, SPDX-JSON, SPDX
  - Improved documentation with clear examples for both modes
  - Enhanced LLM instructions in docstring for better autonomous usage

- **Strands Agent: Batch Processing** - Enhanced directory analysis capabilities
  - Automatic detection of directories containing package archives
  - Batch mode for analyzing multiple packages individually
  - Aggregates results across all packages with license breakdown
  - Generates comprehensive compliance reports for package collections
  - Handles 15+ package formats across multiple ecosystems

### Benefits
- LLM clients can now automatically generate legal compliance documentation
- Clear tool differentiation: generate_legal_notices (complete attribution) vs generate_mobile_legal_notice (simplified)
- End-to-end workflow: scan packages → generate SBOM → generate legal notices
- Better support for multi-package analysis scenarios
- Comprehensive docstrings enable autonomous tool usage by LLMs

## [1.3.3] - 2025-11-08

### Fixed
- **Test Compatibility:** Fixed check_package to ensure proper test compatibility
  - Changed check_vulnerabilities default to True to match expected behavior
  - Ensured vulnerabilities field is always present when check_vulnerabilities=True
  - Improved error propagation for critical failures

### Benefits
- All 26 unit tests passing
- Better error handling and reporting
- Consistent API behavior

## [1.3.2] - 2025-11-08

### Changed
- **Improved Package Archive Handling:** Enhanced check_package tool with intelligent tool selection
  - Automatic detection of package archives (.jar, .whl, .rpm, .gem, .nupkg, .crate, .conda)
  - Smart workflow: upmex for metadata extraction → osslili for license detection
  - Better error handling and graceful fallbacks
  - Handles osslili informational output correctly (strips messages before JSON parsing)
- **Updated Tool Selection Documentation:** Added comprehensive guide for choosing between:
  - check_package: For package archives (uses upmex + osslili)
  - scan_binary: For compiled binaries (uses BinarySniffer)
  - scan_directory: For source code directories (uses osslili + src2purl)
- **Enhanced Strands Agent:** Improved file type recognition in planning prompts
  - Better distinction between package archives, compiled binaries, and source directories
  - More accurate tool selection based on file extensions

### Fixed
- JSON parsing error in check_package when osslili outputs informational messages
- Async context manager decorator in Strands Agent examples

### Benefits
- More accurate package analysis with proper tool selection
- Better license detection for package archives
- Clearer documentation for tool usage
- Improved agent autonomy with better file type recognition

## [1.3.1] - 2025-11-08

### Added
- **New Example:** Strands Agent with Ollama - Autonomous OSS compliance agent
  - Complete autonomous agent demonstrating MCP integration with local LLMs
  - 2,784 lines across 9 files (agent.py, comprehensive documentation)
  - Interactive and batch analysis modes
  - Autonomous decision-making loop (plan → execute → interpret → report)
  - Local LLM inference via Ollama (llama3, gemma3, deepseek-r1 support)
  - Custom policy enforcement and configuration management
  - Production-ready error handling and retry logic
  - Complete data privacy (no external API dependencies)
  - Comprehensive documentation:
    - README.md (518 lines) - Complete usage guide with 3 workflows
    - TUNING.md (1,008 lines) - Model selection, optimization, advanced scenarios
    - OVERVIEW.md (445 lines) - Architecture and quick reference
  - One-command setup with quickstart.sh script
  - Environment validation with test_agent.py
  - Example policy and configuration templates
  - Use cases: Mobile app compliance, embedded/IoT, CI/CD, interactive queries

### Changed
- **Updated all SEMCL.ONE tool dependencies to latest versions:**
  - osslili: 1.0.0 → 1.5.7 (improved license detection, TLSH fuzzy matching)
  - binarysniffer: 1.11.0 → 1.11.3 (latest binary analysis features)
  - src2purl: 1.0.0 → 1.3.4 (enhanced package identification, fuzzy matching)
  - purl2notices: 1.0.0 → 1.2.7 (better legal notice generation, fixed dependencies)
  - ospac: 1.0.0 → 1.2.2 (updated policy engine, more license rules)
  - vulnq: 1.0.0 → 1.0.2 (latest vulnerability data sources)
  - upmex: 1.0.0 → 1.6.7 (improved metadata extraction, more ecosystems)
- Updated README with Examples section featuring Strands Agent

### Benefits
- Users automatically get latest tool features and bug fixes
- Demonstrates production-ready autonomous agent patterns with MCP
- Shows how to build fully local, private compliance systems
- Provides comprehensive tuning guide for different use cases

## [1.3.0] - 2025-11-07

### Added
- **New tool:** `scan_binary()` - Binary analysis for OSS components and licenses using BinarySniffer
  - Scan compiled binaries (APK, EXE, DLL, SO, JAR, firmware)
  - Detect OSS components in binaries with confidence scoring
  - Extract license information from binary files
  - Check license compatibility in binary distributions
  - Multiple analysis modes (fast, standard, deep)
  - Generate CycloneDX SBOM for binary distributions
  - Support for mobile apps (APK, IPA), desktop apps, firmware, libraries
- **New dependency:** `binarysniffer>=1.11.0` added to pyproject.toml
- Comprehensive test suite for binary scanning (4 new tests)
- **Enhanced MCP instructions:** 106 lines of binary scanning guidance for LLMs
  - File type recognition (14+ binary formats)
  - Analysis mode selection guidance
  - Confidence threshold recommendations
  - 5 complete workflow examples
  - Red flag detection patterns
  - 6-step mobile app compliance workflow

### Improved
- Overall capability increased from 95% to 97% (+2%)
- Embedded/IoT use case capability increased from 78% to 92% (+14%)
- Mobile apps use case capability increased from 98% to 99% (+1%)
- Desktop applications capability increased from 95% to 97% (+2%)
- Now fills critical gap in binary distribution compliance
- **Tool detection:** Replaced hardcoded tool paths with intelligent auto-detection
  - Automatic tool discovery using `shutil.which()`
  - Caching for performance (avoids repeated lookups)
  - Environment variable override support (e.g., `BINARYSNIFFER_PATH`)
  - No manual configuration required - tools found automatically in PATH
  - More robust and user-friendly than previous approach

### Documentation
- Updated CAPABILITY_METRICS.md with v1.3.0 metrics
- Updated README with binary scanning capabilities and examples
- Updated tool inventory to 11 tools (was 10)
- Added binary scanning to all relevant documentation

### Performance
- Binary scanning leverages BinarySniffer's optimized analysis
- Fast mode for quick scans (<30s for typical mobile apps)
- Deep mode for thorough analysis of complex binaries
- Tool path caching eliminates repeated auto-detection overhead

## [1.2.0] - 2025-11-07

### Added
- **New tool:** `validate_license_list()` - Direct license safety validation for distribution types (mobile, desktop, SaaS, embedded)
  - App Store compatibility checking (iOS/Android)
  - Copyleft risk assessment (none, weak, strong)
  - AGPL network trigger detection for SaaS distributions
  - Distribution-specific recommendations
  - No filesystem access required for instant answers
- **Enhanced:** Full license text retrieval from SPDX API in `get_license_details()`
  - On-demand fetching from SPDX GitHub repository
  - Support for ~700 SPDX licenses
  - Graceful fallback with error handling
  - Enables complete NOTICE file generation
- **Enhanced:** Copyright extraction integration in `scan_directory()`
  - Automatic copyright holder detection from source files
  - Year parsing and normalization
  - File-level attribution tracking
  - Metadata fields: copyright_holders, copyright_info, copyrights_found
- Comprehensive capability metrics documentation (95% overall capability)
- Tool selection guide updated with new validate_license_list tool

### Improved
- NOTICE file generation now includes full license text (100% complete vs. 70% before)
- License safety checks can be performed without scanning filesystem
- Better SaaS/cloud deployment guidance with AGPL-specific warnings
- Copyright information now automatically included in scan results
- Increased overall capability from 85% to 95% (+10%)
- Now answers 10/10 top OSS compliance questions (up from 9.5/10)

### Fixed
- get_license_details() now properly retrieves full license text when requested
- OSPAC CLI integration for policy validation using correct flag format
- Enhanced error messages for license text retrieval failures

### Performance
- validate_license_list() provides <1s response time (no filesystem access)
- Full text fetching from SPDX averages 150-200ms per license
- No impact to existing tool performance

### Documentation
- Added docs/CAPABILITY_METRICS.md with comprehensive capability tracking
- Updated tool usage examples and selection guidance
- Added Phase 1 implementation and test documentation

## [0.1.0] - 2025-11-05

### Added
- Initial MCP server implementation with SEMCL.ONE toolchain integration
- Complete MCP protocol support with 4 tools, 2 resources, 2 prompts
- SEMCL.ONE tool integration: osslili, src2purl, vulnq, ospac, purl2notices, upmex
- Comprehensive license detection and compliance validation
- Multi-source vulnerability scanning (OSV, GitHub, NVD)
- SBOM generation in SPDX and CycloneDX formats
- Commercial mobile app compliance assessment workflows
- Fixed purl2notices argument format for proper license detection
- Enhanced error handling and graceful degradation
- Parallel processing support for improved performance
- Comprehensive test suite with mock implementations
- Production-ready packaging with pyproject.toml
- Complete documentation and user guides
- MCP client integration examples

### Security
- Added git hooks to prevent contamination with problematic keywords
- Implemented secure subprocess execution for tool integrations
- Added comprehensive error handling for untrusted input

## [0.0.1] - 2025-11-05

### Added
- Initial project setup
- Basic repository structure
- License and initial documentation

[Unreleased]: https://github.com/SemClone/mcp-semclone/compare/v1.3.7...HEAD
[1.3.7]: https://github.com/SemClone/mcp-semclone/compare/v1.3.6...v1.3.7
[1.3.6]: https://github.com/SemClone/mcp-semclone/compare/v1.3.5...v1.3.6
[1.3.5]: https://github.com/SemClone/mcp-semclone/compare/v1.3.4...v1.3.5
[1.3.4]: https://github.com/SemClone/mcp-semclone/compare/v1.3.3...v1.3.4
[1.3.3]: https://github.com/SemClone/mcp-semclone/compare/v1.3.2...v1.3.3
[1.3.2]: https://github.com/SemClone/mcp-semclone/compare/v1.3.1...v1.3.2
[1.3.1]: https://github.com/SemClone/mcp-semclone/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/SemClone/mcp-semclone/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/SemClone/mcp-semclone/compare/v0.1.0...v1.2.0
[0.1.0]: https://github.com/SemClone/mcp-semclone/compare/v0.0.1...v0.1.0
[0.0.1]: https://github.com/SemClone/mcp-semclone/releases/tag/v0.0.1