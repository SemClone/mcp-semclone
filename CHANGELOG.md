# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/SemClone/mcp-semclone/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/SemClone/mcp-semclone/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/SemClone/mcp-semclone/compare/v0.1.0...v1.2.0
[0.1.0]: https://github.com/SemClone/mcp-semclone/compare/v0.0.1...v0.1.0
[0.0.1]: https://github.com/SemClone/mcp-semclone/releases/tag/v0.0.1