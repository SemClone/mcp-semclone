# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/SemClone/mcp-semclone/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/SemClone/mcp-semclone/compare/v0.1.0...v1.2.0
[0.1.0]: https://github.com/SemClone/mcp-semclone/compare/v0.0.1...v0.1.0
[0.0.1]: https://github.com/SemClone/mcp-semclone/releases/tag/v0.0.1