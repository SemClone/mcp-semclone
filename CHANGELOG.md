# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive server instructions for LLM context injection
- Workflow pattern documentation (license-first approach, tool execution order)
- Tool selection guidance for different compliance scenarios
- Performance constraint documentation (timeouts, depth limits, package limits)
- Input format requirements and examples (PURLs, CPEs, SPDX identifiers)
- Common usage workflow examples for typical scenarios
- Enhanced resource access documentation

### Improved
- LLM understanding of when and how to use each tool effectively
- Automatic optimization of tool selection based on task requirements
- Better error handling guidance for LLMs
- Documentation of tool dependencies and interactions

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

[Unreleased]: https://github.com/SemClone/mcp-semclone/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/SemClone/mcp-semclone/compare/v0.0.1...v0.1.0
[0.0.1]: https://github.com/SemClone/mcp-semclone/releases/tag/v0.0.1