#!/usr/bin/env python3
"""Test suite for MCP SEMCL.ONE server."""

import json
import pytest
import asyncio
import subprocess
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from mcp_semclone.server import ScanResult, mcp, _run_tool
from mcp_semclone import server as server_module


class TestMCPServer:
    """Test cases for the MCP server."""

    @pytest.mark.asyncio
    async def test_scan_directory_success(self):
        """Test successful directory scan."""
        # Mock purl2notices JSON output
        purl2notices_output = {
            "metadata": {"total_packages": 0},
            "licenses": []
        }

        with patch("mcp_semclone.server._run_tool") as mock_run, \
             patch("json.load", return_value=purl2notices_output), \
             patch("os.path.exists", return_value=True), \
             patch("os.unlink"), \
             patch("tempfile.NamedTemporaryFile"), \
             patch("pathlib.Path.exists", return_value=True):

            mock_run.return_value = MagicMock(returncode=0, stdout="")

            result = await server_module.scan_directory(
                "/test",
                check_licenses=False,
                check_vulnerabilities=False
            )

            assert "licenses" in result
            assert "metadata" in result
            assert result["metadata"]["total_licenses"] == 0

    @pytest.mark.asyncio
    async def test_scan_directory_nonexistent(self):
        """Test scanning non-existent directory."""
        with patch("pathlib.Path.exists", return_value=False):
            result = await server_module.scan_directory("/nonexistent/path")
            assert "error" in result
            assert "does not exist" in result["error"]

    @pytest.mark.asyncio
    async def test_scan_directory_with_licenses(self):
        """Test directory scan with license detection."""
        # Mock purl2notices JSON output with MIT license
        purl2notices_output = {
            "metadata": {"total_packages": 1},
            "licenses": [
                {
                    "id": "MIT",
                    "packages": [
                        {
                            "name": "test-pkg",
                            "version": "1.0.0",
                            "purl": "pkg:npm/test-pkg@1.0.0"
                        }
                    ],
                    "copyrights": ["Copyright Test Author"]
                }
            ]
        }

        with patch("mcp_semclone.server._run_tool") as mock_run, \
             patch("json.load", return_value=purl2notices_output), \
             patch("os.path.exists", return_value=True), \
             patch("os.unlink"), \
             patch("tempfile.NamedTemporaryFile"), \
             patch("pathlib.Path.exists", return_value=True):

            mock_run.return_value = MagicMock(returncode=0, stdout="")

            result = await server_module.scan_directory("/test", check_vulnerabilities=False)

            assert "licenses" in result
            assert len(result["licenses"]) == 1
            assert result["licenses"][0]["spdx_id"] == "MIT"

    @pytest.mark.asyncio
    async def test_scan_directory_with_vulnerabilities(self):
        """Test directory scan with vulnerability checking."""
        # Mock purl2notices JSON output with packages for vulnerability checking
        purl2notices_output = {
            "metadata": {"total_packages": 2},
            "licenses": [
                {
                    "id": "Apache-2.0",
                    "packages": [
                        {
                            "name": "vuln-test-pkg",
                            "version": "2.5.0",
                            "purl": "pkg:npm/vuln-test-pkg@2.5.0"
                        }
                    ],
                    "copyrights": ["Copyright Apache Foundation"]
                }
            ]
        }

        with patch("mcp_semclone.server._run_tool") as mock_run, \
             patch("json.load", return_value=purl2notices_output), \
             patch("os.path.exists", return_value=True), \
             patch("os.unlink"), \
             patch("tempfile.NamedTemporaryFile"), \
             patch("pathlib.Path.exists", return_value=True):

            mock_run.return_value = MagicMock(returncode=0, stdout="")

            result = await server_module.scan_directory("/test", check_licenses=False)

            assert "licenses" in result
            assert "metadata" in result

    @pytest.mark.asyncio
    async def test_check_package_purl(self):
        """Test checking a package by PURL."""
        with patch("mcp_semclone.server._run_tool") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=json.dumps({
                    "vulnerabilities": [
                        {"id": "CVE-2021-5678", "severity": "CRITICAL"}
                    ]
                })
            )

            result = await server_module.check_package("pkg:npm/express@4.17.1")

            assert "vulnerabilities" in result
            assert "identifier" in result
            assert result["identifier"] == "pkg:npm/express@4.17.1"
            assert result["purl"] == "pkg:npm/express@4.17.1"

    @pytest.mark.asyncio
    async def test_check_package_cpe(self):
        """Test checking a package by CPE."""
        with patch("mcp_semclone.server._run_tool") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=json.dumps({
                    "vulnerabilities": [
                        {"id": "CVE-2021-44228", "severity": "CRITICAL"}
                    ]
                })
            )

            result = await server_module.check_package("cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*")

            assert "vulnerabilities" in result
            assert result["identifier"] == "cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*"
            assert result["purl"] is None

    @pytest.mark.asyncio
    async def test_validate_policy(self):
        """Test policy validation."""
        with patch("mcp_semclone.server._run_tool") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=json.dumps({
                    "valid": True,
                    "violations": [],
                    "allowed": ["MIT", "Apache-2.0"]
                })
            )

            result = await server_module.validate_policy(["MIT", "Apache-2.0"])

            assert "valid" in result
            assert result["valid"] is True
            assert "violations" in result
            assert len(result["violations"]) == 0

    @pytest.mark.asyncio
    async def test_validate_policy_with_violations(self):
        """Test policy validation with violations."""
        with patch("mcp_semclone.server._run_tool") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=json.dumps({
                    "valid": False,
                    "violations": [
                        {
                            "license": "GPL-3.0",
                            "reason": "Copyleft license not allowed for commercial distribution"
                        }
                    ]
                })
            )

            result = await server_module.validate_policy(["MIT", "GPL-3.0"], distribution="binary")

            assert "valid" in result
            assert result["valid"] is False
            assert "violations" in result
            assert len(result["violations"]) == 1
            assert result["violations"][0]["license"] == "GPL-3.0"

    @pytest.mark.asyncio
    async def test_generate_sbom(self):
        """Test SBOM generation."""
        with patch("mcp_semclone.server.scan_directory") as mock_scan:
            mock_scan.return_value = {
                "packages": [{"purl": "pkg:npm/express@4.17.1", "name": "express"}],
                "licenses": [{"spdx_id": "MIT", "file": "LICENSE"}]
            }

            result = await server_module.generate_sbom(path="/test", output_format="spdx")

            assert "sbom" in result
            assert result["sbom"]["spdxVersion"] == "SPDX-2.3"
            assert result["sbom"]["dataLicense"] == "CC0-1.0"
            assert len(result["sbom"]["packages"]) == 1

    @pytest.mark.asyncio
    async def test_generate_sbom_with_output_file(self, tmp_path):
        """Test SBOM generation with file output."""
        output_file = tmp_path / "sbom.json"

        with patch("mcp_semclone.server.scan_directory") as mock_scan:
            mock_scan.return_value = {
                "packages": [{"purl": "pkg:npm/express@4.17.1"}],
                "licenses": [{"spdx_id": "MIT"}]
            }

            with patch("builtins.open", create=True) as mock_open:
                mock_file = MagicMock()
                mock_open.return_value.__enter__.return_value = mock_file

                result = await server_module.generate_sbom(path="/test", output_file=str(output_file))

                assert "message" in result
                assert str(output_file) in result["message"]
                mock_open.assert_called_once_with(str(output_file), "w")

    @pytest.mark.asyncio
    async def test_get_license_database(self):
        """Test getting license database."""
        from pathlib import Path

        # Mock filesystem access for license database
        mock_license_files = [
            MagicMock(stem="MIT"),
            MagicMock(stem="Apache-2.0")
        ]

        mock_license_data = {
            "MIT": {"license": {"id": "MIT", "name": "MIT License", "osi_approved": True}},
            "Apache-2.0": {"license": {"id": "Apache-2.0", "name": "Apache License 2.0", "osi_approved": True}}
        }

        with patch("pathlib.Path.exists") as mock_exists, \
             patch("pathlib.Path.glob") as mock_glob, \
             patch("builtins.open", create=True) as mock_open:

            # Mock directory exists
            mock_exists.return_value = True

            # Mock glob returning license files
            mock_glob.return_value = mock_license_files

            # Mock file reading
            def mock_file_read(file_path, *args, **kwargs):
                stem = file_path.stem if hasattr(file_path, 'stem') else str(file_path).split('/')[-1].replace('.json', '')
                mock_file = MagicMock()
                mock_file.__enter__ = lambda self: self
                mock_file.__exit__ = lambda self, *args: None
                mock_file.read = lambda: json.dumps(mock_license_data.get(stem, {}))
                return mock_file

            mock_open.side_effect = mock_file_read

            result = await server_module.get_license_database()

            assert "licenses" in result
            assert len(result["licenses"]) == 2
            assert "MIT" in result["licenses"]
            assert "Apache-2.0" in result["licenses"]

    @pytest.mark.asyncio
    async def test_get_policy_templates(self):
        """Test getting policy templates."""
        result = await server_module.get_policy_templates()

        assert "templates" in result
        assert len(result["templates"]) > 0
        assert "commercial" in [t["name"] for t in result["templates"]]
        assert "open_source" in [t["name"] for t in result["templates"]]

    @pytest.mark.asyncio
    async def test_compliance_check_prompt(self):
        """Test compliance check prompt."""
        result = await server_module.compliance_check()

        assert isinstance(result, str)
        assert "Compliance Check Workflow" in result
        assert "Project Path" in result
        assert "Distribution Type" in result

    @pytest.mark.asyncio
    async def test_vulnerability_assessment_prompt(self):
        """Test vulnerability assessment prompt."""
        result = await server_module.vulnerability_assessment()

        assert isinstance(result, str)
        assert "Vulnerability Assessment Workflow" in result
        assert "Severity Threshold" in result
        assert "CRITICAL" in result

    @pytest.mark.asyncio
    async def test_error_handling(self):
        """Test error handling in various methods."""
        with patch("mcp_semclone.server._run_tool") as mock_run:
            mock_run.side_effect = Exception("Command failed")

            result = await server_module.check_package("pkg:npm/test@1.0.0")
            assert "error" in result
            assert "Command failed" in result["error"]

            result = await server_module.validate_policy(["MIT"])
            assert "error" in result

            # For generate_sbom, patch the scan_directory function call directly
            with patch("mcp_semclone.server.scan_directory") as mock_scan:
                mock_scan.side_effect = Exception("Scan failed")
                result = await server_module.generate_sbom(path="/test")
                assert "error" in result

    @pytest.mark.asyncio
    async def test_scan_binary_success(self):
        """Test successful binary scan."""
        with patch("mcp_semclone.server._run_tool") as mock_run:
            # Mock binarysniffer license output
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=json.dumps({
                    "licenses": [
                        {"spdx_id": "Apache-2.0", "file": "lib/library.so"},
                        {"spdx_id": "MIT", "file": "lib/utils.so"}
                    ],
                    "compatibility_warnings": []
                })
            )

            with patch("pathlib.Path.exists", return_value=True):
                result = await server_module.scan_binary("/test/app.apk")

            assert "licenses" in result
            assert "components" in result
            assert "metadata" in result
            assert result["metadata"]["path"] == "/test/app.apk"

    @pytest.mark.asyncio
    async def test_scan_binary_with_sbom(self):
        """Test binary scan with SBOM generation."""
        with patch("mcp_semclone.server._run_tool") as mock_run:
            # Mock binarysniffer analyze output with CycloneDX SBOM
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=json.dumps({
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.4",
                    "components": [
                        {
                            "name": "openssl",
                            "version": "1.1.1",
                            "licenses": [{"license": {"id": "Apache-2.0"}}]
                        }
                    ]
                })
            )

            with patch("pathlib.Path.exists", return_value=True):
                result = await server_module.scan_binary(
                    "/test/app.apk",
                    generate_sbom=True
                )

            assert "sbom" in result
            assert "metadata" in result
            assert result["metadata"].get("sbom_format") == "CycloneDX"

    @pytest.mark.asyncio
    async def test_scan_binary_nonexistent(self):
        """Test scanning non-existent binary."""
        with patch("pathlib.Path.exists", return_value=False):
            result = await server_module.scan_binary("/nonexistent/binary.apk")
            assert "error" in result
            assert "does not exist" in result["error"]

    @pytest.mark.asyncio
    async def test_scan_binary_with_compatibility_check(self):
        """Test binary scan with license compatibility checking."""
        with patch("mcp_semclone.server._run_tool") as mock_run:
            # Mock binarysniffer license output with compatibility warnings
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=json.dumps({
                    "licenses": [
                        {"spdx_id": "GPL-2.0", "file": "lib/gpl.so"},
                        {"spdx_id": "MIT", "file": "lib/mit.so"}
                    ],
                    "compatibility_warnings": [
                        {
                            "severity": "high",
                            "message": "GPL-2.0 may be incompatible with proprietary code"
                        }
                    ]
                })
            )

            with patch("pathlib.Path.exists", return_value=True):
                result = await server_module.scan_binary(
                    "/test/app.apk",
                    check_compatibility=True
                )

            assert "compatibility_warnings" in result
            assert len(result["compatibility_warnings"]) == 1
            assert result["summary"]["has_compatibility_warnings"] is True


class TestScanResult:
    """Test cases for ScanResult model."""

    def test_scan_result_initialization(self):
        """Test ScanResult model initialization."""
        result = ScanResult()
        assert result.packages == []
        assert result.licenses == []
        assert result.vulnerabilities == []
        assert result.policy_violations == []
        assert result.metadata == {}

    def test_scan_result_with_data(self):
        """Test ScanResult with data."""
        result = ScanResult(
            packages=[{"purl": "pkg:npm/test@1.0.0"}],
            licenses=[{"spdx_id": "MIT"}],
            vulnerabilities=[{"id": "CVE-2021-1234"}],
            policy_violations=[{"license": "GPL-3.0"}],
            metadata={"total": 1}
        )

        assert len(result.packages) == 1
        assert len(result.licenses) == 1
        assert len(result.vulnerabilities) == 1
        assert len(result.policy_violations) == 1
        assert result.metadata["total"] == 1

    def test_scan_result_serialization(self):
        """Test ScanResult serialization."""
        result = ScanResult(
            packages=[{"purl": "pkg:npm/test@1.0.0"}],
            licenses=[{"spdx_id": "MIT"}]
        )

        data = result.model_dump()
        assert "packages" in data
        assert "licenses" in data
        assert data["packages"][0]["purl"] == "pkg:npm/test@1.0.0"
        assert data["licenses"][0]["spdx_id"] == "MIT"


class TestRunTool:
    """Test cases for the _run_tool function."""

    def test_run_tool_success(self):
        """Test successful tool execution."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="success output",
                stderr=""
            )

            result = _run_tool("test_tool", ["--arg1", "value1"])

            assert result.returncode == 0
            assert result.stdout == "success output"
            mock_run.assert_called_once()

    def test_run_tool_with_input(self):
        """Test tool execution with input data."""
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="success",
                stderr=""
            )

            result = _run_tool("test_tool", ["--json"], input_data='{"test": "data"}')

            mock_run.assert_called_once()
            call_args = mock_run.call_args
            assert call_args[1]["input"] == '{"test": "data"}'

    def test_run_tool_timeout(self):
        """Test tool timeout handling."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired("cmd", 60)

            with pytest.raises(subprocess.TimeoutExpired):
                _run_tool("test_tool", ["--slow"])

    def test_run_tool_not_found(self):
        """Test tool not found handling."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError("command not found")

            with pytest.raises(FileNotFoundError):
                _run_tool("nonexistent_tool", ["--help"])