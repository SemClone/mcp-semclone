#!/usr/bin/env python3
"""Basic usage examples for MCP SEMCL.ONE server."""

import asyncio
import json
from pathlib import Path

# Example of how an MCP client would interact with the server
# Note: This is pseudo-code as the actual MCP client implementation
# depends on the specific client library being used


async def example_scan_directory():
    """Example: Scan a directory for compliance issues."""
    print("\n=== Scanning Directory for Compliance Issues ===")
    
    # This would be sent to the MCP server
    request = {
        "tool": "scan_directory",
        "arguments": {
            "path": "/path/to/your/project",
            "check_licenses": True,
            "check_vulnerabilities": True,
            "recursive": True
        }
    }
    
    print(f"Request: {json.dumps(request, indent=2)}")
    
    # Simulated response from server
    response = {
        "packages": [
            {"purl": "pkg:npm/express@4.17.1", "path": "package.json"},
            {"purl": "pkg:pypi/django@3.2.0", "path": "requirements.txt"}
        ],
        "licenses": [
            {"spdx_id": "MIT", "file": "LICENSE"},
            {"spdx_id": "BSD-3-Clause", "file": "node_modules/qs/LICENSE"}
        ],
        "vulnerabilities": [
            {
                "id": "CVE-2021-1234",
                "severity": "HIGH",
                "package": "pkg:npm/express@4.17.1",
                "fixed_versions": ["4.17.2", "4.18.0"]
            }
        ],
        "metadata": {
            "total_packages": 2,
            "total_licenses": 2,
            "unique_licenses": 2,
            "total_vulnerabilities": 1,
            "critical_vulnerabilities": 0
        }
    }
    
    print(f"\nResponse Summary:")
    print(f"  - Packages found: {response['metadata']['total_packages']}")
    print(f"  - Unique licenses: {response['metadata']['unique_licenses']}")
    print(f"  - Vulnerabilities: {response['metadata']['total_vulnerabilities']}")
    
    if response['vulnerabilities']:
        print(f"\n  ⚠️  Vulnerabilities detected:")
        for vuln in response['vulnerabilities']:
            print(f"    - {vuln['id']} ({vuln['severity']}): {vuln['package']}")
            print(f"      Fix available in: {', '.join(vuln['fixed_versions'])}")


async def example_check_package():
    """Example: Check a specific package for issues."""
    print("\n=== Checking Specific Package ===")
    
    request = {
        "tool": "check_package",
        "arguments": {
            "identifier": "pkg:npm/lodash@4.17.20",
            "check_vulnerabilities": True,
            "check_licenses": True
        }
    }
    
    print(f"Request: {json.dumps(request, indent=2)}")
    
    response = {
        "identifier": "pkg:npm/lodash@4.17.20",
        "purl": "pkg:npm/lodash@4.17.20",
        "licenses": [{"spdx_id": "MIT", "source": "package.json"}],
        "vulnerabilities": {
            "count": 2,
            "items": [
                {
                    "id": "CVE-2021-23337",
                    "severity": "HIGH",
                    "summary": "Prototype pollution vulnerability",
                    "fixed_in": ["4.17.21"]
                }
            ]
        }
    }
    
    print(f"\nPackage: {response['identifier']}")
    print(f"License: {response['licenses'][0]['spdx_id']}")
    print(f"Vulnerabilities: {response['vulnerabilities']['count']}")
    
    if response['vulnerabilities']['count'] > 0:
        print("\nRecommendation: Upgrade to version 4.17.21 or later")


async def example_validate_policy():
    """Example: Validate licenses against a policy."""
    print("\n=== Validating License Policy ===")
    
    request = {
        "tool": "validate_policy",
        "arguments": {
            "licenses": ["MIT", "Apache-2.0", "GPL-3.0"],
            "distribution": "binary"
        }
    }
    
    print(f"Request: {json.dumps(request, indent=2)}")
    
    response = {
        "valid": False,
        "violations": [
            {
                "license": "GPL-3.0",
                "reason": "Copyleft license not allowed for binary distribution",
                "severity": "HIGH",
                "recommendation": "Replace with MIT, Apache-2.0, or BSD-licensed alternative"
            }
        ],
        "allowed": ["MIT", "Apache-2.0"],
        "policy": "commercial_distribution"
    }
    
    print(f"\nValidation Result: {'✅ PASSED' if response['valid'] else '❌ FAILED'}")
    
    if not response['valid']:
        print(f"\nPolicy Violations:")
        for violation in response['violations']:
            print(f"  - {violation['license']}: {violation['reason']}")
            print(f"    Recommendation: {violation['recommendation']}")


async def example_generate_sbom():
    """Example: Generate an SBOM for a project."""
    print("\n=== Generating SBOM ===")
    
    request = {
        "tool": "generate_sbom",
        "arguments": {
            "path": "/path/to/project",
            "format": "spdx",
            "output_file": "sbom.json"
        }
    }
    
    print(f"Request: {json.dumps(request, indent=2)}")
    
    response = {
        "message": "SBOM saved to sbom.json",
        "sbom": {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "name": "my-project",
            "creationInfo": {
                "created": "2025-01-05T10:30:00Z",
                "creators": ["Tool: mcp-semclone-1.0.0"]
            },
            "packages": [
                {
                    "name": "express",
                    "SPDXID": "SPDXRef-Package-express",
                    "downloadLocation": "https://registry.npmjs.org/express/-/express-4.17.1.tgz",
                    "filesAnalyzed": False,
                    "licenseConcluded": "MIT"
                }
            ]
        }
    }
    
    print(f"\n{response['message']}")
    print(f"SBOM Format: {response['sbom']['spdxVersion']}")
    print(f"Packages included: {len(response['sbom']['packages'])}")


async def example_workflow_compliance_check():
    """Example: Complete compliance check workflow."""
    print("\n" + "="*60)
    print("COMPLETE COMPLIANCE CHECK WORKFLOW")
    print("="*60)
    
    # Step 1: Scan the project
    print("\nStep 1: Scanning project...")
    scan_result = {
        "packages": 15,
        "licenses": ["MIT", "Apache-2.0", "GPL-3.0", "BSD-3-Clause"],
        "vulnerabilities": 3
    }
    print(f"  Found {scan_result['packages']} packages")
    print(f"  Licenses: {', '.join(scan_result['licenses'])}")
    print(f"  Vulnerabilities: {scan_result['vulnerabilities']}")
    
    # Step 2: Validate against policy
    print("\nStep 2: Validating against commercial distribution policy...")
    policy_result = {
        "valid": False,
        "violations": ["GPL-3.0"]
    }
    print(f"  Policy validation: {'PASSED' if policy_result['valid'] else 'FAILED'}")
    if not policy_result['valid']:
        print(f"  Problematic licenses: {', '.join(policy_result['violations'])}")
    
    # Step 3: Check vulnerabilities
    print("\nStep 3: Analyzing vulnerabilities...")
    vuln_summary = {
        "critical": 0,
        "high": 1,
        "medium": 2,
        "low": 0
    }
    print(f"  Critical: {vuln_summary['critical']}")
    print(f"  High: {vuln_summary['high']}")
    print(f"  Medium: {vuln_summary['medium']}")
    print(f"  Low: {vuln_summary['low']}")
    
    # Step 4: Generate report
    print("\nStep 4: Generating compliance report...")
    print("  Report saved to: compliance_report_2025-01-05.pdf")
    
    # Summary
    print("\n" + "-"*60)
    print("COMPLIANCE CHECK SUMMARY")
    print("-"*60)
    print(f"Overall Status: {'✅ COMPLIANT' if policy_result['valid'] and vuln_summary['critical'] == 0 else '❌ NON-COMPLIANT'}")
    print("\nRequired Actions:")
    if not policy_result['valid']:
        print("  1. Replace GPL-3.0 licensed components")
    if vuln_summary['high'] > 0:
        print("  2. Fix 1 high-severity vulnerability")
    if vuln_summary['medium'] > 0:
        print("  3. Review 2 medium-severity vulnerabilities")


async def main():
    """Run all examples."""
    print("\n" + "#"*60)
    print("# MCP SEMCL.ONE Server - Usage Examples")
    print("#"*60)
    
    # Run individual examples
    await example_scan_directory()
    await example_check_package()
    await example_validate_policy()
    await example_generate_sbom()
    
    # Run complete workflow
    await example_workflow_compliance_check()
    
    print("\n" + "#"*60)
    print("# Examples completed")
    print("#"*60)


if __name__ == "__main__":
    asyncio.run(main())