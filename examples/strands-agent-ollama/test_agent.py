#!/usr/bin/env python3
"""
Test script for Strands Agent example.
Verifies that all components work together correctly.
"""

import sys
import subprocess
import shutil
from pathlib import Path


def check_requirement(name: str, check_func) -> bool:
    """Check if a requirement is met."""
    try:
        check_func()
        print(f"✅ {name}")
        return True
    except Exception as e:
        print(f"❌ {name}: {e}")
        return False


def main():
    """Run all checks."""
    print("="*60)
    print("Strands Agent - Environment Check")
    print("="*60)
    print()

    checks_passed = 0
    total_checks = 0

    # Check 1: Python version
    total_checks += 1
    if check_requirement(
        "Python 3.10+",
        lambda: sys.version_info >= (3, 10)
    ):
        checks_passed += 1
        print(f"   Version: {sys.version}")

    # Check 2: Ollama installed
    total_checks += 1
    if check_requirement(
        "Ollama installed",
        lambda: shutil.which("ollama") is not None
    ):
        checks_passed += 1
        result = subprocess.run(
            ["ollama", "list"],
            capture_output=True,
            text=True
        )
        if "llama3" in result.stdout:
            print("   ✅ llama3 model available")
        else:
            print("   ⚠️  llama3 model not found (run: ollama pull llama3)")

    # Check 3: Required Python packages
    total_checks += 1
    packages_ok = True
    for pkg in ["mcp", "ollama"]:
        try:
            __import__(pkg)
            print(f"✅ Package '{pkg}' installed")
        except ImportError:
            print(f"❌ Package '{pkg}' not installed")
            packages_ok = False

    if packages_ok:
        checks_passed += 1

    # Check 4: mcp-semclone available
    total_checks += 1
    try:
        import mcp_semclone
        print(f"✅ mcp-semclone installed")
        print(f"   Version: {mcp_semclone.__version__}")
        checks_passed += 1
    except ImportError:
        print("❌ mcp-semclone not installed")
        print("   Run: pip install mcp-semclone")

    # Check 5: SEMCL.ONE tools in PATH
    total_checks += 1
    tools = ["osslili", "binarysniffer", "ospac"]
    tools_found = 0
    for tool in tools:
        if shutil.which(tool):
            tools_found += 1
            print(f"✅ Tool '{tool}' found in PATH")
        else:
            print(f"⚠️  Tool '{tool}' not in PATH (may cause issues)")

    if tools_found >= 2:  # At least 2 tools should be available
        checks_passed += 1

    # Check 6: Example files present
    total_checks += 1
    example_dir = Path(__file__).parent
    required_files = [
        "agent.py",
        "requirements.txt",
        "README.md",
        "policy.yaml",
        "agent_config.yaml"
    ]
    files_ok = True
    for file in required_files:
        file_path = example_dir / file
        if file_path.exists():
            print(f"✅ File '{file}' present")
        else:
            print(f"❌ File '{file}' missing")
            files_ok = False

    if files_ok:
        checks_passed += 1

    # Summary
    print()
    print("="*60)
    print(f"Checks Passed: {checks_passed}/{total_checks}")
    print("="*60)

    if checks_passed == total_checks:
        print("\n✅ All checks passed! Ready to run the agent.")
        print("\nQuick start:")
        print("  python agent.py /path/to/project")
        return 0
    else:
        print(f"\n⚠️  {total_checks - checks_passed} check(s) failed.")
        print("Please resolve the issues above before running the agent.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
