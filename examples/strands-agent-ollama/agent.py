#!/usr/bin/env python3
"""
Strands Agent - Autonomous OSS Compliance Agent using Ollama + MCP

This agent demonstrates how to build an autonomous compliance system that:
- Uses Ollama (granite3-dense:8b recommended) for local LLM inference
- Connects to mcp-semclone MCP server for compliance tools
- Performs end-to-end OSS compliance workflows
- Generates actionable compliance reports

Author: SEMCL.ONE
License: Apache-2.0
"""

import asyncio
import json
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from contextlib import asynccontextmanager
import argparse

try:
    import ollama
except ImportError:
    print("❌ Error: 'ollama' package not installed")
    print("Install with: pip install ollama")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.markdown import Markdown
except ImportError:
    print("❌ Error: 'rich' package not installed")
    print("Install with: pip install rich")
    sys.exit(1)

try:
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ImportError:
    print("❌ Error: 'mcp' package not installed")
    print("Install with: pip install mcp")
    sys.exit(1)


@dataclass
class AgentConfig:
    """Agent configuration."""
    llm_model: str = "granite3-dense:8b"
    llm_temperature: float = 0.1
    mcp_server_command: str = "python"
    mcp_server_args: List[str] = None
    timeout: int = 300
    verbose: bool = False

    def __post_init__(self):
        if self.mcp_server_args is None:
            # Default to running mcp_semclone.server module
            self.mcp_server_args = ["-m", "mcp_semclone.server"]


class StrandsComplianceAgent:
    """Autonomous OSS compliance agent using Ollama + MCP."""

    def __init__(self, config: AgentConfig):
        self.config = config
        self.session: Optional[ClientSession] = None
        self.available_tools: List[Dict] = []
        self.conversation_history: List[Dict] = []

    async def initialize(self):
        """Initialize MCP connection and discover tools."""
        print(f"🚀 Initializing Strands Compliance Agent...")
        print(f"   LLM: {self.config.llm_model}")
        print(f"   MCP Server: {self.config.mcp_server_command} {' '.join(self.config.mcp_server_args)}")

        # Verify Ollama is available
        try:
            models = ollama.list()
            model_names = []
            if hasattr(models, 'models'):
                for m in models.models:
                    if hasattr(m, 'model'):
                        model_names.append(m.model)
                    elif isinstance(m, dict):
                        model_names.append(m.get('model', m.get('name', 'unknown')))

            if not any(self.config.llm_model in name for name in model_names):
                print(f"⚠️  Warning: {self.config.llm_model} not found in Ollama")
                print(f"   Available models: {', '.join(model_names)}")
                print(f"   Pull with: ollama pull {self.config.llm_model}")
        except Exception as e:
            print(f"⚠️  Warning: Could not verify Ollama installation: {e}")

        print("✅ Agent initialized")

    @asynccontextmanager
    async def connect_mcp(self):
        """Connect to MCP server and discover tools."""
        print("\n🔌 Connecting to MCP server...")

        server_params = StdioServerParameters(
            command=self.config.mcp_server_command,
            args=self.config.mcp_server_args,
            env=None
        )

        try:
            async with stdio_client(server_params) as (read, write):
                async with ClientSession(read, write) as session:
                    self.session = session

                    # Initialize session
                    await session.initialize()

                    # Discover available tools
                    tools_response = await session.list_tools()
                    self.available_tools = [
                        {
                            "name": tool.name,
                            "description": tool.description,
                            "parameters": tool.inputSchema if hasattr(tool, 'inputSchema') else {}
                        }
                        for tool in tools_response.tools
                    ]

                    print(f"✅ Connected to MCP server")
                    print(f"📦 Discovered {len(self.available_tools)} tools:")
                    for tool in self.available_tools:
                        print(f"   - {tool['name']}: {tool['description'][:80]}...")

                    # Keep session alive for agent operations
                    yield session

        except Exception as e:
            print(f"❌ Error connecting to MCP server: {e}")
            raise

    def _build_system_prompt(self) -> str:
        """Build system prompt with available MCP tools."""
        tools_desc = "\n".join([
            f"- {t['name']}: {t['description']}"
            for t in self.available_tools
        ])

        return f"""You are an expert OSS compliance analyst with access to powerful analysis tools.

AVAILABLE MCP TOOLS:
{tools_desc}

YOUR CAPABILITIES:
- Analyze source code and binaries for OSS licenses
- Detect security vulnerabilities in dependencies
- Validate license policies and compatibility
- Generate legal notices and SBOMs
- Provide actionable compliance recommendations

RESPONSE FORMAT:
When analyzing compliance issues, always:
1. Identify the file type and select appropriate tool
2. Explain your tool selection reasoning
3. Interpret results in plain language
4. Highlight critical compliance issues
5. Provide specific, actionable recommendations

Be concise but thorough. Focus on compliance risks and remediation steps."""

    async def query_llm(self, user_message: str, context: Optional[Dict] = None) -> str:
        """Query Ollama LLM with user message and optional context."""
        messages = [
            {
                "role": "system",
                "content": self._build_system_prompt()
            }
        ]

        # Add conversation history
        messages.extend(self.conversation_history)

        # Add current message
        user_content = user_message
        if context:
            user_content = f"{user_message}\n\nContext:\n{json.dumps(context, indent=2)}"

        messages.append({
            "role": "user",
            "content": user_content
        })

        if self.config.verbose:
            print(f"\n💭 LLM Query: {user_message[:100]}...")

        try:
            response = ollama.chat(
                model=self.config.llm_model,
                messages=messages,
                options={
                    "temperature": self.config.llm_temperature,
                    "num_predict": 2000,
                }
            )

            llm_response = response['message']['content']

            # Update conversation history
            self.conversation_history.append({"role": "user", "content": user_content})
            self.conversation_history.append({"role": "assistant", "content": llm_response})

            # Keep history manageable (last 10 exchanges)
            if len(self.conversation_history) > 20:
                self.conversation_history = self.conversation_history[-20:]

            return llm_response

        except Exception as e:
            print(f"❌ Error querying LLM: {e}")
            return f"Error: Could not get LLM response: {e}"

    async def execute_tool(self, session: ClientSession, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute an MCP tool."""
        if self.config.verbose:
            print(f"\n🔧 Executing tool: {tool_name}")
            print(f"   Arguments: {json.dumps(arguments, indent=2)}")

        try:
            result = await session.call_tool(tool_name, arguments=arguments)

            # Extract content from result
            if hasattr(result, 'content'):
                content = result.content
                if isinstance(content, list) and len(content) > 0:
                    # Get first content item
                    first_content = content[0]
                    if hasattr(first_content, 'text'):
                        result_data = json.loads(first_content.text)
                    else:
                        result_data = {"raw": str(first_content)}
                else:
                    result_data = {"raw": str(content)}
            else:
                result_data = {"raw": str(result)}

            if self.config.verbose:
                print(f"✅ Tool execution successful")

            return result_data

        except Exception as e:
            print(f"❌ Error executing tool {tool_name}: {e}")
            return {"error": str(e)}

    async def _batch_analyze_packages(self, session: ClientSession, archives: List[Path]) -> str:
        """Batch analyze multiple package archives."""
        all_results = []
        all_licenses = {}
        all_packages = []

        for i, archive in enumerate(archives, 1):
            print(f"[{i}/{len(archives)}] Analyzing {archive.name}...")

            try:
                result = await self.execute_tool(
                    session,
                    "check_package",
                    {
                        "identifier": str(archive),
                        "check_licenses": True,
                        "check_vulnerabilities": False
                    }
                )

                if "error" not in result:
                    all_results.append({
                        "file": archive.name,
                        "result": result
                    })

                    # Aggregate licenses
                    if "licenses" in result and result["licenses"]:
                        for license_info in result["licenses"]:
                            # Handle both dict and string license formats
                            if isinstance(license_info, dict):
                                license_id = license_info.get("license", "Unknown")
                            elif isinstance(license_info, str):
                                license_id = license_info
                            else:
                                license_id = str(license_info)

                            if license_id not in all_licenses:
                                all_licenses[license_id] = {
                                    "count": 0,
                                    "files": []
                                }
                            all_licenses[license_id]["count"] += 1
                            all_licenses[license_id]["files"].append(archive.name)

                    # Track packages
                    if "purl" in result and result["purl"]:
                        all_packages.append({
                            "file": archive.name,
                            "purl": result["purl"]
                        })

                    print(f"    ✅ Complete")
                else:
                    print(f"    ⚠️  Error: {result['error']}")

            except Exception as e:
                print(f"    ❌ Failed: {e}")

        # Build aggregated results
        aggregated = {
            "summary": {
                "total_packages": len(archives),
                "successful_scans": len(all_results),
                "failed_scans": len(archives) - len(all_results),
                "unique_licenses": len(all_licenses),
                "packages_identified": len(all_packages)
            },
            "licenses": all_licenses,
            "packages": all_packages,
            "individual_results": all_results
        }

        print(f"\n📊 Batch analysis complete, gathering additional compliance data...")

        # Step 1: Get license obligations for all unique licenses
        all_license_ids = list(all_licenses.keys())
        obligations_data = {}

        if all_license_ids:
            try:
                print(f"   Fetching obligations for {len(all_license_ids)} unique licenses...")
                obligations_result = await self.execute_tool(
                    session,
                    "get_license_obligations",
                    {"licenses": all_license_ids}
                )
                if "obligations" in obligations_result:
                    obligations_data = obligations_result["obligations"]
            except Exception as e:
                print(f"   ⚠️  Could not fetch obligations: {e}")

        # Step 2: Generate legal notices for all packages with PURLs
        legal_notices = ""
        purls_list = [pkg["purl"] for pkg in all_packages if pkg.get("purl")]

        if purls_list:
            try:
                print(f"   Generating legal notices for {len(purls_list)} packages...")
                notices_result = await self.execute_tool(
                    session,
                    "generate_legal_notices",
                    {
                        "purls": purls_list,
                        "output_format": "text",
                        "include_license_text": False  # Just attribution, not full text
                    }
                )
                if "notices" in notices_result:
                    legal_notices = notices_result["notices"]
            except Exception as e:
                print(f"   ⚠️  Could not generate legal notices: {e}")

        print(f"   Interpreting results...")

        # Build structured package table for LLM
        package_table_rows = []
        for pkg_result in aggregated['individual_results']:
            file_name = pkg_result['file']
            result = pkg_result['result']
            purl = result.get('purl', 'N/A')
            licenses = result.get('licenses', [])

            # Format licenses - deduplicate and sort
            unique_licenses = set()
            if isinstance(licenses, list):
                for lic in licenses:
                    if isinstance(lic, dict):
                        unique_licenses.add(lic.get('license', 'Unknown'))
                    else:
                        unique_licenses.add(str(lic))
            elif licenses:
                unique_licenses.add(str(licenses))

            # Sort for consistent output
            license_str = ', '.join(sorted(unique_licenses)) if unique_licenses else 'None found'

            package_table_rows.append(f"| {file_name} | {purl} | {license_str} |")

        package_table = "\n".join(package_table_rows)

        # Build license summary
        license_summary_lines = []
        for license_id, data in all_licenses.items():
            files_list = ', '.join(data['files'][:3])  # Show first 3 files
            if len(data['files']) > 3:
                files_list += f" ... ({len(data['files'])} total)"
            license_summary_lines.append(f"  - {license_id}: {data['count']} package(s) - {files_list}")

        license_summary = "\n".join(license_summary_lines)

        # Build obligations summary
        obligations_summary_lines = []
        for license_id, oblig_data in obligations_data.items():
            if 'obligations' in oblig_data:
                obligations_summary_lines.append(f"\n{license_id}:")
                for oblig in oblig_data['obligations']:
                    obligations_summary_lines.append(f"  - {oblig}")

        obligations_summary = "\n".join(obligations_summary_lines) if obligations_summary_lines else "No obligations data available"

        # LLM interprets aggregated results with structured data - output as JSON
        interpretation_query = f"""Analyze these batch OSS compliance scan results and provide a comprehensive compliance report in JSON format.

IMPORTANT: Only reference packages that appear in the PACKAGE TABLE below. Do not invent or imagine packages that are not listed.

BATCH SCAN SUMMARY:
- Total packages scanned: {aggregated['summary']['total_packages']}
- Successful scans: {aggregated['summary']['successful_scans']}
- Failed scans: {aggregated['summary']['failed_scans']}
- Unique licenses found: {aggregated['summary']['unique_licenses']}

PACKAGE TABLE (ALL ACTUAL PACKAGES - DO NOT ADD OTHERS):
| Package File | PURL | Licenses |
|---|---|---|
{package_table}

LICENSE SUMMARY:
{license_summary}

LICENSE OBLIGATIONS:
{obligations_summary}

Return ONLY valid JSON (no markdown, no code blocks) with this exact structure:

{{
  "executive_summary": {{
    "status": "compliant|needs-review|non-compliant",
    "summary_text": "Brief 2-3 sentence overview"
  }},
  "package_analysis": [
    {{
      "package": "filename.ext",
      "purl": "pkg:type/name@version or N/A",
      "licenses": "comma-separated licenses",
      "risk_level": "low|medium|high",
      "risk_emoji": "✅|⚠️|❌",
      "considerations": "specific concerns or 'No concerns found'"
    }}
  ],
  "license_compatibility": {{
    "has_conflicts": true|false,
    "copyleft_issues": "description or null",
    "distribution_safe": true|false,
    "notes": "compatibility analysis"
  }},
  "obligations": {{
    "attribution": ["obligation 1", "obligation 2"],
    "source_disclosure": ["obligation 1"] or [],
    "modification_docs": ["obligation 1"] or [],
    "license_notices": ["obligation 1", "obligation 2"],
    "other": ["obligation 1"] or []
  }},
  "critical_issues": [
    {{
      "severity": "high|medium|low",
      "issue": "description",
      "action": "recommended action"
    }}
  ],
  "summary": {{
    "compliance_status": "overall status",
    "key_risks": ["risk 1", "risk 2"],
    "next_steps": ["step 1", "step 2"]
  }}
}}

Return ONLY the JSON object, nothing else."""

        report_json_str = await self.query_llm(interpretation_query)

        # Parse JSON response
        try:
            # Clean up response (remove markdown code blocks if present)
            cleaned = report_json_str.strip()
            if cleaned.startswith('```'):
                # Remove markdown code blocks
                lines = cleaned.split('\n')
                cleaned = '\n'.join([l for l in lines if not l.startswith('```')])

            report_data = json.loads(cleaned)
        except json.JSONDecodeError as e:
            print(f"⚠️  Warning: Could not parse JSON response: {e}")
            print(f"Raw response: {report_json_str[:500]}...")
            # Fallback to plain text
            print(report_json_str)
            return report_json_str

        # Use rich console for beautiful formatted output
        console = Console()

        console.print("\n")
        console.print(Panel.fit(
            "📄 COMPREHENSIVE BATCH COMPLIANCE REPORT",
            style="bold cyan"
        ))
        console.print()

        # 1. Executive Summary
        exec_summary = report_data.get('executive_summary', {})
        status = exec_summary.get('status', 'unknown')
        status_color = "green" if status == "compliant" else ("yellow" if status == "needs-review" else "red")

        console.print(Panel(
            f"[bold {status_color}]Status: {status.upper()}[/bold {status_color}]\n\n{exec_summary.get('summary_text', '')}",
            title="Executive Summary",
            border_style=status_color
        ))
        console.print()

        # 2. Package Analysis Table
        pkg_table = Table(title="Package Analysis", show_header=True, header_style="bold magenta")
        pkg_table.add_column("Package", style="cyan", no_wrap=False)
        pkg_table.add_column("PURL", style="blue", no_wrap=False)
        pkg_table.add_column("Licenses", style="green", no_wrap=False)
        pkg_table.add_column("Risk", justify="center", style="bold")
        pkg_table.add_column("Considerations", no_wrap=False)

        for pkg in report_data.get('package_analysis', []):
            pkg_table.add_row(
                pkg.get('package', ''),
                pkg.get('purl', 'N/A'),
                pkg.get('licenses', ''),
                pkg.get('risk_emoji', ''),
                pkg.get('considerations', '')
            )

        console.print(pkg_table)
        console.print()

        # 3. License Compatibility
        compat = report_data.get('license_compatibility', {})
        compat_color = "green" if compat.get('distribution_safe', False) else "yellow"
        compat_text = f"""**Has Conflicts:** {'Yes ❌' if compat.get('has_conflicts', False) else 'No ✅'}
**Copyleft Issues:** {compat.get('copyleft_issues') or 'None'}
**Distribution Safe:** {'Yes ✅' if compat.get('distribution_safe', False) else 'No ❌'}

{compat.get('notes', '')}"""

        console.print(Panel(compat_text, title="License Compatibility Analysis", border_style=compat_color))
        console.print()

        # 4. Obligations Checklist
        obligations = report_data.get('obligations', {})
        oblig_text = ""

        if obligations.get('attribution'):
            oblig_text += "**Attribution Requirements:**\n"
            for item in obligations['attribution']:
                oblig_text += f"- [ ] {item}\n"
            oblig_text += "\n"

        if obligations.get('source_disclosure'):
            oblig_text += "**Source Code Disclosure:**\n"
            for item in obligations['source_disclosure']:
                oblig_text += f"- [ ] {item}\n"
            oblig_text += "\n"

        if obligations.get('license_notices'):
            oblig_text += "**License/Copyright Notices:**\n"
            for item in obligations['license_notices']:
                oblig_text += f"- [ ] {item}\n"
            oblig_text += "\n"

        if obligations.get('other'):
            oblig_text += "**Other Obligations:**\n"
            for item in obligations['other']:
                oblig_text += f"- [ ] {item}\n"

        if oblig_text:
            console.print(Panel(oblig_text.strip(), title="Project-Wide Obligations Checklist", border_style="yellow"))
            console.print()

        # 5. Critical Issues
        critical_issues = report_data.get('critical_issues', [])
        if critical_issues:
            issues_table = Table(title="Critical Issues & Recommendations", show_header=True)
            issues_table.add_column("Severity", justify="center", style="bold")
            issues_table.add_column("Issue", style="red")
            issues_table.add_column("Recommended Action", style="yellow")

            for issue in critical_issues:
                severity_emoji = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(issue.get('severity', 'low'), "⚪")
                issues_table.add_row(
                    f"{severity_emoji} {issue.get('severity', 'low').upper()}",
                    issue.get('issue', ''),
                    issue.get('action', '')
                )

            console.print(issues_table)
            console.print()

        # 6. Summary
        summary = report_data.get('summary', {})
        summary_text = f"""**Compliance Status:** {summary.get('compliance_status', 'Unknown')}

**Key Risks:**
{chr(10).join(['- ' + risk for risk in summary.get('key_risks', [])])}

**Next Steps:**
{chr(10).join(['- ' + step for step in summary.get('next_steps', [])])}"""

        console.print(Panel(summary_text, title="Summary & Next Steps", border_style="cyan"))
        console.print()

        # Append legal notices if generated
        if legal_notices:
            console.print(Panel.fit(
                "📜 LEGAL NOTICES (ATTRIBUTION)",
                style="bold yellow"
            ))
            console.print()
            console.print(legal_notices)
            console.print()

        return report_json_str

    async def analyze_path(self, session: ClientSession, path: str) -> str:
        """Perform autonomous compliance analysis on a path."""
        print(f"\n{'='*80}")
        print(f"🔍 Analyzing: {path}")
        print(f"{'='*80}")

        # Pre-analysis: Check if it's a directory with package archives
        from pathlib import Path
        path_obj = Path(path)
        directory_context = ""

        if path_obj.is_dir():
            # List files in directory
            files = list(path_obj.iterdir())
            archive_extensions = {'.jar', '.war', '.ear', '.whl', '.egg', '.tar.gz', '.tgz',
                                '.gem', '.nupkg', '.rpm', '.deb', '.apk', '.crate', '.conda'}

            # Count package archives
            archives = [f for f in files if any(str(f).endswith(ext) for ext in archive_extensions)]

            # If directory contains primarily package archives, do batch processing
            if len(archives) >= 3 and len(archives) > len(files) * 0.3:
                print(f"\n📦 Detected {len(archives)} package archives in directory")
                print(f"🔄 Switching to batch processing mode...")
                print(f"   This will analyze each package individually for accurate results\n")

                return await self._batch_analyze_packages(session, archives)

        # Step 1: LLM decides on analysis strategy
        planning_query = f"""I need to analyze this path for OSS compliance: {path}
{directory_context}

FILE TYPE RECOGNITION:
- **Package Archives** (.jar, .war, .ear, .whl, .tar.gz, .tgz, .gem, .nupkg, .crate, .conda)
  → Use check_package (extracts metadata with upmex + licenses with osslili)

- **Compiled Binaries** (.so, .dll, .dylib, .exe, .bin, ELF binaries, .apk, .ipa)
  → Use scan_binary (signature detection with binarysniffer)

- **Source Directories** (folders with source code, build files)
  → Use scan_directory (license inventory + package identification)

Based on the path, determine:
1. What type of file/path is this? (package_archive|compiled_binary|source_directory)
2. Which MCP tool should I use?
3. What analysis parameters are appropriate?

Respond with a JSON object:
{{
  "file_type": "package_archive|compiled_binary|source_directory|unknown",
  "recommended_tool": "check_package|scan_binary|scan_directory",
  "analysis_mode": "fast|standard|deep",
  "reasoning": "brief explanation with file extension recognition"
}}"""

        plan_response = await self.query_llm(planning_query)

        # Parse LLM plan
        try:
            # Extract JSON from response
            json_start = plan_response.find('{')
            json_end = plan_response.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                plan = json.loads(plan_response[json_start:json_end])
            else:
                # Default plan
                plan = {
                    "file_type": "directory",
                    "recommended_tool": "scan_directory",
                    "analysis_mode": "standard",
                    "reasoning": "Default analysis"
                }
        except json.JSONDecodeError:
            plan = {
                "file_type": "directory",
                "recommended_tool": "scan_directory",
                "analysis_mode": "standard",
                "reasoning": "Could not parse LLM plan, using defaults"
            }

        print(f"\n📋 Analysis Plan:")
        print(f"   File Type: {plan['file_type']}")
        print(f"   Tool: {plan['recommended_tool']}")
        print(f"   Mode: {plan.get('analysis_mode', 'N/A')}")
        print(f"   Reasoning: {plan['reasoning']}")

        # Step 2: Execute chosen tool
        tool_name = plan['recommended_tool']
        arguments = {}

        if tool_name == "check_package":
            # For package files, use identifier (path to the package file)
            arguments["identifier"] = path
            arguments["check_licenses"] = True
            arguments["check_vulnerabilities"] = False  # Skip vuln check for speed
        elif tool_name == "scan_binary":
            arguments["path"] = path
            arguments["analysis_mode"] = plan.get('analysis_mode', 'standard')
            arguments["check_licenses"] = True
            arguments["check_compatibility"] = True
        elif tool_name == "scan_directory":
            arguments["path"] = path
            arguments["inventory_licenses"] = True
            arguments["identify_packages"] = True

        print(f"\n⚙️  Executing {tool_name}...")
        results = await self.execute_tool(session, tool_name, arguments)

        # Step 3: LLM interprets results
        if "error" in results:
            print(f"\n❌ Tool execution failed: {results['error']}")
            return f"Analysis failed: {results['error']}"

        print(f"\n📊 Analysis complete, interpreting results...")

        interpretation_query = f"""Analyze these OSS compliance scan results and provide a clear, actionable report:

SCAN RESULTS:
{json.dumps(results, indent=2)}

Provide:
1. Executive summary of compliance status
2. License breakdown (counts and risk levels)
3. Critical issues that need immediate attention
4. Specific recommendations with priority

Format your response in clear sections with risk indicators (✅/⚠️/❌)."""

        report = await self.query_llm(interpretation_query)

        print(f"\n{'-'*80}")
        print("📄 COMPLIANCE REPORT")
        print(f"{'-'*80}\n")
        print(report)
        print(f"\n{'-'*80}\n")

        return report



async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Strands Compliance Agent - Autonomous OSS compliance analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "path",
        help="Path to analyze"
    )
    parser.add_argument(
        "--model",
        default="granite3-dense:8b",
        help="Ollama model to use (default: granite3-dense:8b, recommended for accurate results)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output"
    )

    args = parser.parse_args()

    # Create configuration
    config = AgentConfig(
        llm_model=args.model,
        verbose=args.verbose
    )

    # Initialize agent
    agent = StrandsComplianceAgent(config)
    await agent.initialize()

    # Connect to MCP server and analyze path
    async with agent.connect_mcp() as session:
        await agent.analyze_path(session, args.path)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Goodbye!")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
