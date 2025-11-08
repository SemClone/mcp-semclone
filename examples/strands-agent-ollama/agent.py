#!/usr/bin/env python3
"""
Strands Agent - Autonomous OSS Compliance Agent using Ollama + MCP

This agent demonstrates how to build an autonomous compliance system that:
- Uses Ollama (llama3) for local LLM inference
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
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client
except ImportError:
    print("❌ Error: 'mcp' package not installed")
    print("Install with: pip install mcp")
    sys.exit(1)


@dataclass
class AgentConfig:
    """Agent configuration."""
    llm_model: str = "llama3"
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

    async def analyze_path(self, session: ClientSession, path: str) -> str:
        """Perform autonomous compliance analysis on a path."""
        print(f"\n{'='*80}")
        print(f"🔍 Analyzing: {path}")
        print(f"{'='*80}")

        # Step 1: LLM decides on analysis strategy
        planning_query = f"""I need to analyze this path for OSS compliance: {path}

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
        default="llama3",
        help="Ollama model to use (default: llama3)"
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
