# Strands Agent - Tuning Guide

This guide explains how to tune and optimize the Strands Agent for your specific use cases, including model selection, performance optimization, accuracy tuning, and customization.

## Table of Contents

- [LLM Model Selection](#llm-model-selection)
- [Temperature and Sampling](#temperature-and-sampling)
- [Analysis Mode Configuration](#analysis-mode-configuration)
- [Performance Optimization](#performance-optimization)
- [Accuracy Tuning](#accuracy-tuning)
- [Custom Prompts](#custom-prompts)
- [Policy Customization](#policy-customization)
- [Resource Management](#resource-management)
- [Error Handling](#error-handling)
- [Advanced Scenarios](#advanced-scenarios)

---

## LLM Model Selection

### Available Models

The agent works with any Ollama-supported model. Here are recommendations for different scenarios:

#### For Best Accuracy (Recommended)

```yaml
# agent_config.yaml
llm:
  model: llama3          # Best balance of accuracy and speed
  temperature: 0.1       # Low for deterministic compliance decisions
  max_tokens: 2000       # Standard response length
```

**Best for**: Production compliance analysis, legal review, critical decisions

**Pros**: High accuracy, good reasoning, reliable interpretations
**Cons**: Slower inference (~5-10s per query)
**Model size**: 4.7GB

#### For Speed (Fast Iteration)

```yaml
llm:
  model: gemma3:2b       # Smaller, faster model
  temperature: 0.0       # Deterministic
  max_tokens: 1500       # Shorter responses
```

**Best for**: CI/CD pipelines, quick checks, development testing

**Pros**: Fast inference (~1-2s per query), low memory
**Cons**: May miss nuances, less detailed reasoning
**Model size**: 1.6GB

#### For Deep Reasoning

```yaml
llm:
  model: deepseek-r1:8b  # Reasoning-optimized model
  temperature: 0.2       # Slightly higher for exploration
  max_tokens: 3000       # Allow detailed reasoning
```

**Best for**: Complex compliance scenarios, ambiguous cases, policy design

**Pros**: Excellent reasoning, handles edge cases
**Cons**: Slowest inference (~15-20s), larger responses
**Model size**: 5.2GB

#### Comparison Table

| Model | Size | Speed | Accuracy | Reasoning | Best For |
|-------|------|-------|----------|-----------|----------|
| **llama3** | 4.7GB | Medium | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | Production |
| gemma3:2b | 1.6GB | Fast | ⭐⭐⭐ | ⭐⭐⭐ | CI/CD |
| deepseek-r1:8b | 5.2GB | Slow | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | Complex cases |
| mistral:7b | 4.1GB | Medium | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ | General use |

### Installing Additional Models

```bash
# Install a specific model
ollama pull gemma3:2b

# List available models
ollama list

# Test a model
ollama run gemma3:2b "Explain GPL-3.0 license obligations"
```

### Switching Models at Runtime

```bash
# Use different model for specific analysis
python agent.py /path/to/project --model deepseek-r1:8b

# Use verbose output for debugging
python agent.py /path/to/project --model gemma3:2b --verbose
```

---

## Temperature and Sampling

Temperature controls randomness in LLM responses. For compliance analysis, you want **low randomness** (deterministic decisions).

### Temperature Settings

#### Ultra-Deterministic (0.0)

```yaml
llm:
  temperature: 0.0
```

**Use when**:
- CI/CD pipelines (reproducible results)
- Automated compliance gates
- Policy violation detection

**Behavior**: Always selects most likely token, completely deterministic
**Trade-off**: May be overly conservative, less creative problem-solving

#### Recommended (0.1)

```yaml
llm:
  temperature: 0.1
```

**Use when**:
- Production compliance analysis
- General purpose scanning
- Standard analysis workflows

**Behavior**: Mostly deterministic with slight variation
**Trade-off**: Best balance for compliance work

#### Exploratory (0.3-0.5)

```yaml
llm:
  temperature: 0.3
```

**Use when**:
- Policy design and exploration
- Research and learning
- Handling novel license scenarios

**Behavior**: More varied responses, creative reasoning
**Trade-off**: Less reproducible, may suggest unconventional approaches

### Advanced Sampling Parameters

Edit `agent.py` to add custom Ollama parameters:

```python
response = ollama.chat(
    model=self.config.llm_model,
    messages=messages,
    options={
        "temperature": 0.1,
        "top_k": 40,           # Limit to top 40 tokens
        "top_p": 0.9,          # Nucleus sampling threshold
        "repeat_penalty": 1.1,  # Penalize repetition
        "num_predict": 2000,    # Max tokens
    }
)
```

**Tuning guide**:
- `top_k`: Lower (20-30) = more focused, Higher (50-100) = more diverse
- `top_p`: Lower (0.7-0.8) = conservative, Higher (0.95) = exploratory
- `repeat_penalty`: 1.0 = no penalty, 1.2 = strong penalty against repetition

---

## Analysis Mode Configuration

The agent chooses analysis modes based on context. You can influence these decisions by tuning the system prompt.

### Default Behavior

```python
# In agent.py, the LLM automatically selects:
# - fast: For quick checks, CI/CD, large files (>100MB)
# - standard: For most cases (default)
# - deep: For critical assessments, pre-release, legal review
```

### Force Specific Mode

Modify `agent.py` to always use a specific mode:

```python
# In analyze_path() method, override LLM decision:
arguments = {"path": path}

if tool_name == "scan_binary":
    arguments["analysis_mode"] = "deep"  # Force deep analysis
    arguments["check_licenses"] = True
    arguments["check_compatibility"] = True
```

### Mode Selection Tuning

Adjust the planning prompt in `agent.py`:

```python
planning_query = f"""I need to analyze this path for OSS compliance: {path}

ANALYSIS MODE GUIDELINES:
- fast: Use ONLY for very large files (>500MB) or CI/CD time constraints
- standard: Default for most production scans
- deep: ALWAYS use for:
  * Pre-release compliance review
  * Legal documentation
  * Firmware and embedded systems
  * Files with previous compliance issues
  * Any case where accuracy is critical

Based on the path, determine:
1. Is this likely a binary file or source code directory?
2. Which MCP tool(s) should I use?
3. What analysis parameters are appropriate?
"""
```

### Mode Performance Characteristics

| Mode | Speed | Accuracy | Memory | Use Case |
|------|-------|----------|--------|----------|
| **fast** | ~5s | 85% | Low | CI/CD, quick checks |
| **standard** | ~15s | 95% | Medium | Production scans |
| **deep** | ~45s | 99% | High | Legal review, critical |

---

## Performance Optimization

### 1. Reduce LLM Response Time

```yaml
# agent_config.yaml
llm:
  model: gemma3:2b       # Smaller model
  max_tokens: 1000       # Shorter responses
  temperature: 0.0       # No sampling overhead
```

**Impact**: 3-5x faster LLM inference
**Trade-off**: Less detailed explanations

### 2. Limit Conversation History

```python
# In agent.py, adjust history limit:
if len(self.conversation_history) > 10:  # Reduce from 20 to 10
    self.conversation_history = self.conversation_history[-10:]
```

**Impact**: Lower memory, faster context loading
**Trade-off**: Agent forgets older context

### 3. Parallel Tool Execution

For batch analysis, modify `agent.py` to run tools in parallel:

```python
import asyncio

async def analyze_batch(self, session, paths: List[str]):
    """Analyze multiple paths in parallel."""
    tasks = [
        self.analyze_path(session, path)
        for path in paths
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    return results
```

**Impact**: 4-8x faster for batch operations
**Trade-off**: Higher memory usage

### 4. Cache MCP Tool Results

Add caching to avoid re-scanning unchanged files:

```python
import hashlib
from functools import lru_cache

@lru_cache(maxsize=100)
def _cache_key(path: str) -> str:
    """Generate cache key from file path and modification time."""
    stat = Path(path).stat()
    return f"{path}:{stat.st_mtime}"

# In execute_tool():
cache_key = _cache_key(arguments["path"])
if cache_key in self._tool_cache:
    return self._tool_cache[cache_key]

result = await session.call_tool(tool_name, arguments=arguments)
self._tool_cache[cache_key] = result
return result
```

**Impact**: Instant results for repeated scans
**Trade-off**: May miss changes if modification time unchanged

### 5. Streaming Responses

For very large analyses, stream results:

```python
# Modify execute_tool() to stream results
async def execute_tool_streaming(self, session, tool_name, arguments):
    """Stream tool results as they become available."""
    result = await session.call_tool(tool_name, arguments=arguments)

    # Process results incrementally
    for chunk in result:
        yield chunk  # Stream to LLM immediately
```

**Impact**: Lower latency, better UX for long operations
**Trade-off**: More complex implementation

---

## Accuracy Tuning

### 1. Improve Tool Selection

Enhance the system prompt with more specific guidance:

```python
def _build_system_prompt(self) -> str:
    return f"""You are an expert OSS compliance analyst.

FILE TYPE RECOGNITION (critical for accuracy):
- .apk, .ipa, .aab → ALWAYS use scan_binary
- .exe, .dll, .so, .dylib → ALWAYS use scan_binary
- .jar, .war, .ear → ALWAYS use scan_binary
- .bin, .img, .hex → ALWAYS use scan_binary (firmware)
- Directory with source files → use scan_directory
- When in doubt → use scan_binary (safer)

CONFIDENCE THRESHOLDS:
- Default: 0.5 (balanced)
- High precision: 0.7 (fewer false positives)
- High recall: 0.3 (catch more components)

ALWAYS explain your reasoning for tool selection."""
```

### 2. Validate LLM Decisions

Add validation logic to catch errors:

```python
# After LLM planning:
if plan['file_type'] == 'binary' and plan['recommended_tool'] != 'scan_binary':
    print("⚠️  Warning: Binary file but scan_directory suggested")
    print("   Overriding to scan_binary for accuracy")
    plan['recommended_tool'] = 'scan_binary'
```

### 3. Multi-Pass Analysis

For critical files, analyze multiple times and aggregate:

```python
async def analyze_critical(self, session, path):
    """Run multiple analyses and aggregate results."""
    # Pass 1: Fast scan for overview
    fast_result = await self.execute_tool(
        session, "scan_binary",
        {"path": path, "analysis_mode": "fast"}
    )

    # Pass 2: Deep scan for accuracy
    deep_result = await self.execute_tool(
        session, "scan_binary",
        {"path": path, "analysis_mode": "deep"}
    )

    # LLM compares results and reconciles
    comparison = await self.query_llm(
        f"Compare these two scan results and identify any discrepancies:\n"
        f"Fast: {fast_result}\nDeep: {deep_result}"
    )

    return comparison
```

**Impact**: Catch edge cases and false positives
**Trade-off**: 2x slower

### 4. Confidence Threshold Tuning

Adjust based on your tolerance for false positives:

```yaml
# agent_config.yaml
analysis:
  confidence_threshold: 0.7  # Higher = fewer false positives
```

**Guidelines**:
- **0.3**: High recall, catches everything (many false positives)
- **0.5**: Balanced (recommended for most cases)
- **0.7**: High precision, only confident matches (may miss some)
- **0.9**: Ultra-conservative, very few results

### 5. Add Domain-Specific Knowledge

Enhance the agent with your organization's specific knowledge:

```python
CUSTOM_LICENSE_RULES = """
CUSTOM ORGANIZATIONAL RULES:
- React Native components are approved for mobile apps
- Apache-2.0 with LLVM Exception is allowed
- JSON licenses are considered permissive (despite not being SPDX)
- Internal libraries under "proprietary" are exempt from scanning
"""

# Add to system prompt:
system_prompt = f"{base_prompt}\n\n{CUSTOM_LICENSE_RULES}"
```

---

## Custom Prompts

### Customize Planning Prompt

```python
# In agent.py, modify planning_query:
planning_query = f"""[CUSTOM INSTRUCTIONS]

I need to analyze: {path}

Our organization's priorities:
1. App Store compatibility is CRITICAL
2. We prefer Apache-2.0 and MIT licenses
3. LGPL requires legal team approval
4. Any GPL variant is BLOCKED

Determine the analysis strategy..."""
```

### Customize Interpretation Prompt

```python
# Modify interpretation_query:
interpretation_query = f"""Analyze these results with focus on:

1. CRITICAL BLOCKERS (GPL, AGPL, proprietary without license)
2. App Store compatibility issues
3. Attribution requirements (we need exact text)
4. Vulnerability severity (CVSS > 7.0)

Results: {json.dumps(results, indent=2)}

Format report with:
- Executive summary (2-3 sentences)
- Risk level: CRITICAL/HIGH/MEDIUM/LOW/SAFE
- Immediate action items (numbered list)
- Long-term recommendations"""
```

### Add Domain-Specific Templates

```python
MOBILE_APP_TEMPLATE = """You are analyzing a mobile application.

CRITICAL CHECKS:
✓ GPL-3.0 is BLOCKED (App Store incompatible)
✓ AGPL-3.0 is BLOCKED (network copyleft)
✓ All components need attribution in app
✓ Check for ad SDKs with privacy concerns

Provide mobile-specific recommendations."""

EMBEDDED_TEMPLATE = """You are analyzing embedded firmware.

CRITICAL CHECKS:
✓ GPL requires offering source to customers
✓ Check for linking (static vs dynamic)
✓ Verify license texts fit in flash memory
✓ Consider update mechanisms for compliance

Provide firmware-specific recommendations."""
```

Apply templates based on analysis type:

```python
def _get_domain_template(self, path: str) -> str:
    """Select template based on file type."""
    if path.endswith(('.apk', '.ipa')):
        return MOBILE_APP_TEMPLATE
    elif path.endswith(('.bin', '.hex', '.img')):
        return EMBEDDED_TEMPLATE
    else:
        return ""  # Use default

# In _build_system_prompt():
domain_template = self._get_domain_template(current_analysis_path)
return f"{base_prompt}\n\n{domain_template}"
```

---

## Policy Customization

### 1. Policy File Structure

```yaml
# policy.yaml
policy_name: "Custom Policy"
version: "2.0"

# Simple lists
allowed_licenses:
  - MIT
  - Apache-2.0

# With conditions
conditional_licenses:
  LGPL-2.1:
    condition: "dynamic_linking_only"
    requires_approval: true
    approver: "legal@company.com"

  GPL-2.0:
    condition: "separate_process_only"
    requires_source_disclosure: true
    documentation_required: true

# Custom rules with regex
custom_rules:
  - name: "Block viral licenses in mobile"
    pattern: "(A?GPL|SSPL|EUPL).*"
    applies_to: ["mobile", "saas"]
    action: "block"
    reason: "Copyleft incompatible with business model"

  - name: "Require notices in all distributions"
    pattern: ".*"
    requires_action: "include_notice"
    notice_location: "assets/LICENSES.txt"

# Risk scoring
risk_scoring:
  high_risk:
    - "GPL-3.0"
    - "AGPL-3.0"
    - "SSPL-1.0"
  medium_risk:
    - "LGPL-3.0"
    - "MPL-2.0"
  low_risk:
    - "MIT"
    - "Apache-2.0"
    - "BSD-*"
```

### 2. Teaching the Agent Your Policy

Add policy interpretation to the system prompt:

```python
def _load_policy_guidance(self) -> str:
    """Load policy file and convert to LLM guidance."""
    policy_file = Path("policy.yaml")
    if not policy_file.exists():
        return ""

    with open(policy_file) as f:
        policy = yaml.safe_load(f)

    guidance = f"""
ORGANIZATIONAL LICENSE POLICY ({policy['policy_name']} v{policy['version']}):

ALLOWED (✅ Safe to use):
{chr(10).join(f"- {lic}" for lic in policy['allowed_licenses'])}

BLOCKED (❌ Must not use):
{chr(10).join(f"- {lic}" for lic in policy['blocked_licenses'])}

REQUIRES REVIEW (⚠️ Legal approval needed):
{chr(10).join(f"- {lic}" for lic in policy.get('review_required', []))}

When analyzing, ALWAYS check licenses against this policy.
Clearly flag violations and provide specific remediation steps.
"""
    return guidance

# Add to system prompt:
policy_guidance = self._load_policy_guidance()
system_prompt = f"{base_prompt}\n\n{policy_guidance}"
```

### 3. Multi-Policy Support

Support different policies for different projects:

```python
async def analyze_with_policy(self, session, path, policy_name="default"):
    """Analyze with specific policy."""
    policy_file = f"policies/{policy_name}.yaml"

    # Load policy-specific guidance
    policy_guidance = self._load_policy_guidance(policy_file)

    # Temporarily override system prompt
    original_prompt = self._build_system_prompt
    self._build_system_prompt = lambda: f"{original_prompt()}\n\n{policy_guidance}"

    result = await self.analyze_path(session, path)

    # Restore original prompt
    self._build_system_prompt = original_prompt

    return result
```

Usage:

```bash
python agent.py analyze app.apk --policy mobile-strict
python agent.py analyze firmware.bin --policy embedded-gpl-ok
```

---

## Resource Management

### 1. Memory Limits

```yaml
# agent_config.yaml
resources:
  max_memory_mb: 4096        # Maximum RAM usage
  max_file_size_mb: 500      # Skip files larger than this
  max_conversation_history: 10  # Limit history items
```

Implement in `agent.py`:

```python
import psutil

def _check_memory_usage(self):
    """Check if memory usage exceeds limit."""
    process = psutil.Process()
    memory_mb = process.memory_info().rss / 1024 / 1024

    if memory_mb > self.config.max_memory_mb:
        # Clear caches
        self.conversation_history = []
        self._tool_cache.clear()
        print(f"⚠️  Memory limit reached ({memory_mb:.0f}MB), cleared caches")
```

### 2. Timeout Configuration

```yaml
mcp:
  timeout: 300              # Overall MCP operation timeout
  tool_timeout:
    scan_directory: 600     # 10 minutes for large directories
    scan_binary: 180        # 3 minutes for binaries
    generate_sbom: 300      # 5 minutes for SBOM generation
```

### 3. Concurrent Request Limiting

```python
from asyncio import Semaphore

class StrandsComplianceAgent:
    def __init__(self, config):
        self.config = config
        self.semaphore = Semaphore(4)  # Max 4 concurrent operations

    async def execute_tool(self, session, tool_name, arguments):
        async with self.semaphore:
            # Tool execution here
            pass
```

### 4. Disk Space Management

```python
def _check_disk_space(self, required_mb=1000):
    """Ensure sufficient disk space for analysis."""
    stat = os.statvfs('/')
    available_mb = (stat.f_bavail * stat.f_frsize) / 1024 / 1024

    if available_mb < required_mb:
        raise RuntimeError(
            f"Insufficient disk space: {available_mb:.0f}MB available, "
            f"{required_mb}MB required"
        )
```

---

## Error Handling

### 1. Retry Logic

```python
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10)
)
async def execute_tool_with_retry(self, session, tool_name, arguments):
    """Execute tool with automatic retry on failure."""
    try:
        return await self.execute_tool(session, tool_name, arguments)
    except Exception as e:
        print(f"⚠️  Tool execution failed, retrying: {e}")
        raise
```

### 2. Graceful Degradation

```python
async def analyze_path_robust(self, session, path):
    """Analyze with fallback strategies."""
    try:
        # Try primary strategy
        return await self.analyze_path(session, path)
    except ToolExecutionError as e:
        print(f"⚠️  Primary analysis failed: {e}")

        # Fallback 1: Try simpler analysis mode
        try:
            print("   Trying fast mode as fallback...")
            return await self.analyze_path_simple(session, path)
        except Exception as e2:
            print(f"⚠️  Fallback also failed: {e2}")

            # Fallback 2: Return LLM-based analysis only
            print("   Using LLM-only analysis...")
            return await self.analyze_with_llm_only(path)
```

### 3. Error Context

```python
async def execute_tool(self, session, tool_name, arguments):
    try:
        result = await session.call_tool(tool_name, arguments=arguments)
        return result
    except Exception as e:
        # Provide rich error context
        error_context = {
            "tool": tool_name,
            "arguments": arguments,
            "error": str(e),
            "timestamp": datetime.now().isoformat(),
            "session_state": "active" if session else "closed"
        }

        # Log for debugging
        with open("error_log.json", "a") as f:
            json.dump(error_context, f)
            f.write("\n")

        # Return structured error
        return {
            "error": str(e),
            "context": error_context,
            "suggestion": self._suggest_fix(e)
        }

def _suggest_fix(self, error):
    """Suggest fixes based on error type."""
    if "timeout" in str(error).lower():
        return "Try increasing timeout in agent_config.yaml or use 'fast' analysis mode"
    elif "not found" in str(error).lower():
        return "Check that SEMCL.ONE tools are installed and in PATH"
    else:
        return "Check error_log.json for details"
```

---

## Advanced Scenarios

### 1. Multi-Model Ensemble

Use different models for different tasks:

```python
class EnsembleAgent(StrandsComplianceAgent):
    """Agent using multiple models for different tasks."""

    async def query_llm(self, user_message, context=None, task_type="general"):
        """Route to appropriate model based on task."""

        # Select model based on task
        if task_type == "planning":
            model = "llama3"  # Good at strategic decisions
        elif task_type == "interpretation":
            model = "deepseek-r1:8b"  # Best at analysis
        elif task_type == "reporting":
            model = "mistral:7b"  # Good at formatting
        else:
            model = self.config.llm_model

        # Temporarily override model
        original_model = self.config.llm_model
        self.config.llm_model = model

        result = await super().query_llm(user_message, context)

        self.config.llm_model = original_model
        return result
```

### 2. Human-in-the-Loop

Add approval gates for critical decisions:

```python
async def analyze_with_approval(self, session, path):
    """Require human approval for high-risk findings."""

    # Run analysis
    result = await self.analyze_path(session, path)

    # Parse for risk level
    if "HIGH" in result or "CRITICAL" in result:
        print("\n⚠️  HIGH RISK FINDINGS DETECTED")
        print(result)
        print("\nRequires human review.")

        approval = input("\nProceed with this analysis? (yes/no): ")
        if approval.lower() not in ['yes', 'y']:
            return "Analysis aborted by user"

    return result
```

### 3. Continuous Learning

Collect feedback to improve prompts:

```python
async def analyze_with_feedback(self, session, path):
    """Analyze and collect user feedback."""

    result = await self.analyze_path(session, path)

    print(result)
    print("\n" + "="*60)
    print("Was this analysis helpful? (1-5, 5=excellent): ", end="")
    rating = input()

    print("Any specific issues or suggestions?: ", end="")
    feedback = input()

    # Save feedback
    feedback_data = {
        "path": path,
        "rating": rating,
        "feedback": feedback,
        "result": result,
        "timestamp": datetime.now().isoformat()
    }

    with open("feedback.jsonl", "a") as f:
        json.dump(feedback_data, f)
        f.write("\n")

    # Use feedback to improve prompts over time
    if int(rating) < 3:
        print("\n💡 Feedback recorded. We'll improve this analysis type.")

    return result
```

### 4. Custom Tool Integration

Add your own compliance tools:

```python
async def execute_custom_tool(self, tool_name, arguments):
    """Execute custom organizational tools."""

    if tool_name == "check_internal_blocklist":
        # Call internal API
        response = requests.post(
            "https://internal.company.com/license-check",
            json=arguments
        )
        return response.json()

    elif tool_name == "generate_legal_notice":
        # Custom notice generator
        return self._generate_company_notice(arguments)

    else:
        raise ValueError(f"Unknown custom tool: {tool_name}")
```

### 5. Integration with External Systems

```python
async def analyze_and_notify(self, session, path):
    """Analyze and send results to external systems."""

    result = await self.analyze_path(session, path)

    # Send to compliance tracking system
    requests.post(
        "https://compliance.company.com/api/scan-results",
        json={
            "path": path,
            "result": result,
            "timestamp": datetime.now().isoformat(),
            "agent_version": "1.0"
        }
    )

    # Create JIRA ticket for violations
    if "CRITICAL" in result or "BLOCKED" in result:
        jira_client.create_issue(
            project="COMPLIANCE",
            summary=f"License violation in {path}",
            description=result,
            priority="High"
        )

    # Post to Slack
    if "HIGH" in result:
        slack_client.post_message(
            channel="#compliance-alerts",
            text=f"⚠️ High-risk findings in {path}\n```{result}```"
        )

    return result
```

---

## Quick Reference

### Common Tuning Scenarios

| Scenario | Model | Temp | Mode | Threshold |
|----------|-------|------|------|-----------|
| **Production scan** | llama3 | 0.1 | standard | 0.5 |
| **CI/CD gate** | gemma3:2b | 0.0 | fast | 0.5 |
| **Legal review** | deepseek-r1 | 0.1 | deep | 0.7 |
| **Research** | llama3 | 0.3 | standard | 0.3 |
| **Mobile app** | llama3 | 0.1 | standard | 0.5 |
| **Embedded** | deepseek-r1 | 0.1 | deep | 0.7 |

### Performance vs Accuracy

```
Fast & Less Accurate          ←→          Slow & Very Accurate
├─────────┼─────────┼─────────┼─────────┼─────────┤
gemma3:2b  llama3   mistral   deepseek  ensemble
temp=0.0   temp=0.1 temp=0.1  temp=0.1  temp=0.1
fast mode  standard deep mode deep mode deep+multi
threshold  threshold threshold threshold threshold
  =0.5      =0.5      =0.7      =0.7      =0.9
```

### Checklist for Tuning

- [ ] Select appropriate model for use case
- [ ] Set temperature (0.0-0.1 for compliance)
- [ ] Configure analysis modes
- [ ] Tune confidence thresholds
- [ ] Customize prompts for domain
- [ ] Load organizational policy
- [ ] Set resource limits
- [ ] Add error handling
- [ ] Test with sample files
- [ ] Measure and iterate

---

## Support

For questions about tuning:
- **Documentation**: See README.md for basic usage
- **Examples**: Run `python test_agent.py` to validate setup
- **Issues**: https://github.com/SemClone/mcp-semclone/issues

**Pro Tip**: Start with default settings, measure performance, then tune incrementally. Don't over-optimize without data!
