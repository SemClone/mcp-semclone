# Contributing to mcp-semclone

We welcome contributions to mcp-semclone! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct, which promotes a respectful and inclusive environment for all contributors.

## How to Contribute

### Reporting Issues

- Check if the issue already exists in the [issue tracker](https://github.com/SemClone/mcp-semclone/issues)
- Provide a clear description of the problem
- Include steps to reproduce the issue
- Specify your environment (OS, Python version, mcp-semclone version)
- Include MCP client details (desktop client, etc.)

### Suggesting Enhancements

- Open an issue describing the enhancement
- Explain the use case and benefits
- Provide examples if possible
- Consider MCP protocol compatibility

### Pull Requests

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add or update tests as needed
5. Ensure all tests pass (`pytest`)
6. Update documentation if needed
7. Commit your changes (`git commit -m 'Add amazing feature'`)
8. Push to your branch (`git push origin feature/amazing-feature`)
9. Open a Pull Request

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/SemClone/mcp-semclone.git
   cd mcp-semclone
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install in development mode:
   ```bash
   pip install -e .[dev]
   ```

4. Install SEMCL.ONE dependencies:
   ```bash
   pip install purl2notices osslili binarysniffer ospac vulnq upmex
   ```

5. Install pre-commit hooks:
   ```bash
   pre-commit install
   ```

## Testing

Run the test suite:
```bash
pytest
```

Run with coverage:
```bash
pytest --cov=mcp_semclone tests/
```

Test MCP server directly:
```bash
python -m mcp_semclone.server
```

## Code Style

We use the following tools to maintain code quality:

- **Black** for code formatting
- **isort** for import sorting
- **flake8** for linting
- **mypy** for type checking

Run all checks:
```bash
black mcp_semclone/
isort mcp_semclone/
flake8 mcp_semclone/
mypy mcp_semclone/
```

Or use pre-commit:
```bash
pre-commit run --all-files
```

## Documentation

- Update the README.md if you change functionality
- Add docstrings to all public functions and classes
- Update CHANGELOG.md following [Keep a Changelog](https://keepachangelog.com/) format
- Update guides/MOBILE_APP_COMPLIANCE_GUIDE.md for workflow changes

## Adding New MCP Tools

To add a new MCP tool:

1. Add the tool function to `mcp_semclone/server.py`
2. Follow the MCP tool specification pattern
3. Add proper error handling and validation
4. Update the tool list in the server configuration
5. Add tests for the new functionality
6. Update documentation

Example structure:
```python
@server.call_tool()
async def new_tool(arguments: dict) -> list[TextContent]:
    """New tool description"""
    try:
        # Implementation here
        result = await some_operation(arguments)
        return [TextContent(type="text", text=json.dumps(result))]
    except Exception as e:
        return [TextContent(type="text", text=f"Error: {str(e)}")]
```

## Adding New SEMCL.ONE Tool Integration

To integrate a new SEMCL.ONE tool:

1. Add the tool client to the server initialization
2. Implement error handling for tool availability
3. Add graceful degradation if tool is missing
4. Update the tool detection logic
5. Add comprehensive tests
6. Document the new integration

## MCP Protocol Compliance

- Follow the [MCP specification](https://modelcontextprotocol.io/)
- Ensure all tools return proper TextContent
- Use appropriate error handling patterns
- Test with multiple MCP clients when possible

## Commit Messages

Follow these guidelines for commit messages:

- Use present tense ("Add feature" not "Added feature")
- Use imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit first line to 72 characters
- Reference issues and pull requests when relevant

## Release Process

1. Update version in `pyproject.toml`
2. Update CHANGELOG.md
3. Create a git tag: `git tag v0.1.0`
4. Push tag: `git push origin v0.1.0`
5. GitHub Actions will automatically publish to PyPI

## Security Considerations

- Never commit API keys or sensitive data
- Follow the git hooks to prevent problematic keywords
- Test with untrusted input to ensure safety
- Consider the security implications of tool integrations

## Questions?

Feel free to open an issue or discussion on GitHub if you have questions about contributing.

Thank you for contributing to mcp-semclone!