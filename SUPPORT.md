# Support

## How to Get Help

Thank you for using mcp-semclone! Here are the best ways to get help:

### Documentation

- Check the [README](README.md) for basic usage and setup instructions
- Review the [CONTRIBUTING](CONTRIBUTING.md) guide for development setup
- See the [Mobile App Compliance Guide](guides/MOBILE_APP_COMPLIANCE_GUIDE.md) for workflow instructions
- Look through existing documentation in the `/examples` folder

### Getting Answers

**Before opening an issue:**
1. Search existing [GitHub Issues](../../issues) to see if your question has been answered
2. Check closed issues as well - your question might have been resolved
3. Review the project's documentation thoroughly
4. Test with a simple MCP client setup

### Reporting Issues

If you've found a bug or have a feature request:

1. **Search first**: Check if someone else has already reported the same issue
2. **Create a detailed report**: Use our issue templates when available
3. **Include context**: Provide OS, Python version, MCP client, and SEMCL.ONE tool versions
4. **Share reproducible steps**: Help us understand how to reproduce the issue
5. **Include tool outputs**: Share error messages from SEMCL.ONE tools if relevant

### MCP-Specific Support

For MCP integration issues:
- Specify your MCP client (desktop client, etc.)
- Include your configuration file (redacted of sensitive data)
- Test the server directly with `python -m mcp_semclone.server`
- Check that all SEMCL.ONE tools are properly installed

### Feature Requests

We welcome feature suggestions! Please:
- Check existing issues for similar requests
- Clearly describe the feature and its use case
- Explain why this feature would be valuable to the project
- Consider MCP protocol compatibility

### Security Issues

For security vulnerabilities, please refer to our [SECURITY](SECURITY.md) policy for responsible disclosure guidelines.

## Community Guidelines

Please review our [Code of Conduct](CODE_OF_CONDUCT.md) before participating in discussions.

## Response Times

This project is maintained by a small team. While we strive to respond quickly:
- Issues: Initial response within 7 days
- Pull requests: Review within 14 days
- Security issues: Within 48 hours

## Troubleshooting

### Common Issues

1. **Tools not found**: Ensure all SEMCL.ONE tools are installed and in PATH
2. **Permission errors**: Check file/directory permissions for scanning
3. **MCP connection issues**: Verify server configuration and client setup
4. **API rate limits**: Add optional API keys for higher rate limits

### Debug Mode

Enable debug logging:
```bash
export MCP_LOG_LEVEL=DEBUG
python -m mcp_semclone.server
```

## Additional Resources

- **Project Homepage**: [GitHub Repository](../../)
- **SEMCL.ONE Toolchain**: [Main Project](https://github.com/SemClone/semcl.one)
- **Model Context Protocol**: [MCP Documentation](https://modelcontextprotocol.io/)
- **License**: See [LICENSE](LICENSE) file
- **Contributing**: See [CONTRIBUTING](CONTRIBUTING.md) guide

---

**Note**: This is an open-source project maintained by volunteers. Response times may vary based on contributor availability.