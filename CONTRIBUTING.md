# Contributing to CyberShield OSS

Thank you for your interest in contributing to CyberShield OSS! This guide will help you get started.

## How to Contribute

### Reporting Bugs

1. Check [existing issues](https://github.com/minidu-lab/cybershield-oss/issues) to avoid duplicates
2. Use the **Bug Report** issue template
3. Include: steps to reproduce, expected vs actual behavior, environment info

### Suggesting Features

1. Open a **Feature Request** issue
2. Describe the use case and why it would be valuable
3. Include examples of how it would work

### Submitting Code

1. **Fork** the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass: `pytest tests/ -v`
6. Run linting: `flake8 cybershield/` and `black cybershield/ --check`
7. Submit a **Pull Request**

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/cybershield-oss.git
cd cybershield-oss

# Create virtual environment
python -m venv venv
source venv/bin/activate

# Install with dev dependencies
pip install -r requirements.txt
pip install -e ".[dev]"

# Run tests
pytest tests/ -v --cov=cybershield

# Run linting
flake8 cybershield/
black cybershield/
isort cybershield/
mypy cybershield/
```

## Writing a Custom Scanner

The easiest way to contribute is by adding a new scanner module. See `examples/custom_scanner.py` for a template.

1. Create a new file in `cybershield/scanners/`
2. Inherit from `BaseScanner`
3. Implement the `scan()` method
4. Add tests in `tests/`
5. Register the scanner in `cybershield/core.py`

## Code Style

- Follow PEP 8 (enforced by `flake8`)
- Use `black` for formatting (line length: 88)
- Use `isort` for import ordering
- Add type hints to all public functions
- Write docstrings for all classes and public methods

## Testing Guidelines

- All new features must include tests
- Maintain >80% code coverage
- Use `aioresponses` for mocking HTTP requests
- Use `pytest-asyncio` for async tests
- Never make real HTTP requests in tests

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add directory traversal scanner
fix: handle timeout in XSS scanner
docs: update API usage examples
test: add CSRF token detection tests
refactor: simplify report generation logic
```

## Code of Conduct

By participating, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md).

## Questions?

Open a [Discussion](https://github.com/minidu-lab/cybershield-oss/discussions) or reach out via issues.

---

Thank you for helping make the web more secure! 🛡
