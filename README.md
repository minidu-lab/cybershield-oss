<p align="center">
  <img src="docs/logo.png" alt="CyberShield OSS" width="200">
  <br>
  <strong>CyberShield OSS</strong>
  <br>
  AI-Assisted Cybersecurity Scanner & Developer Education Platform
</p>

<p align="center">
  <a href="https://github.com/minidu-lab/cybershield-oss/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/Python-3.10%2B-blue.svg" alt="Python 3.10+"></a>
  <a href="https://github.com/minidu-lab/cybershield-oss/issues"><img src="https://img.shields.io/github/issues/minidu-lab/cybershield-oss" alt="Issues"></a>
  <a href="https://github.com/minidu-lab/cybershield-oss/stargazers"><img src="https://img.shields.io/github/stars/minidu-lab/cybershield-oss" alt="Stars"></a>
</p>

---

## What is CyberShield OSS?

CyberShield OSS is a **free, open-source** cybersecurity scanner that uses AI to make vulnerability reports understandable for everyone. It scans web applications for common vulnerabilities and uses **Claude by Anthropic** to generate clear, plain-English explanations with actionable remediation guidance.

### Who is it for?

- **Indie developers** who can't afford enterprise security tools like Snyk, Burp Suite, or Veracode
- **Cybersecurity students** who need hands-on practice with real-world vulnerabilities
- **Open-source maintainers** who want to keep their projects secure

## Features

| Feature | Description |
|---------|-------------|
| **XSS Scanner** | Detects reflected and stored cross-site scripting vulnerabilities |
| **SQL Injection Scanner** | Identifies SQL injection points in query parameters and forms |
| **CSRF Scanner** | Checks for missing or weak CSRF token protections |
| **Auth Scanner** | Detects broken authentication patterns (weak sessions, missing headers) |
| **API Key Scanner** | Finds exposed API keys, tokens, and secrets in source code and responses |
| **AI Explanations** | Claude-powered plain-English vulnerability reports |
| **Security Tutor** | Interactive chat interface for learning about security concepts |
| **HTML/JSON Reports** | Export scan results in multiple formats |
| **CI/CD Integration** | GitHub Actions workflow for automated scanning |

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/minidu-lab/cybershield-oss.git
cd cybershield-oss

# Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

### Configuration

Create a `.env` file in the project root:

```env
ANTHROPIC_API_KEY=your_api_key_here
CYBERSHIELD_LOG_LEVEL=INFO
CYBERSHIELD_MAX_CONCURRENT=5
CYBERSHIELD_TIMEOUT=30
```

### Usage

#### Command-Line Scanner

```bash
# Basic scan
cybershield scan https://example.com

# Full scan with all modules
cybershield scan https://example.com --modules all

# Scan specific vulnerabilities
cybershield scan https://example.com --modules xss,sqli,csrf

# Generate HTML report with AI explanations
cybershield scan https://example.com --report html --ai-explain

# Export JSON report
cybershield scan https://example.com --report json -o results.json
```

#### Security Tutor (Interactive Mode)

```bash
# Start the interactive security tutor
cybershield tutor

# Ask about a specific vulnerability
cybershield tutor --topic "SQL injection"
```

#### Python API

```python
from cybershield import CyberShield

# Initialize scanner
scanner = CyberShield(api_key="your_anthropic_api_key")

# Run a scan
results = scanner.scan("https://example.com", modules=["xss", "sqli", "csrf"])

# Get AI-powered explanations
for vuln in results.vulnerabilities:
    explanation = vuln.explain()  # Uses Claude API
    print(f"[{vuln.severity}] {vuln.title}")
    print(f"  → {explanation.summary}")
    print(f"  → Fix: {explanation.remediation}")
```

## Architecture

```
cybershield-oss/
├── cybershield/              # Main package
│   ├── __init__.py           # Package init & version
│   ├── cli.py                # CLI entry point (Click)
│   ├── core.py               # Core scanner orchestrator
│   ├── config.py             # Configuration management
│   ├── scanners/             # Vulnerability scanner modules
│   │   ├── __init__.py
│   │   ├── base.py           # Base scanner class
│   │   ├── xss.py            # XSS detection
│   │   ├── sqli.py           # SQL injection detection
│   │   ├── csrf.py           # CSRF detection
│   │   ├── auth.py           # Authentication issues
│   │   └── api_keys.py       # Exposed secrets detection
│   ├── ai/                   # Claude AI integration
│   │   ├── __init__.py
│   │   ├── client.py         # Anthropic API client wrapper
│   │   ├── explainer.py      # Vulnerability explanation pipeline
│   │   └── tutor.py          # Interactive security tutor
│   ├── reports/              # Report generation
│   │   ├── __init__.py
│   │   ├── base.py           # Base report class
│   │   ├── html.py           # HTML report generator
│   │   └── json_report.py    # JSON report generator
│   └── utils/                # Utilities
│       ├── __init__.py
│       ├── http.py           # HTTP request helpers
│       ├── logger.py         # Logging configuration
│       └── validators.py     # Input validation
├── tests/                    # Test suite
│   ├── __init__.py
│   ├── conftest.py           # Pytest fixtures
│   ├── test_scanners.py      # Scanner unit tests
│   ├── test_ai.py            # AI integration tests
│   └── test_cli.py           # CLI tests
├── examples/                 # Usage examples
│   ├── basic_scan.py
│   └── custom_scanner.py
├── docs/                     # Documentation
│   └── SECURITY.md           # Security policy
├── .github/                  # GitHub configuration
│   ├── workflows/
│   │   └── ci.yml            # CI/CD pipeline
│   └── ISSUE_TEMPLATE/
│       ├── bug_report.md
│       └── feature_request.md
├── .env.example              # Environment variable template
├── .gitignore                # Git ignore rules
├── LICENSE                   # MIT License
├── CONTRIBUTING.md           # Contribution guidelines
├── CODE_OF_CONDUCT.md        # Code of conduct
├── pyproject.toml            # Project metadata & build config
├── requirements.txt          # Python dependencies
└── setup.py                  # Setup script
```

## Vulnerability Severity Levels

| Level | Color | Description |
|-------|-------|-------------|
| **CRITICAL** | 🔴 | Immediate exploitation risk, data breach likely |
| **HIGH** | 🟠 | Significant risk, should be fixed before deployment |
| **MEDIUM** | 🟡 | Moderate risk, should be addressed in next release |
| **LOW** | 🟢 | Minor risk, best practice improvement |
| **INFO** | 🔵 | Informational finding, no immediate risk |

## Claude AI Integration

CyberShield uses **Claude by Anthropic** for two key features:

### 1. Vulnerability Explanation Pipeline

Raw scanner output → Claude API → Developer-friendly report

```
Scanner finds: "Reflected XSS in parameter 'q' at /search?q=<script>alert(1)</script>"
                                    ↓
Claude generates: "Your search page at /search is vulnerable to Cross-Site Scripting (XSS).
                   An attacker could inject malicious JavaScript through the 'q' parameter,
                   which gets reflected back in the page without sanitization. This could
                   allow session hijacking, credential theft, or defacement.

                   To fix this:
                   1. Sanitize the 'q' parameter using html.escape() before rendering
                   2. Add Content-Security-Policy headers
                   3. Use a templating engine with auto-escaping (e.g., Jinja2)"
```

### 2. Security Tutor Chat

An interactive learning mode where students can ask questions about vulnerabilities:

```
Student: "Why is SQL injection dangerous even with a firewall?"
Claude:   "Great question! A firewall protects your network perimeter, but SQL injection
           happens at the application layer — inside the firewall. When a user submits
           data through a form, it goes directly to your database query. If that input
           isn't sanitized, an attacker can modify the query itself..."
```

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Install development dependencies
pip install -r requirements.txt
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Run linting
flake8 cybershield/
black cybershield/ --check

# Run type checking
mypy cybershield/
```

## Roadmap

- [x] Core vulnerability scanners (XSS, SQLi, CSRF, Auth, API Keys)
- [x] Claude AI explanation pipeline
- [x] CLI interface
- [x] HTML/JSON report generation
- [x] Interactive security tutor chat
- [ ] Browser extension for real-time scanning
- [ ] REST API server mode
- [ ] Docker container support
- [ ] Plugin system for custom scanners
- [ ] Dashboard web UI

## Changelog

### v0.2.0 (March 2026)
- Interactive Security Tutor powered by Claude with multi-turn conversations
- Real XSS payload injection testing with form field and header scanning
- Real SQL injection detection (error-based, boolean-based, time-based blind)
- Professional dark-themed HTML report output with findings table
- Improved CLI UX with colored severity output
- Better error handling for API timeouts

### v0.1.0 (March 2026)
- Initial release with core architecture
- Claude AI explanation pipeline
- CLI interface with scan and tutor commands
- 5 vulnerability scanners (XSS, SQLi, CSRF, Auth, API Keys)
- HTML and JSON report generation

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **[Anthropic](https://anthropic.com)** — Claude API for AI-powered explanations
- **[OWASP](https://owasp.org)** — Vulnerability classification standards
- The open-source security community

---

<p align="center">
  Built with ❤️ for developers and cybersecurity students worldwide
  <br>
  <sub>Especially for those in developing regions where access to security tools is limited</sub>
</p>
