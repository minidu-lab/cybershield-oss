# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

If you discover a security vulnerability in CyberShield OSS itself, please report it responsibly.

**Do NOT open a public issue for security vulnerabilities.**

Instead, email: **minidu.website@gmail.com**

Include:
1. Description of the vulnerability
2. Steps to reproduce
3. Potential impact
4. Suggested fix (if any)

We aim to acknowledge reports within 48 hours and provide a fix within 7 days for critical issues.

## Responsible Use

CyberShield OSS is designed for:
- Scanning your own web applications
- Scanning applications you have explicit written permission to test
- Educational purposes in controlled environments

**Never use CyberShield to scan systems without authorization.** Unauthorized scanning may violate laws in your jurisdiction.

## Security Best Practices

When using CyberShield:
1. Keep your `ANTHROPIC_API_KEY` secret — never commit it to version control
2. Use the `.env` file for configuration (it's in `.gitignore`)
3. Review scan reports before sharing — they may contain sensitive information
4. Run scans from trusted networks only
