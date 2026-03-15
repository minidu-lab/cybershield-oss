#!/usr/bin/env python3
"""Basic example: scan a URL and print results.

Usage:
    python examples/basic_scan.py https://example.com
"""

import sys
from cybershield import CyberShield


def main():
    if len(sys.argv) < 2:
        print("Usage: python basic_scan.py <url>")
        print("Example: python basic_scan.py https://example.com")
        sys.exit(1)

    target = sys.argv[1]

    # Initialize scanner (reads ANTHROPIC_API_KEY from .env)
    scanner = CyberShield()

    # Run scan with all modules
    print(f"Scanning {target}...")
    results = scanner.scan(target, modules=["all"])

    # Print summary
    print(f"\nScan completed in {results.duration:.1f}s")
    print(f"Total findings: {len(results.vulnerabilities)}\n")

    for severity, count in results.summary.items():
        if count > 0:
            print(f"  {severity}: {count}")

    # Print each finding
    print("\n--- Findings ---\n")
    for vuln in results.sorted_vulnerabilities():
        print(f"[{vuln.severity}] {vuln.title}")
        print(f"  URL: {vuln.url}")
        print(f"  {vuln.description}")
        if vuln.remediation:
            print(f"  Fix: {vuln.remediation.split(chr(10))[0]}")
        print()

    # Generate HTML report
    report_path = scanner.generate_report(results, format="html")
    print(f"HTML report saved to: {report_path}")


if __name__ == "__main__":
    main()
