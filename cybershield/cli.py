"""Command-line interface for CyberShield OSS.

Provides `cybershield scan` and `cybershield tutor` commands.
"""

from __future__ import annotations

import asyncio
import sys

import click

from cybershield import __version__
from cybershield.config import Config
from cybershield.core import CyberShield
from cybershield.utils.validators import validate_url, validate_modules


BANNER = r"""
   ____      _               ____  _     _      _     _
  / ___|   _| |__   ___ _ __/ ___|| |__ (_) ___| | __| |
 | |  | | | | '_ \ / _ \ '__\___ \| '_ \| |/ _ \ |/ _` |
 | |__| |_| | |_) |  __/ |   ___) | | | | |  __/ | (_| |
  \____\__, |_.__/ \___|_|  |____/|_| |_|_|\___|_|\__,_|
       |___/
"""

SEVERITY_SYMBOLS = {
    "CRITICAL": click.style("●", fg="red", bold=True),
    "HIGH": click.style("●", fg="yellow", bold=True),
    "MEDIUM": click.style("●", fg="yellow"),
    "LOW": click.style("●", fg="green"),
    "INFO": click.style("●", fg="blue"),
}


@click.group()
@click.version_option(version=__version__, prog_name="cybershield")
def cli():
    """CyberShield OSS — AI-Assisted Cybersecurity Scanner."""
    pass


@cli.command()
@click.argument("target_url")
@click.option(
    "--modules",
    "-m",
    default="all",
    help="Comma-separated scanner modules (xss,sqli,csrf,auth,api_keys,all)",
)
@click.option(
    "--report",
    "-r",
    type=click.Choice(["html", "json", "none"]),
    default="none",
    help="Report format to generate",
)
@click.option(
    "--output",
    "-o",
    default=None,
    help="Output file path for the report",
)
@click.option(
    "--ai-explain",
    is_flag=True,
    default=False,
    help="Use Claude AI to generate detailed explanations",
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    default=False,
    help="Enable verbose output",
)
def scan(
    target_url: str,
    modules: str,
    report: str,
    output: str | None,
    ai_explain: bool,
    verbose: bool,
):
    """Scan a target URL for vulnerabilities.

    \b
    Examples:
      cybershield scan https://example.com
      cybershield scan https://example.com -m xss,sqli --ai-explain
      cybershield scan https://example.com -r html -o report.html
    """
    click.echo(click.style(BANNER, fg="cyan"))
    click.echo(f"  Version {__version__}\n")

    # Validate inputs
    try:
        target_url = validate_url(target_url)
    except ValueError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    module_list = [m.strip() for m in modules.split(",")]
    try:
        module_list = validate_modules(module_list)
    except ValueError as e:
        click.echo(click.style(f"Error: {e}", fg="red"), err=True)
        sys.exit(1)

    # Configure
    config = Config.from_env()
    if verbose:
        config.log_level = "DEBUG"

    if ai_explain and not config.anthropic_api_key:
        click.echo(
            click.style(
                "Warning: --ai-explain requires ANTHROPIC_API_KEY in .env",
                fg="yellow",
            ),
            err=True,
        )
        ai_explain = False

    # Run scan
    click.echo(f"  Target:  {target_url}")
    click.echo(f"  Modules: {', '.join(module_list)}")
    click.echo(f"  AI:      {'enabled' if ai_explain else 'disabled'}")
    click.echo()

    scanner = CyberShield(config=config)

    with click.progressbar(
        length=100,
        label="  Scanning",
        bar_template="  %(label)s [%(bar)s] %(info)s",
        fill_char=click.style("█", fg="cyan"),
        empty_char="░",
    ) as bar:
        bar.update(10)
        result = scanner.scan(
            target_url,
            modules=module_list if "all" not in module_list else None,
            ai_explain=ai_explain,
        )
        bar.update(90)

    click.echo()

    # Display results
    summary = result.summary
    click.echo("  ─── Results ───")
    click.echo(
        f"  Found {len(result.vulnerabilities)} issue(s) "
        f"in {result.duration:.1f}s"
    )
    click.echo()

    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = summary[severity]
        if count > 0:
            symbol = SEVERITY_SYMBOLS[severity]
            click.echo(f"  {symbol} {severity}: {count}")

    click.echo()

    # Show individual findings
    for vuln in result.sorted_vulnerabilities():
        symbol = SEVERITY_SYMBOLS[vuln.severity]
        click.echo(f"  {symbol} [{vuln.severity}] {vuln.title}")
        click.echo(f"    URL: {vuln.url}")
        click.echo(f"    {vuln.description[:120]}...")
        if vuln.ai_explanation:
            click.echo(
                click.style("    🤖 AI: ", fg="blue")
                + vuln.ai_explanation[:200]
                + "..."
            )
        click.echo()

    # Generate report
    if report != "none":
        report_path = scanner.generate_report(result, format=report, output_path=output)
        click.echo(
            click.style(f"  Report saved: {report_path}", fg="green")
        )

    # Exit with non-zero if critical/high findings
    if summary["CRITICAL"] > 0 or summary["HIGH"] > 0:
        sys.exit(1)


@cli.command()
@click.option(
    "--topic",
    "-t",
    default=None,
    help="Start with a specific security topic",
)
def tutor(topic: str | None):
    """Start the interactive Security Tutor.

    \b
    Examples:
      cybershield tutor
      cybershield tutor --topic "SQL injection"
    """
    click.echo(click.style(BANNER, fg="cyan"))
    click.echo("  Security Tutor — Interactive Learning Mode")
    click.echo("  Powered by Claude AI")
    click.echo("  Type 'quit' or 'exit' to leave\n")

    config = Config.from_env()
    if not config.anthropic_api_key:
        click.echo(
            click.style(
                "Error: ANTHROPIC_API_KEY required for Security Tutor. "
                "Set it in your .env file.",
                fg="red",
            ),
            err=True,
        )
        sys.exit(1)

    from cybershield.ai.tutor import SecurityTutor

    tutor_instance = SecurityTutor(config, topic=topic)

    if topic:
        click.echo(f"  Topic: {topic}\n")
        # Get initial overview
        response = asyncio.run(_tutor_ask(tutor_instance, f"Give me an overview of {topic}"))
        click.echo(f"\n  🤖 {response}\n")

    while True:
        try:
            question = click.prompt(
                click.style("  You", fg="cyan"), prompt_suffix=" > "
            )
        except (EOFError, KeyboardInterrupt):
            click.echo("\n  Goodbye!")
            break

        if question.lower() in ("quit", "exit", "q"):
            click.echo("  Goodbye!")
            break

        response = asyncio.run(_tutor_ask(tutor_instance, question))
        click.echo(f"\n  🤖 {response}\n")


async def _tutor_ask(tutor_instance, question: str) -> str:
    """Helper to run an async tutor question."""
    return await tutor_instance.ask(question)


def main():
    """Entry point for the CLI."""
    cli()


if __name__ == "__main__":
    main()
