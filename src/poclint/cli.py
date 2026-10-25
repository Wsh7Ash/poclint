#!/usr/bin/env python3
"""poclint — lint a draft bug-bounty report before you submit it."""

from __future__ import annotations

import json
import sys

import click
from rich.console import Console
from rich.table import Table

from .linter import lint_report, split_levels

console = Console()


@click.group()
@click.version_option()
def main():
    """Check a draft finding JSON for completeness and severity calibration."""


@main.command()
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.option("--json-out", is_flag=True, help="Print issues as JSON.")
@click.option("--strict", is_flag=True,
              help="Treat warnings as failures (exit 1).")
def lint(file, json_out, strict):
    """Lint draft report FILE (JSON)."""
    try:
        with open(file, encoding="utf-8") as fh:
            report = json.load(fh)
    except json.JSONDecodeError as exc:
        console.print(f"[red]error:[/red] {file} is not valid JSON: {exc}")
        sys.exit(2)

    issues = lint_report(report)
    errors, warnings = split_levels(issues)

    if json_out:
        click.echo(json.dumps({
            "file": file,
            "errors": errors,
            "warnings": warnings,
            "ok": not errors and not (strict and warnings),
        }, indent=2))
    else:
        if not issues:
            console.print(f"[green]OK:[/green] {file} — no issues")
        else:
            table = Table(title=f"poclint: {file}")
            table.add_column("Level")
            table.add_column("Issue")
            for issue in errors:
                table.add_row("[red]error[/red]", issue[len("error: "):])
            for issue in warnings:
                table.add_row("[yellow]warning[/yellow]", issue[len("warning: "):])
            console.print(table)
        console.print(f"{len(errors)} error(s), {len(warnings)} warning(s)")

    if errors or (strict and warnings):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
