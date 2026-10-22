#!/usr/bin/env python3
import click, json
from rich.console import Console
from .linter import lint_report
console = Console()
@click.group()
@click.version_option()
def main(): pass
@main.command()
@click.argument('file')
def lint(file):
    report = json.load(open(file))
    issues = lint_report(report)
    for i in issues: console.print(f'[yellow]{i}[/yellow]')
    console.print(f'[green]{len(issues)} issue(s)[/green]')
if __name__ == '__main__': main()
