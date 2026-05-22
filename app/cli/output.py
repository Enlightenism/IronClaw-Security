from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text

from ironclaw_sdk.models import ScanResponse

_console = Console()
_err_console = Console(stderr=True)

_VERDICT_STYLES: dict[str, tuple[str, str]] = {
    "allow": ("green", "ALLOW"),
    "warn": ("yellow", "WARN"),
    "quarantine": ("yellow", "QUARANTINE"),
    "block": ("red", "BLOCK"),
}

_SEVERITY_STYLES: dict[str, str] = {
    "low": "green",
    "medium": "yellow",
    "high": "red",
    "critical": "bold red",
}


def _verdict_text(verdict: str) -> Text:
    color, label = _VERDICT_STYLES.get(verdict.lower(), ("white", verdict.upper()))
    return Text(label, style=f"bold {color}")


def _severity_text(severity: str | None) -> Text:
    if severity is None:
        return Text("—", style="dim")
    style = _SEVERITY_STYLES.get(severity.lower(), "white")
    return Text(severity.upper(), style=style)


def format_scan_result(result: ScanResponse, *, compact: bool = False) -> None:
    verdict_text = _verdict_text(result.verdict)

    if compact:
        line = Text()
        line.append(f"[{result.scan_id or '—'}] ", style="dim")
        line.append(verdict_text)
        line.append(f"  risk={result.risk_score}/100", style="cyan")
        line.append(f"  {result.summary}")
        _console.print(line)
        return

    _console.rule(Text("IronClaw Scan Result", style="bold"))
    _console.print(Text("Verdict:    ", style="bold") + verdict_text)
    _console.print(f"[bold]Scan ID:[/bold]    {result.scan_id or '—'}")
    _console.print(f"[bold]Target:[/bold]     [{result.target_type}] {result.target_value}")
    _console.print(f"[bold]Risk Score:[/bold] [cyan]{result.risk_score}/100[/cyan]")
    _console.print("[bold]Severity:[/bold]   " + _severity_text(result.max_severity).__str__())
    _console.print(f"[bold]Summary:[/bold]    {result.summary}")

    if result.explanation:
        _console.print(f"[bold]Explanation:[/bold] {result.explanation}")

    if result.matched_patterns:
        _console.print(f"[bold]Matched Patterns:[/bold] {', '.join(result.matched_patterns)}")

    if result.risky_files:
        _console.print(f"[bold]Risky Files:[/bold] {', '.join(result.risky_files)}")

    if result.failed_checks:
        _console.print(f"[bold]Failed Checks:[/bold] {', '.join(result.failed_checks)}", style="yellow")

    if result.quarantine_reason:
        _console.print(f"[bold]Quarantine Reason:[/bold] {result.quarantine_reason}", style="red")

    if result.sandbox_lane and result.sandbox_lane != "none":
        _console.print(f"[bold]Sandbox Lane:[/bold] {result.sandbox_lane}")

    _console.print(f"[bold]Review Status:[/bold] {result.review_status}")

    if result.timestamp:
        _console.print(f"[bold]Timestamp:[/bold]  {result.timestamp}", style="dim")

    _console.rule()


def format_verdict_table(results: list[ScanResponse]) -> None:
    table = Table(
        title="IronClaw Scan Results",
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        expand=False,
    )
    table.add_column("Scan ID", style="dim", no_wrap=True)
    table.add_column("Target Type", no_wrap=True)
    table.add_column("Target Value", max_width=40)
    table.add_column("Verdict", no_wrap=True)
    table.add_column("Risk", justify="right", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Summary", max_width=50)

    for r in results:
        color, label = _VERDICT_STYLES.get(r.verdict.lower(), ("white", r.verdict.upper()))
        verdict_cell = f"[bold {color}]{label}[/bold {color}]"
        sev_color = _SEVERITY_STYLES.get((r.max_severity or "").lower(), "dim")
        severity_cell = f"[{sev_color}]{(r.max_severity or '—').upper()}[/{sev_color}]"
        table.add_row(
            r.scan_id or "—",
            r.target_type,
            r.target_value[:40] + ("…" if len(r.target_value) > 40 else ""),
            verdict_cell,
            f"[cyan]{r.risk_score}/100[/cyan]",
            severity_cell,
            r.summary,
        )

    _console.print(table)


def format_error(error_type: str, detail: str, command: str | None = None) -> None:
    label = "[bold red]ERROR[/bold red]"
    cmd_part = f" ([dim]{command}[/dim])" if command else ""
    _err_console.print(f"{label}{cmd_part}  {error_type}: {detail}")


def format_json_payload(payload: dict[str, Any], *, compact: bool = False) -> None:
    import json

    if compact:
        _console.print(json.dumps(payload, separators=(",", ":"), sort_keys=True))
    else:
        _console.print_json(json.dumps(payload, sort_keys=True))


__all__ = [
    "format_error",
    "format_json_payload",
    "format_scan_result",
    "format_verdict_table",
]
