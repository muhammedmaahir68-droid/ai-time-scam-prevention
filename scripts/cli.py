"""
CLI Tool for AI Time-Scam Prevention System
=============================================
Usage:
    python scripts/cli.py analyze "Click now or lose your account!"
    python scripts/cli.py analyze --file message.txt
    python scripts/cli.py analyze --interactive
    python scripts/cli.py stats
    python scripts/cli.py demo
"""

import sys
import json
import argparse
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich import box
from loguru import logger

console = Console()

RISK_COLORS = {
    "safe":     "green",
    "low":      "yellow",
    "medium":   "orange3",
    "high":     "red",
    "critical": "bold red on white",
}

RISK_ICONS = {
    "safe":     "✅",
    "low":      "🟡",
    "medium":   "🟠",
    "high":     "🔴",
    "critical": "💀",
}


def print_result(result: dict):
    """Pretty-print a detection result."""
    risk  = result.get("risk_level", "unknown")
    color = RISK_COLORS.get(risk, "white")
    icon  = RISK_ICONS.get(risk, "❓")

    # Header panel
    header = (
        f"{icon} Risk Level: [{color}]{risk.upper()}[/{color}]  |  "
        f"Score: [bold]{result['overall_score']:.3f}[/bold]  |  "
        f"Is Scam: [bold]{'YES ⚠️' if result['is_scam'] else 'NO ✅'}[/bold]"
    )
    console.print(Panel(header, title="🛡️ Detection Result", border_style=color))

    # Scam types
    if result.get("scam_types"):
        console.print(f"  [bold]Detected Scam Types:[/bold] {', '.join(result['scam_types'])}")

    # Signals table
    signals = result.get("signals", [])
    if signals:
        table = Table(title="⚡ Scam Signals", box=box.ROUNDED)
        table.add_column("Type",         style="cyan")
        table.add_column("Severity",     style="red")
        table.add_column("Matched Text", style="yellow", no_wrap=False, max_width=60)
        for s in signals[:10]:
            table.add_row(
                s.get("signal_type", ""),
                f"{s.get('severity', 0):.2f}",
                s.get("matched_text", "")[:60]
            )
        console.print(table)

    # Recommendations
    recs = result.get("recommendations", [])
    if recs:
        console.print("\n  [bold]💡 Recommendations:[/bold]")
        for rec in recs:
            console.print(f"    {rec}")

    # Processing time
    console.print(f"\n  ⏱️  Processing time: {result.get('processing_time_ms', 0):.1f} ms\n")


def cmd_analyze(args):
    """Analyze text content for scams."""
    from src.core.detector import TimeScamDetector

    if args.interactive:
        console.print("[bold cyan]🛡️ AI Time-Scam Prevention — Interactive Mode[/bold cyan]")
        console.print("Type your message/email/text and press Enter (or 'quit' to exit):\n")
        detector = TimeScamDetector()
        while True:
            try:
                text = console.input("[bold]> [/bold]")
                if text.lower() in ("quit", "exit", "q"):
                    break
                if len(text.strip()) < 3:
                    continue
                result = detector.detect(text)
                print_result(result.to_dict())
            except KeyboardInterrupt:
                break
        return

    if args.file:
        text = Path(args.file).read_text(encoding="utf-8")
    elif args.text:
        text = args.text
    else:
        console.print("[red]Error: Provide text, --file, or --interactive[/red]")
        sys.exit(1)

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console) as progress:
        progress.add_task("Analyzing content...", total=None)
        from src.core.detector import TimeScamDetector
        detector = TimeScamDetector()
        result   = detector.detect(text)

    print_result(result.to_dict())

    if args.json:
        console.print_json(json.dumps(result.to_dict(), indent=2))


def cmd_demo(args):
    """Run a demonstration with sample scam texts."""
    from src.core.detector import TimeScamDetector

    samples = [
        ("Phishing Email",    "URGENT: Your PayPal account will be suspended in 24 hours! Verify immediately or lose access!"),
        ("Financial Scam",    "GUARANTEED 500% returns on Bitcoin in just 48 hours! Risk-free! Only 5 spots left!"),
        ("Fake Emergency",    "Mom I'm stuck! I got arrested abroad. Need $500 in iTunes gift cards urgently. Don't tell Dad!"),
        ("Legitimate Email",  "Hi, just a reminder about our meeting tomorrow at 10am. Let me know if you can make it."),
        ("Legitimate Offer",  "Our annual sale starts this weekend! Up to 30% off. Sale runs through Sunday."),
    ]

    detector = TimeScamDetector()
    console.print("[bold cyan]🛡️ AI Time-Scam Prevention — DEMO[/bold cyan]\n")

    for name, text in samples:
        console.rule(f"[bold]{name}[/bold]")
        console.print(f"[dim]Text: {text[:80]}...[/dim]" if len(text) > 80 else f"[dim]Text: {text}[/dim]")
        result = detector.detect(text)
        print_result(result.to_dict())


def main():
    parser = argparse.ArgumentParser(
        description="AI Time-Scam Prevention — CLI Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # analyze command
    analyze_p = subparsers.add_parser("analyze", help="Analyze text for scam indicators")
    analyze_p.add_argument("text", nargs="?", help="Text to analyze")
    analyze_p.add_argument("--file", "-f", help="Path to text file")
    analyze_p.add_argument("--interactive", "-i", action="store_true", help="Interactive mode")
    analyze_p.add_argument("--json", "-j", action="store_true", help="Output raw JSON")

    # demo command
    demo_p = subparsers.add_parser("demo", help="Run a demonstration")

    args = parser.parse_args()

    if args.command == "analyze":
        cmd_analyze(args)
    elif args.command == "demo":
        cmd_demo(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
