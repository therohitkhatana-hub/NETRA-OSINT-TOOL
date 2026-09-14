"""
Interactive, animated launcher for NETRA — Cyber Crime OSINT & Intelligence System.
Jaipur Police Cyber Crime Dept | Cybersecurity Project

Run this instead of typing main.py flags by hand:
    python launch.py
"""
import os
import sys
import time
import warnings

warnings.filterwarnings("ignore")

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.status import Status
from rich.align import Align
from rich.text import Text
from pyfiglet import Figlet
from dotenv import load_dotenv

load_dotenv()
console = Console()

TIER_STYLE = {"HIGH": "bold green", "MED": "bold yellow", "LOW": "dim white"}


def tier(confidence: float) -> str:
    if confidence >= 0.75:
        return "HIGH"
    if confidence >= 0.5:
        return "MED"
    return "LOW"


def animate_banner():
    console.clear()
    fig = Figlet(font="slant")
    banner_text = fig.renderText("NETRA")

    colors = ["bright_cyan", "cyan", "bright_blue", "blue"]
    lines = banner_text.split("\n")
    for i, line in enumerate(lines):
        if line.strip():
            color = colors[i % len(colors)]
            console.print(Align.center(Text(line, style=f"bold {color}")))
            time.sleep(0.04)
        else:
            console.print()

    subtitle = Text()
    subtitle.append("NETRA - Cyber Crime OSINT & Intelligence System\n", style="bold bright_white")
    subtitle.append("Jaipur Police Cyber Crime Dept  ", style="bold bright_cyan")
    subtitle.append("| Rohit Khatana", style="italic bright_black")
    console.print(Align.center(subtitle))
    console.print()

    with console.status("[bold cyan]Initializing NETRA intelligence modules...", spinner="dots"):
        time.sleep(1.0)

    modules_line = Text()
    module_names = [
        "phonenumbers", "XposedOrNot", "WHOIS", "SPF/DMARC", "Gravatar",
        "GitHub", "Wayback Machine", "emailrep.io", "own account-checker",
        "own crawler", "threat-intel", "recon", "Firebase recon",
    ]
    for i, m in enumerate(module_names):
        modules_line.append(f" {m} ", style="on grey15 bright_green")
        if i < len(module_names) - 1:
            modules_line.append("  ")
    console.print(Align.center(modules_line))
    console.print()
    time.sleep(0.3)


def get_inputs():
    console.print(Panel.fit(
        "[bold]Enter at least one identifier[/bold] — phone, email, or both.\n"
        "[dim]Leave a field blank and press Enter to skip it.[/dim]",
        border_style="cyan", title="[bold cyan]Target Identifiers[/bold cyan]",
    ))
    phone = Prompt.ask("[bold cyan]Phone number[/bold cyan] [dim](e.g. +919876543210)[/dim]", default="", show_default=False)
    email = Prompt.ask("[bold cyan]Email address[/bold cyan]", default="", show_default=False)
    phone = phone.strip() or None
    email = email.strip() or None

    if not phone and not email:
        console.print("[bold red]You need to provide at least one identifier.[/bold red]")
        return get_inputs()

    return phone, email


def run_investigation(phone, email):
    from orchestrator import investigate

    console.print()
    stages = [
        "Parsing target identifiers...",
        "Querying phone intelligence sources..." if phone else None,
        "Querying email intelligence sources..." if email else None,
        "Cross-validating findings across modules...",
        "Computing explainable confidence & risk scores...",
    ]
    stages = [s for s in stages if s]

    with console.status("[bold cyan]Executing investigation pipeline...", spinner="dots12") as status:
        for stage in stages:
            status.update(f"[bold cyan]{stage}[/bold cyan]")
            time.sleep(0.3)
        result = investigate(phone=phone, email=email)

    console.print("[bold green]\u2713[/bold green] Investigation complete.\n")
    return result


def render_findings_table(title: str, findings: list, style: str):
    if not findings:
        return
    table = Table(title=title, title_style=f"bold {style}", show_lines=False, header_style=f"bold {style}")
    table.add_column("Tier", width=6)
    table.add_column("Conf.", width=6)
    table.add_column("Source", width=22)
    table.add_column("Finding", overflow="fold")

    for f in sorted(findings, key=lambda x: -x.confidence):
        t = tier(f.confidence)
        row_style = TIER_STYLE[t]
        table.add_row(f"[{row_style}]{t}[/{row_style}]", f"{f.confidence:.2f}", f.source, f.fact)

    console.print(table)
    console.print()


def render_summary(result):
    all_findings = result["phone_findings"] + result["email_findings"] + result["linkage_findings"]
    high = sum(1 for f in all_findings if tier(f.confidence) == "HIGH")
    med = sum(1 for f in all_findings if tier(f.confidence) == "MED")
    low = sum(1 for f in all_findings if tier(f.confidence) == "LOW")
    flags = sum(1 for f in all_findings if "FLAG" in f.fact)

    summary = Text()
    summary.append(f"{len(all_findings)} total findings  ", style="bold white")
    summary.append(f"\u25cf {high} high  ", style="bold green")
    summary.append(f"\u25cf {med} med  ", style="bold yellow")
    summary.append(f"\u25cf {low} low  ", style="dim white")
    summary.append(f"\u26a0 {flags} flag(s)", style="bold red" if flags else "dim white")
    console.print(Panel(Align.center(summary), border_style="bright_black", title="[bold]Summary[/bold]"))
    console.print()


def select_mode():
    console.print(Panel.fit(
        "[bold cyan]1.[/bold cyan] Standard Target Investigation (Phone & Email)\n"
        "[bold cyan]2.[/bold cyan] Passive Firebase Project Reconnaissance (Responsible OSINT)",
        border_style="cyan", title="[bold cyan]Investigation Mode[/bold cyan]",
    ))
    return Prompt.ask("[bold cyan]Select mode[/bold cyan]", choices=["1", "2"], default="1")


def run_firebase_investigation(raw_target: str):
    from firebase_investigate import normalize_hostname, investigate_firebase_project
    from db import init_db, save_findings
    from own_index import index_findings

    hostname = normalize_hostname(raw_target)
    console.print()
    stages = [
        "Checking database exposure status (shallow=true)...",
        "Checking associated Firebase Hosting site & title...",
        "Searching public GitHub code for project configurations...",
        "Searching DuckDuckGo web mentions...",
        "Searching Reddit discussions...",
    ]

    with console.status(f"[bold cyan]Investigating Firebase project: {hostname}...", spinner="dots12") as status:
        for stage in stages:
            status.update(f"[bold cyan]{stage}[/bold cyan]")
            time.sleep(0.3)
        findings = investigate_firebase_project(hostname)

    conn = init_db()
    save_findings(conn, findings)
    conn.close()
    try:
        index_findings(findings)
    except Exception:
        pass

    console.print(f"[bold green]\u2713[/bold green] Firebase investigation complete for [bold]{hostname}[/bold].\n")
    return hostname, findings


def main():
    animate_banner()
    mode = select_mode()

    if mode == "2":
        console.print(Panel.fit(
            "[bold]Enter Firebase RTDB hostname, URL, or project ID[/bold]\n"
            "[dim]e.g. rto-32-default-rtdb.firebaseio.com or my-project-id[/dim]",
            border_style="cyan", title="[bold cyan]Target Firebase Project[/bold cyan]",
        ))
        target = Prompt.ask("[bold cyan]Firebase Hostname / Project ID[/bold cyan]").strip()
        if not target:
            console.print("[bold red]No target provided.[/bold red]")
            return
        hostname, findings = run_firebase_investigation(target)

        result = {"phone_findings": [], "email_findings": findings, "linkage_findings": []}
        render_summary(result)
        render_findings_table(f"Firebase Findings ({hostname})", findings, "cyan")

        if Confirm.ask("[bold cyan]Generate PDF dossier?[/bold cyan]", default=True):
            from report import generate_pdf
            import re
            safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", hostname)
            default_name = f"firebase_case_{safe_name}.pdf"
            out_name = Prompt.ask("[bold cyan]Output filename[/bold cyan]", default=default_name)
            with console.status("[bold cyan]Generating PDF report...", spinner="dots"):
                path = generate_pdf(result, phone=None, email=hostname, output_path=out_name)
                time.sleep(0.3)
            console.print(Panel.fit(f"[bold green]\u2713 Dossier saved:[/bold green] {os.path.abspath(path)}", border_style="green"))
    else:
        phone, email = get_inputs()
        result = run_investigation(phone, email)

        render_summary(result)
        render_findings_table("Phone Findings", result["phone_findings"], "cyan")
        render_findings_table("Email Findings", result["email_findings"], "magenta")
        render_findings_table("Cross-Linkage Findings", result["linkage_findings"], "red")

        if Confirm.ask("[bold cyan]Generate PDF dossier?[/bold cyan]", default=True):
            from report import generate_pdf
            default_name = "netra_report.pdf"
            out_name = Prompt.ask("[bold cyan]Output filename[/bold cyan]", default=default_name)
            with console.status("[bold cyan]Generating PDF report...", spinner="dots"):
                path = generate_pdf(result, phone, email, output_path=out_name)
                time.sleep(0.3)
            console.print(Panel.fit(f"[bold green]\u2713 Dossier saved:[/bold green] {os.path.abspath(path)}", border_style="green"))

    console.print()
    if Confirm.ask("[bold cyan]Run another investigation?[/bold cyan]", default=False):
        console.print()
        main()
    else:
        console.print(Align.center(Text("Thank you for using NETRA - Rohit Khatana | Jaipur Police Cyber Crime Dept", style="italic bright_black")))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold red]Cancelled.[/bold red]")
        sys.exit(0)
