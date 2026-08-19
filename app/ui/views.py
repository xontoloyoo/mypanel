"""UI views for rendering data tables, menu systems, and status cards."""

from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple

from rich.console import Console, Group
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from app.ui.layout import clear_screen, console

# Regex patterns for log line colorization
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TIMESTAMP_REGEX = re.compile(
    r"(\[\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}\]|\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}|\b[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\[\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s[+\-]\d{4}\])"
)
HTTP_METHOD_REGEX = re.compile(r"\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b")
HTTP_STATUS_REGEX = re.compile(r"\s(2\d{2}|3\d{2}|4\d{2}|5\d{2})\s")


def _get_percentage_style(percent: float) -> str:
    """Return color style based on resource utilization percentage."""
    if percent < 60.0:
        return "green"
    if percent < 85.0:
        return "yellow"
    return "bold red"


def colorize_log_line(line: str) -> Text:
    """Format and colorize raw log line with Rich styles."""
    text = Text(line)

    # Highlight Timestamps
    for match in TIMESTAMP_REGEX.finditer(line):
        text.stylize("dim cyan", match.start(), match.end())

    # Highlight IP Addresses
    for match in IP_REGEX.finditer(line):
        text.stylize("bold cyan", match.start(), match.end())

    # Highlight HTTP Methods
    for match in HTTP_METHOD_REGEX.finditer(line):
        text.stylize("bold magenta", match.start(), match.end())

    # Highlight HTTP Status Codes
    for match in HTTP_STATUS_REGEX.finditer(line):
        code = match.group(1)
        if code.startswith("2"):
            style = "bold green"
        elif code.startswith("3"):
            style = "bold yellow"
        else:
            style = "bold red"
        text.stylize(style, match.start(1), match.end(1))

    # Highlight Log Levels
    line_lower = line.lower()
    if "[error]" in line_lower or "[critical]" in line_lower or "error:" in line_lower:
        text.stylize("bold red")
    elif "[warning]" in line_lower or "[warn]" in line_lower or "warning:" in line_lower:
        text.stylize("bold yellow")
    elif "[info]" in line_lower:
        idx = line_lower.find("[info]")
        if idx != -1:
            text.stylize("bold green", idx, idx + 6)
    elif "[debug]" in line_lower:
        idx = line_lower.find("[debug]")
        if idx != -1:
            text.stylize("dim blue", idx, idx + 7)

    return text


def render_dashboard(metrics: Dict[str, Any], services: Dict[str, Dict[str, Any]]) -> Panel:
    """Render comprehensive server monitoring dashboard."""
    res_table = Table(show_header=True, header_style="bold cyan", expand=True, box=None)
    res_table.add_column("Resource", style="bold white", width=12)
    res_table.add_column("Utilization", style="white", width=22)
    res_table.add_column("Details", style="dim white")

    cpu = metrics.get("cpu", {})
    cpu_pct = cpu.get("percent", 0.0)
    cpu_style = _get_percentage_style(cpu_pct)
    res_table.add_row(
        "CPU",
        f"[{cpu_style}]{cpu_pct}%[/{cpu_style}]",
        f"{cpu.get('cores_logical', 1)} Cores ({cpu.get('cores_physical', 1)} Phys) @ {cpu.get('frequency_mhz', 0.0)} MHz",
    )

    ram = metrics.get("ram", {})
    ram_pct = ram.get("percent", 0.0)
    ram_style = _get_percentage_style(ram_pct)
    res_table.add_row(
        "RAM",
        f"[{ram_style}]{ram.get('used_human', '0 B')} / {ram.get('total_human', '0 B')} ({ram_pct}%)[/{ram_style}]",
        f"Free: {ram.get('free_human', '0 B')}",
    )

    disk = metrics.get("disk", {})
    disk_pct = disk.get("percent", 0.0)
    disk_style = _get_percentage_style(disk_pct)
    res_table.add_row(
        "Disk",
        f"[{disk_style}]{disk.get('used_human', '0 B')} / {disk.get('total_human', '0 B')} ({disk_pct}%)[/{disk_style}]",
        f"Path: {disk.get('path', '/')} (Free: {disk.get('free_human', '0 B')})",
    )

    uptime = metrics.get("uptime", "0 mins")
    load = metrics.get("load_avg", {})
    load_str = f"1m: {load.get('1m', 0.0)}, 5m: {load.get('5m', 0.0)}, 15m: {load.get('15m', 0.0)}"
    res_table.add_row("Uptime", f"[green]{uptime}[/green]", f"Load Avg: {load_str}")

    svc_table = Table(show_header=True, header_style="bold magenta", expand=True, box=None)
    svc_table.add_column("Service", style="bold white", width=16)
    svc_table.add_column("Status", width=18)
    svc_table.add_column("Description", style="dim")

    svc_descriptions = {
        "nginx": "Nginx Web Server / Reverse Proxy",
        "mysql": "MySQL / MariaDB Database Server",
        "mariadb": "MariaDB Database Server",
        "ufw": "Uncomplicated Firewall Daemon",
        "php-fpm": "PHP FastCGI Process Manager",
    }

    for svc_name, svc_info in services.items():
        if svc_name == "mariadb" and services.get("mysql", {}).get("is_active"):
            continue

        is_act = svc_info.get("is_active", False)
        status_txt = svc_info.get("status", "unknown").upper()

        if is_act:
            status_badge = f"[bold white on dark_green]  RUNNING  [/bold white on dark_green]"
        else:
            status_badge = f"[bold white on dark_red]  STOPPED  [/bold white on dark_red] [dim]({status_txt})[/dim]"

        desc = svc_descriptions.get(svc_name, "System Daemon")
        svc_table.add_row(svc_name.upper(), status_badge, desc)

    group = Group(
        Panel(res_table, title="[bold cyan]System Resources[/bold cyan]", border_style="blue"),
        Panel(svc_table, title="[bold magenta]Core Services Status[/bold magenta]", border_style="magenta"),
    )

    return Panel(group, title="[bold green]System Dashboard[/bold green]", border_style="green")


def render_sites_table(sites: List[Dict[str, Any]]) -> Table:
    """Render table of configured websites."""
    table = Table(
        title="[bold cyan]Configured Websites (Nginx)[/bold cyan]",
        header_style="bold cyan",
        expand=True,
    )
    table.add_column("No.", style="bold cyan", width=4, justify="center")
    table.add_column("ID", style="dim", width=10, justify="center")
    table.add_column("Domain Name", style="bold white", width=24)
    table.add_column("Document Root Path", style="dim white")
    table.add_column("PHP Version", style="yellow", width=12, justify="center")
    table.add_column("SSL Status", width=16, justify="center")
    table.add_column("Created At", style="dim", width=20)

    if not sites:
        table.add_row("-", "-", "[dim italic]No websites configured yet[/dim italic]", "-", "-", "-", "-")
        return table

    for idx, s in enumerate(sites, 1):
        ssl_val = s.get("ssl_status", 0)
        is_ssl = ssl_val == 1 or str(ssl_val).lower() == "enabled"
        ssl_badge = (
            "[bold green]ENABLED (HTTPS)[/bold green]"
            if is_ssl
            else "[dim]DISABLED[/dim]"
        )
        php_ver = s.get("php_version") or "none"
        raw_id = str(s.get("id", "-"))
        table.add_row(
            str(idx),
            raw_id[:8],
            s.get("domain", "-"),
            s.get("root_path", "-"),
            php_ver.upper() if php_ver != "none" else "Static",
            ssl_badge,
            str(s.get("created_at", "-")),
        )

    return table


def render_databases_table(databases: List[Dict[str, Any]]) -> Table:
    """Render table of MySQL/MariaDB databases."""
    table = Table(
        title="[bold blue]Managed Databases (MySQL/MariaDB)[/bold blue]",
        header_style="bold blue",
        expand=True,
    )
    table.add_column("No.", style="bold cyan", width=4, justify="center")
    table.add_column("ID", style="dim", width=10, justify="center")
    table.add_column("Database Name", style="bold white", width=24)
    table.add_column("Database User", style="cyan", width=20)
    table.add_column("Charset", style="dim", width=14, justify="center")
    table.add_column("Created At", style="dim", width=20)

    if not databases:
        table.add_row("-", "-", "[dim italic]No databases created yet[/dim italic]", "-", "-", "-")
        return table

    for idx, db in enumerate(databases, 1):
        raw_id = str(db.get("id", "-"))
        table.add_row(
            str(idx),
            raw_id[:8],
            db.get("db_name", "-"),
            db.get("db_user", "-"),
            db.get("charset", "utf8mb4"),
            str(db.get("created_at", "-")),
        )

    return table


def render_firewall_table(status: Dict[str, Any], rules: List[Dict[str, Any]]) -> Group:
    """Render firewall status banner and port rules table."""
    is_active = status.get("active", False)
    status_label = "[bold white on dark_green]  UFW ACTIVE  [/bold white on dark_green]" if is_active else "[bold white on dark_red]  UFW INACTIVE  [/bold white on dark_red]"
    status_panel = Panel(
        Text.from_markup(f"Firewall Status: {status_label}  |  Total Rules: [bold cyan]{len(rules)}[/bold cyan]"),
        border_style="green" if is_active else "red",
        padding=(0, 1),
    )

    table = Table(
        title="[bold yellow]Firewall Port Rules (UFW)[/bold yellow]",
        header_style="bold yellow",
        expand=True,
    )
    table.add_column("No.", style="bold cyan", width=4, justify="center")
    table.add_column("ID", style="dim", width=10, justify="center")
    table.add_column("Port / Range", style="bold white", width=16)
    table.add_column("Protocol", style="cyan", width=12, justify="center")
    table.add_column("Action", width=12, justify="center")
    table.add_column("Description / Notes", style="dim white")
    table.add_column("Created At", style="dim", width=20)

    if not rules:
        table.add_row("-", "-", "[dim italic]No custom rules added yet[/dim italic]", "-", "-", "-", "-")
    else:
        for idx, r in enumerate(rules, 1):
            action = r.get("action", "allow").upper()
            action_badge = (
                "[bold green]ALLOW[/bold green]"
                if action == "ALLOW"
                else "[bold red]DENY[/bold red]"
            )
            raw_id = str(r.get("id", "-"))
            table.add_row(
                str(idx),
                raw_id[:8],
                str(r.get("port", "-")),
                r.get("protocol", "tcp").upper(),
                action_badge,
                r.get("description", "") or "[dim]None[/dim]",
                str(r.get("created_at", "-")),
            )

    return Group(status_panel, table)


def render_cron_table(jobs: List[Dict[str, Any]]) -> Table:
    """Render table of registered cron tasks."""
    table = Table(
        title="[bold magenta]Scheduled Cron Tasks[/bold magenta]",
        header_style="bold magenta",
        expand=True,
    )
    table.add_column("No.", style="bold cyan", width=4, justify="center")
    table.add_column("ID", style="dim", width=10, justify="center")
    table.add_column("Task Name", style="bold white", width=22)
    table.add_column("Job Type", style="cyan", width=16)
    table.add_column("Schedule", style="yellow", width=16, justify="center")
    table.add_column("Target / Command", style="dim white")
    table.add_column("Status", width=12, justify="center")
    table.add_column("Created At", style="dim", width=20)

    if not jobs:
        table.add_row("-", "-", "[dim italic]No cron jobs scheduled yet[/dim italic]", "-", "-", "-", "-", "-")
        return table

    for idx, j in enumerate(jobs, 1):
        status_str = j.get("status", "active").upper()
        status_badge = (
            "[bold green]ACTIVE[/bold green]"
            if status_str == "ACTIVE"
            else "[dim]DISABLED[/dim]"
        )
        raw_id = str(j.get("id", "-"))
        table.add_row(
            str(idx),
            raw_id[:8],
            j.get("name", "-"),
            j.get("job_type", "-").replace("_", " ").title(),
            j.get("schedule", "-"),
            j.get("target", "-"),
            status_badge,
            str(j.get("created_at", "-")),
        )

    return table


def render_backups_table(backups: List[Dict[str, Any]]) -> Table:
    """Render table of backup archives history."""
    table = Table(
        title="[bold green]Backup Archives Registry[/bold green]",
        header_style="bold green",
        expand=True,
    )
    table.add_column("No.", style="bold cyan", width=4, justify="center")
    table.add_column("ID", style="dim", width=10, justify="center")
    table.add_column("Type", style="cyan", width=12, justify="center")
    table.add_column("Target Name", style="bold white", width=22)
    table.add_column("File Name", style="dim white")
    table.add_column("Size", style="yellow", width=14, justify="right")
    table.add_column("File Exists", width=12, justify="center")
    table.add_column("Created At", style="dim", width=20)

    if not backups:
        table.add_row("-", "-", "-", "[dim italic]No backups generated yet[/dim italic]", "-", "-", "-", "-")
        return table

    for idx, b in enumerate(backups, 1):
        file_p = b.get("file_path", "")
        file_name = Path(file_p).name if file_p else "-"
        exists_badge = (
            "[green]YES[/green]"
            if b.get("file_exists", True)
            else "[red]MISSING[/red]"
        )
        raw_id = str(b.get("id", "-"))
        table.add_row(
            str(idx),
            raw_id[:8],
            b.get("backup_type", "-").upper(),
            b.get("target", "-"),
            file_name,
            b.get("size_human", "0 B"),
            exists_badge,
            str(b.get("created_at", "-")),
        )

    return table


def render_bundle_info_table(info: Dict[str, Any]) -> Panel:
    """Render structured metadata preview for a migration bundle."""
    grid = Table(show_header=False, box=None, expand=True, padding=(0, 1))
    grid.add_column("Property", style="bold cyan", width=22)
    grid.add_column("Value", style="bold white")

    grid.add_row("Bundle File:", info.get("bundle_path", "unknown"))
    grid.add_row("Archive Size:", info.get("file_size_human", "unknown"))
    grid.add_row("Exported At:", info.get("exported_at", "unknown"))
    grid.add_row("Origin Hostname:", info.get("hostname", "unknown"))
    grid.add_row("Origin OS:", info.get("os", "unknown"))
    grid.add_row("Panel Version:", info.get("version", "unknown"))

    counts = info.get("counts", {})
    counts_table = Table(title="[bold yellow]Contained Configuration Records[/bold yellow]", expand=True)
    counts_table.add_column("Resource Type", style="cyan")
    counts_table.add_column("Record Count", style="bold green", justify="right")

    counts_table.add_row("Websites (Nginx vhosts)", str(counts.get("sites", 0)))
    counts_table.add_row("Databases (MySQL/MariaDB)", str(counts.get("databases", 0)))
    counts_table.add_row("Firewall Port Rules (UFW)", str(counts.get("firewall_rules", 0)))
    counts_table.add_row("Scheduled Cron Tasks", str(counts.get("cron_jobs", 0)))
    counts_table.add_row("Backup Archive History", str(counts.get("backups", 0)))

    group = Group(grid, Text(""), counts_table)
    return Panel(group, title="[bold green]Migration Bundle Metadata Preview[/bold green]", border_style="green")


def render_migration_bundles_table(bundles: List[Dict[str, Any]]) -> Table:
    """Render table of found migration bundles."""
    table = Table(
        title="[bold cyan]Available Migration Bundles[/bold cyan]",
        header_style="bold cyan",
        expand=True,
    )
    table.add_column("ID", style="dim", width=4, justify="center")
    table.add_column("File Name", style="bold white", width=30)
    table.add_column("Size", style="yellow", width=12, justify="right")
    table.add_column("Exported At", style="dim", width=20)
    table.add_column("Origin Host", style="cyan", width=18)
    table.add_column("Sites", width=6, justify="center")
    table.add_column("DBs", width=6, justify="center")
    table.add_column("Rules", width=6, justify="center")
    table.add_column("Cron", width=6, justify="center")

    if not bundles:
        table.add_row("-", "[dim italic]No migration bundles found[/dim italic]", "-", "-", "-", "-", "-", "-", "-")
        return table

    for idx, b in enumerate(bundles, 1):
        file_name = Path(b.get("bundle_path", "")).name
        counts = b.get("counts", {})
        table.add_row(
            str(idx),
            file_name,
            b.get("file_size_human", "-"),
            str(b.get("exported_at", "-")),
            b.get("hostname", "-"),
            str(counts.get("sites", "-")),
            str(counts.get("databases", "-")),
            str(counts.get("firewall_rules", "-")),
            str(counts.get("cron_jobs", "-")),
        )

    return table


def render_doctor_report(diagnostics: List[Any], score: int, rating: str) -> Group:
    """Render full Panel Doctor diagnostics report and health score card."""
    table = Table(
        title="[bold cyan]Panel Doctor: Full System Health Diagnostics[/bold cyan]",
        header_style="bold cyan",
        expand=True,
    )
    table.add_column("Category", style="cyan", width=18)
    table.add_column("Check Item", style="bold white", width=26)
    table.add_column("Status", width=14, justify="center")
    table.add_column("Fixable", width=10, justify="center")
    table.add_column("Message / Details", style="dim white")

    for item in diagnostics:
        st = item.status.lower()
        if st == "passed":
            status_badge = "[bold green]PASSED[/bold green]"
        elif st == "warning":
            status_badge = "[bold yellow]WARNING[/bold yellow]"
        elif st == "fixed":
            status_badge = "[bold cyan]FIXED[/bold cyan]"
        else:
            status_badge = "[bold red]FAILED[/bold red]"

        fixable_badge = "[bold green]YES[/bold green]" if item.fixable else "[dim]NO[/dim]"

        table.add_row(
            item.category,
            item.name,
            status_badge,
            fixable_badge,
            item.message,
        )

    score_color = "bold green" if score >= 80 else "bold yellow" if score >= 60 else "bold red"
    score_panel = Panel(
        Text.from_markup(
            f"[{score_color}]Server Health Score: {score}/100 - {rating}[/{score_color}]\n"
            f"[dim]Run Auto-Repair to automatically remediate fixable warnings and failures.[/dim]"
        ),
        border_style="green" if score >= 80 else "yellow" if score >= 60 else "red",
        padding=(0, 1),
    )

    return Group(table, Text(""), score_panel)


def render_repair_report(repair_results: List[Tuple[str, bool, str]]) -> Table:
    """Render table summarizing auto-repair execution results."""
    table = Table(
        title="[bold green]Panel Doctor: Auto-Repair Summary[/bold green]",
        header_style="bold green",
        expand=True,
    )
    table.add_column("Action / Remediation", style="bold white", width=30)
    table.add_column("Result", width=14, justify="center")
    table.add_column("Status Message", style="dim white")

    if not repair_results:
        table.add_row("[dim italic]No repair actions were required[/dim italic]", "[green]CLEAN[/green]", "All checked items are healthy.")
        return table

    for action, success, msg in repair_results:
        res_badge = "[bold green]SUCCESS[/bold green]" if success else "[bold red]FAILED[/bold red]"
        table.add_row(action, res_badge, msg)

    return table


def render_tuner_dashboard(
    ram_info: Dict[str, Any],
    swap_info: Dict[str, Any],
    recommended_preset: str,
) -> Panel:
    """Render hardware resource summary and recommended tuning profile card."""
    table = Table(show_header=False, box=None, expand=True, padding=(0, 1))
    table.add_column("Metric", style="bold cyan", width=24)
    table.add_column("Value", style="bold white")

    table.add_row("Total Physical RAM:", f"{ram_info.get('total_human', '0 B')} ({ram_info.get('percent', 0)}% used)")
    table.add_row("Active Swap Memory:", f"{swap_info.get('total_human', '0 B')} (Free: {swap_info.get('free_human', '0 B')})")

    preset_color = "yellow" if recommended_preset == "low_end" else "green" if recommended_preset == "balanced" else "magenta"
    preset_label = f"[bold {preset_color}]{recommended_preset.replace('_', ' ').upper()}[/bold {preset_color}]"

    table.add_row("Recommended Preset:", preset_label)

    desc = {
        "low_end": "Conservative memory profile designed for VPS with <= 1.2 GB RAM (ondemand FPM, small buffers).",
        "balanced": "Optimized production profile for standard servers with 2 GB - 4.5 GB RAM.",
        "performance": "High-throughput profile for dedicated/large servers with > 4.5 GB RAM.",
    }.get(recommended_preset, "")

    group = Group(table, Text(""), Text(desc, style="dim italic"))
    return Panel(group, title="[bold green]Server Tuning & Hardware Profile[/bold green]", border_style="green")


def render_params_table(
    service_name: str,
    params: Dict[str, str],
    registry: Dict[str, Any],
) -> Table:
    """Render table of configurable parameters for a service (Tier 2)."""
    table = Table(
        title=f"[bold cyan]Performance Parameter Registry: {service_name.upper()}[/bold cyan]",
        header_style="bold cyan",
        expand=True,
    )
    table.add_column("#", style="dim", width=4, justify="center")
    table.add_column("Parameter Name", style="bold white", width=28)
    table.add_column("Current Value", style="bold yellow", width=16)
    table.add_column("Presets (Low / Bal / Perf)", style="cyan", width=24)
    table.add_column("Description", style="dim white")

    for idx, (param, val) in enumerate(params.items(), 1):
        meta = registry.get(param, {})
        presets = meta.get("presets", {})
        preset_str = f"{presets.get('low_end', '-')}/{presets.get('balanced', '-')}/{presets.get('performance', '-')}"
        desc = meta.get("description", "-")

        table.add_row(
            str(idx),
            param,
            str(val),
            preset_str,
            desc,
        )

    return table


def render_extensions_table(version: str, extensions: List[Dict[str, Any]]) -> Table:
    """Render table of available and installed PHP extensions."""
    table = Table(
        title=f"[bold magenta]PHP {version} Extension Manager[/bold magenta]",
        header_style="bold magenta",
        expand=True,
    )
    table.add_column("#", style="dim", width=4, justify="center")
    table.add_column("Extension", style="bold white", width=18)
    table.add_column("Status", width=16, justify="center")
    table.add_column("Description", style="dim white")

    for idx, ext in enumerate(extensions, 1):
        is_inst = ext.get("installed", False)
        status_badge = "[bold green]INSTALLED[/bold green]" if is_inst else "[dim]AVAILABLE[/dim]"
        table.add_row(
            str(idx),
            ext.get("name", "-"),
            status_badge,
            ext.get("description", "-"),
        )

    return table


def render_disabled_functions_view(
    version: str,
    disabled_funcs: List[str],
    baseline_funcs: Optional[List[str]] = None,
) -> Panel:
    """Render table and summary panel for PHP disabled functions security blacklist.

    Args:
        version: PHP version.
        disabled_funcs: Currently blacklisted function names.
        baseline_funcs: Standard security baseline function names.

    Returns:
        Panel: Rich panel with table and security recommendations.
    """
    baseline_set = set(baseline_funcs or [])
    curr_set = set(disabled_funcs)

    table = Table(
        title=f"[bold cyan]PHP {version} Disabled Functions (Blacklist)[/bold cyan]",
        header_style="bold cyan",
        expand=True,
    )
    table.add_column("#", style="dim", width=4, justify="center")
    table.add_column("Function Name", style="bold white", width=26)
    table.add_column("Status", width=22, justify="center")
    table.add_column("Security Baseline", width=20, justify="center")

    if not disabled_funcs:
        table.add_row("-", "[bold red]ALL FUNCTIONS ENABLED (NO RESTRICTIONS)[/bold red]", "[red]UNPROTECTED[/red]", "-")
    else:
        for idx, fn in enumerate(disabled_funcs, 1):
            is_baseline = fn in baseline_set
            baseline_badge = "[bold green]STANDARD BASELINE[/bold green]" if is_baseline else "[dim]CUSTOM BLOCKED[/dim]"
            table.add_row(
                str(idx),
                fn,
                "[bold red]DISABLED / BLOCKED[/bold red]",
                baseline_badge,
            )

    # Missing critical baseline functions alert
    missing_critical = [f for f in ["exec", "shell_exec", "system", "passthru", "proc_open", "popen"] if f not in curr_set]
    notes: List[str] = [
        f"[bold white]Total Disabled Functions:[/bold white] [bold cyan]{len(disabled_funcs)}[/bold cyan]"
    ]

    if missing_critical:
        notes.append(
            f"[bold yellow]Security Warning:[/bold yellow] High-risk functions not yet blocked: "
            f"[bold red]{', '.join(missing_critical)}[/bold red]. (Use Option [4] to apply baseline)."
        )
    else:
        notes.append("[bold green]Security Status: High-risk shell execution functions are safely blacklisted.[/bold green]")

    group = Group(table, Text(""), *[Text.from_markup(n) for n in notes])
    return Panel(group, title=f"[bold green]PHP {version} Security Policy: disable_functions[/bold green]", border_style="green")


def render_swap_info(swap_info: Dict[str, Any]) -> Panel:
    """Render Linux Swap memory status panel."""
    has_swap = swap_info.get("has_swap", False)
    status_badge = "[bold green]ENABLED[/bold green]" if has_swap else "[bold red]DISABLED (NO SWAP)[/bold red]"

    grid = Table(show_header=False, box=None, expand=True, padding=(0, 1))
    grid.add_column("Metric", style="bold cyan", width=20)
    grid.add_column("Value", style="bold white")

    grid.add_row("Swap Status:", status_badge)
    grid.add_row("Total Allocated:", swap_info.get("total_human", "0 B"))
    grid.add_row("Used Swap:", f"{swap_info.get('used_human', '0 B')} ({swap_info.get('percent', 0)}%)")
    grid.add_row("Free Swap:", swap_info.get('free_human', '0 B'))

    note = (
        "[dim]Swap memory prevents Out-Of-Memory (OOM) kernel panics by using disk space "
        "as an overflow memory buffer when RAM is exhausted.[/dim]"
    )

    group = Group(grid, Text(""), Text.from_markup(note))
    return Panel(group, title="[bold blue]Linux Swap Memory Configuration[/bold blue]", border_style="blue")


def render_log_snapshot(title: str, file_path: str, lines: List[str]) -> Panel:
    """Render a static snapshot of recent log lines."""
    body = Group(*[colorize_log_line(l) for l in lines]) if lines else Text("[No entries]", style="dim")
    return Panel(
        body,
        title=f"[bold cyan]Log Viewer: {title}[/bold cyan]",
        subtitle=f"[dim]{file_path}[/dim]",
        border_style="cyan",
        padding=(0, 1),
    )


def view_live_log_stream(title: str, log_key: str, mgr: Any) -> None:
    """Stream log lines in realtime until user presses Ctrl+C."""
    clear_screen()
    target_path = mgr.get_log_path(log_key)
    console.print(
        Panel(
            Text.from_markup(
                f"[bold yellow]Live Tailing:[/bold yellow] [bold white]{title}[/bold white]\n"
                f"[dim]Path: {target_path}  |  Press [bold red]Ctrl+C[/bold red] to return to menu[/dim]"
            ),
            border_style="yellow",
            padding=(0, 1),
        )
    )

    initial_lines = mgr.read_last_lines(log_key, lines=25)
    for line in initial_lines:
        console.print(colorize_log_line(line))

    console.print("[dim]---------- Live Log Stream Started ----------[/dim]")

    try:
        for new_line in mgr.stream_log(log_key, interval=0.4):
            console.print(colorize_log_line(new_line))
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Stream stopped. Returning to menu...[/bold yellow]")


def render_menu(title: str, options: List[Tuple[str, str]], description: str = "") -> Panel:
    """Render a styled menu options panel with safe key formatting."""
    table = Table(show_header=False, box=None, expand=True, padding=(0, 1))
    table.add_column("Key", width=8)
    table.add_column("Action", style="bold white")

    for key, label in options:
        key_text = Text()
        key_text.append(f"[{key}]", style="bold yellow")
        table.add_row(key_text, label)

    content: Any = table
    if description:
        desc_text = Text(description, style="dim italic")
        content = Group(desc_text, Text(""), table)

    return Panel(
        content,
        title=f"[bold cyan]{title}[/bold cyan]",
        border_style="cyan",
        padding=(0, 1),
    )


def render_vhost_content(domain: str, content: str) -> None:
    """Display Nginx virtual host configuration with syntax highlighting and line numbers.

    Args:
        domain: Domain name.
        content: Nginx configuration file content string.
    """
    syntax = Syntax(content, "nginx", theme="monokai", line_numbers=True, word_wrap=True)
    console.print(Panel(syntax, title=f"[bold cyan]Nginx Configuration: {domain}[/bold cyan]", border_style="cyan"))

