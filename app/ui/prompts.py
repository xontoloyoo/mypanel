"""User interaction helper for terminal inputs, prompts, and dialogs."""

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich.prompt import Confirm, Prompt

from app.ui.layout import console


def pause_for_user(message: str = "Press Enter to continue...") -> None:
    """Pause terminal execution and wait for user to press Enter."""
    console.print(f"\n[dim]{message}[/dim]", end="")
    try:
        input()
    except (KeyboardInterrupt, EOFError):
        pass


def ask_menu_choice(
    prompt_text: str = "Enter option",
    valid_choices: Optional[List[str]] = None,
    default: Optional[str] = None,
) -> str:
    """Prompt user for a valid menu option."""
    if valid_choices:
        return Prompt.ask(
            f"[bold cyan]{prompt_text}[/bold cyan]",
            choices=valid_choices,
            default=default,
            show_choices=False,
            console=console,
        ).strip()
    return Prompt.ask(
        f"[bold cyan]{prompt_text}[/bold cyan]",
        default=default,
        console=console,
    ).strip()


def confirm_action(prompt_text: str = "Are you sure you want to proceed?") -> bool:
    """Prompt user with a confirmation Yes/No question."""
    return Confirm.ask(
        f"[bold yellow]{prompt_text}[/bold yellow]",
        default=False,
        console=console,
    )


def ask_auto_repair_confirmation(issues_count: int) -> bool:
    """Prompt user to confirm automatic remediation of detected issues."""
    return Confirm.ask(
        f"\n[bold yellow]Panel Doctor found {issues_count} fixable issue(s). Run automatic repair now?[/bold yellow]",
        default=True,
        console=console,
    )


def ask_preset_choice(recommended: str = "balanced") -> Optional[str]:
    """Prompt user to choose an optimization preset profile."""
    console.print("\n[bold green]--- 1-Click Server Optimization Presets ---[/bold green]")
    console.print("  [1] Low-End Profile     (<= 1.2 GB RAM: ondemand FPM, minimal buffers)")
    console.print("  [2] Balanced Profile    (2 GB - 4.5 GB RAM: standard production tuning)")
    console.print("  [3] Performance Profile (> 4.5 GB RAM: max children, 1GB InnoDB pool)")
    console.print("  [0] Cancel")

    def_map = {"low_end": "1", "balanced": "2", "performance": "3"}
    default_choice = def_map.get(recommended, "2")

    choice = Prompt.ask(
        "Choose preset profile",
        choices=["1", "2", "3", "0"],
        default=default_choice,
        console=console,
    )
    res_map = {"1": "low_end", "2": "balanced", "3": "performance"}
    return res_map.get(choice)


def ask_param_edit(
    service_name: str,
    params: Dict[str, str],
    registry: Dict[str, Any],
) -> Tuple[Optional[str], Optional[str]]:
    """Prompt user to select a parameter and input a new value."""
    param_list = list(params.keys())
    console.print(f"\n[bold cyan]Select parameter number (1-{len(param_list)}) to edit, or 0 to cancel:[/bold cyan]")
    choice = Prompt.ask("Parameter #", default="0", console=console).strip()

    try:
        idx = int(choice)
        if idx == 0 or idx > len(param_list):
            return None, None
        param_name = param_list[idx - 1]
    except ValueError:
        return None, None

    meta = registry.get(param_name, {})
    curr_val = params.get(param_name, "")
    presets = meta.get("presets", {})
    preset_hint = f"Low: {presets.get('low_end', '-')}, Bal: {presets.get('balanced', '-')}, Perf: {presets.get('performance', '-')}"

    console.print(f"\nEditing [bold yellow]{param_name}[/bold yellow] (Current: [bold green]{curr_val}[/bold green])")
    console.print(f"[dim]Presets: {preset_hint}[/dim]")

    new_val = Prompt.ask("Enter new value", default=curr_val, console=console).strip()
    if not new_val:
        return None, None

    return param_name, new_val


def ask_extension_install(extensions: List[Dict[str, Any]]) -> Optional[str]:
    """Prompt user to choose an available PHP extension to install."""
    console.print("\n[bold magenta]Select PHP Extension to Install:[/bold magenta]")
    for idx, ext in enumerate(extensions, 1):
        status = "[green](Installed)[/green]" if ext.get("installed") else "[yellow](Available)[/yellow]"
        console.print(f"  [{idx}] {ext['name']} {status} - {ext['description']}")
    console.print("  [0] Cancel")

    choices = [str(i) for i in range(len(extensions) + 1)]
    choice = Prompt.ask("Choose extension #", choices=choices, default="0", console=console)

    if choice == "0":
        return None
    idx = int(choice)
    return extensions[idx - 1]["name"]


def ask_function_to_enable(current_list: List[str]) -> Optional[str]:
    """Prompt user to choose a currently blacklisted function to enable/unblock."""
    if not current_list:
        console.print("[yellow]No functions are currently blacklisted.[/yellow]")
        return None

    console.print("\n[bold green]Select function number to enable (unblock), or 0 to cancel:[/bold green]")
    for idx, fn in enumerate(current_list, 1):
        console.print(f"  [{idx}] {fn}")
    console.print("  [0] Cancel")

    choice = Prompt.ask("Function #", default="0", console=console).strip()
    try:
        idx = int(choice)
        if idx == 0 or idx > len(current_list):
            return None
        return current_list[idx - 1]
    except ValueError:
        # Check if user typed the function name directly
        if choice.lower() in current_list:
            return choice.lower()
        return None


def ask_function_to_disable() -> Optional[str]:
    """Prompt user to enter a custom function name to block in disable_functions."""
    console.print("\n[bold red]Block Custom PHP Function (Add to Blacklist)[/bold red]")
    fn_name = Prompt.ask("Enter function name to disable (e.g. phpinfo, proc_open)", console=console).strip().lower()
    return fn_name if fn_name else None


def ask_php_version_selection(installed_versions: List[str]) -> str:
    """Prompt user to choose which PHP version to manage."""
    if len(installed_versions) == 1:
        return installed_versions[0]

    console.print("\n[bold cyan]Select PHP Version:[/bold cyan]")
    for idx, v in enumerate(installed_versions, 1):
        console.print(f"  [{idx}] PHP {v}")

    choices = [str(i) for i in range(1, len(installed_versions) + 1)]
    choice = Prompt.ask("Choose version #", choices=choices, default="1", console=console)
    idx = int(choice)
    return installed_versions[idx - 1]


def ask_swap_setup_inputs() -> Optional[int]:
    """Prompt user to specify swapfile size."""
    console.print("\n[bold blue]--- Configure Linux Swap Memory ---[/bold blue]")
    console.print("  [1] 1 GB Swap")
    console.print("  [2] 2 GB Swap (Recommended for 1GB-2GB RAM)")
    console.print("  [3] 4 GB Swap (Recommended for 4GB RAM)")
    console.print("  [4] Custom Size in GB")
    console.print("  [0] Cancel")

    choice = Prompt.ask("Select Swap size option", choices=["1", "2", "3", "4", "0"], default="2", console=console)
    if choice == "0":
        return None
    elif choice == "1":
        return 1
    elif choice == "2":
        return 2
    elif choice == "3":
        return 4
    else:
        custom_str = Prompt.ask("Enter Swap size in GB (integer, e.g. 2, 4, 8)", default="2", console=console).strip()
        try:
            val = int(custom_str)
            return val if val > 0 else 2
        except ValueError:
            return 2


def ask_site_inputs(available_php_versions: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
    """Interactive input flow for creating a new website.

    Args:
        available_php_versions: Optional list of installed PHP version strings on the system.
    """
    console.print("\n[bold cyan]--- Add New Website ---[/bold cyan]")
    domain = Prompt.ask("Domain Name (e.g., mysite.com or test.local)", console=console).strip().lower()
    if not domain:
        console.print("[red]Domain name cannot be empty.[/red]")
        return None

    default_root = f"/www/wwwroot/{domain}"
    custom_root = Prompt.ask(
        "Document Root Path",
        default=default_root,
        console=console,
    ).strip()

    # Build dynamic PHP version choices based on actual server installations
    if available_php_versions:
        raw_versions = [v for v in available_php_versions if v.lower() != "none"]
        php_choices = ["none"] + sorted(list(set(raw_versions)), key=lambda v: [int(x) for x in v.split(".") if x.isdigit()])
    else:
        php_choices = ["none", "8.1", "8.2", "8.3"]

    default_php = php_choices[1] if len(php_choices) > 1 else "none"

    php_version = Prompt.ask(
        "PHP Version",
        choices=php_choices,
        default=default_php,
        console=console,
    ).strip()

    final_root = custom_root or default_root
    if final_root and not final_root.startswith("/"):
        final_root = f"/www/wwwroot/{final_root}"

    return {
        "domain": domain,
        "root_path": final_root,
        "php_version": php_version,
    }


def ask_database_inputs() -> Optional[Dict[str, Any]]:
    """Interactive input flow for creating a new database."""
    console.print("\n[bold blue]--- Create New Database ---[/bold blue]")
    db_name = Prompt.ask("Database Name", console=console).strip()
    if not db_name:
        console.print("[red]Database name cannot be empty.[/red]")
        return None

    db_user = Prompt.ask(
        "Database User",
        default=db_name,
        console=console,
    ).strip()

    db_pass = Prompt.ask(
        "Password (leave blank to auto-generate secure password)",
        default="",
        console=console,
    ).strip()

    charset = Prompt.ask(
        "Character Set",
        choices=["utf8mb4", "utf8"],
        default="utf8mb4",
        console=console,
    ).strip()

    return {
        "db_name": db_name,
        "db_user": db_user or db_name,
        "db_pass": db_pass or None,
        "charset": charset,
    }


def ask_firewall_inputs() -> Optional[Dict[str, Any]]:
    """Interactive input flow for adding a firewall rule."""
    console.print("\n[bold yellow]--- Add Firewall Port Rule ---[/bold yellow]")
    port = Prompt.ask("Port or Range (e.g. 80, 443, 8000:8080)", console=console).strip()
    if not port:
        console.print("[red]Port cannot be empty.[/red]")
        return None

    protocol = Prompt.ask(
        "Protocol",
        choices=["tcp", "udp", "any"],
        default="tcp",
        console=console,
    ).strip()

    action = Prompt.ask(
        "Action",
        choices=["allow", "deny"],
        default="allow",
        console=console,
    ).strip()

    description = Prompt.ask(
        "Description / Note (optional)",
        default="",
        console=console,
    ).strip()

    return {
        "port": port,
        "protocol": protocol,
        "action": action,
        "description": description,
    }


def ask_ssl_inputs() -> Optional[Dict[str, Any]]:
    """Interactive input flow for requesting Let's Encrypt SSL certificate."""
    console.print("\n[bold green]--- Issue Let's Encrypt SSL Certificate ---[/bold green]")
    domain = Prompt.ask("Domain Name to Secure", console=console).strip().lower()
    if not domain:
        console.print("[red]Domain name cannot be empty.[/red]")
        return None

    email = Prompt.ask(
        "Contact Email for Renewal Alerts (optional, press enter to skip)",
        default="",
        console=console,
    ).strip()

    return {
        "domain": domain,
        "email": email or None,
    }


def ask_cron_job_inputs(
    sites: Optional[List[Dict[str, Any]]] = None,
    databases: Optional[List[Dict[str, Any]]] = None,
) -> Optional[Dict[str, Any]]:
    """Interactive input flow for creating a new scheduled cron job."""
    console.print("\n[bold magenta]--- Schedule New Cron Task ---[/bold magenta]")
    name = Prompt.ask("Task Name (e.g., 'Daily Backup mysite.com')", console=console).strip()
    if not name:
        console.print("[red]Task name cannot be empty.[/red]")
        return None

    console.print("\n[bold cyan]Select Job Type:[/bold cyan]")
    console.print("  [1] Website Files Backup (.tar.gz)")
    console.print("  [2] Database Dump Backup (.sql.gz)")
    console.print("  [3] Custom Shell Command / Script")

    type_choice = Prompt.ask("Choose Type", choices=["1", "2", "3"], default="1", console=console)
    type_map = {"1": "site_backup", "2": "db_backup", "3": "shell_cmd"}
    job_type = type_map[type_choice]

    target = ""
    if job_type == "site_backup":
        if sites:
            console.print("\n[dim]Available Websites:[/dim] " + ", ".join([s["domain"] for s in sites]))
        target = Prompt.ask("Target Domain to Backup", console=console).strip().lower()
    elif job_type == "db_backup":
        if databases:
            console.print("\n[dim]Available Databases:[/dim] " + ", ".join([d["db_name"] for d in databases]))
        target = Prompt.ask("Target Database to Backup", console=console).strip()
    else:
        target = Prompt.ask("Shell Command or Script Path", console=console).strip()

    if not target:
        console.print("[red]Target cannot be empty.[/red]")
        return None

    console.print("\n[bold cyan]Select Execution Schedule:[/bold cyan]")
    console.print("  [1] Every Day at 02:00 AM   (0 2 * * *)")
    console.print("  [2] Every Sunday at 03:00 AM (0 3 * * 0)")
    console.print("  [3] Every Hour               (0 * * * *)")
    console.print("  [4] Custom Cron Expression")

    sched_choice = Prompt.ask("Choose Schedule", choices=["1", "2", "3", "4"], default="1", console=console)
    sched_map = {"1": "0 2 * * *", "2": "0 3 * * 0", "3": "0 * * * *"}

    if sched_choice in sched_map:
        schedule = sched_map[sched_choice]
    else:
        schedule = Prompt.ask(
            "Enter custom cron expression (e.g. '30 4 * * 1-5')",
            default="0 2 * * *",
            console=console,
        ).strip()

    return {
        "name": name,
        "job_type": job_type,
        "target": target,
        "schedule": schedule,
    }


def ask_manual_backup_inputs(
    sites: Optional[List[Dict[str, Any]]] = None,
    databases: Optional[List[Dict[str, Any]]] = None,
) -> Optional[Dict[str, Any]]:
    """Interactive input flow for triggering an immediate manual backup."""
    console.print("\n[bold green]--- Create Immediate Manual Backup ---[/bold green]")
    console.print("  [1] Website Files (.tar.gz)")
    console.print("  [2] Database SQL Dump (.sql.gz)")

    choice = Prompt.ask("Choose Backup Type", choices=["1", "2"], default="1", console=console)
    b_type = "site" if choice == "1" else "database"

    if b_type == "site":
        if sites:
            console.print("\n[dim]Available Websites:[/dim] " + ", ".join([s["domain"] for s in sites]))
        target = Prompt.ask("Domain Name to Backup", console=console).strip().lower()
    else:
        if databases:
            console.print("\n[dim]Available Databases:[/dim] " + ", ".join([d["db_name"] for d in databases]))
        target = Prompt.ask("Database Name to Backup", console=console).strip()

    if not target:
        console.print("[red]Target name cannot be empty.[/red]")
        return None

    return {
        "backup_type": b_type,
        "target": target,
    }


def ask_import_options(
    available_bundles: Optional[List[Dict[str, Any]]] = None,
) -> Optional[Dict[str, Any]]:
    """Interactive input flow for importing and restoring a configuration bundle."""
    console.print("\n[bold green]--- Import & Restore Configuration Bundle ---[/bold green]")

    bundle_path = ""
    if available_bundles:
        console.print("\n[bold cyan]Select Migration Bundle:[/bold cyan]")
        for idx, b in enumerate(available_bundles, 1):
            p = Path(b.get("bundle_path", ""))
            console.print(f"  [{idx}] {p.name} ({b.get('file_size_human', '-')}) - Host: {b.get('hostname', '-')}")
        console.print(f"  [{len(available_bundles) + 1}] Enter Custom File Path")
        console.print("  [0] Cancel")

        choices = [str(i) for i in range(len(available_bundles) + 2)]
        choice = Prompt.ask("Choose option", choices=choices, default="1", console=console)

        if choice == "0":
            return None
        choice_idx = int(choice)
        if 1 <= choice_idx <= len(available_bundles):
            bundle_path = available_bundles[choice_idx - 1]["bundle_path"]

    if not bundle_path:
        bundle_path = Prompt.ask("Enter migration bundle file path (.tar.gz)", console=console).strip()

    if not bundle_path or not Path(bundle_path).exists():
        console.print(f"[red]Error: Bundle file '{bundle_path}' does not exist.[/red]")
        return None

    console.print(f"\n[bold yellow]Target Bundle:[/bold yellow] {bundle_path}")
    if not confirm_action("WARNING: Importing will overwrite current panel database. Proceed?"):
        console.print("[yellow]Import cancelled by user.[/yellow]")
        return None

    sync_system = confirm_action("Re-apply and synchronize Nginx, Cron & Firewall rules to this server?")

    return {
        "bundle_path": bundle_path,
        "sync_system": sync_system,
    }
