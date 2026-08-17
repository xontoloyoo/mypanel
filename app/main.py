"""Main CLI entry point for the cli-panel application."""

from pathlib import Path
import sys
from typing import NoReturn

# Ensure project root is in sys.path when executed directly as a script
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import psutil
from rich.prompt import Prompt

from app.core.database import init_db
from app.core.logger import get_logger
from app.modules.backup import BackupManager
from app.modules.cron import CronManager
from app.modules.database import DatabaseManager
from app.modules.doctor import PanelDoctor
from app.modules.firewall import FirewallManager
from app.modules.log_viewer import LogViewerManager
from app.modules.migration import MigrationManager
from app.modules.php_manager import PHPManager, SECURITY_BASELINE_FUNCTIONS
from app.modules.site import SiteManager
from app.modules.ssl import SSLManager
from app.modules.system import SystemManager, format_bytes
from app.modules.tuner import ConfigTuner, SwapManager, TUNER_REGISTRY
from app.ui.layout import clear_screen, console, render_footer, render_header, show_message
from app.ui.prompts import (
    ask_auto_repair_confirmation,
    ask_cron_job_inputs,
    ask_database_inputs,
    ask_extension_install,
    ask_firewall_inputs,
    ask_function_to_disable,
    ask_function_to_enable,
    ask_import_options,
    ask_manual_backup_inputs,
    ask_menu_choice,
    ask_param_edit,
    ask_php_version_selection,
    ask_preset_choice,
    ask_site_inputs,
    ask_ssl_inputs,
    ask_swap_setup_inputs,
    confirm_action,
    pause_for_user,
)
from app.ui.views import (
    render_backups_table,
    render_bundle_info_table,
    render_cron_table,
    render_dashboard,
    render_databases_table,
    render_disabled_functions_view,
    render_doctor_report,
    render_extensions_table,
    render_firewall_table,
    render_log_snapshot,
    render_menu,
    render_migration_bundles_table,
    render_params_table,
    render_repair_report,
    render_sites_table,
    render_swap_info,
    render_tuner_dashboard,
    render_vhost_content,
    view_live_log_stream,
)

logger = get_logger("main")


class PanelApp:
    """Main interactive terminal application controller."""

    def __init__(self) -> None:
        """Initialize managers and prepare database."""
        init_db()
        self.site_mgr = SiteManager()
        self.db_mgr = DatabaseManager()
        self.fw_mgr = FirewallManager()
        self.sys_mgr = SystemManager()
        self.ssl_mgr = SSLManager()
        self.backup_mgr = BackupManager()
        self.cron_mgr = CronManager()
        self.log_mgr = LogViewerManager()
        self.mig_mgr = MigrationManager()
        self.doctor = PanelDoctor()
        self.tuner = ConfigTuner()
        self.swap_mgr = SwapManager()
        self.php_mgr = PHPManager()

    def show_screen_header(self, subtitle: str = "v0.1-cli") -> None:
        """Clear screen and display standard header."""
        clear_screen()
        console.print(render_header(subtitle=subtitle))
        console.print("")

    # -------------------------------------------------------------------------
    # 1. Website Management Menu
    # -------------------------------------------------------------------------
    def handle_sites_menu(self) -> None:
        """Handle website management submenu loop."""
        while True:
            self.show_screen_header("Websites")
            sites = self.site_mgr.list_sites()
            console.print(render_sites_table(sites))
            console.print("")

            menu_options = [
                ("1", "Add New Website"),
                ("2", "Delete Website"),
                ("3", "Issue SSL Certificate (Let's Encrypt)"),
                ("4", "Disable SSL Certificate"),
                ("5", "View Nginx Vhost Config          [V]"),
                ("6", "Edit Nginx Vhost Config (CLI)    [E]"),
                ("7", "Reset Nginx Config to Default    [R]"),
                ("8", "Refresh List"),
                ("0", "Back to Main Menu"),
            ]
            console.print(render_menu("Website Actions", menu_options))
            console.print(render_footer())

            choice = ask_menu_choice(
                "Choose action",
                ["1", "2", "3", "4", "5", "6", "7", "8", "v", "V", "e", "E", "r", "R", "0"],
                default="0",
            )

            if choice == "1":
                inputs = ask_site_inputs()
                if inputs:
                    with console.status("[bold green]Configuring virtual host and directories..."):
                        ok, msg = self.site_mgr.create_site(
                            domain=inputs["domain"],
                            root_path=inputs["root_path"],
                            php_version=inputs["php_version"],
                        )
                    show_message(msg, "success" if ok else "error")
                    pause_for_user()
            elif choice == "2":
                if not sites:
                    show_message("No websites available to delete.", "warning")
                    pause_for_user()
                    continue

                domain = Prompt.ask("\nEnter domain name to delete", console=console).strip().lower()
                if not domain:
                    continue

                if confirm_action(f"Are you sure you want to delete website '{domain}'?"):
                    del_root = confirm_action("Also permanently delete document root directory?")
                    with console.status("[bold red]Removing Nginx config and database record..."):
                        ok, msg = self.site_mgr.delete_site(domain, delete_root=del_root)
                    show_message(msg, "success" if ok else "error")
                    pause_for_user()
            elif choice == "3":
                if not sites:
                    show_message("No websites registered. Add a website first.", "warning")
                    pause_for_user()
                    continue

                inputs = ask_ssl_inputs()
                if inputs:
                    with console.status(f"[bold green]Requesting Let's Encrypt SSL certificate for '{inputs['domain']}'..."):
                        ok, msg = self.ssl_mgr.request_ssl(
                            domain=inputs["domain"],
                            email=inputs["email"],
                        )
                    show_message(msg, "success" if ok else "error")
                    pause_for_user()
            elif choice == "4":
                if not sites:
                    show_message("No websites registered.", "warning")
                    pause_for_user()
                    continue

                domain = Prompt.ask("\nEnter domain name to disable SSL", console=console).strip().lower()
                if not domain:
                    continue

                if confirm_action(f"Disable SSL for '{domain}' and revert to standard HTTP?"):
                    with console.status("[bold yellow]Reverting Nginx config to HTTP..."):
                        ok, msg = self.ssl_mgr.disable_ssl(domain)
                    show_message(msg, "success" if ok else "error")
                    pause_for_user()
            elif choice in ("5", "v", "V"):
                if not sites:
                    show_message("No websites registered.", "warning")
                    pause_for_user()
                    continue

                domain = Prompt.ask("\nEnter domain name to view Nginx config", console=console).strip().lower()
                if not domain:
                    continue

                ok, content = self.site_mgr.read_vhost_config(domain)
                if ok:
                    clear_screen()
                    render_vhost_content(domain, content)
                    pause_for_user("Press Enter to return to Website menu...")
                else:
                    show_message(content, "error")
                    pause_for_user()
            elif choice in ("6", "e", "E"):
                if not sites:
                    show_message("No websites registered.", "warning")
                    pause_for_user()
                    continue

                domain = Prompt.ask("\nEnter domain name to edit Nginx config", console=console).strip().lower()
                if not domain:
                    continue

                ok, msg = self.site_mgr.edit_vhost_config_interactive(domain)
                show_message(msg, "success" if ok else "error")
                pause_for_user()
            elif choice in ("7", "r", "R"):
                if not sites:
                    show_message("No websites registered.", "warning")
                    pause_for_user()
                    continue

                domain = Prompt.ask("\nEnter domain name to reset Nginx config", console=console).strip().lower()
                if not domain:
                    continue

                if confirm_action(f"Are you sure you want to RESET Nginx config for '{domain}' to panel default template?"):
                    with console.status(f"[bold yellow]Resetting Nginx configuration for '{domain}'..."):
                        ok, msg = self.site_mgr.reset_vhost_config(domain)
                    show_message(msg, "success" if ok else "error")
                    pause_for_user()
            elif choice == "8":
                continue
            elif choice == "0":
                break

    # -------------------------------------------------------------------------
    # 2. Database Management Menu
    # -------------------------------------------------------------------------
    def handle_databases_menu(self) -> None:
        """Handle database management submenu loop."""
        while True:
            self.show_screen_header("Databases")
            databases = self.db_mgr.list_databases()
            console.print(render_databases_table(databases))
            console.print("")

            menu_options = [
                ("1", "Create New Database"),
                ("2", "Delete Database"),
                ("3", "Change User Password"),
                ("4", "Refresh List"),
                ("0", "Back to Main Menu"),
            ]
            console.print(render_menu("Database Actions", menu_options))
            console.print(render_footer())

            choice = ask_menu_choice("Choose action", ["1", "2", "3", "4", "0"], default="0")

            if choice == "1":
                inputs = ask_database_inputs()
                if inputs:
                    with console.status("[bold blue]Creating database and user in MySQL..."):
                        ok, msg = self.db_mgr.create_database(
                            db_name=inputs["db_name"],
                            db_user=inputs["db_user"],
                            db_pass=inputs["db_pass"],
                            charset=inputs["charset"],
                        )
                    show_message(msg, "success" if ok else "error")
                    pause_for_user()
            elif choice == "2":
                if not databases:
                    show_message("No databases available to delete.", "warning")
                    pause_for_user()
                    continue

                db_name = Prompt.ask("\nEnter database name to delete", console=console).strip()
                if not db_name:
                    continue

                if confirm_action(f"Are you sure you want to DROP database '{db_name}'? (Data will be lost!)"):
                    del_user = confirm_action("Also drop the associated MySQL user?")
                    with console.status("[bold red]Dropping database..."):
                        ok, msg = self.db_mgr.delete_database(db_name, delete_user=del_user)
                    show_message(msg, "success" if ok else "error")
                    pause_for_user()
            elif choice == "3":
                db_user = Prompt.ask("\nEnter database username", console=console).strip()
                if not db_user:
                    continue
                new_pass = Prompt.ask("Enter new password (min 6 characters)", console=console).strip()
                if not new_pass:
                    continue

                with console.status("[bold blue]Updating user password..."):
                    ok, msg = self.db_mgr.change_password(db_user, new_pass)
                show_message(msg, "success" if ok else "error")
                pause_for_user()
            elif choice == "4":
                continue
            elif choice == "0":
                break

    # -------------------------------------------------------------------------
    # 3. Firewall Management Menu
    # -------------------------------------------------------------------------
    def handle_firewall_menu(self) -> None:
        """Handle firewall management submenu loop."""
        while True:
            self.show_screen_header("Firewall")
            status = self.fw_mgr.get_status()
            rules = self.fw_mgr.list_rules()
            console.print(render_firewall_table(status, rules))
            console.print("")

            toggle_label = "Disable Firewall (UFW)" if status.get("active") else "Enable Firewall (UFW)"
            menu_options = [
                ("1", "Open Port / Add Rule"),
                ("2", "Delete Port Rule"),
                ("3", toggle_label),
                ("4", "Refresh Rules"),
                ("0", "Back to Main Menu"),
            ]
            console.print(render_menu("Firewall Actions", menu_options))
            console.print(render_footer())

            choice = ask_menu_choice("Choose action", ["1", "2", "3", "4", "0"], default="0")

            if choice == "1":
                inputs = ask_firewall_inputs()
                if inputs:
                    with console.status("[bold yellow]Adding firewall rule..."):
                        ok, msg = self.fw_mgr.add_rule(
                            port=inputs["port"],
                            protocol=inputs["protocol"],
                            action=inputs["action"],
                            description=inputs["description"],
                        )
                    show_message(msg, "success" if ok else "error")
                    pause_for_user()
            elif choice == "2":
                if not rules:
                    show_message("No firewall rules available to delete.", "warning")
                    pause_for_user()
                    continue

                rule_id_str = Prompt.ask("\nEnter rule ID to delete", console=console).strip()
                try:
                    rule_id = int(rule_id_str)
                except ValueError:
                    show_message("Invalid rule ID. Please enter a valid number.", "error")
                    pause_for_user()
                    continue

                if confirm_action(f"Delete firewall rule ID {rule_id}?"):
                    with console.status("[bold red]Deleting firewall rule..."):
                        ok, msg = self.fw_mgr.delete_rule(rule_id)
                    show_message(msg, "success" if ok else "error")
                    pause_for_user()
            elif choice == "3":
                target_state = not status.get("active", False)
                action_word = "ENABLE" if target_state else "DISABLE"
                if confirm_action(f"{action_word} the UFW firewall?"):
                    with console.status(f"[bold yellow]Toggling firewall {action_word.lower()}..."):
                        ok, msg = self.fw_mgr.toggle_firewall(target_state)
                    show_message(msg, "success" if ok else "error")
                    pause_for_user()
            elif choice == "4":
                continue
            elif choice == "0":
                break

    # -------------------------------------------------------------------------
    # 4. System Monitor & Services
    # -------------------------------------------------------------------------
    def handle_system_dashboard(self) -> None:
        """Display live server resources and core service statuses."""
        while True:
            self.show_screen_header("System Monitor")
            with console.status("[bold cyan]Gathering server performance metrics..."):
                metrics = self.sys_mgr.get_system_metrics()
                services = self.sys_mgr.check_core_services()

            console.print(render_dashboard(metrics, services))
            console.print("")

            menu_options = [
                ("r", "Refresh Metrics"),
                ("0", "Back to Main Menu"),
            ]
            console.print(render_menu("Monitor Actions", menu_options))
            console.print(render_footer())

            choice = ask_menu_choice("Choose action", ["r", "R", "0"], default="r")
            if choice.lower() == "r":
                continue
            elif choice == "0":
                break

    # -------------------------------------------------------------------------
    # 5. Cron & Backup Management Menu
    # -------------------------------------------------------------------------
    def handle_cron_backup_menu(self) -> None:
        """Handle scheduled cron tasks and backup archives submenu loop."""
        while True:
            self.show_screen_header("Cron & Backups")
            jobs = self.cron_mgr.list_jobs()
            backups = self.backup_mgr.list_backups()

            console.print(render_cron_table(jobs))
            console.print("")
            console.print(render_backups_table(backups))
            console.print("")

            menu_options = [
                ("1", "Schedule New Cron Task / Backup"),
                ("2", "Toggle Task (Active / Disabled)"),
                ("3", "Delete Cron Task"),
                ("4", "Create Immediate Manual Backup (Site or DB)"),
                ("5", "Delete Backup Archive File"),
                ("6", "Refresh Lists"),
                ("0", "Back to Main Menu"),
            ]
            console.print(render_menu("Cron & Backup Actions", menu_options))
            console.print(render_footer())

            choice = ask_menu_choice("Choose action", ["1", "2", "3", "4", "5", "6", "0"], default="0")

            if choice == "1":
                sites = self.site_mgr.list_sites()
                databases = self.db_mgr.list_databases()
                inputs = ask_cron_job_inputs(sites=sites, databases=databases)
                if inputs:
                    with console.status("[bold magenta]Registering scheduled cron task..."):
                        ok, msg = self.cron_mgr.add_job(
                            name=inputs["name"],
                            job_type=inputs["job_type"],
                            schedule=inputs["schedule"],
                            target=inputs["target"],
                        )
                    show_message(msg, "success" if ok else "error")
                    pause_for_user()
            elif choice == "2":
                if not jobs:
                    show_message("No scheduled tasks available to toggle.", "warning")
                    pause_for_user()
                    continue

                job_id_str = Prompt.ask("\nEnter Task ID to toggle", console=console).strip()
                try:
                    job_id = int(job_id_str)
                    target_job = next((j for j in jobs if j["id"] == job_id), None)
                    if not target_job:
                        show_message(f"Task ID {job_id} not found.", "error")
                        pause_for_user()
                        continue

                    new_state = target_job.get("status") != "active"
                    action_word = "activate" if new_state else "disable"
                    if confirm_action(f"{action_word.capitalize()} task '{target_job['name']}'?"):
                        with console.status(f"[bold yellow]Updating crontab..."):
                            ok, msg = self.cron_mgr.toggle_job(job_id, enable=new_state)
                        show_message(msg, "success" if ok else "error")
                        pause_for_user()
                except ValueError:
                    show_message("Invalid Task ID.", "error")
                    pause_for_user()
            elif choice == "3":
                if not jobs:
                    show_message("No scheduled tasks available to delete.", "warning")
                    pause_for_user()
                    continue

                job_id_str = Prompt.ask("\nEnter Task ID to delete", console=console).strip()
                try:
                    job_id = int(job_id_str)
                    if confirm_action(f"Delete cron task ID {job_id}?"):
                        with console.status("[bold red]Removing from crontab and database..."):
                            ok, msg = self.cron_mgr.delete_job(job_id)
                        show_message(msg, "success" if ok else "error")
                        pause_for_user()
                except ValueError:
                    show_message("Invalid Task ID.", "error")
                    pause_for_user()
            elif choice == "4":
                sites = self.site_mgr.list_sites()
                databases = self.db_mgr.list_databases()
                inputs = ask_manual_backup_inputs(sites=sites, databases=databases)
                if inputs:
                    b_type = inputs["backup_type"]
                    target = inputs["target"]
                    if b_type == "site":
                        with console.status(f"[bold green]Compressing website files for '{target}'..."):
                            ok, msg = self.backup_mgr.backup_site(target)
                    else:
                        with console.status(f"[bold green]Dumping database '{target}' to .sql.gz..."):
                            ok, msg = self.backup_mgr.backup_database(target)
                    show_message(msg, "success" if ok else "error")
                    pause_for_user()
            elif choice == "5":
                if not backups:
                    show_message("No backup archives recorded.", "warning")
                    pause_for_user()
                    continue

                backup_id_str = Prompt.ask("\nEnter Backup ID to delete", console=console).strip()
                try:
                    backup_id = int(backup_id_str)
                    if confirm_action(f"Permanently delete backup archive ID {backup_id}?"):
                        with console.status("[bold red]Deleting backup file..."):
                            ok, msg = self.backup_mgr.delete_backup(backup_id)
                        show_message(msg, "success" if ok else "error")
                        pause_for_user()
                except ValueError:
                    show_message("Invalid Backup ID.", "error")
                    pause_for_user()
            elif choice == "6":
                continue
            elif choice == "0":
                break

    # -------------------------------------------------------------------------
    # 6. Realtime Log Viewer Menu
    # -------------------------------------------------------------------------
    def handle_log_viewer_menu(self) -> None:
        """Handle realtime log viewing and log management submenu loop."""
        log_targets = {
            "1": ("Nginx Access Log", "nginx_access"),
            "2": ("Nginx Error Log", "nginx_error"),
            "3": ("Control Panel App Log", "panel_log"),
            "4": ("System Syslog", "syslog"),
            "5": ("Authentication & SSH Log", "auth_log"),
        }

        while True:
            self.show_screen_header("Log Viewer")

            menu_options = [
                ("1", "Nginx Access Log        (/var/log/nginx/access.log)"),
                ("2", "Nginx Error Log         (/var/log/nginx/error.log)"),
                ("3", "Control Panel App Log   (logs/app.log)"),
                ("4", "System Syslog           (/var/log/syslog)"),
                ("5", "Authentication Log      (/var/log/auth.log)"),
                ("6", "Clear / Truncate a Log File"),
                ("0", "Back to Main Menu"),
            ]
            console.print(render_menu("Log Viewer Targets", menu_options))
            console.print(render_footer())

            choice = ask_menu_choice("Choose log to inspect", ["1", "2", "3", "4", "5", "6", "0"], default="0")

            if choice in log_targets:
                title, log_key = log_targets[choice]
                p = self.log_mgr.get_log_path(log_key)
                console.print(f"\n[bold cyan]Target:[/bold cyan] {title} ([dim]{p}[/dim])")
                console.print("  [1] View Last 50 Lines (Snapshot)")
                console.print("  [2] Realtime Live Stream (Tail -f)")
                console.print("  [0] Cancel")

                sub_choice = ask_menu_choice("Select mode", ["1", "2", "0"], default="1")
                if sub_choice == "1":
                    lines = self.log_mgr.read_last_lines(log_key, lines=50)
                    clear_screen()
                    console.print(render_log_snapshot(title, str(p), lines))
                    pause_for_user("Press Enter to return to Log Viewer menu...")
                elif sub_choice == "2":
                    view_live_log_stream(title, log_key, self.log_mgr)
                    pause_for_user("Press Enter to return to Log Viewer menu...")
            elif choice == "6":
                console.print("\n[bold red]Select log file to clear:[/bold red]")
                for k, (t, _) in log_targets.items():
                    console.print(f"  [{k}] {t}")
                clear_target_key = ask_menu_choice("Choose target", ["1", "2", "3", "4", "5", "0"], default="0")
                if clear_target_key in log_targets:
                    t_title, t_key = log_targets[clear_target_key]
                    if confirm_action(f"Are you sure you want to TRUNCATE '{t_title}'? (All contents will be erased!)"):
                        ok, msg = self.log_mgr.clear_log(t_key)
                        show_message(msg, "success" if ok else "error")
                        pause_for_user()
            elif choice == "0":
                break

    # -------------------------------------------------------------------------
    # 7. Server Migration & Configuration Export/Import Menu
    # -------------------------------------------------------------------------
    def handle_migration_menu(self) -> None:
        """Handle server configuration export, inspection, and import submenu loop."""
        while True:
            self.show_screen_header("Server Migration & Config")

            menu_options = [
                ("1", "Export Server Configuration Bundle (.tar.gz)"),
                ("2", "Inspect / Preview Migration Bundle"),
                ("3", "Import & Restore Configuration Bundle"),
                ("4", "List Available Migration Bundles"),
                ("0", "Back to Main Menu"),
            ]
            console.print(render_menu("Migration Actions", menu_options))
            console.print(render_footer())

            choice = ask_menu_choice("Choose action", ["1", "2", "3", "4", "0"], default="0")

            if choice == "1":
                with console.status("[bold green]Packaging database and metadata into portable bundle..."):
                    ok, msg, bundle_path = self.mig_mgr.export_config()
                show_message(msg, "success" if ok else "error")
                if ok:
                    console.print(f"\n[dim]Export Path:[/dim] [bold cyan]{bundle_path}[/bold cyan]")
                pause_for_user()
            elif choice == "2":
                bundles = self.mig_mgr.list_bundles()
                if bundles:
                    console.print("\n[bold cyan]Select Migration Bundle to Inspect:[/bold cyan]")
                    for idx, b in enumerate(bundles, 1):
                        p = Path(b.get("bundle_path", ""))
                        console.print(f"  [{idx}] {p.name} ({b.get('file_size_human', '-')})")
                    console.print(f"  [{len(bundles) + 1}] Enter Custom File Path")
                    console.print("  [0] Cancel")

                    opt = ask_menu_choice(
                        "Choose option",
                        [str(i) for i in range(len(bundles) + 2)],
                        default="1",
                    )
                    if opt == "0":
                        continue
                    opt_idx = int(opt)
                    if 1 <= opt_idx <= len(bundles):
                        target_path = bundles[opt_idx - 1]["bundle_path"]
                    else:
                        target_path = Prompt.ask("Enter bundle path (.tar.gz)", console=console).strip()
                else:
                    target_path = Prompt.ask("\nEnter bundle path (.tar.gz)", console=console).strip()

                if not target_path:
                    continue

                with console.status("[bold cyan]Inspecting bundle manifest..."):
                    ok, manifest, msg = self.mig_mgr.inspect_bundle(target_path)
                if ok:
                    clear_screen()
                    console.print(render_bundle_info_table(manifest))
                else:
                    show_message(msg, "error")
                pause_for_user()
            elif choice == "3":
                bundles = self.mig_mgr.list_bundles()
                opts = ask_import_options(bundles)
                if opts:
                    with console.status("[bold yellow]Restoring database and synchronizing services..."):
                        ok, msg = self.mig_mgr.import_config(
                            opts["bundle_path"],
                            sync_system=opts["sync_system"],
                        )
                    show_message(msg, "success" if ok else "error")
                    pause_for_user()
            elif choice == "4":
                bundles = self.mig_mgr.list_bundles()
                clear_screen()
                console.print(render_migration_bundles_table(bundles))
                pause_for_user()
            elif choice == "0":
                break

    # -------------------------------------------------------------------------
    # 8. Panel Doctor (Self-Diagnostic & Auto-Repair) Menu
    # -------------------------------------------------------------------------
    def handle_doctor_menu(self) -> None:
        """Handle Panel Doctor diagnostics and auto-repair submenu loop."""
        while True:
            self.show_screen_header("Panel Doctor")

            menu_options = [
                ("1", "Run Full System Diagnostics"),
                ("2", "Run Auto-Repair for Detected Issues"),
                ("0", "Back to Main Menu"),
            ]
            console.print(render_menu("Doctor Actions", menu_options))
            console.print(render_footer())

            choice = ask_menu_choice("Choose action", ["1", "2", "0"], default="1")

            if choice == "1":
                with console.status("[bold cyan]Running system diagnostics & integrity check..."):
                    items = self.doctor.run_diagnostics()
                    score, rating = self.doctor.calculate_health_score(items)

                clear_screen()
                console.print(render_doctor_report(items, score, rating))

                fixable_count = sum(1 for it in items if it.fixable and it.status in ("warning", "failed"))
                if fixable_count > 0:
                    if ask_auto_repair_confirmation(fixable_count):
                        with console.status("[bold green]Executing auto-repair remediation..."):
                            repair_res = self.doctor.auto_repair(items)
                        console.print("")
                        console.print(render_repair_report(repair_res))

                pause_for_user()
            elif choice == "2":
                with console.status("[bold green]Executing auto-repair remediation..."):
                    repair_res = self.doctor.auto_repair()
                clear_screen()
                console.print(render_repair_report(repair_res))
                pause_for_user()
            elif choice == "0":
                break

    # -------------------------------------------------------------------------
    # 9. Server Tuning & PHP Config Menu
    # -------------------------------------------------------------------------
    def handle_php_disabled_functions_menu(self, current_php_ver: str = "8.2") -> None:
        """Handle dedicated PHP disabled functions security blacklist management."""
        php_ver = current_php_ver
        while True:
            self.show_screen_header(f"PHP {php_ver} Disabled Functions")
            disabled_funcs = self.php_mgr.get_disabled_functions(php_ver)
            console.print(render_disabled_functions_view(php_ver, disabled_funcs, SECURITY_BASELINE_FUNCTIONS))
            console.print("")

            menu_options = [
                ("1", "View Currently Disabled Functions"),
                ("2", "Enable / Unblock a Function (Remove from Blacklist)"),
                ("3", "Disable / Block a Custom Function (Add to Blacklist)"),
                ("4", "1-Click Apply Recommended Security Baseline (19 Functions)"),
                ("5", "Clear / Enable All Functions (Empty Blacklist)"),
                ("6", "Switch Target PHP Version"),
                ("0", "Back to Tuning Menu"),
            ]
            console.print(render_menu("Security Actions", menu_options))
            console.print(render_footer())

            choice = ask_menu_choice("Choose action", ["1", "2", "3", "4", "5", "6", "0"], default="1")

            if choice == "1":
                continue
            elif choice == "2":
                fn_to_enable = ask_function_to_enable(disabled_funcs)
                if fn_to_enable:
                    with console.status(f"[bold green]Unblocking '{fn_to_enable}' in PHP {php_ver}..."):
                        ok, msg = self.php_mgr.enable_function(php_ver, fn_to_enable)
                    show_message(msg, "success" if ok else "error")
                    pause_for_user()
            elif choice == "3":
                fn_to_disable = ask_function_to_disable()
                if fn_to_disable:
                    with console.status(f"[bold red]Blocking '{fn_to_disable}' in PHP {php_ver}..."):
                        ok, msg = self.php_mgr.disable_function(php_ver, fn_to_disable)
                    show_message(msg, "success" if ok else "error")
                    pause_for_user()
            elif choice == "4":
                if confirm_action(f"Apply 19 standard security baseline functions to PHP {php_ver}?"):
                    with console.status(f"[bold green]Enforcing security baseline in PHP {php_ver}..."):
                        ok, msg = self.php_mgr.apply_security_baseline(php_ver)
                    show_message(msg, "success" if ok else "error")
                    pause_for_user()
            elif choice == "5":
                if confirm_action(f"WARNING: Enable ALL functions in PHP {php_ver}? (Disables security blacklist!)"):
                    with console.status(f"[bold yellow]Clearing disabled functions in PHP {php_ver}..."):
                        ok, msg = self.php_mgr.clear_all_disabled(php_ver)
                    show_message(msg, "success" if ok else "error")
                    pause_for_user()
            elif choice == "6":
                installed = self.php_mgr.list_installed_versions()
                php_ver = ask_php_version_selection(installed)
            elif choice == "0":
                break

    def handle_tuner_menu(self) -> None:
        """Handle server optimization presets, parameter tuning, and PHP extensions."""
        current_php_ver = "8.2"
        while True:
            self.show_screen_header("Server Tuning & PHP Config")

            menu_options = [
                ("1", "Auto-Tune Server & 1-Click Optimization Presets (Tier 1)"),
                ("2", "PHP & PHP-FPM Parameter Tweak (Tier 2 - 16 Params)"),
                ("3", "Nginx Web Server Parameter Tweak (Tier 2 - 13 Params)"),
                ("4", "MariaDB Database Parameter Tweak (Tier 2 - 10 Params)"),
                ("5", "PHP Extensions Manager (Install 1-Click Extensions)"),
                ("6", "Direct Raw Config File Editor with Syntax Check (Tier 3)"),
                ("7", "Swap Memory Manager (Check / Auto-Create Swap)"),
                ("8", "PHP Disabled Functions Manager (Security Blacklist)"),
                ("0", "Back to Main Menu"),
            ]
            console.print(render_menu("Tuning & Performance Actions", menu_options))
            console.print(render_footer())

            choice = ask_menu_choice("Choose action", ["1", "2", "3", "4", "5", "6", "7", "8", "0"], default="1")

            if choice == "1":
                # Tier 1: Presets
                vmem = psutil.virtual_memory()
                ram_info = {"total_human": format_bytes(vmem.total), "percent": vmem.percent}
                swap_info = self.swap_mgr.get_swap_info()
                recommended = self.tuner.detect_optimal_preset()

                clear_screen()
                console.print(render_tuner_dashboard(ram_info, swap_info, recommended))

                selected_preset = ask_preset_choice(recommended)
                if selected_preset:
                    if confirm_action(f"Apply '{selected_preset.replace('_', ' ').upper()}' profile across PHP, Nginx, and MariaDB?"):
                        with console.status(f"[bold green]Applying {selected_preset} profile across services..."):
                            ok, msg = self.tuner.apply_preset("all", selected_preset)
                        show_message(msg, "success" if ok else "error")
                        pause_for_user()

            elif choice == "2":
                # Tier 2: PHP parameters (16 params)
                php_ver = Prompt.ask("\nEnter PHP Version", choices=["8.1", "8.2", "8.3", "8.0", "7.4"], default=current_php_ver, console=console)
                current_php_ver = php_ver
                params = self.tuner.get_current_params("php", php_version=php_ver)
                clear_screen()
                console.print(render_params_table("PHP & PHP-FPM", params, TUNER_REGISTRY["php"]))

                p_name, p_val = ask_param_edit("php", params, TUNER_REGISTRY["php"])
                if p_name and p_val:
                    with console.status(f"[bold green]Updating {p_name} to {p_val}..."):
                        ok, msg = self.tuner.update_parameter("php", p_name, p_val, php_version=php_ver)
                    show_message(msg, "success" if ok else "error")
                    pause_for_user()

            elif choice == "3":
                # Tier 2: Nginx parameters (13 params)
                params = self.tuner.get_current_params("nginx")
                clear_screen()
                console.print(render_params_table("Nginx Web Server", params, TUNER_REGISTRY["nginx"]))

                p_name, p_val = ask_param_edit("nginx", params, TUNER_REGISTRY["nginx"])
                if p_name and p_val:
                    with console.status(f"[bold green]Updating {p_name} to {p_val}..."):
                        ok, msg = self.tuner.update_parameter("nginx", p_name, p_val)
                    show_message(msg, "success" if ok else "error")
                    pause_for_user()

            elif choice == "4":
                # Tier 2: MySQL parameters (10 params)
                params = self.tuner.get_current_params("mysql")
                clear_screen()
                console.print(render_params_table("MariaDB / MySQL", params, TUNER_REGISTRY["mysql"]))

                p_name, p_val = ask_param_edit("mysql", params, TUNER_REGISTRY["mysql"])
                if p_name and p_val:
                    with console.status(f"[bold green]Updating {p_name} to {p_val}..."):
                        ok, msg = self.tuner.update_parameter("mysql", p_name, p_val)
                    show_message(msg, "success" if ok else "error")
                    pause_for_user()

            elif choice == "5":
                # PHP Extensions
                php_ver = Prompt.ask("\nEnter PHP Version", choices=["8.1", "8.2", "8.3", "8.0", "7.4"], default=current_php_ver, console=console)
                current_php_ver = php_ver
                extensions = self.php_mgr.get_available_extensions(php_ver)
                clear_screen()
                console.print(render_extensions_table(php_ver, extensions))

                ext_to_install = ask_extension_install(extensions)
                if ext_to_install:
                    with console.status(f"[bold magenta]Installing php{php_ver}-{ext_to_install}..."):
                        ok, msg = self.php_mgr.install_extension(php_ver, ext_to_install)
                    show_message(msg, "success" if ok else "error")
                    pause_for_user()

            elif choice == "6":
                # Tier 3: Direct Raw Config Editor
                console.print("\n[bold cyan]Select Target Configuration File to Edit:[/bold cyan]")
                console.print("  [1] Nginx Main Config       (/etc/nginx/nginx.conf)")
                console.print("  [2] Nginx WAF Rules         (/etc/nginx/waf/waf_default.conf)")
                console.print(f"  [3] PHP-FPM php.ini         (/etc/php/{current_php_ver}/fpm/php.ini)")
                console.print(f"  [4] PHP-FPM Pool Config     (/etc/php/{current_php_ver}/fpm/pool.d/www.conf)")
                console.print("  [5] MariaDB Server Config   (/etc/mysql/mariadb.conf.d/50-server.cnf)")
                console.print("  [0] Cancel")

                raw_choice = Prompt.ask("Choose target", choices=["1", "2", "3", "4", "5", "0"], default="1", console=console)
                if raw_choice == "1":
                    ok, msg = self.tuner.open_raw_editor("nginx", "nginx_conf")
                    show_message(msg, "success" if ok else "error")
                    pause_for_user()
                elif raw_choice == "2":
                    ok, msg = self.tuner.open_raw_editor("nginx", "nginx_waf")
                    show_message(msg, "success" if ok else "error")
                    pause_for_user()
                elif raw_choice == "3":
                    ok, msg = self.tuner.open_raw_editor("php", "php_ini", current_php_ver)
                    show_message(msg, "success" if ok else "error")
                    pause_for_user()
                elif raw_choice == "4":
                    ok, msg = self.tuner.open_raw_editor("php", "php_fpm", current_php_ver)
                    show_message(msg, "success" if ok else "error")
                    pause_for_user()
                elif raw_choice == "5":
                    ok, msg = self.tuner.open_raw_editor("mysql", "mysql_cnf")
                    show_message(msg, "success" if ok else "error")
                    pause_for_user()

            elif choice == "7":
                # Swap Manager
                swap_info = self.swap_mgr.get_swap_info()
                clear_screen()
                console.print(render_swap_info(swap_info))

                size_gb = ask_swap_setup_inputs()
                if size_gb:
                    if confirm_action(f"Create and activate {size_gb} GB swapfile on /swapfile?"):
                        with console.status(f"[bold blue]Creating {size_gb} GB swapfile..."):
                            ok, msg = self.swap_mgr.setup_swap(size_gb)
                        show_message(msg, "success" if ok else "error")
                        pause_for_user()

            elif choice == "8":
                # Dedicated Disabled Functions Manager
                self.handle_php_disabled_functions_menu(current_php_ver)

            elif choice == "0":
                break

    # -------------------------------------------------------------------------
    # Main Navigation Loop
    # -------------------------------------------------------------------------
    def run(self) -> None:
        """Run the main interactive menu loop."""
        logger.info("cli-panel interactive session started.")
        while True:
            self.show_screen_header("Main Menu")

            main_options = [
                ("1", "Website Management     (Nginx vhosts, webroots & SSL Let's Encrypt)"),
                ("2", "Database Management    (MySQL/MariaDB databases & users)"),
                ("3", "Firewall & Security    (UFW port rules & status)"),
                ("4", "System Monitor         (Live CPU, RAM, Disk & Services)"),
                ("5", "Cron & Backups         (Scheduled tasks & automated backup archives)"),
                ("6", "Log Viewer             (Realtime tail & snapshot for Nginx & System logs)"),
                ("7", "Server Migration       (Export/import full config bundles between servers)"),
                ("8", "Panel Doctor           (Self-check health diagnostics & auto-repair engine)"),
                ("9", "Server Tuning & PHP    (Auto-tune presets, 39 parameters, Swap & Extensions)"),
                ("0", "Exit Control Panel"),
            ]

            console.print(render_menu("Main Navigation", main_options, "Select a feature module to manage:"))
            console.print(render_footer())

            choice = ask_menu_choice("Select menu", ["1", "2", "3", "4", "5", "6", "7", "8", "9", "0"], default="0")

            if choice == "1":
                self.handle_sites_menu()
            elif choice == "2":
                self.handle_databases_menu()
            elif choice == "3":
                self.handle_firewall_menu()
            elif choice == "4":
                self.handle_system_dashboard()
            elif choice == "5":
                self.handle_cron_backup_menu()
            elif choice == "6":
                self.handle_log_viewer_menu()
            elif choice == "7":
                self.handle_migration_menu()
            elif choice == "8":
                self.handle_doctor_menu()
            elif choice == "9":
                self.handle_tuner_menu()
            elif choice == "0":
                clear_screen()
                console.print("\n[bold cyan]Thank you for using cli-panel. Goodbye![/bold cyan]\n")
                logger.info("cli-panel interactive session ended by user.")
                break


def main() -> None:
    """Application entry point with graceful interrupt and CLI flag handling."""
    # Handle standalone CLI flags (e.g. python app/main.py --doctor)
    if "--doctor" in sys.argv or "-d" in sys.argv:
        init_db()
        doctor = PanelDoctor()
        items = doctor.run_diagnostics()
        score, rating = doctor.calculate_health_score(items)
        console.print(render_doctor_report(items, score, rating))

        if "--repair" in sys.argv:
            console.print("\n[bold green]Running requested auto-repair...[/bold green]")
            repair_res = doctor.auto_repair(items)
            console.print(render_repair_report(repair_res))

        sys.exit(0)

    try:
        app = PanelApp()
        app.run()
    except (KeyboardInterrupt, EOFError):
        console.print("\n\n[bold yellow]Session interrupted. Exiting cli-panel safely.[/bold yellow]\n")
        logger.info("cli-panel session terminated by keyboard interrupt.")
        sys.exit(0)
    except Exception as exc:
        logger.exception("Unexpected fatal error in cli-panel: %s", exc)
        console.print(f"\n[bold red]Fatal Error:[/bold red] {exc}\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
