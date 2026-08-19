"""Panel Doctor self-diagnostic and auto-repair engine for system health."""

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import sqlite3
from typing import Any, Callable, Dict, List, Optional, Tuple

import psutil

from app.core.database import DB_PATH, Database, get_db, init_db
from app.core.executor import run_cmd
from app.core.logger import BASE_DIR, get_logger
from app.modules.system import SystemManager, format_bytes

logger = get_logger("doctor")


@dataclass
class DiagnosticItem:
    """Represents a single diagnostic health check result."""

    category: str
    name: str
    status: str  # 'passed', 'warning', 'failed', 'fixed'
    message: str
    fixable: bool = False
    fix_action: Optional[str] = None


class PanelDoctor:
    """Self-diagnostic and auto-repair engine for cli-panel."""

    def __init__(self, db: Optional[Database] = None) -> None:
        """Initialize PanelDoctor with database handler.

        Args:
            db: Database instance.
        """
        self.db = db or get_db()

    def run_diagnostics(self) -> List[DiagnosticItem]:
        """Execute full suite of system, dependency, database, and storage diagnostics.

        Returns:
            List[DiagnosticItem]: List of diagnostic test results.
        """
        results: List[DiagnosticItem] = []

        # 1. Dependency & Binary Checks
        results.extend(self._check_dependencies())

        # 2. Core Services Status Checks
        results.extend(self._check_services())

        # 3. Storage Paths & Disk Utilization Checks
        results.extend(self._check_storage_and_paths())

        # 4. SQLite Database Health & Schema Checks
        results.extend(self._check_database_integrity())

        # 5. Nginx Configuration Syntax Check
        results.append(self._check_nginx_syntax())

        # 6. System Resource Limits
        results.extend(self._check_resource_limits())

        return results

    def _check_dependencies(self) -> List[DiagnosticItem]:
        """Check for presence of required system binaries."""
        items: List[DiagnosticItem] = []
        binaries = {
            "nginx": ("Nginx Web Server", True),
            "mysql": ("MySQL / MariaDB Client", False),
            "mariadb": ("MariaDB Server", False),
            "certbot": ("Certbot SSL Client", False),
            "ufw": ("UFW Firewall CLI", False),
            "crontab": ("Crontab Scheduling Daemon", False),
            "tar": ("Tar Archiver Utility", True),
            "gzip": ("Gzip Compression Utility", True),
            "sqlite3": ("SQLite3 CLI Engine", False),
        }

        for bin_name, (label, is_critical) in binaries.items():
            loc = shutil.which(bin_name)
            if not loc:
                cmd_check = run_cmd(f"which {bin_name}")
                if cmd_check.success and cmd_check.stdout.strip():
                    loc = cmd_check.stdout.strip()

            if loc:
                items.append(
                    DiagnosticItem(
                        category="Dependencies",
                        name=f"{label} ({bin_name})",
                        status="passed",
                        message=f"Binary located at: {loc}",
                    )
                )
            else:
                status = "failed" if is_critical and os.name != "nt" else "warning"
                items.append(
                    DiagnosticItem(
                        category="Dependencies",
                        name=f"{label} ({bin_name})",
                        status=status,
                        message="Binary not detected in system PATH.",
                        fixable=False,
                    )
                )

        return items

    def _check_services(self) -> List[DiagnosticItem]:
        """Check active status of key system services."""
        items: List[DiagnosticItem] = []
        services = ["nginx", "mysql", "ufw", "cron", "php-fpm"]

        for svc in services:
            st = SystemManager.get_service_status(svc)
            is_active = st.get("is_active", False)
            status_desc = st.get("status", "inactive")

            if is_active:
                items.append(
                    DiagnosticItem(
                        category="Services",
                        name=f"Service '{svc}'",
                        status="passed",
                        message=f"Service is active and running ({status_desc}).",
                    )
                )
            elif status_desc == "not-installed":
                items.append(
                    DiagnosticItem(
                        category="Services",
                        name=f"Service '{svc}'",
                        status="warning",
                        message="Service binary/unit not installed in current environment.",
                        fixable=False,
                    )
                )
            else:
                items.append(
                    DiagnosticItem(
                        category="Services",
                        name=f"Service '{svc}'",
                        status="warning",
                        message=f"Service status: {status_desc}.",
                        fixable=True,
                        fix_action=f"restart_service_{svc}",
                    )
                )

        return items

    def _check_storage_and_paths(self) -> List[DiagnosticItem]:
        """Check presence and write permissions for standard directories."""
        items: List[DiagnosticItem] = []
        paths_to_verify = [
            Path("/www/wwwroot") if os.name != "nt" else BASE_DIR / "data" / "wwwroot",
            Path("/www/backup/site") if os.name != "nt" else BASE_DIR / "data" / "backup" / "site",
            Path("/www/backup/database") if os.name != "nt" else BASE_DIR / "data" / "backup" / "database",
            Path("/www/backup/migration") if os.name != "nt" else BASE_DIR / "data" / "backups" / "migration",
            BASE_DIR / "logs",
            BASE_DIR / "data",
        ]

        for p in paths_to_verify:
            if not p.exists():
                items.append(
                    DiagnosticItem(
                        category="Storage & Paths",
                        name=f"Directory '{p}'",
                        status="warning",
                        message="Directory does not exist.",
                        fixable=True,
                        fix_action="create_missing_dirs",
                    )
                )
            elif not os.access(p, os.W_OK):
                items.append(
                    DiagnosticItem(
                        category="Storage & Paths",
                        name=f"Directory '{p}'",
                        status="failed",
                        message="Directory exists but is not writable.",
                        fixable=True,
                        fix_action="fix_permissions",
                    )
                )
            else:
                items.append(
                    DiagnosticItem(
                        category="Storage & Paths",
                        name=f"Directory '{p.name or p}'",
                        status="passed",
                        message=f"Path '{p}' is accessible and writable.",
                    )
                )

        return items

    def _check_database_integrity(self) -> List[DiagnosticItem]:
        """Verify SQLite database integrity and table schema completeness."""
        items: List[DiagnosticItem] = []
        db_file = Path(self.db.db_path)

        if not db_file.exists():
            items.append(
                DiagnosticItem(
                    category="Database Integrity",
                    name="SQLite Database File",
                    status="failed",
                    message=f"Database file '{db_file}' not found.",
                    fixable=True,
                    fix_action="repair_database",
                )
            )
            return items

        try:
            with sqlite3.connect(str(db_file)) as conn:
                cursor = conn.cursor()

                # 1. PRAGMA integrity_check
                cursor.execute("PRAGMA integrity_check;")
                check_row = cursor.fetchone()
                if check_row and check_row[0] == "ok":
                    items.append(
                        DiagnosticItem(
                            category="Database Integrity",
                            name="SQLite PRAGMA Integrity Check",
                            status="passed",
                            message="Database binary structure is healthy and consistent.",
                        )
                    )
                else:
                    items.append(
                        DiagnosticItem(
                            category="Database Integrity",
                            name="SQLite PRAGMA Integrity Check",
                            status="failed",
                            message=f"Integrity check reported issues: {check_row}",
                            fixable=True,
                            fix_action="repair_database",
                        )
                    )

                # 2. Table completeness check
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
                existing_tables = {row[0] for row in cursor.fetchall()}
                required_tables = ["sites", "databases", "firewall_rules", "cron_jobs", "backups", "settings"]
                missing_tables = [t for t in required_tables if t not in existing_tables]

                if not missing_tables:
                    items.append(
                        DiagnosticItem(
                            category="Database Integrity",
                            name="Database Schema Tables",
                            status="passed",
                            message=f"All {len(required_tables)} core schema tables are present.",
                        )
                    )
                else:
                    items.append(
                        DiagnosticItem(
                            category="Database Integrity",
                            name="Database Schema Tables",
                            status="warning",
                            message=f"Missing schema tables: {', '.join(missing_tables)}",
                            fixable=True,
                            fix_action="repair_database",
                        )
                    )

        except Exception as exc:
            items.append(
                DiagnosticItem(
                    category="Database Integrity",
                    name="SQLite Connection Check",
                    status="failed",
                    message=f"Database error: {exc}",
                    fixable=True,
                    fix_action="repair_database",
                )
            )

        return items

    def _check_nginx_syntax(self) -> DiagnosticItem:
        """Validate Nginx configuration syntax via nginx -t."""
        res = run_cmd("nginx -t")
        if res.success:
            return DiagnosticItem(
                category="Services",
                name="Nginx Configuration Syntax",
                status="passed",
                message="Nginx configuration test passed (syntax is ok).",
            )
        elif "not found" in res.stderr.lower() or "not recognized" in res.stderr.lower():
            return DiagnosticItem(
                category="Services",
                name="Nginx Configuration Syntax",
                status="warning",
                message="Nginx binary not installed in current environment.",
            )
        else:
            err_msg = res.stderr.strip().split("\n")[0] if res.stderr else "Syntax error in vhost files."
            return DiagnosticItem(
                category="Services",
                name="Nginx Configuration Syntax",
                status="failed",
                message=f"Configuration test failed: {err_msg}",
            )

    def _check_resource_limits(self) -> List[DiagnosticItem]:
        """Check disk and memory resource utilization."""
        items: List[DiagnosticItem] = []

        # 1. Disk usage
        try:
            root_path = "/" if os.name != "nt" else str(BASE_DIR.anchor)
            disk = psutil.disk_usage(root_path)
            if disk.percent < 85.0:
                status = "passed"
                msg = f"Disk usage is healthy ({disk.percent}% used, {format_bytes(disk.free)} free)."
            elif disk.percent < 95.0:
                status = "warning"
                msg = f"Disk usage is high ({disk.percent}% used, {format_bytes(disk.free)} free)."
            else:
                status = "failed"
                msg = f"Disk usage is critical ({disk.percent}% used, {format_bytes(disk.free)} free)."

            items.append(
                DiagnosticItem(
                    category="Resource Limits",
                    name="Disk Partition Capacity",
                    status=status,
                    message=msg,
                )
            )
        except Exception as exc:
            items.append(
                DiagnosticItem(
                    category="Resource Limits",
                    name="Disk Partition Capacity",
                    status="warning",
                    message=f"Could not read disk usage: {exc}",
                )
            )

        # 2. RAM usage
        try:
            mem = psutil.virtual_memory()
            if mem.percent < 90.0:
                status = "passed"
                msg = f"RAM usage is healthy ({mem.percent}% used, {format_bytes(mem.available)} available)."
            else:
                status = "warning"
                msg = f"RAM usage is high ({mem.percent}% used, {format_bytes(mem.available)} available)."

            items.append(
                DiagnosticItem(
                    category="Resource Limits",
                    name="System Memory (RAM)",
                    status=status,
                    message=msg,
                )
            )
        except Exception as exc:
            items.append(
                DiagnosticItem(
                    category="Resource Limits",
                    name="System Memory (RAM)",
                    status="warning",
                    message=f"Could not read memory metrics: {exc}",
                )
            )

        return items

    def calculate_health_score(self, items: List[DiagnosticItem]) -> Tuple[int, str]:
        """Calculate aggregate server health score (0-100) and rating string.

        Args:
            items: List of diagnostic test items.

        Returns:
            Tuple[int, str]: (Health score integer, Rating description).
        """
        score = 100
        for it in items:
            if it.status == "failed":
                score -= 15
            elif it.status == "warning":
                score -= 4

        score = max(0, min(100, score))

        if score >= 90:
            rating = "Excellent / Healthy"
        elif score >= 75:
            rating = "Good / Minor Warnings"
        elif score >= 50:
            rating = "Fair / Action Recommended"
        else:
            rating = "Critical / Maintenance Required"

        return score, rating

    def auto_repair(
        self,
        items_to_fix: Optional[List[DiagnosticItem]] = None,
    ) -> List[Tuple[str, bool, str]]:
        """Attempt automatic remediation for fixable diagnostic issues.

        Args:
            items_to_fix: Optional subset of items to fix. If None, runs full diagnostic first.

        Returns:
            List[Tuple[str, bool, str]]: List of (Action Name, Success, Status Message).
        """
        if items_to_fix is None:
            diagnostics = self.run_diagnostics()
            items_to_fix = [d for d in diagnostics if d.fixable and d.status in ("warning", "failed")]

        results: List[Tuple[str, bool, str]] = []
        handled_actions = set()

        for it in items_to_fix:
            action = it.fix_action
            if not action or action in handled_actions:
                continue
            handled_actions.add(action)

            if action == "create_missing_dirs":
                try:
                    paths = [
                        Path("/www/wwwroot") if os.name != "nt" else BASE_DIR / "data" / "wwwroot",
                        Path("/www/backup/site") if os.name != "nt" else BASE_DIR / "data" / "backup" / "site",
                        Path("/www/backup/database") if os.name != "nt" else BASE_DIR / "data" / "backup" / "database",
                        Path("/www/backup/migration") if os.name != "nt" else BASE_DIR / "data" / "backups" / "migration",
                        BASE_DIR / "logs",
                        BASE_DIR / "data",
                    ]
                    for p in paths:
                        p.mkdir(parents=True, exist_ok=True)
                    try:
                        from app.modules.site import ensure_default_block_config, ensure_waf_snippet
                        ensure_waf_snippet()
                        ensure_default_block_config()
                    except Exception:
                        pass
                    results.append(("Create Missing Directories", True, "Standard directory structure and Nginx configs restored."))
                    logger.info("Auto-repair: Created missing storage directories and Nginx configs.")
                except Exception as exc:
                    results.append(("Create Missing Directories", False, str(exc)))

            elif action == "repair_database":
                try:
                    init_db()
                    results.append(("Repair Database Schema", True, "SQLite database and tables re-initialized."))
                    logger.info("Auto-repair: SQLite database schema initialized/repaired.")
                except Exception as exc:
                    results.append(("Repair Database Schema", False, str(exc)))

            elif action.startswith("restart_service_"):
                svc_name = action.replace("restart_service_", "")
                if svc_name == "php-fpm":
                    res = run_cmd("systemctl restart php8.2-fpm || systemctl restart php8.3-fpm || systemctl restart php8.1-fpm || systemctl restart php-fpm")
                elif svc_name == "mysql":
                    res = run_cmd("systemctl restart mysql || systemctl restart mariadb")
                else:
                    res = run_cmd(f"systemctl restart {svc_name}")

                if res.success:
                    results.append((f"Restart Service '{svc_name}'", True, "Service restarted successfully."))
                    logger.info("Auto-repair: Restarted service '%s'.", svc_name)
                else:
                    results.append((f"Restart Service '{svc_name}'", False, res.stderr or "Failed to start service."))

        return results
