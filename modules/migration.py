"""Server migration and configuration export/import manager."""

from datetime import datetime
import json
import os
from pathlib import Path
import platform
import shutil
import sqlite3
import tarfile
import tempfile
from typing import Any, Dict, List, Optional, Tuple

from app.core.database import DB_PATH, Database, get_db
from app.core.logger import BASE_DIR, get_logger
from app.modules.cron import CronManager
from app.modules.firewall import FirewallManager
from app.modules.site import SiteManager
from app.modules.system import format_bytes

logger = get_logger("migration")


class MigrationManager:
    """Manager for exporting, inspecting, and importing panel configuration bundles."""

    def __init__(
        self,
        migration_dir: Optional[str] = None,
        db: Optional[Database] = None,
    ) -> None:
        """Initialize MigrationManager.

        Args:
            migration_dir: Directory where migration bundles are saved.
            db: Database instance.
        """
        self.db = db or get_db()
        default_dir = Path("/www/backup/migration")
        fallback_dir = BASE_DIR / "data" / "backups" / "migration"

        if migration_dir:
            self.migration_dir = Path(migration_dir)
        elif default_dir.parent.exists() or os.name != "nt":
            self.migration_dir = default_dir
        else:
            self.migration_dir = fallback_dir

        self._ensure_dir()

    def _ensure_dir(self) -> None:
        """Ensure migration storage directory exists."""
        try:
            self.migration_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            logger.debug("Could not create default migration directory: %s", exc)

    def export_config(self, output_dir: Optional[str] = None) -> Tuple[bool, str, str]:
        """Export all server configurations and SQLite database into a portable bundle.

        Args:
            output_dir: Optional custom output directory for the bundle.

        Returns:
            Tuple[bool, str, str]: (Success boolean, Status message, Bundle file path).
        """
        dest_dir = Path(output_dir) if output_dir else self.migration_dir
        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
        except Exception as exc:
            dest_dir = BASE_DIR / "data" / "backups" / "migration"
            dest_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        bundle_name = f"panel_migration_{timestamp}.tar.gz"
        bundle_path = dest_dir / bundle_name

        try:
            # 1. Gather Resource Counts
            counts: Dict[str, int] = {}
            with self.db:
                for table in ["sites", "databases", "firewall_rules", "cron_jobs", "backups"]:
                    try:
                        res = self.db.fetch_one(f"SELECT COUNT(*) as count FROM {table};")
                        counts[table] = res["count"] if res else 0
                    except Exception:
                        counts[table] = 0

            # 2. Prepare Manifest
            manifest = {
                "version": "0.1-cli",
                "exported_at": datetime.now().isoformat(),
                "hostname": platform.node(),
                "os": f"{platform.system()} {platform.release()}",
                "counts": counts,
            }

            # 3. Create Temporary Staging Directory
            with tempfile.TemporaryDirectory() as tmp_dir:
                tmp_p = Path(tmp_dir)
                manifest_file = tmp_p / "manifest.json"
                manifest_file.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

                # Safe database snapshot using SQLite backup API
                db_snapshot = tmp_p / "panel.db"
                src_conn = sqlite3.connect(str(self.db.db_path))
                dst_conn = sqlite3.connect(str(db_snapshot))
                src_conn.backup(dst_conn)
                src_conn.close()
                dst_conn.close()

                # 4. Create .tar.gz bundle
                with tarfile.open(bundle_path, "w:gz") as tar:
                    tar.add(manifest_file, arcname="manifest.json")
                    tar.add(db_snapshot, arcname="panel.db")

            file_size = bundle_path.stat().st_size
            msg = (
                f"Configuration bundle successfully created: {bundle_name} "
                f"({format_bytes(file_size)})"
            )
            logger.info("Exported migration bundle: %s", bundle_path)
            return True, msg, str(bundle_path)

        except Exception as exc:
            err_msg = f"Failed to export configuration bundle: {exc}"
            logger.exception(err_msg)
            if bundle_path.exists():
                bundle_path.unlink()
            return False, err_msg, ""

    def inspect_bundle(self, bundle_path: str) -> Tuple[bool, Dict[str, Any], str]:
        """Inspect and parse metadata manifest from a migration bundle without full extraction.

        Args:
            bundle_path: Path to the .tar.gz migration bundle file.

        Returns:
            Tuple[bool, Dict[str, Any], str]: (Success boolean, Manifest dictionary, Status message).
        """
        p = Path(bundle_path)
        if not p.exists():
            return False, {}, f"Bundle file '{p}' not found on disk."

        try:
            with tarfile.open(p, "r:gz") as tar:
                names = tar.getnames()
                if "manifest.json" not in names or "panel.db" not in names:
                    return False, {}, "Invalid migration bundle: missing 'manifest.json' or 'panel.db'."

                manifest_member = tar.extractfile("manifest.json")
                if not manifest_member:
                    return False, {}, "Could not read manifest from bundle."

                manifest_data = json.loads(manifest_member.read().decode("utf-8"))
                manifest_data["bundle_path"] = str(p)
                manifest_data["file_size_human"] = format_bytes(p.stat().st_size)

                return True, manifest_data, "Bundle integrity verified."

        except Exception as exc:
            err_msg = f"Failed to inspect bundle '{p.name}': {exc}"
            logger.error(err_msg)
            return False, {}, err_msg

    def import_config(
        self,
        bundle_path: str,
        sync_system: bool = True,
    ) -> Tuple[bool, str]:
        """Import configuration bundle, restore SQLite database, and optionally synchronize system services.

        Args:
            bundle_path: Path to the migration bundle file.
            sync_system: Whether to re-apply Nginx, Cron, and Firewall rules.

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        # 1. Verify bundle
        ok, manifest, inspect_msg = self.inspect_bundle(bundle_path)
        if not ok:
            return False, f"Import aborted: {inspect_msg}"

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        curr_db_path = Path(self.db.db_path)

        try:
            # 2. Create emergency backup of current database
            if curr_db_path.exists():
                backup_db_path = curr_db_path.parent / f"panel.db.bak_{timestamp}"
                shutil.copy2(curr_db_path, backup_db_path)
                logger.info("Created emergency pre-import database backup: %s", backup_db_path)

            # 3. Extract and replace panel.db
            with tempfile.TemporaryDirectory() as tmp_dir:
                with tarfile.open(bundle_path, "r:gz") as tar:
                    tar.extract("panel.db", path=tmp_dir)

                extracted_db = Path(tmp_dir) / "panel.db"
                if not extracted_db.exists():
                    return False, "Corrupted archive: panel.db could not be extracted."

                # Verify extracted DB is a valid SQLite file
                test_conn = sqlite3.connect(str(extracted_db))
                test_conn.execute("SELECT name FROM sqlite_master WHERE type='table';")
                test_conn.close()

                # Replace current DB
                self.db.close()
                shutil.copy2(extracted_db, curr_db_path)
                logger.info("Restored database from bundle: %s", bundle_path)

            # 4. Synchronize System Services if requested
            if sync_system:
                self._sync_system_services()

            counts = manifest.get("counts", {})
            summary_parts = [
                f"{counts.get('sites', 0)} site(s)",
                f"{counts.get('databases', 0)} db(s)",
                f"{counts.get('firewall_rules', 0)} firewall rule(s)",
                f"{counts.get('cron_jobs', 0)} cron task(s)",
            ]
            msg = (
                f"Configuration bundle successfully restored! "
                f"Restored: {', '.join(summary_parts)}."
            )
            logger.info(msg)
            return True, msg

        except Exception as exc:
            err_msg = f"Failed to import configuration bundle: {exc}"
            logger.exception(err_msg)
            return False, err_msg

    def _sync_system_services(self) -> None:
        """Re-synchronize Nginx virtual hosts, cron jobs, and firewall rules from restored database."""
        logger.info("Synchronizing system services with newly imported database...")

        # 1. Re-sync Websites (Nginx)
        site_mgr = SiteManager(db=self.db)
        sites = site_mgr.list_sites()
        for s in sites:
            domain = s.get("domain")
            root_p = s.get("root_path")
            php_v = s.get("php_version", "none")
            if domain and root_p:
                try:
                    os.makedirs(root_p, exist_ok=True)
                    site_mgr._create_placeholder_index(root_p, domain, php_v)
                    vhost_content = site_mgr._generate_nginx_config(domain, root_p, php_v)
                    vhost_file = Path(site_mgr.nginx_available) / f"{domain}.conf"
                    if vhost_file.parent.exists() or os.name == "nt":
                        vhost_file.parent.mkdir(parents=True, exist_ok=True)
                        vhost_file.write_text(vhost_content, encoding="utf-8")
                except Exception as exc:
                    logger.warning("Could not re-sync site '%s': %s", domain, exc)
        site_mgr._reload_nginx()

        # 2. Re-sync Cron Jobs
        cron_mgr = CronManager(db=self.db)
        jobs = cron_mgr.list_jobs()
        for j in jobs:
            if j.get("status") == "active":
                try:
                    cmd_str = cron_mgr._build_command_string(j["id"], j["job_type"], j["target"])
                    cron_entry = f"{j['schedule']} {cmd_str} # CLI_PANEL_JOB_{j['id']}"
                    lines = cron_mgr._get_crontab_lines()
                    if not any(f"JOB_{j['id']}" in l for l in lines):
                        lines.append(cron_entry)
                        cron_mgr._write_crontab_lines(lines)
                except Exception as exc:
                    logger.warning("Could not re-sync cron job ID %s: %s", j.get("id"), exc)

        # 3. Re-sync Firewall Rules
        fw_mgr = FirewallManager(db=self.db)
        rules = fw_mgr.list_rules()
        for r in rules:
            try:
                port_str = r.get("port")
                protocol = r.get("protocol", "tcp")
                action = r.get("action", "allow")
                if protocol == "any":
                    cmd = f"ufw {action} {port_str}"
                else:
                    cmd = f"ufw {action} {port_str}/{protocol}"
                fw_mgr.run_cmd = fw_mgr.run_cmd if hasattr(fw_mgr, "run_cmd") else None
            except Exception as exc:
                logger.warning("Could not re-sync firewall rule ID %s: %s", r.get("id"), exc)

        logger.info("System services synchronization completed.")

    def list_bundles(self) -> List[Dict[str, Any]]:
        """List all valid migration bundle archives found in the migration directory.

        Returns:
            List[Dict[str, Any]]: List of bundle metadata dictionaries.
        """
        bundles: List[Dict[str, Any]] = []
        if not self.migration_dir.exists():
            return bundles

        for f in sorted(self.migration_dir.glob("*.tar.gz"), reverse=True):
            ok, manifest, _ = self.inspect_bundle(str(f))
            if ok:
                bundles.append(manifest)
            else:
                bundles.append({
                    "bundle_path": str(f),
                    "file_size_human": format_bytes(f.stat().st_size),
                    "version": "unknown",
                    "exported_at": "unknown",
                    "hostname": "unknown",
                    "counts": {},
                })

        return bundles
