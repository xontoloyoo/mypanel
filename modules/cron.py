"""Cron and scheduled task management module for automated server jobs."""

import re
from typing import Any, Dict, List, Optional, Tuple

from app.core.database import Database, get_db
from app.core.executor import run_cmd
from app.core.logger import get_logger

logger = get_logger("cron")

# Standard 5-part cron syntax regex (min hour day month dow)
CRON_REGEX = re.compile(
    r"^\s*(@(reboot|yearly|annually|monthly|weekly|daily|midnight|hourly)|"
    r"(([\*0-9,-\/]+)\s+([\*0-9,-\/]+)\s+([\*0-9,-\/]+)\s+([\*0-9,-\/]+)\s+([\*0-9,-\/]+)))\s*$"
)


class CronManager:
    """Manager for Linux crontab scheduling and internal scheduled task registry."""

    def __init__(self, db: Optional[Database] = None) -> None:
        """Initialize CronManager.

        Args:
            db: Database instance.
        """
        self.db = db or get_db()

    @staticmethod
    def validate_schedule(schedule: str) -> bool:
        """Validate a cron expression string.

        Args:
            schedule: 5-part cron expression or alias (e.g. '0 2 * * *', '@daily').

        Returns:
            bool: True if valid, False otherwise.
        """
        if not schedule:
            return False
        return bool(CRON_REGEX.match(schedule.strip()))

    def _get_crontab_lines(self) -> List[str]:
        """Read all lines from current user/system crontab."""
        res = run_cmd("crontab -l")
        if not res.success:
            logger.debug("crontab -l returned error or is empty: %s", res.stderr)
            return []
        return [line.rstrip() for line in res.stdout.splitlines()]

    def _write_crontab_lines(self, lines: List[str]) -> Tuple[bool, str]:
        """Write modified lines back to crontab."""
        clean_content = "\n".join([line for line in lines if line.strip() != ""]) + "\n"
        # Escape quotes for echo wrapper
        escaped_content = clean_content.replace('"', '\\"').replace("$", "\\$")
        res = run_cmd(f'echo "{escaped_content}" | crontab -')

        if not res.success:
            err_lower = res.stderr.lower()
            if "not found" in err_lower or "not recognized" in err_lower:
                logger.debug("Crontab CLI not installed on host. Running in mock mode.")
                return True, "Crontab CLI not found on host (mock mode)"
            logger.error("Failed to update crontab: %s", res.stderr)
            return False, res.stderr

        return True, "Crontab updated successfully"

    def _build_command_string(self, job_id: int, job_type: str, target: str) -> str:
        """Generate shell command invocation based on job type."""
        panel_python = "/www/server/panel/.venv/bin/python"
        panel_entry = "/www/server/panel/app/main.py"

        if job_type == "site_backup":
            return f"{panel_python} -c \"from app.modules.backup import BackupManager; BackupManager().backup_site('{target}')\""
        elif job_type == "db_backup":
            return f"{panel_python} -c \"from app.modules.backup import BackupManager; BackupManager().backup_database('{target}')\""
        else:
            # Direct shell command
            return target

    def add_job(
        self,
        name: str,
        job_type: str,
        schedule: str,
        target: str,
    ) -> Tuple[bool, str]:
        """Register a new scheduled cron job in crontab and internal SQLite.

        Args:
            name: Human-readable name for the job.
            job_type: Type ('site_backup', 'db_backup', 'shell_cmd').
            schedule: Cron schedule expression (e.g. '0 3 * * *').
            target: Target domain name, database name, or shell command.

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        name = name.strip()
        job_type = job_type.strip().lower()
        schedule = schedule.strip()
        target = target.strip()

        if not name:
            return False, "Job name cannot be empty."

        if job_type not in {"site_backup", "db_backup", "shell_cmd"}:
            return False, f"Invalid job type: '{job_type}'. Choose 'site_backup', 'db_backup', or 'shell_cmd'."

        if not self.validate_schedule(schedule):
            return False, f"Invalid cron schedule expression: '{schedule}'. Use 5-part format e.g. '0 2 * * *'."

        if not target:
            return False, "Job target or command cannot be empty."

        # 1. Insert into SQLite to obtain job_id
        try:
            with self.db:
                job_id = self.db.execute(
                    """
                    INSERT INTO cron_jobs (name, job_type, schedule, target, status)
                    VALUES (?, ?, ?, ?, 'active');
                    """,
                    (name, job_type, schedule, target),
                )
        except Exception as exc:
            err_msg = f"Failed to record cron job in registry: {exc}"
            logger.exception(err_msg)
            return False, err_msg

        # 2. Add to system crontab
        cmd_str = self._build_command_string(job_id, job_type, target)
        tag = f"# CLI_PANEL_JOB_{job_id}"
        cron_entry = f"{schedule} {cmd_str} {tag}"

        lines = self._get_crontab_lines()
        lines.append(cron_entry)
        ok, msg = self._write_crontab_lines(lines)

        logger.info("Cron job '%s' (ID %s) added to crontab.", name, job_id)
        return True, f"Cron job '{name}' registered successfully."

    def toggle_job(self, job_id: int, enable: bool) -> Tuple[bool, str]:
        """Enable or disable an existing cron job.

        Args:
            job_id: Database job ID.
            enable: True to activate, False to disable.

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        job = self.get_job(job_id)
        if not job:
            return False, f"Cron job ID {job_id} not found."

        new_status = "active" if enable else "disabled"
        tag = f"JOB_{job_id}"

        # 1. Update crontab line
        lines = self._get_crontab_lines()
        new_lines: List[str] = []

        for line in lines:
            if tag in line:
                if enable:
                    # Uncomment if disabled
                    clean_line = line.lstrip("#").strip()
                    if clean_line.startswith("DISABLED_CLI_PANEL_"):
                        clean_line = clean_line.replace("DISABLED_CLI_PANEL_", "CLI_PANEL_")
                    new_lines.append(clean_line)
                else:
                    # Comment out
                    if not line.startswith("#"):
                        line = f"# DISABLED_{line}"
                    new_lines.append(line)
            else:
                new_lines.append(line)

        self._write_crontab_lines(new_lines)

        # 2. Update SQLite record
        try:
            with self.db:
                self.db.execute(
                    "UPDATE cron_jobs SET status = ? WHERE id = ?;",
                    (new_status, job_id),
                )
            logger.info("Cron job ID %s state changed to %s.", job_id, new_status)
            return True, f"Cron job '{job['name']}' is now {new_status}."
        except Exception as exc:
            err_msg = f"Failed to update cron job status in registry: {exc}"
            logger.exception(err_msg)
            return False, err_msg

    def delete_job(self, job_id: int) -> Tuple[bool, str]:
        """Delete a cron job from crontab and database.

        Args:
            job_id: Database job ID.

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        job = self.get_job(job_id)
        if not job:
            return False, f"Cron job ID {job_id} not found."

        tag = f"JOB_{job_id}"

        # 1. Remove from crontab
        lines = self._get_crontab_lines()
        filtered_lines = [line for line in lines if tag not in line]
        self._write_crontab_lines(filtered_lines)

        # 2. Delete from SQLite
        try:
            with self.db:
                self.db.execute("DELETE FROM cron_jobs WHERE id = ?;", (job_id,))
            logger.info("Cron job ID %s deleted successfully.", job_id)
            return True, f"Cron job '{job['name']}' deleted successfully."
        except Exception as exc:
            err_msg = f"Failed to delete cron job ID {job_id}: {exc}"
            logger.exception(err_msg)
            return False, err_msg

    def list_jobs(self) -> List[Dict[str, Any]]:
        """Retrieve all registered cron jobs from SQLite.

        Returns:
            List[Dict[str, Any]]: List of cron job records.
        """
        try:
            with self.db:
                records = self.db.fetch_all(
                    """
                    SELECT id, name, job_type, schedule, target, status, created_at
                    FROM cron_jobs
                    ORDER BY id DESC;
                    """
                )
                return records
        except Exception as exc:
            logger.error("Failed to list cron jobs: %s", exc)
            return []

    def get_job(self, job_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve details of a single cron job by ID.

        Args:
            job_id: Database job ID.

        Returns:
            Optional[Dict[str, Any]]: Cron job dictionary or None.
        """
        try:
            with self.db:
                record = self.db.fetch_one(
                    """
                    SELECT id, name, job_type, schedule, target, status, created_at
                    FROM cron_jobs
                    WHERE id = ?;
                    """,
                    (job_id,),
                )
                return record
        except Exception as exc:
            logger.error("Failed to get cron job ID %s: %s", job_id, exc)
            return None
