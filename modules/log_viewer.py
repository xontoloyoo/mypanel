"""Realtime log viewer module for system, web server, and application logs."""

from collections import deque
import os
from pathlib import Path
import time
from typing import Any, Dict, Generator, List, Optional, Tuple

from app.core.logger import BASE_DIR, LOG_FILE, get_logger

logger = get_logger("log_viewer")

# Standard Linux and Application Log Paths
LOG_REGISTRY: Dict[str, Dict[str, Any]] = {}


class LogViewerManager:
    """Manager for reading, streaming, and managing server and panel log files."""

    def __init__(self, custom_paths: Optional[Dict[str, str]] = None) -> None:
        """Initialize LogViewerManager with default registry and custom overrides.

        Args:
            custom_paths: Optional dictionary to override default log paths.
        """
        self.default_paths: Dict[str, List[Path]] = {
            "nginx_access": [
                Path("/var/log/nginx/access.log"),
                Path("/www/wwwlogs/access.log"),
                BASE_DIR / "logs" / "nginx_access.log",
            ],
            "nginx_error": [
                Path("/var/log/nginx/error.log"),
                Path("/www/wwwlogs/error.log"),
                BASE_DIR / "logs" / "nginx_error.log",
            ],
            "panel_log": [
                LOG_FILE,
                BASE_DIR / "logs" / "app.log",
            ],
            "syslog": [
                Path("/var/log/syslog"),
                Path("/var/log/messages"),
                BASE_DIR / "logs" / "syslog.log",
            ],
            "auth_log": [
                Path("/var/log/auth.log"),
                Path("/var/log/secure"),
                BASE_DIR / "logs" / "auth.log",
            ],
        }

        if custom_paths:
            for key, p_str in custom_paths.items():
                self.default_paths[key] = [Path(p_str)]

    def get_log_path(self, log_key: str) -> Path:
        """Find the active or best candidate path for a log key.

        Args:
            log_key: Key identifying the target log.

        Returns:
            Path: Resolved Path instance for the log file.
        """
        candidates = self.default_paths.get(log_key, [BASE_DIR / "logs" / f"{log_key}.log"])
        for candidate in candidates:
            if candidate.exists():
                return candidate
        # Return primary candidate even if not created yet
        return candidates[0]

    def read_last_lines(self, log_key: str, lines: int = 50) -> List[str]:
        """Read the last N lines of a specified log file.

        Args:
            log_key: Key identifying the target log.
            lines: Number of trailing lines to read (default: 50).

        Returns:
            List[str]: List of log line strings.
        """
        target_path = self.get_log_path(log_key)
        if not target_path.exists():
            return [f"[INFO] Log file '{target_path}' does not exist on disk yet."]

        try:
            with open(target_path, "r", encoding="utf-8", errors="replace") as f:
                trailing_lines = list(deque(f, maxlen=lines))
                return [l.rstrip("\r\n") for l in trailing_lines]
        except Exception as exc:
            logger.error("Failed to read log file '%s': %s", target_path, exc)
            return [f"[ERROR] Could not read log file: {exc}"]

    def stream_log(
        self,
        log_key: str,
        interval: float = 0.5,
    ) -> Generator[str, None, None]:
        """Live stream new appended lines from a log file (generator).

        Args:
            log_key: Key identifying the target log.
            interval: Poll interval in seconds if no new line is ready.

        Yields:
            str: Newly written log line.
        """
        target_path = self.get_log_path(log_key)
        if not target_path.exists():
            # Create empty file if missing to start streaming
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.touch()

        with open(target_path, "r", encoding="utf-8", errors="replace") as f:
            # Seek to the end of file for live tailing
            f.seek(0, os.SEEK_END)
            while True:
                line = f.readline()
                if line:
                    yield line.rstrip("\r\n")
                else:
                    time.sleep(interval)

    def clear_log(self, log_key: str) -> Tuple[bool, str]:
        """Truncate and clear the contents of a log file.

        Args:
            log_key: Key identifying the target log.

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        target_path = self.get_log_path(log_key)
        if not target_path.exists():
            return True, f"Log file '{target_path.name}' is already empty or does not exist."

        try:
            with open(target_path, "w", encoding="utf-8") as f:
                f.truncate(0)
            logger.info("Cleared log file: %s", target_path)
            return True, f"Log file '{target_path.name}' cleared successfully."
        except Exception as exc:
            err_msg = f"Failed to clear log file '{target_path.name}': {exc}"
            logger.error(err_msg)
            return False, err_msg
