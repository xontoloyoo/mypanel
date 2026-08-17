"""System monitoring module for CPU, RAM, Disk, and Uptime metrics."""

from datetime import timedelta
import os
from pathlib import Path
import platform
import time
from typing import Any, Dict, List, Optional, Tuple

import psutil

from app.core.executor import run_cmd
from app.core.logger import get_logger

logger = get_logger("system")


def format_bytes(size: float) -> str:
    """Format bytes into a human-readable string (B, KB, MB, GB, TB).

    Args:
        size: Size in bytes.

    Returns:
        str: Human-readable string representation.
    """
    for unit in ["B", "KB", "MB", "GB", "TB", "PB"]:
        if abs(size) < 1024.0:
            if unit in ["MB", "GB", "TB", "PB"]:
                return f"{size:.2f} {unit}"
            return f"{int(size)} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def format_uptime(seconds: float) -> str:
    """Format uptime in seconds into human-readable duration.

    Args:
        seconds: Elapsed uptime in seconds.

    Returns:
        str: Human-readable duration (e.g., '2 days, 4 hours, 15 mins').
    """
    td = timedelta(seconds=int(seconds))
    days = td.days
    hours, remainder = divmod(td.seconds, 3600)
    minutes, _ = divmod(remainder, 60)

    parts: List[str] = []
    if days > 0:
        parts.append(f"{days} day{'s' if days != 1 else ''}")
    if hours > 0 or days > 0:
        parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
    parts.append(f"{minutes} min{'s' if minutes != 1 else ''}")

    return ", ".join(parts)


class SystemManager:
    """Manager for retrieving system performance metrics and service statuses."""

    @staticmethod
    def get_cpu_metrics() -> Dict[str, Any]:
        """Retrieve CPU usage percentage, core count, and frequency.

        Returns:
            Dict[str, Any]: CPU metrics dictionary.
        """
        try:
            percent = psutil.cpu_percent(interval=0.1)
            logical_cores = psutil.cpu_count(logical=True) or 1
            physical_cores = psutil.cpu_count(logical=False) or 1
            freq = psutil.cpu_freq()
            freq_current = round(freq.current, 2) if freq else 0.0

            return {
                "percent": percent,
                "cores_logical": logical_cores,
                "cores_physical": physical_cores,
                "frequency_mhz": freq_current,
            }
        except Exception as exc:
            logger.error("Failed to retrieve CPU metrics: %s", exc)
            return {
                "percent": 0.0,
                "cores_logical": 1,
                "cores_physical": 1,
                "frequency_mhz": 0.0,
            }

    @staticmethod
    def get_ram_metrics() -> Dict[str, Any]:
        """Retrieve RAM usage metrics.

        Returns:
            Dict[str, Any]: RAM metrics dictionary.
        """
        try:
            mem = psutil.virtual_memory()
            return {
                "total_bytes": mem.total,
                "used_bytes": mem.used,
                "free_bytes": mem.available,
                "percent": mem.percent,
                "total_human": format_bytes(mem.total),
                "used_human": format_bytes(mem.used),
                "free_human": format_bytes(mem.available),
            }
        except Exception as exc:
            logger.error("Failed to retrieve RAM metrics: %s", exc)
            return {
                "total_bytes": 0,
                "used_bytes": 0,
                "free_bytes": 0,
                "percent": 0.0,
                "total_human": "0 B",
                "used_human": "0 B",
                "free_human": "0 B",
            }

    @staticmethod
    def get_disk_metrics(path: Optional[str] = None) -> Dict[str, Any]:
        """Retrieve Disk partition usage metrics.

        Args:
            path: Target partition path (defaults to root partition).

        Returns:
            Dict[str, Any]: Disk metrics dictionary.
        """
        if not path:
            path = "/" if os.name != "nt" else os.path.splitdrive(os.getcwd())[0] + "\\"
            if not os.path.exists(path):
                path = "."

        try:
            disk = psutil.disk_usage(path)
            return {
                "path": path,
                "total_bytes": disk.total,
                "used_bytes": disk.used,
                "free_bytes": disk.free,
                "percent": disk.percent,
                "total_human": format_bytes(disk.total),
                "used_human": format_bytes(disk.used),
                "free_human": format_bytes(disk.free),
            }
        except Exception as exc:
            logger.error("Failed to retrieve Disk metrics for path '%s': %s", path, exc)
            return {
                "path": path,
                "total_bytes": 0,
                "used_bytes": 0,
                "free_bytes": 0,
                "percent": 0.0,
                "total_human": "0 B",
                "used_human": "0 B",
                "free_human": "0 B",
            }

    @staticmethod
    def get_uptime_metrics() -> Dict[str, Any]:
        """Retrieve server boot time and uptime duration.

        Returns:
            Dict[str, Any]: Uptime metrics dictionary.
        """
        try:
            boot_time = psutil.boot_time()
            uptime_seconds = max(0.0, time.time() - boot_time)
            return {
                "boot_time": boot_time,
                "seconds": uptime_seconds,
                "uptime_human": format_uptime(uptime_seconds),
            }
        except Exception as exc:
            logger.error("Failed to retrieve Uptime metrics: %s", exc)
            return {
                "boot_time": time.time(),
                "seconds": 0.0,
                "uptime_human": "0 mins",
            }

    @staticmethod
    def get_load_avg() -> Dict[str, float]:
        """Retrieve 1m, 5m, and 15m load averages with safe Windows fallback.

        Returns:
            Dict[str, float]: Load average dictionary.
        """
        try:
            if hasattr(os, "getloadavg"):
                lavg = os.getloadavg()
                return {
                    "1m": round(lavg[0], 2),
                    "5m": round(lavg[1], 2),
                    "15m": round(lavg[2], 2),
                }
            if hasattr(psutil, "getloadavg"):
                lavg = psutil.getloadavg()
                return {
                    "1m": round(lavg[0], 2),
                    "5m": round(lavg[1], 2),
                    "15m": round(lavg[2], 2),
                }
        except Exception as exc:
            logger.debug("Load average reading failed: %s", exc)

        # Fallback estimation based on CPU percentage
        cpu_usage = psutil.cpu_percent(interval=None)
        estimated_load = round(cpu_usage / 100.0, 2)
        return {
            "1m": estimated_load,
            "5m": estimated_load,
            "15m": estimated_load,
        }

    @classmethod
    def get_system_metrics(cls) -> Dict[str, Any]:
        """Retrieve comprehensive system metrics dictionary.

        Returns:
            Dict[str, Any]: Combined system metrics.
        """
        uptime_data = cls.get_uptime_metrics()
        return {
            "os": platform.system(),
            "release": platform.release(),
            "hostname": platform.node(),
            "cpu": cls.get_cpu_metrics(),
            "ram": cls.get_ram_metrics(),
            "disk": cls.get_disk_metrics(),
            "uptime": uptime_data["uptime_human"],
            "uptime_details": uptime_data,
            "load_avg": cls.get_load_avg(),
        }

    @staticmethod
    def get_service_status(service_name: str) -> Dict[str, Any]:
        """Check whether a systemd service is active/running with smart aliasing.

        Args:
            service_name: Name of the service (e.g., 'nginx', 'mysql', 'php-fpm').

        Returns:
            Dict[str, Any]: Service status dictionary.
        """
        # 1. Special handling for PHP-FPM (Debian/Ubuntu versioned daemons: php8.2-fpm, php8.3-fpm, etc.)
        if service_name in ("php-fpm", "php"):
            # Check generic php-fpm first
            res = run_cmd("systemctl is-active php-fpm")
            st = res.stdout.strip().lower()
            if st == "active":
                return {"service": "php-fpm", "status": "active", "is_active": True}

            # Discover installed PHP versions
            candidates: List[str] = []
            etc_php = Path("/etc/php")
            if etc_php.exists() and etc_php.is_dir():
                try:
                    for v_dir in sorted(etc_php.iterdir(), reverse=True):
                        if (v_dir / "fpm").is_dir():
                            candidates.append(f"php{v_dir.name}-fpm")
                except Exception:
                    pass

            for fallback_ver in ["php8.2-fpm", "php8.3-fpm", "php8.1-fpm", "php8.0-fpm", "php7.4-fpm"]:
                if fallback_ver not in candidates:
                    candidates.append(fallback_ver)

            installed_inactive: Optional[Tuple[str, str]] = None
            for cand in candidates:
                c_res = run_cmd(f"systemctl is-active {cand}")
                c_st = c_res.stdout.strip().lower()
                if c_st == "active":
                    return {
                        "service": "php-fpm",
                        "status": f"active ({cand})",
                        "is_active": True,
                    }
                elif c_st in ("inactive", "failed", "dead", "activating"):
                    if not installed_inactive:
                        installed_inactive = (cand, c_st)

            if installed_inactive:
                cand_name, cand_st = installed_inactive
                return {
                    "service": "php-fpm",
                    "status": f"{cand_st} ({cand_name})",
                    "is_active": False,
                }

            is_not_installed = (
                not res.success
                and ("not found" in res.stderr.lower() or "not-found" in res.stderr.lower())
            )
            return {
                "service": "php-fpm",
                "status": "not-installed" if is_not_installed else (st or "inactive"),
                "is_active": False,
            }

        # 2. Standard Service Check
        result = run_cmd(f"systemctl is-active {service_name}")
        status_text = result.stdout.strip().lower()

        # Check mariadb alias if mysql is queried
        if service_name == "mysql" and status_text != "active":
            m_res = run_cmd("systemctl is-active mariadb")
            m_st = m_res.stdout.strip().lower()
            if m_st == "active":
                return {
                    "service": "mysql",
                    "status": "active (mariadb)",
                    "is_active": True,
                }

        if not status_text and not result.success:
            if "not found" in result.stderr.lower() or "not-found" in result.stderr.lower():
                status_text = "not-installed"
            else:
                status_text = "inactive"

        is_active = status_text == "active"
        return {
            "service": service_name,
            "status": status_text if status_text else "inactive",
            "is_active": is_active,
        }

    @classmethod
    def check_core_services(cls) -> Dict[str, Dict[str, Any]]:
        """Batch check status of core server services (nginx, mysql/mariadb, ufw, php-fpm).

        Returns:
            Dict[str, Dict[str, Any]]: Dictionary of core service statuses.
        """
        services = ["nginx", "mysql", "mariadb", "ufw", "php-fpm"]
        statuses: Dict[str, Dict[str, Any]] = {}

        for svc in services:
            statuses[svc] = cls.get_service_status(svc)

        # Merge mysql/mariadb if mariadb is active
        if not statuses["mysql"]["is_active"] and statuses["mariadb"]["is_active"]:
            statuses["mysql"] = {
                "service": "mysql",
                "status": "active (mariadb)",
                "is_active": True,
            }

        return statuses
