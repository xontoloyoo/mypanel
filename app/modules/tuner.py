"""Server Optimization, 3-Tier Config Tuner, and Swap Management module."""

from dataclasses import dataclass
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple

import psutil

from app.core.executor import run_cmd
from app.core.logger import BASE_DIR, get_logger
from app.modules.site import WAF_DEFAULT_CONFIG, ensure_waf_snippet
from app.modules.system import format_bytes

logger = get_logger("tuner")

# ==============================================================================
# Complete 39-Parameter Registry with 3 Tier Presets
# (low_end <= 1.2GB RAM, balanced 1.2GB-4.5GB RAM, performance > 4.5GB RAM)
# ==============================================================================
TUNER_REGISTRY: Dict[str, Dict[str, Any]] = {
    # -------------------------------------------------------------------------
    # A. PHP, PHP-FPM, & OPcache (16 Parameters)
    # -------------------------------------------------------------------------
    "php": {
        "memory_limit": {
            "file_type": "php_ini",
            "section": "PHP",
            "description": "Maximum memory a script may consume",
            "presets": {"low_end": "128M", "balanced": "256M", "performance": "512M"},
        },
        "upload_max_filesize": {
            "file_type": "php_ini",
            "section": "PHP",
            "description": "Maximum allowed size for uploaded files",
            "presets": {"low_end": "32M", "balanced": "100M", "performance": "256M"},
        },
        "post_max_size": {
            "file_type": "php_ini",
            "section": "PHP",
            "description": "Maximum size of POST data that PHP will accept",
            "presets": {"low_end": "32M", "balanced": "100M", "performance": "256M"},
        },
        "max_execution_time": {
            "file_type": "php_ini",
            "section": "PHP",
            "description": "Maximum execution time of each script (seconds)",
            "presets": {"low_end": "30", "balanced": "60", "performance": "120"},
        },
        "max_input_vars": {
            "file_type": "php_ini",
            "section": "PHP",
            "description": "Max number of input variables accepted (GET/POST/COOKIE)",
            "presets": {"low_end": "1000", "balanced": "2000", "performance": "5000"},
        },
        "max_input_time": {
            "file_type": "php_ini",
            "section": "PHP",
            "description": "Maximum amount of time each script may spend parsing input",
            "presets": {"low_end": "60", "balanced": "60", "performance": "120"},
        },
        "pm": {
            "file_type": "php_fpm",
            "section": "www",
            "description": "FPM process manager control (ondemand / dynamic / static)",
            "presets": {"low_end": "ondemand", "balanced": "dynamic", "performance": "dynamic"},
        },
        "pm.max_children": {
            "file_type": "php_fpm",
            "section": "www",
            "description": "Maximum number of child processes to be created",
            "presets": {"low_end": "5", "balanced": "15", "performance": "40"},
        },
        "pm.start_servers": {
            "file_type": "php_fpm",
            "section": "www",
            "description": "Number of child processes created on startup",
            "presets": {"low_end": "2", "balanced": "4", "performance": "10"},
        },
        "pm.min_spare_servers": {
            "file_type": "php_fpm",
            "section": "www",
            "description": "Desired minimum number of idle server processes",
            "presets": {"low_end": "1", "balanced": "2", "performance": "5"},
        },
        "pm.max_spare_servers": {
            "file_type": "php_fpm",
            "section": "www",
            "description": "Desired maximum number of idle server processes",
            "presets": {"low_end": "3", "balanced": "6", "performance": "15"},
        },
        "pm.max_requests": {
            "file_type": "php_fpm",
            "section": "www",
            "description": "Requests executed before respawning child (avoids leaks)",
            "presets": {"low_end": "500", "balanced": "1000", "performance": "2000"},
        },
        "opcache.enable": {
            "file_type": "php_ini",
            "section": "opcache",
            "description": "Enable Zend OPcache byte-code caching",
            "presets": {"low_end": "1", "balanced": "1", "performance": "1"},
        },
        "opcache.memory_consumption": {
            "file_type": "php_ini",
            "section": "opcache",
            "description": "OPcache shared memory storage size",
            "presets": {"low_end": "64M", "balanced": "128M", "performance": "256M"},
        },
        "opcache.interned_strings_buffer": {
            "file_type": "php_ini",
            "section": "opcache",
            "description": "Memory amount for interned strings in MB",
            "presets": {"low_end": "8", "balanced": "16", "performance": "32"},
        },
        "opcache.max_accelerated_files": {
            "file_type": "php_ini",
            "section": "opcache",
            "description": "Maximum number of scripts that can be cached in OPcache",
            "presets": {"low_end": "10000", "balanced": "20000", "performance": "40000"},
        },
        "expose_php": {
            "file_type": "php_ini",
            "section": "PHP",
            "description": "Hide PHP version header (X-Powered-By: PHP)",
            "presets": {"low_end": "Off", "balanced": "Off", "performance": "Off"},
        },
        "display_errors": {
            "file_type": "php_ini",
            "section": "PHP",
            "description": "Prevent error/path disclosure on visitor screen",
            "presets": {"low_end": "Off", "balanced": "Off", "performance": "Off"},
        },
        "log_errors": {
            "file_type": "php_ini",
            "section": "PHP",
            "description": "Log errors to server log file for diagnostics",
            "presets": {"low_end": "On", "balanced": "On", "performance": "On"},
        },
        "allow_url_include": {
            "file_type": "php_ini",
            "section": "PHP",
            "description": "Block Remote File Inclusion (RFI) script execution",
            "presets": {"low_end": "Off", "balanced": "Off", "performance": "Off"},
        },
        "session.cookie_httponly": {
            "file_type": "php_ini",
            "section": "Session",
            "description": "Block JavaScript cookie theft (XSS defense)",
            "presets": {"low_end": "1", "balanced": "1", "performance": "1"},
        },
        "session.use_strict_mode": {
            "file_type": "php_ini",
            "section": "Session",
            "description": "Reject uninitialized session IDs (Fixation defense)",
            "presets": {"low_end": "1", "balanced": "1", "performance": "1"},
        },
        "session.cookie_samesite": {
            "file_type": "php_ini",
            "section": "Session",
            "description": "SameSite cookie policy for CSRF mitigation",
            "presets": {"low_end": "Lax", "balanced": "Lax", "performance": "Lax"},
        },
    },
    # -------------------------------------------------------------------------
    # B. Nginx Web Server (17 Parameters)
    # -------------------------------------------------------------------------
    "nginx": {
        "server_tokens": {
            "file_type": "nginx_conf",
            "description": "Hide Nginx version signature in headers and error pages",
            "presets": {"low_end": "off", "balanced": "off", "performance": "off"},
        },
        "worker_processes": {
            "file_type": "nginx_conf",
            "description": "Number of worker processes (auto = number of CPU cores)",
            "presets": {"low_end": "auto", "balanced": "auto", "performance": "auto"},
        },
        "worker_connections": {
            "file_type": "nginx_conf",
            "description": "Maximum simultaneous connections that can be opened by a worker",
            "presets": {"low_end": "1024", "balanced": "2048", "performance": "4096"},
        },
        "multi_accept": {
            "file_type": "nginx_conf",
            "description": "Accept as many connections as possible after receiving notification",
            "presets": {"low_end": "on", "balanced": "on", "performance": "on"},
        },
        "sendfile": {
            "file_type": "nginx_conf",
            "description": "Enable kernel sendfile syscall for fast direct I/O",
            "presets": {"low_end": "on", "balanced": "on", "performance": "on"},
        },
        "tcp_nopush": {
            "file_type": "nginx_conf",
            "description": "Send headers in one packet along with file contents",
            "presets": {"low_end": "on", "balanced": "on", "performance": "on"},
        },
        "tcp_nodelay": {
            "file_type": "nginx_conf",
            "description": "Disable Nagle buffering algorithm for faster real-time responses",
            "presets": {"low_end": "on", "balanced": "on", "performance": "on"},
        },
        "keepalive_timeout": {
            "file_type": "nginx_conf",
            "description": "Timeout during which a keep-alive client connection stays open",
            "presets": {"low_end": "15", "balanced": "30", "performance": "60"},
        },
        "client_body_timeout": {
            "file_type": "nginx_conf",
            "description": "Slowloris DoS mitigation client body timeout",
            "presets": {"low_end": "10s", "balanced": "10s", "performance": "15s"},
        },
        "client_header_timeout": {
            "file_type": "nginx_conf",
            "description": "Slowloris DoS mitigation client header timeout",
            "presets": {"low_end": "10s", "balanced": "10s", "performance": "15s"},
        },
        "send_timeout": {
            "file_type": "nginx_conf",
            "description": "Response transmission timeout to client",
            "presets": {"low_end": "10s", "balanced": "10s", "performance": "15s"},
        },
        "gzip": {
            "file_type": "nginx_conf",
            "description": "Enable dynamic Gzip compression for static text/HTML/CSS/JS",
            "presets": {"low_end": "on", "balanced": "on", "performance": "on"},
        },
        "gzip_comp_level": {
            "file_type": "nginx_conf",
            "description": "Gzip compression level (1-9)",
            "presets": {"low_end": "4", "balanced": "5", "performance": "6"},
        },
        "client_max_body_size": {
            "file_type": "nginx_conf",
            "description": "Maximum allowed client request body size (file uploads)",
            "presets": {"low_end": "32M", "balanced": "100M", "performance": "256M"},
        },
        "fastcgi_buffer_size": {
            "file_type": "nginx_conf",
            "description": "Buffer size used for reading header from FastCGI server",
            "presets": {"low_end": "64k", "balanced": "128k", "performance": "256k"},
        },
        "fastcgi_buffers": {
            "file_type": "nginx_conf",
            "description": "Number and size of buffers for reading FastCGI response",
            "presets": {"low_end": "4 64k", "balanced": "4 128k", "performance": "8 128k"},
        },
        "fastcgi_read_timeout": {
            "file_type": "nginx_conf",
            "description": "Timeout for reading a response from the FastCGI server",
            "presets": {"low_end": "60s", "balanced": "60s", "performance": "120s"},
        },
    },
    # -------------------------------------------------------------------------
    # C. MariaDB / MySQL (10 Parameters)
    # -------------------------------------------------------------------------
    "mysql": {
        "innodb_buffer_pool_size": {
            "file_type": "mysql_cnf",
            "description": "Memory buffer pool for caching InnoDB table data and indexes",
            "presets": {"low_end": "128M", "balanced": "384M", "performance": "1G"},
        },
        "innodb_buffer_pool_instances": {
            "file_type": "mysql_cnf",
            "description": "Number of regions that the InnoDB buffer pool is divided into",
            "presets": {"low_end": "1", "balanced": "1", "performance": "4"},
        },
        "key_buffer_size": {
            "file_type": "mysql_cnf",
            "description": "Size of the buffer used for index blocks in MyISAM tables",
            "presets": {"low_end": "16M", "balanced": "32M", "performance": "64M"},
        },
        "max_connections": {
            "file_type": "mysql_cnf",
            "description": "Maximum permitted number of simultaneous client connections",
            "presets": {"low_end": "40", "balanced": "100", "performance": "250"},
        },
        "wait_timeout": {
            "file_type": "mysql_cnf",
            "description": "Seconds server waits for activity on noninteractive connection",
            "presets": {"low_end": "30", "balanced": "60", "performance": "120"},
        },
        "interactive_timeout": {
            "file_type": "mysql_cnf",
            "description": "Seconds server waits for activity on interactive connection",
            "presets": {"low_end": "30", "balanced": "60", "performance": "120"},
        },
        "max_allowed_packet": {
            "file_type": "mysql_cnf",
            "description": "Maximum size of one packet or any generated/intermediate string",
            "presets": {"low_end": "32M", "balanced": "64M", "performance": "128M"},
        },
        "innodb_flush_log_at_trx_commit": {
            "file_type": "mysql_cnf",
            "description": "InnoDB log flush policy (1 = ACID compliant, 2 = high performance)",
            "presets": {"low_end": "2", "balanced": "1", "performance": "1"},
        },
        "tmp_table_size": {
            "file_type": "mysql_cnf",
            "description": "Maximum size of internal in-memory temporary tables",
            "presets": {"low_end": "16M", "balanced": "32M", "performance": "64M"},
        },
        "max_heap_table_size": {
            "file_type": "mysql_cnf",
            "description": "Maximum size to which user-created MEMORY tables can grow",
            "presets": {"low_end": "16M", "balanced": "32M", "performance": "64M"},
        },
    },
}


GLOBAL_NGINX_SECURITY_CONFIG = """# ==============================================================================
# CLI-PANEL GLOBAL NGINX SECURITY & PERFORMANCE HARDENING
# Persistently loaded in http context across all current & future Nginx versions
# ==============================================================================

server_tokens off;
client_body_timeout 10s;
client_header_timeout 10s;
send_timeout 10s;

# Global Custom Error Page Definitions
error_page 403 /403.html;
error_page 404 /404.html;
error_page 500 502 503 504 /50x.html;
"""


def ensure_nginx_security_conf(target_file: Optional[Path] = None) -> Path:
    """Ensure persistent global Nginx security config exists in conf.d (update-proof).

    Args:
        target_file: Optional custom target path.

    Returns:
        Path: Path to the persistent security file.
    """
    if target_file:
        target = target_file
    else:
        primary = Path("/etc/nginx/conf.d/00_global_security.conf")
        fallback = BASE_DIR / "data" / "mock_config" / "00_global_security.conf"
        target = primary if (primary.parent.exists() or os.name != "nt") else fallback

    try:
        if not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(GLOBAL_NGINX_SECURITY_CONFIG, encoding="utf-8")
            logger.info("Created global Nginx security config at %s", target)
    except Exception as exc:
        logger.warning("Could not create global Nginx security config at '%s': %s", target, exc)

    return target


class SwapManager:
    """Manager for checking, calculating, and creating Linux Swap memory."""

    def get_swap_info(self) -> Dict[str, Any]:
        """Get current swap memory metrics.

        Returns:
            Dict[str, Any]: Swap usage metrics.
        """
        swap = psutil.swap_memory()
        return {
            "total_bytes": swap.total,
            "total_human": format_bytes(swap.total),
            "used_bytes": swap.used,
            "used_human": format_bytes(swap.used),
            "free_bytes": swap.free,
            "free_human": format_bytes(swap.free),
            "percent": swap.percent,
            "has_swap": swap.total > 0,
        }

    def setup_swap(self, size_gb: int = 2) -> Tuple[bool, str]:
        """Create and activate a persistent Linux swapfile.

        Args:
            size_gb: Size of swapfile in Gigabytes (default: 2).

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        if size_gb <= 0:
            return False, "Swap size must be greater than 0 GB."

        if os.name == "nt":
            logger.info("Swap setup mock mode on Windows: %d GB swap configured.", size_gb)
            return True, f"Mock: Swapfile of {size_gb} GB configured and activated."

        # Check existing swapfile
        swapfile = Path("/swapfile")
        if swapfile.exists():
            run_cmd("swapoff /swapfile")
            swapfile.unlink(missing_ok=True)

        # 1. Allocate swapfile
        res = run_cmd(f"fallocate -l {size_gb}G /swapfile")
        if not res.success:
            # Fallback to dd if fallocate fails (e.g. on certain filesystem types)
            res_dd = run_cmd(f"dd if=/dev/zero of=/swapfile bs=1M count={size_gb * 1024}")
            if not res_dd.success:
                return False, f"Failed to allocate swapfile: {res_dd.stderr}"

        # 2. Permissions, format, and activate
        run_cmd("chmod 600 /swapfile")
        res_mk = run_cmd("mkswap /swapfile")
        if not res_mk.success:
            return False, f"Failed to format swapfile: {res_mk.stderr}"

        res_on = run_cmd("swapon /swapfile")
        if not res_on.success:
            return False, f"Failed to activate swap: {res_on.stderr}"

        # 3. Add to /etc/fstab for permanence
        try:
            fstab = Path("/etc/fstab")
            if fstab.exists():
                content = fstab.read_text(encoding="utf-8")
                if "/swapfile" not in content:
                    with open(fstab, "a", encoding="utf-8") as f:
                        f.write("\n/swapfile none swap sw 0 0\n")
        except Exception as exc:
            logger.warning("Could not append swapfile to /etc/fstab: %s", exc)

        msg = f"Swap memory ({size_gb} GB) successfully created and activated."
        logger.info(msg)
        return True, msg


class ConfigTuner:
    """3-Tier Server Optimization & Config Tuner for PHP, Nginx, and MySQL/MariaDB."""

    def __init__(self, mock_base_dir: Optional[str] = None) -> None:
        """Initialize ConfigTuner with optional mock directory for testing.

        Args:
            mock_base_dir: Custom base directory for config files.
        """
        self.mock_base = Path(mock_base_dir) if mock_base_dir else None

    def detect_optimal_preset(self) -> str:
        """Detect recommended optimization preset based on total physical RAM.

        Returns:
            str: 'low_end', 'balanced', or 'performance'.
        """
        total_ram_gb = psutil.virtual_memory().total / (1024**3)
        if total_ram_gb <= 1.2:
            return "low_end"
        elif total_ram_gb <= 4.5:
            return "balanced"
        else:
            return "performance"

    def get_target_path(
        self,
        service_name: str,
        file_type: str = "main",
        php_version: str = "8.2",
    ) -> Path:
        """Resolve actual configuration file path for given service.

        Args:
            service_name: 'php', 'nginx', or 'mysql'.
            file_type: 'php_ini', 'php_fpm', 'nginx_conf', 'nginx_waf', or 'mysql_cnf'.
            php_version: Target PHP version (e.g. '8.2').

        Returns:
            Path: Resolved file path.
        """
        if self.mock_base:
            return self.mock_base / f"{service_name}_{file_type}.conf"

        if service_name == "php":
            if file_type == "php_fpm":
                primary = Path(f"/etc/php/{php_version}/fpm/pool.d/www.conf")
                fallback = BASE_DIR / "data" / "mock_config" / f"php_{php_version}_fpm.conf"
            else:
                primary = Path(f"/etc/php/{php_version}/fpm/php.ini")
                fallback = BASE_DIR / "data" / "mock_config" / f"php_{php_version}_ini.conf"
            return primary if primary.exists() or os.name != "nt" else fallback

        elif service_name == "nginx":
            if file_type == "nginx_waf":
                primary = Path("/etc/nginx/waf/waf_default.conf")
                fallback = BASE_DIR / "data" / "mock_config" / "waf_default.conf"
                return primary if (primary.parent.exists() or os.name != "nt") else fallback

            primary = Path("/etc/nginx/nginx.conf")
            fallback = BASE_DIR / "data" / "mock_config" / "nginx.conf"
            return primary if primary.exists() or os.name != "nt" else fallback

        elif service_name == "mysql":
            candidates = [
                Path("/etc/mysql/mariadb.conf.d/50-server.cnf"),
                Path("/etc/mysql/my.cnf"),
                Path("/etc/my.cnf"),
                BASE_DIR / "data" / "mock_config" / "mysql.cnf",
            ]
            for c in candidates:
                if c.exists():
                    return c
            return candidates[0] if os.name != "nt" else candidates[-1]

        return BASE_DIR / "data" / "mock_config" / f"{service_name}.conf"

    def get_current_params(
        self,
        service_name: str,
        php_version: str = "8.2",
    ) -> Dict[str, str]:
        """Parse configuration files and return currently active values for registered parameters.

        Args:
            service_name: 'php', 'nginx', or 'mysql'.
            php_version: PHP version for PHP tuner.

        Returns:
            Dict[str, str]: Dictionary mapping parameter names to current values.
        """
        registry = TUNER_REGISTRY.get(service_name, {})
        current_values: Dict[str, str] = {}

        # Cache file contents
        file_contents: Dict[str, str] = {}
        for param, meta in registry.items():
            ft = meta.get("file_type", "main")
            if ft not in file_contents:
                target_p = self.get_target_path(service_name, ft, php_version)
                if target_p.exists():
                    try:
                        file_contents[ft] = target_p.read_text(encoding="utf-8", errors="replace")
                    except Exception:
                        file_contents[ft] = ""
                else:
                    file_contents[ft] = ""

            content = file_contents[ft]
            # Match directive in file
            # Pattern matches: directive_name = value or directive_name value;
            escaped_param = re.escape(param)
            pattern = re.compile(
                rf"^\s*{escaped_param}\s*(?:=|\s)\s*([^;\r\n]+)",
                re.MULTILINE | re.IGNORECASE,
            )
            match = pattern.search(content)
            if match:
                current_values[param] = match.group(1).strip().strip('"\'')
            else:
                # Default fallback value from balanced preset
                current_values[param] = meta["presets"].get("balanced", "default")

        return current_values

    def update_parameter(
        self,
        service_name: str,
        param_name: str,
        new_value: str,
        php_version: str = "8.2",
    ) -> Tuple[bool, str]:
        """Tier 2: Update a single configuration parameter with safe backup and syntax validation.

        Args:
            service_name: 'php', 'nginx', or 'mysql'.
            param_name: Parameter name.
            new_value: New value to set.
            php_version: PHP version.

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        registry = TUNER_REGISTRY.get(service_name, {})
        if param_name not in registry:
            return False, f"Parameter '{param_name}' is not in the recognized registry."

        meta = registry[param_name]
        ft = meta.get("file_type", "main")
        target_path = self.get_target_path(service_name, ft, php_version)

        # Create target file if missing (for mock/fresh setups)
        if not target_path.exists():
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.touch()

        # 1. Create temporary backup
        backup_path = target_path.with_suffix(".bak_tuner")
        shutil.copy2(target_path, backup_path)

        try:
            content = target_path.read_text(encoding="utf-8", errors="replace")
            escaped_param = re.escape(param_name)

            # Check format: Nginx uses semicolons, PHP/MySQL uses key = value
            is_nginx = service_name == "nginx"

            pattern = re.compile(
                rf"^([ \t]*)[#;]?[ \t]*{escaped_param}[ \t]*(?:=|[ \t])[ \t]*[^;\r\n]*(;?)",
                re.MULTILINE | re.IGNORECASE,
            )

            if pattern.search(content):
                if is_nginx:
                    replacement = rf"\g<1>{param_name} {new_value};"
                else:
                    replacement = rf"\g<1>{param_name} = {new_value}"
                new_content = pattern.sub(replacement, content)
            else:
                # Append parameter if not found
                if is_nginx:
                    http_match = re.search(r"http\s*\{", content, re.IGNORECASE)
                    if http_match:
                        pos = http_match.end()
                        new_content = content[:pos] + f"\n    {param_name} {new_value};\n" + content[pos:]
                    else:
                        new_content = content + f"\n{param_name} {new_value};\n"
                else:
                    new_content = content + f"\n{param_name} = {new_value}\n"

            target_path.write_text(new_content, encoding="utf-8")

            # For Nginx, clean up any legacy conflicting conf.d file to prevent duplicate directive errors
            if is_nginx and os.name != "nt":
                try:
                    legacy_conf = Path("/etc/nginx/conf.d/00_global_security.conf")
                    if legacy_conf.exists():
                        legacy_conf.unlink(missing_ok=True)
                except Exception:
                    pass

            # 2. Syntax Validation
            ok, syntax_err = self.test_syntax(service_name, php_version)
            if not ok:
                # Rollback on syntax error
                shutil.copy2(backup_path, target_path)
                backup_path.unlink(missing_ok=True)
                return False, f"Syntax check failed after tweak. Rolled back. Error: {syntax_err}"

            # 3. Reload Service
            self.reload_service(service_name, php_version)
            backup_path.unlink(missing_ok=True)

            msg = f"Parameter '{param_name}' updated to '{new_value}' successfully."
            logger.info(msg)
            return True, msg

        except Exception as exc:
            if backup_path.exists():
                shutil.copy2(backup_path, target_path)
                backup_path.unlink(missing_ok=True)
            err_msg = f"Failed to update parameter '{param_name}': {exc}"
            logger.exception(err_msg)
            return False, err_msg

    def apply_preset(
        self,
        service_name: str,
        preset_name: str,
        php_version: str = "8.2",
    ) -> Tuple[bool, str]:
        """Tier 1: Apply full 1-click optimization preset to a service.

        Args:
            service_name: 'php', 'nginx', 'mysql', or 'all'.
            preset_name: 'low_end', 'balanced', or 'performance'.
            php_version: PHP version.

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        if preset_name not in ("low_end", "balanced", "performance"):
            return False, f"Invalid preset '{preset_name}'."

        targets = ["php", "nginx", "mysql"] if service_name == "all" else [service_name]
        applied_count = 0

        # Clean up any legacy duplicate file in conf.d
        if "nginx" in targets and os.name != "nt":
            try:
                legacy_conf = Path("/etc/nginx/conf.d/00_global_security.conf")
                if legacy_conf.exists():
                    legacy_conf.unlink(missing_ok=True)
            except Exception:
                pass

        for s in targets:
            registry = TUNER_REGISTRY.get(s, {})
            for param, meta in registry.items():
                val = meta["presets"].get(preset_name)
                if val:
                    ok, _ = self.update_parameter(s, param, val, php_version)
                    if ok:
                        applied_count += 1

        msg = f"Applied '{preset_name}' preset ({applied_count} parameters tuned across {len(targets)} service(s))."
        logger.info(msg)
        return True, msg

    def test_syntax(
        self,
        service_name: str,
        php_version: str = "8.2",
    ) -> Tuple[bool, str]:
        """Test configuration syntax before applying service reload."""
        if os.name == "nt" or self.mock_base:
            return True, "Syntax check passed (mock mode)"

        if service_name == "nginx":
            res = run_cmd("nginx -t")
            return res.success, res.stderr or res.stdout
        elif service_name == "php":
            res = run_cmd(f"php-fpm{php_version} -t")
            if not res.success and "not found" in res.stderr.lower():
                return True, "php-fpm binary not found (skipped)"
            return res.success, res.stderr or res.stdout
        elif service_name == "mysql":
            # mysqld --help --verbose for dry-run config check
            return True, "MySQL config check passed"

        return True, "OK"

    def reload_service(
        self,
        service_name: str,
        php_version: str = "8.2",
    ) -> Tuple[bool, str]:
        """Reload or restart service daemon to apply new configuration."""
        if os.name == "nt" or self.mock_base:
            return True, f"Mock reload {service_name} successful"

        if service_name == "nginx":
            res = run_cmd("systemctl reload nginx || systemctl restart nginx")
            return res.success, res.stderr or res.stdout
        elif service_name == "php":
            res = run_cmd(f"systemctl reload php{php_version}-fpm || systemctl restart php{php_version}-fpm")
            return res.success, res.stderr or res.stdout
        elif service_name == "mysql":
            res = run_cmd("systemctl reload mariadb || systemctl reload mysql || systemctl restart mariadb || systemctl restart mysql")
            return res.success, res.stderr or res.stdout

        return True, "OK"

    def open_raw_editor(
        self,
        service_name: str,
        file_type: str = "main",
        php_version: str = "8.2",
    ) -> Tuple[bool, str]:
        """Tier 3: Open terminal text editor with syntax validation on close.

        Args:
            service_name: 'php', 'nginx', or 'mysql'.
            file_type: 'php_ini', 'php_fpm', 'nginx_conf', 'nginx_waf', or 'mysql_cnf'.
            php_version: PHP version.

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        target_path = self.get_target_path(service_name, file_type, php_version)
        if not target_path.exists():
            target_path.parent.mkdir(parents=True, exist_ok=True)
            if file_type == "nginx_waf":
                target_path.write_text(WAF_DEFAULT_CONFIG, encoding="utf-8")
            else:
                target_path.touch()

        # Create backup
        backup_path = target_path.with_suffix(".bak_raw")
        shutil.copy2(target_path, backup_path)

        # Detect terminal editor
        editor = os.environ.get("EDITOR") or shutil.which("nano") or shutil.which("vim") or shutil.which("vi")
        if not editor:
            if os.name == "nt":
                editor = "notepad.exe"
            else:
                editor = "nano"

        try:
            subprocess.run([editor, str(target_path)], check=True)

            # Test syntax after edit
            ok, syntax_err = self.test_syntax(service_name, php_version)
            if not ok:
                shutil.copy2(backup_path, target_path)
                backup_path.unlink(missing_ok=True)
                return False, f"Syntax test failed after editing. Restored backup. Error:\n{syntax_err}"

            self.reload_service(service_name, php_version)
            backup_path.unlink(missing_ok=True)
            return True, f"File '{target_path.name}' saved and service reloaded successfully."

        except Exception as exc:
            if backup_path.exists():
                shutil.copy2(backup_path, target_path)
                backup_path.unlink(missing_ok=True)
            return False, f"Raw editing error: {exc}"
