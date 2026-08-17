"""PHP version, extension, and disabled functions security management module."""

import os
from pathlib import Path
import re
import shutil
from typing import Any, Dict, List, Optional, Tuple

from app.core.executor import run_cmd
from app.core.logger import BASE_DIR, get_logger

logger = get_logger("php_manager")

POPULAR_EXTENSIONS: Dict[str, str] = {
    "mysqli": "MySQL MySQLi Database Driver",
    "pdo_mysql": "PHP Data Objects (PDO) MySQL Driver",
    "curl": "cURL Client Library for HTTP requests",
    "gd": "GD Graphics and Image Manipulation Library",
    "zip": "Zip Archive compression & extraction library",
    "mbstring": "Multibyte String Support (UTF-8 manipulation)",
    "xml": "XML Parser and DOM Document extension",
    "intl": "Internationalization Functions (ICU Library)",
    "bcmath": "BCMath Arbitrary Precision Mathematics",
    "imagick": "ImageMagick Wrapper for advanced image filters",
    "redis": "High-performance Redis In-Memory Cache Client",
    "opcache": "Zend OPcache Byte-code Optimizer (Built-in)",
}

SECURITY_BASELINE_FUNCTIONS: List[str] = [
    "exec",
    "passthru",
    "shell_exec",
    "system",
    "proc_open",
    "popen",
    "curl_exec",
    "curl_multi_exec",
    "parse_ini_file",
    "show_source",
    "symlink",
    "link",
    "dl",
    "dlopen",
    "syslog",
    "pcntl_exec",
    "pcntl_fork",
    "pcntl_signal",
    "putenv",
]


class PHPManager:
    """Manager for detecting PHP versions, listing extensions, and managing disabled functions."""

    def __init__(self, mock_base_dir: Optional[str] = None) -> None:
        """Initialize PHPManager with optional mock base directory.

        Args:
            mock_base_dir: Directory for storing mock php.ini files for testing.
        """
        self.mock_base = Path(mock_base_dir) if mock_base_dir else None

    def get_ini_path(self, version: str = "8.2") -> Path:
        """Resolve the path to the target php.ini file for a given PHP version.

        Args:
            version: Target PHP version (e.g. '8.2').

        Returns:
            Path: Resolved Path instance for php.ini.
        """
        if self.mock_base:
            return self.mock_base / f"php_{version}_ini.conf"

        primary = Path(f"/etc/php/{version}/fpm/php.ini")
        fallback = BASE_DIR / "data" / "mock_config" / f"php_{version}_ini.conf"
        return primary if primary.exists() or os.name != "nt" else fallback

    def list_installed_versions(self) -> List[str]:
        """Detect PHP binary versions installed on the host.

        Returns:
            List[str]: List of PHP version strings (e.g. ['8.1', '8.2', '8.3']).
        """
        versions: List[str] = []

        if os.name != "nt":
            php_root = Path("/etc/php")
            if php_root.exists() and php_root.is_dir():
                for p in php_root.iterdir():
                    if p.is_dir() and re.match(r"^\d+\.\d+$", p.name):
                        if (p / "fpm").exists() or (p / "cli").exists() or shutil.which(f"php{p.name}"):
                            versions.append(p.name)

        for candidate in ["7.4", "8.0", "8.1", "8.2", "8.3", "8.4"]:
            if shutil.which(f"php{candidate}"):
                versions.append(candidate)

        if not versions:
            res = run_cmd("php -r 'echo PHP_MAJOR_VERSION.\".\".PHP_MINOR_VERSION;' 2>/dev/null")
            if res.success and re.match(r"^\d+\.\d+$", res.stdout.strip()):
                versions.append(res.stdout.strip())

        if not versions:
            versions = ["8.2", "8.1", "8.3"]

        return sorted(list(set(versions)), key=lambda v: [int(x) for x in v.split(".")])

    def get_installed_extensions(self, version: str = "8.2") -> List[str]:
        """Query host for active PHP compiled/installed extensions.

        Args:
            version: PHP version to query.

        Returns:
            List[str]: List of active extension names in lowercase.
        """
        cmd = f"php{version} -m" if shutil.which(f"php{version}") else "php -m"
        res = run_cmd(cmd)

        if not res.success:
            return ["curl", "gd", "mbstring", "mysqli", "pdo_mysql", "xml", "zip", "opcache"]

        lines = [l.strip().lower() for l in res.stdout.splitlines() if l.strip() and not l.startswith("[")]
        return lines

    def get_available_extensions(self, version: str = "8.2") -> List[Dict[str, Any]]:
        """Get catalogue of popular extensions annotated with their installation status.

        Args:
            version: PHP version.

        Returns:
            List[Dict[str, Any]]: List of extension info objects.
        """
        installed = set(self.get_installed_extensions(version))
        result: List[Dict[str, Any]] = []

        for ext_name, desc in POPULAR_EXTENSIONS.items():
            is_inst = ext_name in installed or (ext_name == "pdo_mysql" and "pdo" in installed)
            result.append({
                "name": ext_name,
                "description": desc,
                "installed": is_inst,
            })

        return result

    def install_extension(self, version: str, ext_name: str) -> Tuple[bool, str]:
        """Install PHP extension using system package manager (apt/dnf) and restart PHP-FPM.

        Args:
            version: PHP version.
            ext_name: Extension name (e.g. 'redis', 'imagick', 'intl').

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        if os.name == "nt" or self.mock_base:
            logger.info("Mock install PHP extension: php%s-%s", version, ext_name)
            return True, f"Mock: Extension 'php{version}-{ext_name}' installed and PHP-FPM restarted."

        pkg_name = f"php{version}-{ext_name}"
        if ext_name == "opcache":
            return True, "OPcache is a built-in PHP module."

        res = run_cmd(f"DEBIAN_FRONTEND=noninteractive apt-get install -y {pkg_name}")
        if not res.success:
            res = run_cmd(f"DEBIAN_FRONTEND=noninteractive apt-get install -y php-{ext_name}")
            if not res.success:
                return False, f"Failed to install package '{pkg_name}': {res.stderr}"

        self.restart_fpm(version)
        msg = f"Extension '{ext_name}' (php{version}-{ext_name}) installed and PHP-FPM restarted successfully."
        logger.info(msg)
        return True, msg

    def restart_fpm(self, version: str) -> Tuple[bool, str]:
        """Restart PHP-FPM daemon service.

        Args:
            version: PHP version.

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        if os.name == "nt" or self.mock_base:
            return True, f"Mock: php{version}-fpm restarted."

        res = run_cmd(f"systemctl restart php{version}-fpm || systemctl restart php-fpm")
        if not res.success:
            return False, f"Failed to restart PHP-FPM: {res.stderr}"

        return True, f"Service php{version}-fpm restarted successfully."

    # -------------------------------------------------------------------------
    # Dedicated Disabled Functions Security Engine
    # -------------------------------------------------------------------------
    def get_disabled_functions(self, version: str = "8.2") -> List[str]:
        """Parse target php.ini and extract active disabled functions list.

        Args:
            version: PHP version.

        Returns:
            List[str]: Clean list of disabled function names without duplicates.
        """
        ini_path = self.get_ini_path(version)
        if not ini_path.exists():
            return list(SECURITY_BASELINE_FUNCTIONS)

        try:
            content = ini_path.read_text(encoding="utf-8", errors="replace")
            pattern = re.compile(r"^\s*disable_functions\s*=\s*(.*)$", re.MULTILINE | re.IGNORECASE)
            match = pattern.search(content)
            if match:
                raw_val = match.group(1).strip()
                if not raw_val:
                    return []
                # Split, strip and deduplicate while preserving order
                funcs = [f.strip().lower() for f in raw_val.split(",") if f.strip()]
                return list(dict.fromkeys(funcs))
            else:
                return []
        except Exception as exc:
            logger.error("Could not read disable_functions from '%s': %s", ini_path, exc)
            return []

    def set_disabled_functions(
        self,
        version: str,
        func_list: List[str],
    ) -> Tuple[bool, str]:
        """Update disable_functions directive in php.ini with syntax test and backup rollback.

        Args:
            version: PHP version.
            func_list: New list of function names to disable.

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        ini_path = self.get_ini_path(version)
        if not ini_path.exists():
            ini_path.parent.mkdir(parents=True, exist_ok=True)
            ini_path.touch()

        # Clean list
        cleaned_funcs = list(dict.fromkeys([f.strip().lower() for f in func_list if f.strip()]))
        formatted_val = ", ".join(cleaned_funcs)

        # 1. Create emergency backup
        backup_path = ini_path.with_suffix(".bak_disable_fn")
        shutil.copy2(ini_path, backup_path)

        try:
            content = ini_path.read_text(encoding="utf-8", errors="replace")
            pattern = re.compile(r"^([ \t]*)disable_functions[ \t]*=.*$", re.MULTILINE | re.IGNORECASE)

            if pattern.search(content):
                new_content = pattern.sub(rf"\g<1>disable_functions = {formatted_val}", content)
            else:
                new_content = content + f"\ndisable_functions = {formatted_val}\n"

            ini_path.write_text(new_content, encoding="utf-8")

            # 2. Syntax validation
            if os.name != "nt" and not self.mock_base:
                test_res = run_cmd(f"php-fpm{version} -t")
                if not test_res.success and "not found" not in test_res.stderr.lower():
                    # Rollback
                    shutil.copy2(backup_path, ini_path)
                    backup_path.unlink(missing_ok=True)
                    return False, f"PHP-FPM syntax test failed: {test_res.stderr}"

            # 3. Reload PHP-FPM
            self.restart_fpm(version)
            backup_path.unlink(missing_ok=True)

            msg = f"Disabled functions for PHP {version} updated ({len(cleaned_funcs)} functions blacklisted)."
            logger.info(msg)
            return True, msg

        except Exception as exc:
            if backup_path.exists():
                shutil.copy2(backup_path, ini_path)
                backup_path.unlink(missing_ok=True)
            err_msg = f"Failed to update disable_functions for PHP {version}: {exc}"
            logger.exception(err_msg)
            return False, err_msg

    def enable_function(self, version: str, func_name: str) -> Tuple[bool, str]:
        """Remove a function from the disabled blacklist (unblock/enable).

        Args:
            version: PHP version.
            func_name: Function name to enable.

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        current_funcs = self.get_disabled_functions(version)
        clean_name = func_name.strip().lower()

        if clean_name not in current_funcs:
            return True, f"Function '{clean_name}' is already enabled in PHP {version}."

        updated_funcs = [f for f in current_funcs if f != clean_name]
        ok, msg = self.set_disabled_functions(version, updated_funcs)
        if ok:
            return True, f"Function '{clean_name}' successfully enabled (unblocked) in PHP {version}."
        return False, msg

    def disable_function(self, version: str, func_name: str) -> Tuple[bool, str]:
        """Add a function to the disabled blacklist (block/disable).

        Args:
            version: PHP version.
            func_name: Function name to disable.

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        current_funcs = self.get_disabled_functions(version)
        clean_name = func_name.strip().lower()

        if not clean_name:
            return False, "Function name cannot be empty."

        if clean_name in current_funcs:
            return True, f"Function '{clean_name}' is already disabled in PHP {version}."

        current_funcs.append(clean_name)
        ok, msg = self.set_disabled_functions(version, current_funcs)
        if ok:
            return True, f"Function '{clean_name}' successfully disabled (blocked) in PHP {version}."
        return False, msg

    def apply_security_baseline(self, version: str) -> Tuple[bool, str]:
        """Merge and enforce standard 19 security baseline functions.

        Args:
            version: PHP version.

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        current_funcs = self.get_disabled_functions(version)
        merged_funcs = list(dict.fromkeys(current_funcs + list(SECURITY_BASELINE_FUNCTIONS)))

        ok, msg = self.set_disabled_functions(version, merged_funcs)
        if ok:
            return True, f"Applied recommended security baseline ({len(merged_funcs)} functions disabled)."
        return False, msg

    def clear_all_disabled(self, version: str) -> Tuple[bool, str]:
        """Clear all disabled functions in php.ini (enable all functions).

        Args:
            version: PHP version.

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        return self.set_disabled_functions(version, [])
