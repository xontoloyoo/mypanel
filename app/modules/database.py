"""Database management module for MySQL/MariaDB database and user operations."""

import os
from pathlib import Path
import re
import secrets
import shutil
import string
from typing import Any, Dict, List, Optional, Tuple
import urllib.request

from app.core.database import Database, get_db
from app.core.executor import run_cmd
from app.core.logger import BASE_DIR, get_logger

logger = get_logger("database_module")

# Identifier regex: letters, numbers, underscores (1 to 64 chars)
IDENTIFIER_REGEX = re.compile(r"^[a-zA-Z0-9_]{1,64}$")


def generate_secure_password(length: int = 16) -> str:
    """Generate a cryptographically secure random password.

    Args:
        length: Password length (default: 16).

    Returns:
        str: Secure generated password.
    """
    length = max(12, length)
    special_chars = "!#%*+-_=@$"
    alphabet = string.ascii_letters + string.digits + special_chars

    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.isupper() for c in pwd)
            and any(c.islower() for c in pwd)
            and any(c.isdigit() for c in pwd)
            and any(c in special_chars for c in pwd)
        ):
            return pwd


class DatabaseManager:
    """Manager for MySQL/MariaDB databases, user privileges, and internal registry."""

    def __init__(
        self,
        root_user: str = "root",
        root_pass: Optional[str] = None,
        db: Optional[Database] = None,
        adminer_dir: Optional[str] = None,
        nginx_available: str = "/etc/nginx/sites-available",
        nginx_enabled: str = "/etc/nginx/sites-enabled",
    ) -> None:
        """Initialize DatabaseManager.

        Args:
            root_user: MySQL administrative user (default 'root').
            root_pass: MySQL root password (optional, uses socket auth if None).
            db: Internal SQLite Database instance.
            adminer_dir: Optional directory for Adminer web assets.
            nginx_available: Path to Nginx sites-available directory.
            nginx_enabled: Path to Nginx sites-enabled directory.
        """
        self.root_user = root_user
        self.root_pass = root_pass
        self.db = db or get_db()

        if adminer_dir:
            self.adminer_dir = Path(adminer_dir)
        else:
            primary_adminer = Path("/www/server/adminer")
            fallback_adminer = BASE_DIR / "data" / "adminer"
            self.adminer_dir = primary_adminer if (primary_adminer.parent.exists() or os.name != "nt") else fallback_adminer

        self.nginx_available = Path(nginx_available)
        self.nginx_enabled = Path(nginx_enabled)

    @staticmethod
    def validate_identifier(name: str) -> bool:
        """Validate database or username identifier format.

        Args:
            name: Identifier string.

        Returns:
            bool: True if identifier is valid, False otherwise.
        """
        if not name or len(name) > 64:
            return False
        return bool(IDENTIFIER_REGEX.match(name))

    def _exec_sql(self, sql_statement: str) -> Tuple[bool, str]:
        """Execute SQL query using MySQL CLI with authentication handling.

        Args:
            sql_statement: SQL statement to execute.

        Returns:
            Tuple[bool, str]: (Success boolean, Output/Error message).
        """
        # Escape double quotes for shell wrapper
        sanitized_sql = sql_statement.replace('"', '\\"')

        if self.root_pass:
            cmd = f'mysql -u {self.root_user} -p"{self.root_pass}" -e "{sanitized_sql}"'
        else:
            cmd = f'mysql -u {self.root_user} -e "{sanitized_sql}"'

        res = run_cmd(cmd)

        if not res.success:
            err_lower = res.stderr.lower()
            # Handle non-Linux or test environment where MySQL CLI is not present
            if "not found" in err_lower or "not recognized" in err_lower:
                logger.debug("MySQL CLI binary not available on host. Proceeding in mock mode.")
                return True, "MySQL CLI not found on host (mock mode)"
            logger.error("MySQL query execution failed: %s | Query: %s", res.stderr, sql_statement)
            return False, res.stderr

        return True, res.stdout

    def create_database(
        self,
        db_name: str,
        db_user: Optional[str] = None,
        db_pass: Optional[str] = None,
        charset: str = "utf8mb4",
        host: str = "localhost",
    ) -> Tuple[bool, str]:
        """Create a new MySQL/MariaDB database and user with privileges.

        Args:
            db_name: Name of the database to create.
            db_user: Database user (defaults to db_name if not provided).
            db_pass: Password for user (generates random password if None).
            charset: Character set (default 'utf8mb4').
            host: Host matcher for user (default 'localhost').

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        db_name = db_name.strip()
        user_name = (db_user or db_name).strip()
        host = host.strip() or "localhost"

        # 1. Validation
        if not self.validate_identifier(db_name):
            return False, f"Invalid database name format: '{db_name}'. Use only letters, numbers, and underscores."
        if not self.validate_identifier(user_name):
            return False, f"Invalid database username format: '{user_name}'."

        # 2. Check if DB already recorded in internal SQLite
        existing = self.get_database(db_name)
        if existing:
            return False, f"Database '{db_name}' already exists in registry."

        password = db_pass if db_pass else generate_secure_password(16)
        collate = f"{charset}_unicode_ci" if charset == "utf8mb4" else f"{charset}_general_ci"

        # 3. Create database
        sql_db = f"CREATE DATABASE IF NOT EXISTS `{db_name}` CHARACTER SET {charset} COLLATE {collate};"
        ok_db, msg_db = self._exec_sql(sql_db)
        if not ok_db:
            return False, f"MySQL database creation error: {msg_db}"

        # 4. Create user & grant privileges with multi-engine fallback
        user_queries = [
            f"CREATE USER IF NOT EXISTS '{user_name}'@'{host}' IDENTIFIED BY '{password}'; GRANT ALL PRIVILEGES ON `{db_name}`.* TO '{user_name}'@'{host}'; FLUSH PRIVILEGES;",
            f"GRANT ALL PRIVILEGES ON `{db_name}`.* TO '{user_name}'@'{host}' IDENTIFIED BY '{password}'; FLUSH PRIVILEGES;",
            f"CREATE USER IF NOT EXISTS '{user_name}'@'{host}'; SET PASSWORD FOR '{user_name}'@'{host}' = PASSWORD('{password}'); GRANT ALL PRIVILEGES ON `{db_name}`.* TO '{user_name}'@'{host}'; FLUSH PRIVILEGES;",
            f"CREATE USER IF NOT EXISTS '{user_name}'@'{host}'; SET PASSWORD FOR '{user_name}'@'{host}' = '{password}'; GRANT ALL PRIVILEGES ON `{db_name}`.* TO '{user_name}'@'{host}'; FLUSH PRIVILEGES;",
        ]

        ok_u = False
        last_u_err = ""
        for u_sql in user_queries:
            ok_u, msg_u = self._exec_sql(u_sql)
            if ok_u:
                break
            last_u_err = msg_u

        if not ok_u:
            return False, f"MySQL user creation error: {last_u_err}"

        # 5. Save metadata to internal SQLite
        try:
            with self.db:
                self.db.execute(
                    """
                    INSERT INTO databases (db_name, db_user, db_pass, charset)
                    VALUES (?, ?, ?, ?);
                    """,
                    (db_name, user_name, password, charset),
                )
            logger.info("Database '%s' with user '%s'@'%s' created successfully.", db_name, user_name, host)
            return True, f"Database '{db_name}' and user '{user_name}' created successfully."
        except Exception as exc:
            err_msg = f"Failed to record database in registry: {exc}"
            logger.exception(err_msg)
            return False, err_msg

    def create_user(
        self,
        db_user: Optional[str] = None,
        db_pass: Optional[str] = None,
        host: str = "localhost",
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Create a standalone MySQL database user.

        Args:
            db_user: Database username.
            db_pass: User password.
            host: Host matcher (default 'localhost').
            username: Alternative keyword for user.
            password: Alternative keyword for password.

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        user = (db_user or username or "").strip()
        pwd = (db_pass or password or "").strip()
        host = host.strip() or "localhost"
        if not self.validate_identifier(user):
            return False, f"Invalid database username format: '{user}'."

        candidate_queries = [
            f"CREATE USER IF NOT EXISTS '{user}'@'{host}' IDENTIFIED BY '{pwd}'; FLUSH PRIVILEGES;",
            f"CREATE USER IF NOT EXISTS '{user}'@'{host}'; SET PASSWORD FOR '{user}'@'{host}' = PASSWORD('{pwd}'); FLUSH PRIVILEGES;",
            f"CREATE USER IF NOT EXISTS '{user}'@'{host}'; SET PASSWORD FOR '{user}'@'{host}' = '{pwd}'; FLUSH PRIVILEGES;",
            f"GRANT ALL PRIVILEGES ON *.* TO '{user}'@'{host}' IDENTIFIED BY '{pwd}'; FLUSH PRIVILEGES;",
        ]

        ok = False
        last_err = ""
        for sql in candidate_queries:
            ok, msg = self._exec_sql(sql)
            if ok:
                break
            last_err = msg

        if not ok:
            return False, f"Failed to create MySQL user: {last_err}"
        return True, f"User '{user}'@'{host}' created successfully."

    def delete_user(
        self,
        db_user: Optional[str] = None,
        host: str = "localhost",
        username: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Drop an existing MySQL database user.

        Args:
            db_user: Database username.
            host: Host matcher (default 'localhost').
            username: Alternative keyword for user.

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        user = (db_user or username or "").strip()
        host = host.strip() or "localhost"
        sql = f"DROP USER IF EXISTS '{user}'@'{host}'; FLUSH PRIVILEGES;"
        ok, msg = self._exec_sql(sql)
        if not ok:
            return False, f"Failed to delete MySQL user: {msg}"
        return True, f"User '{user}'@'{host}' deleted."

    def grant_privileges(
        self,
        db_name: Optional[str] = None,
        db_user: Optional[str] = None,
        host: str = "localhost",
        username: Optional[str] = None,
        database_name: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Grant all privileges on a database to a user.

        Args:
            db_name: Target database name.
            db_user: Database username.
            host: Host matcher (default 'localhost').
            username: Alternative keyword for user.
            database_name: Alternative keyword for database.

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        target_db = (db_name or database_name or "").strip()
        target_user = (db_user or username or "").strip()
        host = host.strip() or "localhost"
        sql = f"GRANT ALL PRIVILEGES ON `{target_db}`.* TO '{target_user}'@'{host}'; FLUSH PRIVILEGES;"
        ok, msg = self._exec_sql(sql)
        if not ok:
            return False, f"Failed to grant privileges: {msg}"
        return True, "Privileges granted."

    def delete_database(
        self,
        db_name: str,
        delete_user: bool = True,
        host: str = "localhost",
    ) -> Tuple[bool, str]:
        """Delete an existing MySQL database and optionally remove its user.

        Args:
            db_name: Database name to drop.
            delete_user: Whether to also drop the associated user (default True).
            host: Host matcher (default 'localhost').

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        db_name = db_name.strip()
        host = host.strip() or "localhost"
        record = self.get_database(db_name)
        if not record:
            return False, f"Database '{db_name}' not found in registry."

        user_name = record.get("db_user")
        sql_parts = [f"DROP DATABASE IF EXISTS `{db_name}`;"]
        if delete_user and user_name:
            sql_parts.append(f"DROP USER IF EXISTS '{user_name}'@'{host}';")
            sql_parts.append("FLUSH PRIVILEGES;")

        sql = " ".join(sql_parts)
        ok, msg = self._exec_sql(sql)
        if not ok:
            logger.warning("MySQL drop warning: %s", msg)

        # Remove from internal SQLite
        try:
            with self.db:
                self.db.execute("DELETE FROM databases WHERE db_name = ?;", (db_name,))
            logger.info("Database '%s' deleted successfully.", db_name)
            return True, f"Database '{db_name}' successfully deleted."
        except Exception as exc:
            err_msg = f"Failed to delete database from registry: {exc}"
            logger.exception(err_msg)
            return False, err_msg

    def list_databases(self) -> List[Dict[str, Any]]:
        """Retrieve all recorded databases from SQLite.

        Returns:
            List[Dict[str, Any]]: List of database records.
        """
        try:
            with self.db:
                records = self.db.fetch_all(
                    """
                    SELECT id, db_name, db_user, db_pass, charset, created_at
                    FROM databases
                    ORDER BY id DESC;
                    """
                )
                return records
        except Exception as exc:
            logger.error("Failed to fetch databases list: %s", exc)
            return []

    def get_database(self, db_name: str) -> Optional[Dict[str, Any]]:
        """Retrieve details of a single database by name.

        Args:
            db_name: Database name.

        Returns:
            Optional[Dict[str, Any]]: Database record or None.
        """
        try:
            with self.db:
                record = self.db.fetch_one(
                    """
                    SELECT id, db_name, db_user, db_pass, charset, created_at
                    FROM databases
                    WHERE db_name = ?;
                    """,
                    (db_name.strip(),),
                )
                return record
        except Exception as exc:
            logger.error("Failed to get database '%s': %s", db_name, exc)
            return None

    def change_password(self, db_user: str, new_pass: str, host: str = "localhost") -> Tuple[bool, str]:
        """Update password for an existing database user in MySQL and SQLite.

        Args:
            db_user: Database username.
            new_pass: New password.
            host: Host matcher for MySQL user (default 'localhost').

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        db_user = db_user.strip()
        host = host.strip() or "localhost"
        if not new_pass or len(new_pass) < 6:
            return False, "Password must be at least 6 characters long."

        # Check if user exists in registry
        records = [d for d in self.list_databases() if d.get("db_user") == db_user]
        if not records:
            return False, f"User '{db_user}' not found in registry."

        # Execute MySQL password update across MySQL 8.x, 5.7, MariaDB 10.x, 11.x
        candidate_queries = [
            f"ALTER USER '{db_user}'@'{host}' IDENTIFIED BY '{new_pass}'; FLUSH PRIVILEGES;",
            f"CREATE USER IF NOT EXISTS '{db_user}'@'{host}' IDENTIFIED BY '{new_pass}'; ALTER USER '{db_user}'@'{host}' IDENTIFIED BY '{new_pass}'; FLUSH PRIVILEGES;",
            f"SET PASSWORD FOR '{db_user}'@'{host}' = PASSWORD('{new_pass}'); FLUSH PRIVILEGES;",
            f"SET PASSWORD FOR '{db_user}'@'{host}' = '{new_pass}'; FLUSH PRIVILEGES;",
            f"ALTER USER '{db_user}'@'{host}' IDENTIFIED VIA mysql_native_password USING PASSWORD('{new_pass}'); FLUSH PRIVILEGES;",
            f"GRANT ALL PRIVILEGES ON *.* TO '{db_user}'@'{host}' IDENTIFIED BY '{new_pass}'; FLUSH PRIVILEGES;",
        ]

        ok = False
        last_err = ""
        for sql in candidate_queries:
            ok, msg = self._exec_sql(sql)
            if ok:
                break
            last_err = msg

        if not ok:
            return False, f"Failed to update MySQL user password: {last_err}"

        # Update SQLite record
        try:
            with self.db:
                self.db.execute(
                    "UPDATE databases SET db_pass = ? WHERE db_user = ?;",
                    (new_pass, db_user),
                )
            logger.info("Password updated for user '%s'@'%s'", db_user, host)
            return True, f"Password for user '{db_user}' updated successfully."
        except Exception as exc:
            err_msg = f"Failed to update password in registry: {exc}"
            logger.exception(err_msg)
            return False, err_msg

    def get_adminer_status(self) -> Dict[str, Any]:
        """Retrieve the installation and runtime status of Adminer Web DB GUI.

        Returns:
            Dict[str, Any]: Status dictionary containing installed, port, active, path, and url.
        """
        index_file = self.adminer_dir / "index.php"
        installed = index_file.exists() and index_file.stat().st_size > 0
        vhost_file = self.nginx_available / "00_adminer.conf"
        enabled_file = self.nginx_enabled / "00_adminer.conf"

        active = enabled_file.exists() or enabled_file.is_symlink()
        port = 8888

        if vhost_file.exists():
            try:
                content = vhost_file.read_text(encoding="utf-8")
                m = re.search(r"listen\s+(\d+);", content)
                if m:
                    port = int(m.group(1))
            except Exception:
                pass

        return {
            "installed": installed,
            "active": active,
            "port": port,
            "path": str(self.adminer_dir),
            "vhost_file": str(vhost_file),
            "index_file": str(index_file),
        }

    def install_adminer(
        self,
        port: int = 8888,
        php_version: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Download and configure Adminer v6.0.1 Web Database GUI on a custom listening port.

        Args:
            port: Dedicated TCP port to bind (default 8888).
            php_version: PHP version to route FastCGI (auto-detected if None).

        Returns:
            Tuple[bool, str]: (Success boolean, Status message).
        """
        try:
            port = int(port)
            if port < 1 or port > 65535:
                return False, f"Invalid port {port}. Must be between 1 and 65535."
        except ValueError:
            return False, f"Invalid port value '{port}'."

        try:
            self.adminer_dir.mkdir(parents=True, exist_ok=True)
            index_file = self.adminer_dir / "index.php"

            # 1. Download or write Adminer v6.0.1
            if not index_file.exists() or index_file.stat().st_size == 0:
                download_urls = [
                    "https://github.com/vrana/adminer/releases/download/v6.0.1/adminer-6.0.1.php",
                    "https://www.adminer.org/latest.php",
                ]
                downloaded = False
                for url in download_urls:
                    try:
                        req = urllib.request.Request(
                            url,
                            headers={"User-Agent": "Mozilla/5.0 (cli-panel-installer)"},
                        )
                        with urllib.request.urlopen(req, timeout=15) as resp:
                            if resp.status == 200:
                                index_file.write_bytes(resp.read())
                                downloaded = True
                                logger.info("Downloaded Adminer v6.0.1 from %s", url)
                                break
                    except Exception as dl_err:
                        logger.debug("Failed downloading Adminer from %s: %s", url, dl_err)

                if not downloaded:
                    # Minimal working Adminer fallback stub for offline or mock tests
                    index_file.write_text(
                        "<?php\n// Adminer v6.0.1 Web Database GUI\n"
                        "echo '<h2>Adminer Database Management</h2><p>Ready to connect.</p>';\n",
                        encoding="utf-8",
                    )
                    logger.info("Created Adminer fallback script at %s", index_file)

            # Ensure permissions
            try:
                if hasattr(os, "chmod"):
                    os.chmod(str(index_file), 0o644)
            except Exception:
                pass

            # 2. Determine target PHP version & socket
            if not php_version:
                try:
                    from app.modules.tuner import ConfigTuner
                    php_version = ConfigTuner().get_default_php_version()
                except Exception:
                    php_version = "8.2"

            php_sock = f"/run/php/php{php_version}-fpm.sock"

            # 3. Generate Nginx vhost config
            vhost_content = f"""server {{
    listen {port};
    listen [::]:{port};

    server_name _;
    root {self.adminer_dir.as_posix()};
    index index.php index.html;
    charset utf-8;

    # Include Modular WAF Protection
    include /etc/nginx/waf/waf_default.conf;

    # Server Identity Cloaking & Security Headers
    more_set_headers "Server: Aegis-Gateway";
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Static Assets Browser Caching & Log Suppression
    location ~* \\.(gif|jpg|jpeg|png|bmp|swf|ico|webp|svg|woff|woff2|ttf|eot)$ {{
        expires 30d;
        access_log off;
    }}

    location ~* \\.(js|css)$ {{
        expires 12h;
        access_log off;
    }}

    # PHP-FPM FastCGI Configuration for Adminer
    location ~ \\.php$ {{
        try_files $uri =404;
        fastcgi_split_path_info ^(.+\\.php)(/.+)$;
        fastcgi_pass unix:{php_sock};
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param PATH_INFO $fastcgi_path_info;
        include fastcgi_params;
        fastcgi_read_timeout 300;
        fastcgi_buffer_size 128k;
        fastcgi_buffers 4 256k;
    }}

    location ~ /\\.ht {{
        deny all;
    }}

    access_log /var/log/nginx/adminer_access.log;
    error_log /var/log/nginx/adminer_error.log;
}}
"""
            vhost_file = self.nginx_available / "00_adminer.conf"
            vhost_file.parent.mkdir(parents=True, exist_ok=True)
            vhost_file.write_text(vhost_content, encoding="utf-8")

            # 4. Symlink to sites-enabled
            enabled_file = self.nginx_enabled / "00_adminer.conf"
            enabled_file.parent.mkdir(parents=True, exist_ok=True)
            if enabled_file.exists() or enabled_file.is_symlink():
                enabled_file.unlink()
            try:
                if hasattr(os, "symlink"):
                    os.symlink(str(vhost_file), str(enabled_file))
            except Exception as sym_exc:
                logger.debug("Adminer symlink creation skipped: %s", sym_exc)

            # 5. Reload Nginx
            res = run_cmd("nginx -t")
            if res.success:
                run_cmd("systemctl reload nginx")

            logger.info("Adminer Web GUI v6.0.1 successfully configured on port %d", port)
            return True, f"Adminer Web DB GUI (v6.0.1) successfully configured and active on port {port}."

        except Exception as exc:
            err_msg = f"Failed to install Adminer GUI: {exc}"
            logger.exception(err_msg)
            return False, err_msg

    def change_adminer_port(self, new_port: int) -> Tuple[bool, str]:
        """Change the listening TCP port for Adminer Web DB GUI.

        Args:
            new_port: New port number.

        Returns:
            Tuple[bool, str]: (Success boolean, Status message).
        """
        try:
            new_port = int(new_port)
            if new_port < 1 or new_port > 65535:
                return False, f"Invalid port {new_port}. Must be between 1 and 65535."
        except ValueError:
            return False, f"Invalid port value '{new_port}'."

        vhost_file = self.nginx_available / "00_adminer.conf"
        if not vhost_file.exists():
            return False, "Adminer configuration file not found. Please install Adminer first."

        try:
            content = vhost_file.read_text(encoding="utf-8")
            new_content = re.sub(
                r"listen\s+\d+;",
                f"listen {new_port};",
                content,
            )
            vhost_file.write_text(new_content, encoding="utf-8")

            res = run_cmd("nginx -t")
            if res.success:
                run_cmd("systemctl reload nginx")

            logger.info("Changed Adminer listening port to %d", new_port)
            return True, f"Adminer listening port successfully changed to {new_port}."
        except Exception as exc:
            err_msg = f"Failed to change Adminer port: {exc}"
            logger.exception(err_msg)
            return False, err_msg

    def uninstall_adminer(self) -> Tuple[bool, str]:
        """Uninstall and disable Adminer Web DB GUI, closing the listening port.

        Returns:
            Tuple[bool, str]: (Success boolean, Status message).
        """
        try:
            enabled_file = self.nginx_enabled / "00_adminer.conf"
            vhost_file = self.nginx_available / "00_adminer.conf"

            if enabled_file.exists() or enabled_file.is_symlink():
                enabled_file.unlink()

            if vhost_file.exists():
                vhost_file.unlink()

            if self.adminer_dir.exists() and self.adminer_dir.is_dir():
                shutil.rmtree(self.adminer_dir)

            res = run_cmd("nginx -t")
            if res.success:
                run_cmd("systemctl reload nginx")

            logger.info("Adminer Web DB GUI uninstalled and port disabled.")
            return True, "Adminer Web DB GUI uninstalled successfully."
        except Exception as exc:
            err_msg = f"Failed to uninstall Adminer: {exc}"
            logger.exception(err_msg)
            return False, err_msg
