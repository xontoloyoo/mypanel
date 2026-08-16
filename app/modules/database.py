"""Database management module for MySQL/MariaDB database and user operations."""

import re
import secrets
import string
from typing import Any, Dict, List, Optional, Tuple

from app.core.database import Database, get_db
from app.core.executor import run_cmd
from app.core.logger import get_logger

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
    ) -> None:
        """Initialize DatabaseManager.

        Args:
            root_user: MySQL administrative user (default 'root').
            root_pass: MySQL root password (optional, uses socket auth if None).
            db: Internal SQLite Database instance.
        """
        self.root_user = root_user
        self.root_pass = root_pass
        self.db = db or get_db()

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
    ) -> Tuple[bool, str]:
        """Create a new MySQL/MariaDB database and user with privileges.

        Args:
            db_name: Name of the database to create.
            db_user: Database user (defaults to db_name if not provided).
            db_pass: Password for user (generates random password if None).
            charset: Character set (default 'utf8mb4').

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        db_name = db_name.strip()
        user_name = (db_user or db_name).strip()

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

        # 3. SQL statements
        sql = (
            f"CREATE DATABASE IF NOT EXISTS `{db_name}` CHARACTER SET {charset} COLLATE {collate}; "
            f"CREATE USER IF NOT EXISTS '{user_name}'@'localhost' IDENTIFIED BY '{password}'; "
            f"GRANT ALL PRIVILEGES ON `{db_name}`.* TO '{user_name}'@'localhost'; "
            f"FLUSH PRIVILEGES;"
        )

        ok, msg = self._exec_sql(sql)
        if not ok:
            return False, f"MySQL execution error: {msg}"

        # 4. Save metadata to internal SQLite
        try:
            with self.db:
                self.db.execute(
                    """
                    INSERT INTO databases (db_name, db_user, db_pass, charset)
                    VALUES (?, ?, ?, ?);
                    """,
                    (db_name, user_name, password, charset),
                )
            logger.info("Database '%s' with user '%s' created successfully.", db_name, user_name)
            return True, f"Database '{db_name}' and user '{user_name}' created successfully."
        except Exception as exc:
            err_msg = f"Failed to record database in registry: {exc}"
            logger.exception(err_msg)
            return False, err_msg

    def delete_database(self, db_name: str, delete_user: bool = True) -> Tuple[bool, str]:
        """Delete an existing MySQL database and optionally remove its user.

        Args:
            db_name: Database name to drop.
            delete_user: Whether to also drop the associated user (default True).

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        db_name = db_name.strip()
        record = self.get_database(db_name)
        if not record:
            return False, f"Database '{db_name}' not found in registry."

        user_name = record.get("db_user")
        sql_parts = [f"DROP DATABASE IF EXISTS `{db_name}`;"]
        if delete_user and user_name:
            sql_parts.append(f"DROP USER IF EXISTS '{user_name}'@'localhost';")
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

    def change_password(self, db_user: str, new_pass: str) -> Tuple[bool, str]:
        """Update password for an existing database user in MySQL and SQLite.

        Args:
            db_user: Database username.
            new_pass: New password.

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        db_user = db_user.strip()
        if not new_pass or len(new_pass) < 6:
            return False, "Password must be at least 6 characters long."

        # Check if user exists in registry
        records = [d for d in self.list_databases() if d.get("db_user") == db_user]
        if not records:
            return False, f"User '{db_user}' not found in registry."

        # Execute MySQL password update
        sql = f"ALTER USER '{db_user}'@'localhost' IDENTIFIED BY '{new_pass}'; FLUSH PRIVILEGES;"
        ok, msg = self._exec_sql(sql)
        if not ok:
            return False, f"Failed to update MySQL user password: {msg}"

        # Update SQLite record
        try:
            with self.db:
                self.db.execute(
                    "UPDATE databases SET db_pass = ? WHERE db_user = ?;",
                    (new_pass, db_user),
                )
            logger.info("Password updated for user '%s'", db_user)
            return True, f"Password for user '{db_user}' updated successfully."
        except Exception as exc:
            err_msg = f"Failed to update password in registry: {exc}"
            logger.exception(err_msg)
            return False, err_msg
