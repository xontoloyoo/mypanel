"""Internal SQLite database connection handler and query helper."""

from pathlib import Path
import sqlite3
from typing import Any, List, Optional, Tuple, Union

from app.core.logger import get_logger

logger = get_logger("database")

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
DB_PATH = DATA_DIR / "panel.db"


def dict_factory(cursor: sqlite3.Cursor, row: Tuple[Any, ...]) -> dict[str, Any]:
    """Convert SQLite row tuple into a standard Python dictionary."""
    fields = [col[0] for col in cursor.description]
    return dict(zip(fields, row))


class Database:
    """SQLite Database manager with context manager support and helper methods."""

    def __init__(self, db_path: Optional[Union[str, Path]] = None) -> None:
        """Initialize database manager.

        Args:
            db_path: Path to SQLite database file. Defaults to data/panel.db.
        """
        self.db_path = Path(db_path) if db_path else DB_PATH
        self._ensure_dir()
        self._conn: Optional[sqlite3.Connection] = None

    def _ensure_dir(self) -> None:
        """Ensure parent directory for database exists."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        """Establish and configure SQLite database connection."""
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path))
            self._conn.row_factory = dict_factory
            self._conn.execute("PRAGMA foreign_keys = ON;")
        return self._conn

    def close(self) -> None:
        """Close database connection if open."""
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "Database":
        """Enter context manager, establishing connection."""
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Exit context manager, committing on success or rolling back on error."""
        if self._conn:
            if exc_type is not None:
                self._conn.rollback()
                logger.error("Database transaction rolled back due to: %s", exc_val)
            else:
                self._conn.commit()
            self.close()

    def execute(self, query: str, params: Union[tuple, dict] = ()) -> int:
        """Execute INSERT, UPDATE, or DELETE query.

        Args:
            query: SQL query string.
            params: Parameters tuple or dict for parameterized query.

        Returns:
            int: Last inserted row id for INSERTs, or rowcount for UPDATE/DELETE.
        """
        conn = self.connect()
        cursor = conn.cursor()
        try:
            cursor.execute(query, params)
            if query.strip().upper().startswith("INSERT"):
                result = cursor.lastrowid or cursor.rowcount
            else:
                result = cursor.rowcount
            return result
        except Exception as exc:
            logger.error("Database execution error on '%s': %s", query, exc)
            raise

    def fetch_all(self, query: str, params: Union[tuple, dict] = ()) -> List[dict[str, Any]]:
        """Execute a SELECT query and return all matching records as list of dicts.

        Args:
            query: SQL SELECT query string.
            params: Parameters tuple or dict.

        Returns:
            List[dict[str, Any]]: List of matching records.
        """
        conn = self.connect()
        cursor = conn.cursor()
        try:
            cursor.execute(query, params)
            return cursor.fetchall()
        except Exception as exc:
            logger.error("Database fetch_all error on '%s': %s", query, exc)
            raise

    def fetch_one(self, query: str, params: Union[tuple, dict] = ()) -> Optional[dict[str, Any]]:
        """Execute a SELECT query and return the first matching record as a dict.

        Args:
            query: SQL SELECT query string.
            params: Parameters tuple or dict.

        Returns:
            Optional[dict[str, Any]]: Record dictionary or None.
        """
        conn = self.connect()
        cursor = conn.cursor()
        try:
            cursor.execute(query, params)
            return cursor.fetchone()
        except Exception as exc:
            logger.error("Database fetch_one error on '%s': %s", query, exc)
            raise

    def execute_script(self, script: str) -> None:
        """Execute a multi-statement SQL script.

        Args:
            script: SQL script containing multiple statements.
        """
        conn = self.connect()
        try:
            conn.executescript(script)
        except Exception as exc:
            logger.error("Database execute_script error: %s", exc)
            raise

    def init_db(self) -> None:
        """Initialize database schema with initial tables if they do not exist."""
        schema = """
        CREATE TABLE IF NOT EXISTS sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE NOT NULL,
            root_path TEXT NOT NULL,
            php_version TEXT,
            ssl_status INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS databases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            db_name TEXT UNIQUE NOT NULL,
            db_user TEXT NOT NULL,
            db_pass TEXT NOT NULL,
            charset TEXT DEFAULT 'utf8mb4',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS firewall_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            port TEXT NOT NULL,
            protocol TEXT DEFAULT 'tcp',
            action TEXT DEFAULT 'allow',
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );

        CREATE TABLE IF NOT EXISTS cron_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            job_type TEXT NOT NULL,
            schedule TEXT NOT NULL,
            target TEXT,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS backups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            backup_type TEXT NOT NULL,
            target TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_size INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        """
        logger.info("Initializing database schema at: %s", self.db_path)
        with self:
            self.execute_script(schema)
        logger.info("Database schema initialized successfully.")


def get_db(db_path: Optional[Union[str, Path]] = None) -> Database:
    """Convenience factory function to get a Database instance."""
    return Database(db_path=db_path)


def init_db(db_path: Optional[Union[str, Path]] = None) -> None:
    """Convenience function to initialize default database schema."""
    Database(db_path=db_path).init_db()
