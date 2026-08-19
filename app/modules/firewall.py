"""Firewall management module for UFW and port rule management."""

from typing import Any, Dict, List, Optional, Tuple, Union

from app.core.database import Database, generate_short_id, get_db
from app.core.executor import run_cmd
from app.core.logger import get_logger

logger = get_logger("firewall")


class FirewallManager:
    """Manager for UFW (Uncomplicated Firewall) rules and internal SQLite registry."""

    def __init__(self, db: Optional[Database] = None) -> None:
        """Initialize FirewallManager with database instance.

        Args:
            db: Internal SQLite Database instance.
        """
        self.db = db or get_db()

    @staticmethod
    def validate_port(port: Union[str, int]) -> bool:
        """Validate port number (1-65535) or port range (e.g. '8000:8080').

        Args:
            port: Port integer or string.

        Returns:
            bool: True if valid port or port range, False otherwise.
        """
        port_str = str(port).strip()
        if not port_str:
            return False

        # Check port range (e.g. 8000:8080)
        if ":" in port_str:
            parts = port_str.split(":")
            if len(parts) != 2:
                return False
            p1, p2 = parts[0].strip(), parts[1].strip()
            if not p1.isdigit() or not p2.isdigit():
                return False
            val1, val2 = int(p1), int(p2)
            return 1 <= val1 <= 65535 and 1 <= val2 <= 65535 and val1 <= val2

        # Check single port
        if not port_str.isdigit():
            return False
        val = int(port_str)
        return 1 <= val <= 65535

    def get_ufw_status(self) -> Dict[str, Any]:
        """Check UFW service status and whether it is active.

        Returns:
            Dict[str, Any]: {'active': bool, 'status_raw': str}.
        """
        res = run_cmd("ufw status", check_root=True)
        if not res.success:
            return {"active": False, "status_raw": res.stderr}

        is_active = "Status: active" in res.stdout or "Status: running" in res.stdout
        return {"active": is_active, "status_raw": res.stdout}

    def enable_ufw(self) -> Tuple[bool, str]:
        """Enable UFW firewall.

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        # Always ensure port 22/SSH is allowed before enabling to prevent lockout
        run_cmd("ufw allow 22/tcp", check_root=True)
        res = run_cmd("echo 'y' | ufw enable", check_root=True)
        if not res.success:
            if "not found" in res.stderr.lower() or "not recognized" in res.stderr.lower():
                logger.debug("UFW not installed. Mocking enable.")
                return True, "UFW enabled (mock mode)"
            logger.error("Failed to enable UFW: %s", res.stderr)
            return False, res.stderr

        logger.info("UFW firewall enabled successfully.")
        return True, "Firewall enabled successfully (Port 22 SSH auto-allowed)."

    def disable_ufw(self) -> Tuple[bool, str]:
        """Disable UFW firewall.

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        res = run_cmd("ufw disable", check_root=True)
        if not res.success:
            if "not found" in res.stderr.lower() or "not recognized" in res.stderr.lower():
                logger.debug("UFW not installed. Mocking disable.")
                return True, "UFW disabled (mock mode)"
            logger.error("Failed to disable UFW: %s", res.stderr)
            return False, res.stderr

        logger.info("UFW firewall disabled successfully.")
        return True, "Firewall disabled successfully."

    def get_status(self) -> Dict[str, Any]:
        """Check UFW service status and whether it is active (alias).

        Returns:
            Dict[str, Any]: {'active': bool, 'status_raw': str}.
        """
        return self.get_ufw_status()

    def toggle_firewall(self, enable: bool = True) -> Tuple[bool, str]:
        """Toggle UFW firewall on or off.

        Args:
            enable: True to enable UFW, False to disable.

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        if enable:
            return self.enable_ufw()
        return self.disable_ufw()

    def add_rule(
        self,
        port: Union[str, int],
        protocol: str = "tcp",
        action: str = "allow",
        description: str = "",
    ) -> Tuple[bool, str]:
        """Open or close a port in UFW and record in SQLite.

        Args:
            port: Port or port range.
            protocol: 'tcp', 'udp', or 'any'.
            action: 'allow' or 'deny'.
            description: Optional note.

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        port_str = str(port).strip()
        protocol = protocol.strip().lower()
        action = action.strip().lower()

        # 1. Validation
        if not self.validate_port(port_str):
            return False, f"Invalid port or port range: '{port_str}'."

        if protocol not in ("tcp", "udp", "any"):
            return False, f"Invalid protocol: '{protocol}'. Choose 'tcp', 'udp', or 'any'."

        if action not in ("allow", "deny"):
            return False, f"Invalid action: '{action}'. Choose 'allow' or 'deny'."

        # 2. Check duplicate in DB
        with self.db:
            existing = self.db.fetch_one(
                "SELECT id FROM firewall_rules WHERE port = ? AND protocol = ?;",
                (port_str, protocol),
            )
        if existing:
            return False, f"Firewall rule for port {port_str}/{protocol} already exists in registry."

        # 3. Execute UFW command
        if protocol == "any":
            cmd = f"ufw {action} {port_str}"
        else:
            cmd = f"ufw {action} {port_str}/{protocol}"

        res = run_cmd(cmd, check_root=True)
        if not res.success:
            if "not found" in res.stderr.lower() or "not recognized" in res.stderr.lower():
                logger.debug("UFW CLI not found on host. Adding rule to registry in mock mode.")
            else:
                logger.error("UFW rule execution error: %s", res.stderr)
                return False, f"UFW execution error: {res.stderr}"

        # 4. Save rule in SQLite
        try:
            rule_id = generate_short_id()
            with self.db:
                self.db.execute(
                    """
                    INSERT INTO firewall_rules (id, port, protocol, action, description)
                    VALUES (?, ?, ?, ?, ?);
                    """,
                    (rule_id, port_str, protocol, action, description),
                )
            logger.info("Firewall rule added: %s %s/%s (%s)", action, port_str, protocol, description)
            return True, f"Firewall rule for port {port_str}/{protocol} ({action}) added successfully."
        except Exception as exc:
            err_msg = f"Failed to record firewall rule: {exc}"
            logger.exception(err_msg)
            return False, err_msg

    def delete_rule(self, rule_id: Union[int, str]) -> Tuple[bool, str]:
        """Delete an existing firewall rule by ID from UFW and SQLite.

        Args:
            rule_id: Database rule ID to delete.

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        rule = self.get_rule(rule_id)
        if not rule:
            return False, f"Rule with ID {rule_id} not found."

        port_str = rule.get("port")
        protocol = rule.get("protocol", "tcp")
        action = rule.get("action", "allow")

        # 1. Execute UFW delete command
        if protocol == "any":
            cmd = f"ufw delete {action} {port_str}"
        else:
            cmd = f"ufw delete {action} {port_str}/{protocol}"

        res = run_cmd(cmd, check_root=True)
        if not res.success:
            if "not found" in res.stderr.lower() or "not recognized" in res.stderr.lower():
                logger.debug("UFW CLI not found on host. Deleting rule in mock mode.")
            else:
                logger.warning("UFW delete returned error: %s", res.stderr)

        # 2. Remove from SQLite
        try:
            with self.db:
                self.db.execute("DELETE FROM firewall_rules WHERE id = ?;", (str(rule_id),))
            logger.info("Firewall rule ID %s deleted successfully.", rule_id)
            return True, f"Firewall rule for port {port_str}/{protocol} deleted successfully."
        except Exception as exc:
            err_msg = f"Failed to delete firewall rule ID {rule_id}: {exc}"
            logger.exception(err_msg)
            return False, err_msg

    def list_rules(self) -> List[Dict[str, Any]]:
        """Retrieve all recorded firewall rules from SQLite.

        Returns:
            List[Dict[str, Any]]: List of firewall rule dictionaries.
        """
        try:
            with self.db:
                records = self.db.fetch_all(
                    """
                    SELECT id, port, protocol, action, description, created_at
                    FROM firewall_rules
                    ORDER BY created_at DESC;
                    """
                )
                return records
        except Exception as exc:
            logger.error("Failed to fetch firewall rules: %s", exc)
            return []

    def get_rule(self, rule_id: Union[int, str]) -> Optional[Dict[str, Any]]:
        """Retrieve details of a single firewall rule by ID.

        Args:
            rule_id: Database rule ID.

        Returns:
            Optional[Dict[str, Any]]: Firewall rule dictionary or None.
        """
        try:
            with self.db:
                record = self.db.fetch_one(
                    """
                    SELECT id, port, protocol, action, description, created_at
                    FROM firewall_rules
                    WHERE id = ?;
                    """,
                    (str(rule_id),),
                )
                return record
        except Exception as exc:
            logger.error("Failed to get firewall rule ID %s: %s", rule_id, exc)
            return None
