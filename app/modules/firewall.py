"""Firewall management module for UFW and port rule management."""

from typing import Any, Dict, List, Optional, Tuple, Union

from app.core.database import Database, get_db
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
            bool: True if port or range is valid, False otherwise.
        """
        port_str = str(port).strip()
        if not port_str:
            return False

        if ":" in port_str:
            # Port range e.g. "8000:8080"
            parts = port_str.split(":")
            if len(parts) != 2:
                return False
            try:
                start_p, end_p = int(parts[0]), int(parts[1])
                return 1 <= start_p <= 65535 and 1 <= end_p <= 65535 and start_p <= end_p
            except ValueError:
                return False

        try:
            p = int(port_str)
            return 1 <= p <= 65535
        except ValueError:
            return False

    def get_status(self) -> Dict[str, Any]:
        """Check status of UFW firewall and count recorded rules.

        Returns:
            Dict[str, Any]: Status dictionary containing active state and rules count.
        """
        res = run_cmd("ufw status")
        stdout_lower = res.stdout.lower()

        if "status: active" in stdout_lower:
            is_active = True
            status_text = "active"
        elif "status: inactive" in stdout_lower:
            is_active = False
            status_text = "inactive"
        else:
            if "not found" in res.stderr.lower() or "not recognized" in res.stderr.lower():
                status_text = "not-installed"
            else:
                status_text = "inactive"
            is_active = False

        rules = self.list_rules()
        return {
            "active": is_active,
            "status_text": status_text,
            "rules_count": len(rules),
        }

    def toggle_firewall(self, enable: bool = True) -> Tuple[bool, str]:
        """Enable or disable the UFW firewall.

        Args:
            enable: True to enable, False to disable.

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        action = "--force enable" if enable else "disable"
        res = run_cmd(f"ufw {action}", check_root=True)

        if not res.success:
            if "not found" in res.stderr.lower() or "not recognized" in res.stderr.lower():
                logger.debug("UFW CLI not found on host. Simulating state toggle.")
                return True, f"Firewall {'enabled' if enable else 'disabled'} (mock mode)"
            logger.error("Failed to toggle firewall: %s", res.stderr)
            return False, f"Failed to toggle firewall: {res.stderr}"

        msg = f"Firewall successfully {'enabled' if enable else 'disabled'}."
        logger.info(msg)
        return True, msg

    def add_rule(
        self,
        port: Union[str, int],
        protocol: str = "tcp",
        action: str = "allow",
        description: str = "",
    ) -> Tuple[bool, str]:
        """Add a new firewall rule to UFW and record in SQLite.

        Args:
            port: Single port or port range string.
            protocol: Protocol ('tcp', 'udp', or 'any').
            action: Action ('allow' or 'deny').
            description: Optional note / description for the rule.

        Returns:
            Tuple[bool, str]: (Success boolean, Status/error message).
        """
        port_str = str(port).strip()
        protocol = protocol.strip().lower()
        action = action.strip().lower()

        # 1. Validation
        if not self.validate_port(port_str):
            return False, f"Invalid port or port range: '{port_str}'. Must be 1-65535 or format 'start:end'."

        if protocol not in {"tcp", "udp", "any"}:
            return False, f"Invalid protocol: '{protocol}'. Choose 'tcp', 'udp', or 'any'."

        if action not in {"allow", "deny"}:
            return False, f"Invalid action: '{action}'. Choose 'allow' or 'deny'."

        # 2. Check duplicate rule in database
        try:
            with self.db:
                existing = self.db.fetch_one(
                    """
                    SELECT id FROM firewall_rules
                    WHERE port = ? AND protocol = ? AND action = ?;
                    """,
                    (port_str, protocol, action),
                )
                if existing:
                    return False, f"Rule for port '{port_str}' ({protocol} - {action}) already exists."
        except Exception as exc:
            logger.error("Database query failed: %s", exc)

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
            with self.db:
                self.db.execute(
                    """
                    INSERT INTO firewall_rules (port, protocol, action, description)
                    VALUES (?, ?, ?, ?);
                    """,
                    (port_str, protocol, action, description),
                )
            logger.info("Firewall rule added: %s %s/%s (%s)", action, port_str, protocol, description)
            return True, f"Firewall rule for port {port_str}/{protocol} ({action}) added successfully."
        except Exception as exc:
            err_msg = f"Failed to record firewall rule: {exc}"
            logger.exception(err_msg)
            return False, err_msg

    def delete_rule(self, rule_id: int) -> Tuple[bool, str]:
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
                self.db.execute("DELETE FROM firewall_rules WHERE id = ?;", (rule_id,))
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
                    ORDER BY id DESC;
                    """
                )
                return records
        except Exception as exc:
            logger.error("Failed to fetch firewall rules: %s", exc)
            return []

    def get_rule(self, rule_id: int) -> Optional[Dict[str, Any]]:
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
                    (rule_id,),
                )
                return record
        except Exception as exc:
            logger.error("Failed to get firewall rule ID %s: %s", rule_id, exc)
            return None
