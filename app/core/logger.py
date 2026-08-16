"""Centralized application logger writing to logs/app.log."""

import logging
from pathlib import Path

# Project root directory (cli-panel/)
BASE_DIR = Path(__file__).resolve().parent.parent.parent
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "app.log"

_configured = False


def _setup_root_logger() -> None:
    """Initialize root file handler and formatter for cli_panel loggers."""
    global _configured
    if _configured:
        return

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(
        fmt="[%(asctime)s] [%(levelname)s] [%(module)s]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = logging.FileHandler(LOG_FILE, encoding="utf-8")
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.DEBUG)

    panel_logger = logging.getLogger("cli_panel")
    panel_logger.setLevel(logging.DEBUG)

    if not panel_logger.handlers:
        panel_logger.addHandler(file_handler)

    _configured = True


def get_logger(name: str = "cli_panel") -> logging.Logger:
    """Get a configured logger instance for the given module or component name.

    Args:
        name: Module or component name identifier.

    Returns:
        logging.Logger: Configured logger instance.
    """
    _setup_root_logger()
    if name == "cli_panel" or name.startswith("cli_panel."):
        return logging.getLogger(name)
    return logging.getLogger(f"cli_panel.{name}")
