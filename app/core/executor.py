"""Command execution wrapper for bash and subprocess operations."""

from dataclasses import dataclass
import os
import subprocess
from typing import Sequence, Union

from app.core.logger import get_logger

logger = get_logger("executor")


@dataclass
class ExecutionResult:
    """Result of a shell command execution.

    Attributes:
        success: True if exit code was 0, False otherwise.
        stdout: Standard output string.
        stderr: Standard error string.
        returncode: Exit status code.
    """

    success: bool
    stdout: str
    stderr: str
    returncode: int

    @property
    def output(self) -> str:
        """Combined stdout and stderr or stdout if stderr is empty."""
        if self.stdout and self.stderr:
            return f"{self.stdout}\n{self.stderr}".strip()
        return self.stdout or self.stderr


class CommandExecutor:
    """Handles execution of system shell commands with logging and safety checks."""

    @staticmethod
    def is_root() -> bool:
        """Check if current process has root / superuser privileges."""
        try:
            return os.geteuid() == 0  # type: ignore[attr-defined]
        except AttributeError:
            # Windows / non-POSIX environment
            return False

    @classmethod
    def run(
        cls,
        cmd: Union[str, Sequence[str]],
        timeout: int = 60,
        check_root: bool = False,
    ) -> ExecutionResult:
        """Execute a shell command with timeout and error handling.

        Args:
            cmd: Command string or sequence of arguments.
            timeout: Maximum allowed execution time in seconds (default: 60).
            check_root: Whether to verify superuser privileges before running.

        Returns:
            ExecutionResult: Dataclass containing execution outcome and outputs.
        """
        cmd_str = cmd if isinstance(cmd, str) else " ".join(cmd)
        logger.debug("Executing command: %s", cmd_str)

        if check_root and hasattr(os, "geteuid") and not cls.is_root():
            error_msg = f"Root privilege required for command: {cmd_str}"
            logger.error(error_msg)
            return ExecutionResult(
                success=False,
                stdout="",
                stderr=error_msg,
                returncode=1,
            )

        try:
            use_shell = isinstance(cmd, str)
            process = subprocess.run(
                cmd,
                shell=use_shell,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding="utf-8",
                errors="replace",
            )

            stdout = process.stdout.strip()
            stderr = process.stderr.strip()
            success = process.returncode == 0

            if success:
                logger.debug("Command succeeded [code %s]: %s", process.returncode, cmd_str)
            else:
                logger.warning(
                    "Command failed [code %s]: %s | Error: %s",
                    process.returncode,
                    cmd_str,
                    stderr,
                )

            return ExecutionResult(
                success=success,
                stdout=stdout,
                stderr=stderr,
                returncode=process.returncode,
            )

        except subprocess.TimeoutExpired as exc:
            err_msg = f"Command timed out after {timeout} seconds: {cmd_str}"
            logger.error(err_msg)
            stdout_str = (
                exc.stdout.decode("utf-8", errors="replace").strip()
                if isinstance(exc.stdout, bytes)
                else (exc.stdout or "").strip()
            )
            stderr_str = (
                exc.stderr.decode("utf-8", errors="replace").strip()
                if isinstance(exc.stderr, bytes)
                else (exc.stderr or err_msg).strip()
            )
            return ExecutionResult(
                success=False,
                stdout=stdout_str,
                stderr=stderr_str,
                returncode=-1,
            )
        except Exception as exc:
            err_msg = f"Unexpected error executing command '{cmd_str}': {exc}"
            logger.exception(err_msg)
            return ExecutionResult(
                success=False,
                stdout="",
                stderr=err_msg,
                returncode=-1,
            )


def run_cmd(
    cmd: Union[str, Sequence[str]],
    timeout: int = 60,
    check_root: bool = False,
) -> ExecutionResult:
    """Helper function to execute a shell command via CommandExecutor."""
    return CommandExecutor.run(cmd=cmd, timeout=timeout, check_root=check_root)
