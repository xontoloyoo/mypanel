"""Terminal layout components including header, footer, and panel frames."""

import os
import platform
import sys
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# Configure console
console = Console()


def clear_screen() -> None:
    """Clear terminal screen in a cross-platform manner."""
    os.system("cls" if os.name == "nt" else "clear")


def render_header(
    title: str = "LIGHTWEIGHT LINUX CONTROL PANEL",
    subtitle: str = "v0.1-cli",
) -> Panel:
    """Render a styled header banner with system context.

    Args:
        title: Main panel header title.
        subtitle: Version or environment subtitle.

    Returns:
        Panel: Rendered Rich panel for the header.
    """
    node_name = platform.node() or "localhost"
    os_name = f"{platform.system()} {platform.release()}"

    header_text = Text()
    header_text.append("[*] ", style="bold yellow")
    header_text.append(title, style="bold cyan")
    header_text.append(f" [{subtitle}]", style="bold green")
    header_text.append("\n")
    header_text.append("Host: ", style="dim")
    header_text.append(node_name, style="bold white")
    header_text.append("  |  OS: ", style="dim")
    header_text.append(os_name, style="bold white")

    return Panel(
        header_text,
        border_style="cyan",
        expand=True,
        padding=(0, 1),
    )


def render_footer() -> Text:
    """Render concise navigation hints at the bottom of the screen.

    Returns:
        Text: Formatted navigation hints.
    """
    footer_text = Text()
    footer_text.append("[*] Use numbers to navigate  ", style="dim cyan")
    footer_text.append("[*] [0] Back / Exit  ", style="dim yellow")
    footer_text.append("[*] Ctrl+C to quit", style="dim red")
    return footer_text


def show_message(message: str, type: str = "info") -> None:
    """Display a notification banner panel.

    Args:
        message: Notification message text.
        type: Status type ('success', 'error', 'warning', 'info').
    """
    styles = {
        "success": ("bold green", "[SUCCESS]", "green"),
        "error": ("bold red", "[ERROR]", "red"),
        "warning": ("bold yellow", "[WARNING]", "yellow"),
        "info": ("bold cyan", "[INFO]", "cyan"),
    }

    style_tag, label, border = styles.get(type, ("bold cyan", "[INFO]", "cyan"))

    text = Text()
    text.append(f"{label} ", style=style_tag)
    text.append(message, style="white")

    panel = Panel(
        text,
        border_style=border,
        padding=(0, 1),
    )
    console.print(panel)
