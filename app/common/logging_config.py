import logging

from rich.console import Console
from rich.text import Text


class CompactLogFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        """Attach a compact module and line location to a log record.

        Args:
            record (logging.LogRecord): Record to annotate in place with location.

        Returns:
            bool: Always True so the annotated record is emitted.
        """
        module = ".".join(record.name.split(".")[-2:])
        if len(module) > 32: module = "…" + module[-31:]
        record.location = f"{module}:{record.lineno}"
        return True


class CompactRichHandler(logging.Handler):
    LEVEL_COLORS = {
        "DEBUG": "cyan",
        "INFO": "green",
        "WARNING": "yellow",
        "ERROR": "bold red",
        "CRITICAL": "bold white on red",
    }

    def __init__(self):
        """Initialize the Rich stderr console and timestamp formatter.

        Returns:
            None: No return value.
        """
        super().__init__()

        self.console = Console(
            stderr=True,
            force_terminal=None,
            color_system="auto",
            soft_wrap=True,
        )

        self.setFormatter(
            logging.Formatter(datefmt="%H:%M:%S")
        )

    def emit(self, record: logging.LogRecord):
        """Render one compact log line and any exception traceback.

        Args:
            record (logging.LogRecord): Record with a location supplied by
                CompactLogFilter.

        Returns:
            None: No return value.
        """
        try:
            timestamp = self.formatter.formatTime(record, "%H:%M:%S")
            level = record.levelname
            location = record.location
            message = record.getMessage()

            line = Text(no_wrap=True, overflow="ignore")

            line.append(f"{timestamp} ", style="dim")
            line.append(f"{level:<8} ", style=self.LEVEL_COLORS.get(level, "white"))
            line.append(f"{location:<38} ", style="cyan")
            line.append("| ", style="dim")
            line.append(message)

            self.console.print(line, soft_wrap=True, crop=False)

            if record.exc_info: self.console.print_exception(show_locals=False)

        except Exception:
            self.handleError(record)


def setup_logging(level: int = logging.INFO):
    """Replace root handlers with compact Rich logging and quiet noisy clients.

    Args:
        level (int): Root logging threshold; defaults to logging.INFO.

    Returns:
        None: No return value.
    """
    handler = CompactRichHandler()
    handler.addFilter(CompactLogFilter())
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level)
    root.addHandler(handler)

    for name in ("pika", "urllib3", "httpx"):
        logging.getLogger(name).setLevel(logging.WARNING)