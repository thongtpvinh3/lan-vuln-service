from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


@dataclass
class BaseEvent:
    event: str
    scan_id: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    message_id: str = field(default_factory=lambda: str(uuid4()))
    schema_version: int = 1
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"))

    def to_dict(self) -> dict:
        """Serialize all event dataclass fields into a dictionary.

        Returns:
            dict: Event envelope including IDs, timestamp, schema version, and data.
        """
        return asdict(self)
