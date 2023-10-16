"""Models."""
from __future__ import annotations

from enum import Enum, auto


class DisconnectReason(Enum):
    """Disconnect reason."""

    ERROR = auto()
    INVALID_COMMAND = auto()
    TIMEOUT = auto()
    UNEXPECTED = auto()
