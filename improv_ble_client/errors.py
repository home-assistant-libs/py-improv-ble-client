"""Exceptions."""
from __future__ import annotations

from typing import TYPE_CHECKING

from bleak.exc import BleakError
from bleak_retry_connector import BLEAK_RETRY_EXCEPTIONS as BLEAK_EXCEPTIONS

from .models import DisconnectReason

if TYPE_CHECKING:
    from .protocol import Error


class ImprovError(Exception):
    """Base class for exceptions."""


class Disconnected(ImprovError):
    """Raised when the connection is lost."""

    def __init__(self, reason: DisconnectReason):
        self.reason = reason
        super().__init__(reason.name)


class InvalidCommand(ImprovError):
    """Raised when a received command can't be parsed."""


class NotConnected(ImprovError):
    """Raised when connection is lost while sending a command."""


class ProvisioningFailed(ImprovError):
    """Raised when the device rejects a command."""

    def __init__(self, error: Error):
        self.error = error
        super().__init__(error.name)


class Timeout(BleakError, ImprovError):
    """Raised when am operation times out."""


class UnexpectedDisconnect(Disconnected, BleakError):
    """Raised when the connection is unexpectedly lost."""

    def __init__(self):
        super().__init__(DisconnectReason.UNEXPECTED)


IMPROV_EXCEPTIONS = (
    *BLEAK_EXCEPTIONS,
    Disconnected,
    InvalidCommand,
    ProvisioningFailed,
)
