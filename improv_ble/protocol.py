"""Models for the Improv via BLE protocol."""

from __future__ import annotations

from enum import IntEnum, IntFlag
import struct
from typing import Final, TypeVar

from .errors import InvalidCommand

SERVICE_UUID: Final = "00467768-6228-2272-4663-277478268000"
CHARACTERISTIC_UUID_CAPABILITIES: Final = "00467768-6228-2272-4663-277478268005"
CHARACTERISTIC_UUID_STATE: Final = "00467768-6228-2272-4663-277478268001"
CHARACTERISTIC_UUID_ERROR: Final = "00467768-6228-2272-4663-277478268002"
CHARACTERISTIC_UUID_RPC_COMMAND: Final = "00467768-6228-2272-4663-277478268003"
CHARACTERISTIC_UUID_RPC_RESULT: Final = "00467768-6228-2272-4663-277478268004"


class Capabilities(IntFlag):
    """State."""

    IDENTIFY = 1


class State(IntEnum):
    """State."""

    AUTHORIZATION_REQUIRED = 1
    AUTHORIZED = 2
    PROVISIONING = 3
    PROVISIONED = 4


class Error(IntEnum):
    """Error."""

    NO_ERROR = 0
    INVALID_RPC_PACKET = 1
    UNKNOWN_RPC_COMMAND = 2
    UNABLE_TO_CONNECT = 3
    NOT_AUTHORIZED = 4
    UNKNOWN_ERROR = 0xFF


STATE_MAP: dict[str, type[IntEnum | IntFlag]] = {
    CHARACTERISTIC_UUID_CAPABILITIES: Capabilities,
    CHARACTERISTIC_UUID_ERROR: Error,
    CHARACTERISTIC_UUID_STATE: State,
}


class Command:
    """Base class for commands."""

    cmd_id: int
    _format: str
    _len: int
    _strings: list[bytes]

    def __init__(self, strings: list[bytes]) -> None:
        """Initialize."""
        self._format = self._calc_format(strings)
        self._len = self._calc_len(strings)
        self._strings = strings

    def as_bytes(self) -> bytes:
        """Return serialized representation of the command."""
        return self._pack(self._strings)

    @classmethod
    def from_bytes(cls, data: bytes) -> Command:
        """Initialize from serialized representation of the command."""
        cls._validate(data)
        return cls(cls._extract_strings(data))

    @property
    def _header(self) -> bytes:
        """Return packed header."""
        return struct.pack("!BB", self.cmd_id, self._len)

    @staticmethod
    def _calc_checksum(data: bytes) -> int:
        """Calculate as simple sum checksum."""
        return sum(data) & 0xFF

    @classmethod
    def _calc_format(cls, strings: list[bytes]) -> str:
        if not strings:
            return ""
        fmt = "!"
        for string in strings:
            fmt += f"b{len(string)}s"
        return fmt

    @classmethod
    def _calc_len(cls, strings: list[bytes]) -> int:
        return struct.calcsize(cls._calc_format(strings))

    @classmethod
    def _extract_strings(cls, data: bytes) -> list[bytes]:
        pos = 2
        end = len(data) - 1
        strings = []
        while pos < end:
            str_len = data[pos]
            if pos + str_len > end:
                raise InvalidCommand("Invalid strings", data.hex())
            pos += 1
            strings.append(data[pos : pos + str_len])
            pos += str_len
        if pos != end:
            raise InvalidCommand("Invalid strings", data.hex())
        return strings

    def _pack(self, strings: list[bytes]) -> bytes:
        """Pack the command to bytes."""
        tmp: list[int | bytes] = []
        for string in strings:
            tmp.append(len(string))
            tmp.append(string)
        data = self._header + struct.pack(self._format, *tmp)
        return data + bytes([self._calc_checksum(data)])

    @classmethod
    def _validate(cls, data: bytes) -> None:
        """Raise if the data is not valid."""
        if len(data) < 3 or (len(data) - 3) != data[1]:
            raise InvalidCommand("Invalid length", data.hex())
        if hasattr(cls, "cmd_id") and data[0] != cls.cmd_id:
            raise InvalidCommand("Invalid cmd_id", data.hex())
        if data[-1] != cls._calc_checksum(data[:-1]):
            raise InvalidCommand("Invalid checksum", data.hex())
        strings = cls._extract_strings(data)
        if len(data) != 3 + cls._calc_len(strings):
            raise InvalidCommand("Invalid length", data.hex())


_CMD_T = TypeVar("_CMD_T", bound=Command)


class UnknownCommand(Command):
    """Unknown command."""

    def __init__(self, cmd_id: int, strings: list[bytes]):
        """Initialize."""
        super().__init__(strings)
        self.cmd_id = cmd_id

    def __str__(self) -> str:
        return f"{self.__class__.__name__} data: {self.as_bytes().hex()}"

    @classmethod
    def from_bytes(cls, data: bytes) -> UnknownCommand:
        """Initialize from serialized representation of the command."""
        cls._validate(data)
        return cls(data[0], cls._extract_strings(data))


class WiFiSettingsCmd(Command):
    """WiFi Settings Command."""

    cmd_id = 0x01

    def __init__(self, ssid: bytes, password: bytes) -> None:
        """Initialize."""
        super().__init__([ssid, password])
        self.ssid = ssid
        self.password = password

    def __str__(self) -> str:
        return (
            f"{self.__class__.__name__} ssid:{self.ssid.hex()}, password:"
            f"{self.password.hex()}"
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> WiFiSettingsCmd:
        """Initialize from serialized representation of the command."""
        cls._validate(data)
        strings = cls._extract_strings(data)
        return cls(strings[0], strings[1])

    @classmethod
    def _validate(cls, data: bytes) -> None:
        """Raise if the data is not valid."""
        super()._validate(data)
        if len(cls._extract_strings(data)) != 2:
            raise InvalidCommand("Invalid strings", data.hex())


class WiFiSettingsRes(Command):
    """WiFi Settings Response."""

    cmd_id = 0x01
    redirect_url: bytes | None

    def __init__(self, redirect_url: bytes | None, extra_strings: list[bytes]) -> None:
        """Initialize."""
        if redirect_url is not None:
            strings = [redirect_url] + extra_strings
        else:
            strings = extra_strings
        super().__init__(strings)
        self.redirect_url = redirect_url

    def __str__(self) -> str:
        url: str | None = None
        if self.redirect_url is not None:
            url = self.redirect_url.decode()
        return f"{self.__class__.__name__} url:'{url}'"

    @classmethod
    def from_bytes(cls, data: bytes) -> Command:
        """Initialize from serialized representation of the command."""
        cls._validate(data)
        strings = cls._extract_strings(data)
        redirect_url: bytes | None = None
        extra_strings: list[bytes] = []
        if strings:
            redirect_url = strings[0]
            extra_strings = strings[1:]
        return cls(redirect_url, extra_strings)


class IdentifyCmd(Command):
    """Identify Command."""

    cmd_id = 0x02

    def __init__(self) -> None:
        """Initialize."""
        super().__init__([])

    def __str__(self) -> str:
        return f"{self.__class__.__name__}"

    @classmethod
    def from_bytes(cls, data: bytes) -> IdentifyCmd:
        """Initialize from serialized representation of the command."""
        cls._validate(data)
        return cls()

    @classmethod
    def _validate(cls, data: bytes) -> None:
        """Raise if the data is not valid."""
        super()._validate(data)
        if len(cls._extract_strings(data)) != 0:
            raise InvalidCommand("Invalid strings", data.hex())


RESULT_TYPES: dict[int, type[Command]] = {
    0x01: WiFiSettingsRes,
}


def parse_result(data: bytes) -> Command:
    """Parse data and return Command."""
    if len(data) < 3 or (len(data) - 3) != data[1]:
        raise InvalidCommand("Invalid length", data.hex())

    if command_type := RESULT_TYPES.get(data[0]):
        tmp = command_type.from_bytes(data)
        return tmp

    return UnknownCommand.from_bytes(data)
