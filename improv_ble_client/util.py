"""Utility functions."""

from __future__ import annotations

import contextlib
from enum import Enum
from typing import Any, TypeVar

_EnumT = TypeVar("_EnumT", bound=Enum)


def try_parse_enum(cls: type[_EnumT], value: Any) -> _EnumT | None:
    """Try to parse the value into an Enum.

    Return None if parsing fails.
    """
    with contextlib.suppress(ValueError):
        return cls(value)
    return None
