"""Improv via BLE client."""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Coroutine
from contextlib import suppress
from enum import Enum, IntEnum, IntFlag
import logging
from typing import Any, TypeVar, cast

from bleak import BleakClient
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from bleak.backends.service import BleakGATTServiceCollection
from bleak_retry_connector import (
    BleakClientWithServiceCache,
    establish_connection,
    retry_bluetooth_connection_error,
)

from . import protocol as prot
from .errors import (
    CharacteristicMissingError,
    Disconnected,
    ImprovError,
    InvalidCommand,
    NotConnected,
    NotSupported,
    ProvisioningFailed,
    Timeout,
    UnexpectedDisconnect,
)
from .models import DisconnectReason
from .protocol import (
    _CMD_T,
    CHARACTERISTIC_UUID_CAPABILITIES,
    CHARACTERISTIC_UUID_ERROR,
    CHARACTERISTIC_UUID_RPC_COMMAND,
    CHARACTERISTIC_UUID_RPC_RESULT,
    CHARACTERISTIC_UUID_STATE,
    IMPROV_CHARACTERISTICS,
    SERVICE_DATA_UUID,
    SERVICE_UUID,
    STATE_MAP,
    parse_result,
)
from .util import try_parse_enum

_LOGGER = logging.getLogger(__name__)

_T = TypeVar("_T")
_EnumT = TypeVar("_EnumT", bound=Enum)

DISCONNECT_DELAY = 90

DEFAULT_ATTEMPTS = 3


def device_filter(advertisement_data: AdvertisementData) -> bool:
    """Return True if the device is supported and ready to be provisioned."""
    uuids = advertisement_data.service_uuids
    service_data = advertisement_data.service_data
    if SERVICE_UUID not in uuids or SERVICE_DATA_UUID not in service_data:
        return False
    try:
        improv_service_data = prot.ImprovServiceData.from_bytes(
            service_data[SERVICE_DATA_UUID]
        )
    except InvalidCommand:
        return False
    return improv_service_data.state not in (
        prot.State.PROVISIONING,
        prot.State.PROVISIONED,
    )


class NotificationHandler:
    """Container for notification handlers."""

    error_callbacks: list[Callable[[prot.Error], None]]
    state_callbacks: list[Callable[[prot.State], None]]

    def __init__(self) -> None:
        """Initialize."""
        self.reset()

    def notify(self, state: prot.Error | prot.State) -> None:
        """Handle notification update."""
        if isinstance(state, prot.Error):
            for error_callback in self.error_callbacks:
                error_callback(state)
        else:
            for state_callback in self.state_callbacks:
                state_callback(state)

    def reset(self) -> None:
        """Reset."""
        self.error_callbacks = []
        self.state_callbacks = []

    def subscribe_error(
        self, callback: Callable[[prot.Error], None]
    ) -> Callable[[], None]:
        """Subscribe to error notifications."""

        def remove() -> None:
            with suppress(ValueError):
                self.error_callbacks.remove(callback)

        self.error_callbacks.append(callback)
        return remove

    def subscribe_state(
        self, callback: Callable[[prot.State], None]
    ) -> Callable[[], None]:
        """Subscribe to state notifications."""

        def remove() -> None:
            with suppress(ValueError):
                self.state_callbacks.remove(callback)

        self.state_callbacks.append(callback)
        return remove


class ImprovBLEClient:
    """Provision a device with support for Improv over BLE."""

    _key_holder_id: bytes | None = None
    _secret: bytes | None = None

    def __init__(
        self, ble_device: BLEDevice, advertisement_data: AdvertisementData | None = None
    ):
        """Initialize."""
        self._advertisement_data = advertisement_data
        self._background_tasks: set[asyncio.Task] = set()
        self._ble_device = ble_device
        self._capabilities: prot.Capabilities | None = None
        self._client: BleakClient | None = None
        self._notification_handlers = NotificationHandler()
        self._response_handlers: dict[int, asyncio.Future[prot.Command]] = {}
        self._connect_lock = asyncio.Lock()
        self._disconnect_reason: DisconnectReason | None = None
        self._disconnect_timer: asyncio.TimerHandle | None = None
        self._expected_disconnect = False
        self._procedure_lock = asyncio.Lock()
        self.loop = asyncio.get_running_loop()

    def set_ble_device_and_advertisement_data(
        self, ble_device: BLEDevice, advertisement_data: AdvertisementData
    ) -> None:
        """Set the ble device."""
        self._ble_device = ble_device
        self._advertisement_data = advertisement_data

    @property
    def address(self) -> str:
        """Get the address of the device."""
        return str(self._ble_device.address)

    @property
    def name(self) -> str:
        """Get the name of the device."""
        return str(self._ble_device.name or self._ble_device.address)

    @property
    def rssi(self) -> int | None:
        """Get the rssi of the device."""
        if self._advertisement_data:
            return self._advertisement_data.rssi
        return None

    @property
    def capabilities(self) -> prot.Capabilities:
        """Get the capabilities of the device.

        Only available after connection is established.
        """
        if self._capabilities is None:
            raise NotConnected
        return self._capabilities

    @property
    def can_identify(self) -> bool:
        """Return if the device supports identify."""
        return bool(
            self._capabilities and self._capabilities & prot.Capabilities.IDENTIFY
        )

    async def identify(self) -> None:
        """Identify the device."""
        _LOGGER.debug("%s: identify", self.name)
        if not self.can_identify:
            raise NotSupported

        async def _identify() -> None:
            await self.send_cmd(prot.IdentifyCmd())

        await self._execute(_identify)

    @property
    def can_get_device_info(self) -> bool:
        """Return if the device supports device info (v2.1)."""
        return bool(
            self._capabilities and self._capabilities & prot.Capabilities.DEVICE_INFO
        )

    async def get_device_info(self) -> prot.DeviceInfoRes:
        """Get device information (v2.1).

        Returns firmware name, version, hardware chip/variant, and device name.
        Does not require service authorization.
        """
        _LOGGER.debug("%s: get_device_info", self.name)
        if not self.can_get_device_info:
            raise NotSupported

        async def _get_device_info() -> prot.DeviceInfoRes:
            response_fut = self.receive_response(prot.DeviceInfoRes)
            await self.send_cmd(prot.DeviceInfoCmd())
            return await response_fut

        return await self._execute(_get_device_info)

    @property
    def can_scan_wifi(self) -> bool:
        """Return if the device supports WiFi scanning (v2.2)."""
        return bool(
            self._capabilities and self._capabilities & prot.Capabilities.SCAN_WIFI
        )

    async def scan_wifi(self) -> prot.ScanWifiRes:
        """Scan for available WiFi networks (v2.2).

        Returns list of networks with SSID, RSSI, and authentication type.
        """
        _LOGGER.debug("%s: scan_wifi", self.name)
        if not self.can_scan_wifi:
            raise NotSupported

        async def _scan_wifi() -> prot.ScanWifiRes:
            response_fut = self.receive_response(prot.ScanWifiRes)
            await self.send_cmd(prot.ScanWifiCmd())
            return await response_fut

        return await self._execute(_scan_wifi)

    @property
    def can_set_hostname(self) -> bool:
        """Return if the device supports hostname get/set (v2.3)."""
        return bool(
            self._capabilities and self._capabilities & prot.Capabilities.HOSTNAME
        )

    async def get_hostname(self) -> str:
        """Get device hostname (v2.3).

        Only available while device is in "Authorized" state.
        """
        _LOGGER.debug("%s: get_hostname", self.name)
        if not self.can_set_hostname:
            raise NotSupported

        async def _get_hostname() -> str:
            response_fut = self.receive_response(prot.HostnameRes)
            await self.send_cmd(prot.HostnameCmd())
            result = await response_fut
            return result.hostname.decode()

        return await self._execute(_get_hostname)

    async def set_hostname(self, hostname: str) -> str:
        """Set device hostname (v2.3).

        Hostname must conform to RFC 1123 and be limited to 255 characters.
        Only available while device is in "Authorized" state.
        Returns the hostname that was set.
        """
        _LOGGER.debug("%s: set_hostname: %s", self.name, hostname)
        if not self.can_set_hostname:
            raise NotSupported

        async def _set_hostname() -> str:
            response_fut = self.receive_response(prot.HostnameRes)
            await self.send_cmd(prot.HostnameCmd(hostname.encode()))
            result = await response_fut
            return result.hostname.decode()

        return await self._execute(_set_hostname)

    async def need_authorization(self) -> bool:
        """Return if the device needs authorization."""
        _LOGGER.debug("%s: need_authorization", self.name)

        async def _need_authorization() -> bool:
            state = await self.read_characteristic(CHARACTERISTIC_UUID_STATE)
            return state == prot.State.AUTHORIZATION_REQUIRED

        return await self._execute(_need_authorization)

    async def provision(
        self,
        ssid: str,
        password: str,
        state_callback: Callable[[prot.State], None] | None,
    ) -> str | None:
        """Provision the device.

        Returns the redirect url or None.
        """
        _LOGGER.debug("%s: provision ssid: %s, pw: %s", self.name, ssid, password)

        async def _provision() -> str | None:
            """Execute the procedure"""

            def handle_error(value: prot.Error) -> None:
                if value == prot.Error.NO_ERROR or error_fut.done():
                    return
                error_fut.set_result(value)

            def handle_state(state: prot.State) -> None:
                if state_callback:
                    state_callback(state)

            subscriptions = [
                self._notification_handlers.subscribe_error(handle_error),
                self._notification_handlers.subscribe_state(handle_state),
            ]
            error_fut: asyncio.Future[prot.Error] = self.loop.create_future()
            provisioned_fut = self.receive_response(prot.WiFiSettingsRes)

            try:
                await self.send_cmd(
                    prot.WiFiSettingsCmd(bytes(ssid, "utf-8"), bytes(password, "utf-8"))
                )

                done, pending = await asyncio.wait(
                    (error_fut, provisioned_fut),
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for future in pending:
                    future.cancel()
                if done.pop() is error_fut:
                    raise ProvisioningFailed(error_fut.result())

                if (redirect_url := provisioned_fut.result().redirect_url) is None:
                    return None
                return redirect_url.decode()
            finally:
                for unsub in subscriptions:
                    unsub()

        return await self._execute(_provision)

    async def subscribe_state_updates(
        self, state_callback: Callable[[prot.State], None]
    ) -> Callable[[], None]:
        """Subscribe to state updates.

        When subscribing, state_callback is be called with the current state
        If the device disconnects, state_callback is called with State.DISCONNECTED
        """
        _LOGGER.debug("%s: subscribe_state_updates", self.name)

        async def _subscribe_state_updates() -> Callable[[], None]:
            state = cast(
                prot.State,
                await self.read_characteristic(CHARACTERISTIC_UUID_STATE),
            )
            state_callback(state)
            return self._notification_handlers.subscribe_state(state_callback)

        return await self._execute(_subscribe_state_updates)

    @retry_bluetooth_connection_error(DEFAULT_ATTEMPTS)  # type: ignore[misc]
    async def _execute(self, procedure: Callable[[], Coroutine[Any, Any, _T]]) -> _T:
        """Execute a procedure."""
        if self._procedure_lock.locked():
            _LOGGER.debug(
                "%s: Procedure already in progress, waiting for it to complete; "
                "RSSI: %s",
                self.name,
                self.rssi,
            )
        async with self._procedure_lock:
            try:
                await self._ensure_connected()
                return await procedure()
            except asyncio.CancelledError as err:
                if self._disconnect_reason is None:
                    raise ImprovError from err
                if self._disconnect_reason == DisconnectReason.TIMEOUT:
                    raise Timeout from err
                if self._disconnect_reason == DisconnectReason.UNEXPECTED:
                    raise UnexpectedDisconnect from err
                raise Disconnected(self._disconnect_reason) from err
            except ImprovError:
                self._disconnect(DisconnectReason.ERROR)
                raise

    async def _ensure_connected(self) -> None:
        """Ensure connection to device is established."""
        if self._connect_lock.locked():
            _LOGGER.debug(
                "%s: Connection already in progress, waiting for it to complete; "
                "RSSI: %s",
                self.name,
                self.rssi,
            )
        if self._client and self._client.is_connected:
            self._reset_disconnect_timer()
            return
        async with self._connect_lock:
            # Check again while holding the lock
            if self._client and self._client.is_connected:
                self._reset_disconnect_timer()
                return
            _LOGGER.debug("%s: Connecting; RSSI: %s", self.name, self.rssi)
            client = await establish_connection(
                BleakClientWithServiceCache,
                self._ble_device,
                self.name,
                self._disconnected,
                use_services_cache=False,  # True
                ble_device_callback=lambda: self._ble_device,
            )
            _LOGGER.debug("%s: Connected; RSSI: %s", self.name, self.rssi)

            self._client = client

            # Make sure the device has all improv characteristics
            try:
                self._resolve_characteristics(client.services)
            except CharacteristicMissingError as err:
                _LOGGER.debug(
                    "%s: characteristic missing, clearing cache: %s; RSSI: %s",
                    self.name,
                    err,
                    self.rssi,
                    exc_info=True,
                )
                await client.clear_cache()
                self._cancel_disconnect_timer()
                await self._execute_disconnect_with_lock(DisconnectReason.ERROR)
                raise

            self._disconnect_reason = None
            self._reset_disconnect_timer()

            _LOGGER.debug(
                "%s: Subscribe to notifications; RSSI: %s", self.name, self.rssi
            )
            await client.start_notify(
                CHARACTERISTIC_UUID_ERROR, self._notification_handler
            )
            await client.start_notify(
                CHARACTERISTIC_UUID_RPC_RESULT, self._rpc_result_handler
            )
            await client.start_notify(
                CHARACTERISTIC_UUID_STATE, self._notification_handler
            )

            # Read capabilities from device
            self._capabilities = cast(
                prot.Capabilities,
                await self.read_characteristic(CHARACTERISTIC_UUID_CAPABILITIES),
            )
            _LOGGER.debug(
                "%s: Capabilities: %s; RSSI: %s",
                self.name,
                self._capabilities,
                self.rssi,
            )

    def _resolve_characteristics(self, services: BleakGATTServiceCollection) -> None:
        """Resolve characteristics."""
        for characteristic in IMPROV_CHARACTERISTICS:
            if not services.get_characteristic(characteristic):
                raise CharacteristicMissingError(characteristic)

    def _raise_if_not_connected(self) -> None:
        """Raise if the connection to device is lost."""
        if self._client and self._client.is_connected:
            self._reset_disconnect_timer()
            return
        raise NotConnected

    def _cancel_disconnect_timer(self):
        """Cancel disconnect timer."""
        if self._disconnect_timer:
            self._disconnect_timer.cancel()
            self._disconnect_timer = None

    def _reset_disconnect_timer(self) -> None:
        """Reset disconnect timer.

        If the disconnect timer expires, disconnect from the device.
        """

        async def _disconnect() -> None:
            """Execute disconnect request."""
            _LOGGER.debug(
                "%s: Disconnecting after timeout of %s",
                self.name,
                DISCONNECT_DELAY,
            )
            await self._execute_disconnect(DisconnectReason.TIMEOUT)

        def _schedule_disconnect() -> None:
            self._cancel_disconnect_timer()
            self._async_create_background_task(_disconnect())

        self._cancel_disconnect_timer()
        self._expected_disconnect = False
        self._disconnect_timer = self.loop.call_later(
            DISCONNECT_DELAY, _schedule_disconnect
        )

    def _disconnected(self, client: BleakClient) -> None:
        """Disconnected callback from Bleak."""
        if self._expected_disconnect:
            _LOGGER.debug(
                "%s: Disconnected from device; RSSI: %s", self.name, self.rssi
            )
            return
        _LOGGER.warning(
            "%s: Device unexpectedly disconnected; RSSI: %s",
            self.name,
            self.rssi,
        )
        self._client = None
        self._disconnect(DisconnectReason.UNEXPECTED)

    def _disconnect(self, reason: DisconnectReason) -> None:
        """Schedule disconnect from device."""
        self._async_create_background_task(self._execute_disconnect(reason))

    async def _execute_disconnect(self, reason: DisconnectReason) -> None:
        """Execute disconnection."""
        _LOGGER.debug("%s: Execute disconnect", self.name)
        if self._connect_lock.locked():
            _LOGGER.debug(
                "%s: Disconnect already in progress, waiting for it to complete; "
                "RSSI: %s",
                self.name,
                self.rssi,
            )
        async with self._connect_lock:
            await self._execute_disconnect_with_lock(reason)
        _LOGGER.debug("%s: Execute disconnect done", self.name)

    async def _execute_disconnect_with_lock(self, reason: DisconnectReason) -> None:
        """Execute disconnection."""
        assert self._connect_lock.locked(), "Lock not held"
        client = self._client
        self._client = None
        if client and client.is_connected:
            self._expected_disconnect = True
            await client.disconnect()
        self._reset(reason)

    def _reset(self, reason: DisconnectReason) -> None:
        """Reset."""
        _LOGGER.debug("%s: reset", self.name)
        self._capabilities = None
        self._notification_handlers.notify(prot.State.DISCONNECTED)
        self._notification_handlers.reset()
        for fut in self._response_handlers.values():
            fut.cancel()
        self._response_handlers = {}
        self._disconnect_reason = reason
        self._cancel_disconnect_timer()

    def _validate_state(
        self, characteristic_uuid: str, data: bytes
    ) -> IntEnum | IntFlag | None:
        if (
            len(data) != 1
            or (state := try_parse_enum(STATE_MAP[characteristic_uuid], data[0]))
            is None
        ):
            _LOGGER.warning(
                "Unexpected characteristic data %s:%s",
                characteristic_uuid,
                data.hex(),
            )
            return None
        return cast(IntEnum | IntFlag | None, state)

    async def _notification_handler(
        self, characteristic: BleakGATTCharacteristic, data: bytes
    ) -> None:
        self._reset_disconnect_timer()
        if (state := self._validate_state(characteristic.uuid, data)) is None:
            self._disconnect(DisconnectReason.INVALID_COMMAND)
            return
        _LOGGER.debug("Notification: %s: %s", characteristic.uuid, state.name)
        self._notification_handlers.notify(cast(prot.Error | prot.State, state))

    async def _rpc_result_handler(
        self, characteristic: BleakGATTCharacteristic, data: bytes
    ) -> None:
        """Notification handler."""
        self._reset_disconnect_timer()
        try:
            command = parse_result(data)
        except InvalidCommand as err:
            _LOGGER.warning("Received invalid command %s (%s)", err, data.hex())
            self._disconnect(DisconnectReason.INVALID_COMMAND)
            return
        _LOGGER.debug("RX: %s (%s)", command, data.hex())
        if fut := self._response_handlers.pop(command.cmd_id, None):
            if fut and not fut.done():
                fut.set_result(command)

    async def read_characteristic(self, characteristic_uuid: str) -> IntEnum | IntFlag:
        """Read characteristic."""
        self._raise_if_not_connected()
        assert self._client
        data = await self._client.read_gatt_char(characteristic_uuid)
        if (state := self._validate_state(characteristic_uuid, data)) is None:
            self._disconnect(DisconnectReason.INVALID_COMMAND)
            raise InvalidCommand
        return state

    async def send_cmd(self, command: prot.Command) -> None:
        """Send a command."""
        data = command.as_bytes()
        _LOGGER.debug("TX: %s (%s)", command, data.hex())

        self._raise_if_not_connected()
        assert self._client
        await self._client.write_gatt_char(CHARACTERISTIC_UUID_RPC_COMMAND, data, True)

    def receive_response(self, cmd: type[_CMD_T]) -> asyncio.Future[_CMD_T]:
        """Receive a response."""
        fut: asyncio.Future[_CMD_T] = self.loop.create_future()
        self._response_handlers[cmd.cmd_id] = cast(asyncio.Future[prot.Command], fut)
        return fut

    def _async_create_background_task(
        self, func: Coroutine[Any, Any, _T]
    ) -> asyncio.Task[_T]:
        """Create a background task and add it to the set of background tasks."""
        task = asyncio.create_task(func)
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)
        return task
