import asyncio
import time
import typing

from ..tl import functions, types

if typing.TYPE_CHECKING:
    from .telegramclient import TelegramClient


def _json_to_native(value):
    if isinstance(value, types.JsonObject):
        return {item.key: _json_to_native(item.value) for item in value.value}
    if isinstance(value, types.JsonArray):
        return [_json_to_native(item) for item in value.value]
    if isinstance(value, (types.JsonString, types.JsonNumber, types.JsonBool)):
        return value.value
    return None


class AppConfig:
    def __init__(self, client: "TelegramClient", ttl: float = 3600):
        self._client = client
        self._ttl = ttl
        self._hash = 0
        self._data = {}
        self._last_fetch = 0.0

    async def get(self, *, force: bool = False) -> dict:
        if self._client._mb_entity_cache.self_bot:
            return self._data

        now = time.monotonic()
        if not force and self._data and now - self._last_fetch < self._ttl:
            return self._data

        result = await self._client(functions.help.GetAppConfigRequest(hash=self._hash))
        self._last_fetch = now
        if not isinstance(result, types.help.AppConfigNotModified):
            self._hash = result.hash
            self._data = _json_to_native(result.config)

        return self._data

    async def _refresh_loop(self):
        try:
            if await self._client.is_bot():
                return
        except (ConnectionError, asyncio.CancelledError):
            return
        except Exception:
            pass

        while self._client.is_connected():
            try:
                await self.get(force=True)
            except (ConnectionError, asyncio.CancelledError):
                return
            except Exception:
                self._client._log[__name__].exception(
                    "Unhandled exception while refreshing the app config"
                )

            try:
                await asyncio.wait_for(self._client.disconnected, timeout=self._ttl)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                return
            except Exception:
                continue

    def __await__(self):
        return self.get().__await__()

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        try:
            return self._data[name]
        except KeyError:
            raise AttributeError(name)
