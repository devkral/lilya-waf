from __future__ import annotations

import asyncio
import functools
import ipaddress
import time
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING, Any, Final, Literal, TypeVar, cast, overload

from lilya.exceptions import PermissionDenied
from lilya.requests import Connection

from ._epoch import reset_epoch

if TYPE_CHECKING:
    import edgy
    from aiocache import BaseCache


SCOPE_NAME = "real-clientip"

__all__ = [
    "Action",
    "invertedset",
    "ALL",
    "SAFE",
    "UNSAFE",
    "RatelimitResult",
    "RatelimitExceeded",
    "NoMatchingRatelimit",
    "MissingRate",
    "LockoutException",
    "parse_ip_to_net",
]

lilya_waf_connection: ContextVar[Connection] = ContextVar("lilya_waf_connection")
lilya_waf_registry: ContextVar[edgy.Registry | None] = ContextVar(
    "lilya_waf_registry", default=None
)

T_OBJ_TYPE = TypeVar("T_OBJ_TYPE", bound=object | None)
T_OBJ_TYPE2 = TypeVar("T_OBJ_TYPE2", bound=object | None)


class Action(IntEnum):
    PEEK = 1
    INCREASE = 2
    RESET = 3
    RESET_EPOCH = 4


@dataclass(slots=True, kw_only=True)
class RatelimitResult:
    group: str
    # limit is the amount after which request_limit triggers, inf when simply allowed
    limit: int
    count: int = 0
    # how many ratelimits with the same name did trigger
    request_limit: int = 0
    end: float = 0.0
    cache: BaseCache | None = field(default=None, compare=False, hash=False, repr=False)
    cache_key: str = field(default="", compare=False, hash=False, repr=False)

    async def check(self, wait: bool = False, block: bool = False) -> bool:
        if self.request_limit > 0:
            if wait and (remaining_dur := self.end - time.time()) > 0.0:
                await asyncio.sleep(remaining_dur)
            if block:
                raise RatelimitExceeded(ratelimit=self)
            return False
        return True

    @property
    def can_reset(self) -> bool:
        return bool(self.cache and self.cache_key)

    async def reset(self, epoch: None | int | object = None) -> int | None:
        if not self.can_reset:
            return None
        cache = cast("BaseCache", self.cache)
        if epoch is None:
            count: int | None = await cache.get(self.cache_key, 0)
            await asyncio.gather(
                *(cache.delete(x) for x in [self.cache_key, f"{self.cache_key}_expire"])
            )
            return count
        else:
            return await reset_epoch(epoch, cache, self.cache_key)

    def _decorate_intern(self, obj: object, name: str, replace: bool) -> RatelimitResult:
        if replace:
            setattr(obj, name, self)
            return self
        else:
            oldrlimit = getattr(obj, name, None)
            if oldrlimit != self:
                if not oldrlimit:
                    setattr(obj, name, self)
                elif bool(oldrlimit.request_limit) != bool(self.request_limit):
                    if self.request_limit:
                        setattr(obj, name, self)
                elif oldrlimit.end > self.end:
                    self.request_limit += oldrlimit.request_limit
                    setattr(obj, name, self)
                else:
                    # oldrlimit.end <= self.end
                    oldrlimit.request_limit += self.request_limit
            return getattr(obj, name)

    async def decorate_object_and_return_ratelimit(
        self,
        obj: T_OBJ_TYPE,
        *,
        name: str = "ratelimit",
        wait: bool = False,
        block: bool = False,
        replace: bool = False,
    ) -> RatelimitResult:
        # connection can be None, so use False
        # for decorate
        if not name or obj is None:
            await self.check(wait=wait, block=block)
            return self
        new_ratelimit = self._decorate_intern(obj=obj, name=name, replace=replace)
        await new_ratelimit.check(wait=wait, block=block)
        return new_ratelimit

    @overload
    async def decorate_object(
        self,
        obj: T_OBJ_TYPE,
        *,
        name: str = "ratelimit",
        wait: bool = False,
        block: bool = False,
        replace: bool = False,
    ) -> T_OBJ_TYPE: ...
    @overload
    async def decorate_object(
        self,
        obj: Literal[False] = False,
        *,
        name: str = "ratelimit",
        wait: bool = False,
        block: bool = False,
        replace: bool = False,
    ) -> Callable[[T_OBJ_TYPE2], T_OBJ_TYPE2]: ...

    async def decorate_object(
        self,
        obj: T_OBJ_TYPE | Literal[False] = False,
        *,
        name: str = "ratelimit",
        wait: bool = False,
        block: bool = False,
        replace: bool = False,
    ) -> Callable[[T_OBJ_TYPE2], T_OBJ_TYPE2] | T_OBJ_TYPE:
        # connection can be None, so use False
        if obj is False:
            return functools.partial(
                self.decorate_object,
                name=name,
                wait=wait,
                block=block,
                replace=replace,
            )
        await self.decorate_object_and_return_ratelimit(
            obj=obj, name=name, replace=replace, wait=wait, block=block
        )
        return obj


class invertedset(frozenset):
    """
    Inverts a collection
    """

    def __contains__(self, item: Any) -> bool:
        return not super().__contains__(item)


ALL: Final = invertedset()
SAFE: Final = frozenset(["GET", "HEAD", "OPTIONS"])
UNSAFE: Final = invertedset(SAFE)


class RatelimitExceeded(PermissionDenied):
    ratelimit = None

    def __init__(self, *args: Any, ratelimit: RatelimitResult) -> None:
        self.ratelimit = ratelimit
        super().__init__(*args)


class NoMatchingRatelimit(PermissionDenied):
    continue_fn: Callable[[], Awaitable[Any]] | None = None


class MissingRate(ValueError):
    pass


class LockoutException(Exception):
    pass


@functools.lru_cache(maxsize=256)
def parse_ip_to_net(
    ip: ipaddress.IPv6Network
    | ipaddress.IPv4Network
    | ipaddress.IPv6Address
    | ipaddress.IPv4Address
    | str,
) -> tuple[ipaddress.IPv6Network, bool]:
    _ip: ipaddress.IPv6Network | ipaddress.IPv4Network = ipaddress.ip_network(ip, strict=False)
    is_ipv4 = False
    if isinstance(_ip, ipaddress.IPv4Network):
        _ip = ipaddress.IPv6Network(f"::ffff:{_ip.network_address}/128", strict=False)
        is_ipv4 = True
    return _ip, is_ipv4
