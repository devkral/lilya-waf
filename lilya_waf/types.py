from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable, Sequence, Set
from typing import (
    TYPE_CHECKING,
    Any,
    Literal,
    NotRequired,
    Protocol,
    Required,
    Self,
    TypedDict,
    TypeVar,
)

if TYPE_CHECKING:
    import edgy
    from aiocache import BaseCache
    from lilya.requests import Connection
    from lilya.types import ASGIApp

    from .misc import Action

key_type = str | tuple | list | bytes | int | Literal[True]
rate_type = str | tuple[int, int | float] | list

key_out_type = TypeVar(
    "key_out_type",
    bytes,
    int,
    Literal[True],
    str,
    Awaitable[bytes | int | Literal[True] | str],
    covariant=True,
)


class WafKeyFunction(Protocol[key_out_type]):
    @staticmethod
    def __call__(
        _connection: Connection | None,
        _group: str,
        _action: Action,
        _rate: tuple[int, int | float] | None,
        /,
    ) -> key_out_type: ...


class WafASGIWrapper(Protocol):
    def __call__(
        self,
        app: ASGIApp,
        /,
    ) -> ASGIApp: ...

    registry: edgy.Registry | None


type _key_arg = """(
    key_type
    | Awaitable[key_type]
    | WafKeyFunction
)"""
type _group_arg = """(
    str | Awaitable[str] | Callable[[Connection | None, Action], Awaitable[str] | str]
)"""
type _rate_arg = """(
    None
    | rate_type
)"""
type _method_arg = """(
str
| Iterable[str]
| Callable[
    [Connection | None, str, Action], Iterable[str] | str | Awaitable[Iterable[str] | str]
])"""


class RatelimitProtocol(Protocol):
    key: str
    rate: str
    decorate_name: str
    replace: bool
    wait: bool
    block: bool
    groups: Set[str]


class RuleProtocol(Protocol):
    stop: bool
    methods: Set[str]
    cache: BaseCache

    @classmethod
    async def fetch_rules(cls, connection: Connection | None, /) -> Sequence[Self]:
        """Return effective rules in right position."""
        ...

    def get_ratelimits(
        self,
    ) -> Iterable[RatelimitProtocol] | Awaitable[Iterable[RatelimitProtocol]]: ...


class APPLY_RATELIMIT_RULES_KWARGS_DECORATOR(TypedDict):
    epoch: NotRequired[int | object | None]
    group: NotRequired[_group_arg | None]
    rules: Required[
        Sequence[RuleProtocol]
        | Awaitable[Sequence[RuleProtocol]]
        | Callable[[Connection | None], Sequence[RuleProtocol] | Awaitable[Sequence[RuleProtocol]]]
    ]


class APPLY_RATELIMIT_RULES_KWARGS(TypedDict):
    connection: Required[Connection | None | Literal["retrieve"]]
    epoch: NotRequired[int | object | None]
    group: Required[_group_arg]
    rules: Required[
        Sequence[RuleProtocol]
        | Awaitable[Sequence[RuleProtocol]]
        | Callable[[Connection | None], Sequence[RuleProtocol] | Awaitable[Sequence[RuleProtocol]]]
    ]


class APPLY_RATELIMIT_DB_KWARGS_DECORATOR(TypedDict):
    epoch: NotRequired[int | object | None]
    group: NotRequired[_group_arg | None]
    registry: NotRequired[edgy.Registry]


class APPLY_RATELIMIT_DB_KWARGS(TypedDict):
    connection: Required[Connection | None | Literal["retrieve"]]
    epoch: NotRequired[int | object | None]
    group: Required[_group_arg]
    registry: NotRequired[edgy.Registry]


class _APPLY_RATELIMIT_INNER_KWARGS(TypedDict):
    empty_to: Required[bytes | int]
    connection: Required[Connection | None]
    epoch: Required[int | object]
    group: Required[str]
    rate: Required[tuple[int, int | float]]
    cache: Required[BaseCache]
    key: Required[_key_arg]
    hash_context: Required[Any]


class _APPLY_RATELIMIT_FULL_KWARGS_BASE(TypedDict):
    empty_to: NotRequired[bytes | int]
    epoch: NotRequired[int | object | None]
    cache: Required[BaseCache | str]
    methods: NotRequired[_method_arg]
    rate: Required[_rate_arg]
    key: Required[_key_arg]
    hash_context: NotRequired[Any | None]
    decorate_name: NotRequired[str]
    replace: NotRequired[bool]
    wait: NotRequired[bool]
    block: NotRequired[bool]


class APPLY_RATELIMIT_FULL_KWARGS_DECORATOR(_APPLY_RATELIMIT_FULL_KWARGS_BASE):
    group: NotRequired[_group_arg | None]


class APPLY_RATELIMIT_FULL_KWARGS(_APPLY_RATELIMIT_FULL_KWARGS_BASE):
    connection: Required[Connection | None | Literal["retrieve"]]
    group: Required[_group_arg]
