from __future__ import annotations

import asyncio
import base64
import functools
import hashlib
import re
import time
from collections.abc import Awaitable, Callable, Iterable, Sequence, Set
from functools import partial
from importlib import import_module
from inspect import isawaitable
from typing import TYPE_CHECKING, Any, Final, TypeVar, Unpack, cast, overload

from lilya.conf import settings as lilya_settings
from lilya.requests import Connection

from ._epoch import epoch_call_count, reset_epoch
from .misc import (
    ALL,
    Action,
    MissingRate,
    NoMatchingRatelimit,
    RatelimitResult,
    invertedset,
    lilya_waf_connection,
    lilya_waf_registry,
)
from .types import (
    _APPLY_RATELIMIT_INNER_KWARGS,
    APPLY_RATELIMIT_DB_KWARGS,
    APPLY_RATELIMIT_DB_KWARGS_DECORATOR,
    APPLY_RATELIMIT_FULL_KWARGS,
    APPLY_RATELIMIT_FULL_KWARGS_DECORATOR,
    APPLY_RATELIMIT_RULES_KWARGS,
    APPLY_RATELIMIT_RULES_KWARGS_DECORATOR,
    RatelimitProtocol,
    RuleProtocol,
    WafKeyFunction,
    _group_arg,
    _method_arg,
)

if TYPE_CHECKING:
    # too limited for now
    # from lilya.protocols.cache import CacheBackend
    import edgy
    from aiocache import BaseCache


_rate_regex: Final = re.compile(r"(\d+)/([0-9.]+)?([smhdw])?")

DECO_CALLABLE = TypeVar("DECO_CALLABLE", bound="Callable[..., Awaitable[Any]]")
DECO_APPLY_RATELIMITS_INPUT = TypeVar(
    "DECO_APPLY_RATELIMITS_INPUT",
    APPLY_RATELIMIT_DB_KWARGS_DECORATOR,
    APPLY_RATELIMIT_FULL_KWARGS_DECORATOR,
    APPLY_RATELIMIT_RULES_KWARGS_DECORATOR,
)


class _missing_rate_sentinel:
    pass


_missing_rate_tuple: Final = (_missing_rate_sentinel, 1)

_PERIOD_MAP: Final = {
    None: 1,  # second, fallback
    "s": 1,  # second
    "m": 60,  # minute
    "h": 3600,  # hour
    "d": 86400,  # day
    "w": 604800,  # week
}


# clear if you test multiple RATELAnyIMIT_GROUP_HASH definitions
@functools.lru_cache
def _get_group_hash(group: str, hashalgo: str = "sha256") -> str:
    return base64.b85encode(
        hashlib.new(
            hashalgo,
            group.encode("utf-8"),
        ).digest()
    ).decode("ascii")


def _get_cache_key(group: str, hashctx: Any) -> str:
    return "waf:{group}:{parts}".format(
        group=_get_group_hash(group),
        parts=base64.b85encode(hashctx.digest()).decode("ascii"),
    )


@functools.lru_cache(maxsize=1024)
def _parse_parts(rate: tuple, methods: frozenset, hashalgo: str) -> Any:
    hasher = hashlib.new(hashalgo, str(rate[1]).encode("utf-8"))

    if isinstance(methods, invertedset):
        hasher.update(b"i")
    else:
        hasher.update(b"n")
    hasher.update("".join(sorted(methods)).encode("utf-8"))

    return hasher


def _check_rate(
    fn: Callable[..., tuple[int, int | float]],
) -> Callable[..., tuple[int, int | float]]:
    @functools.wraps(fn)
    def _wrapper(*args: Any) -> tuple[int, int | float]:
        rate = fn(*args)
        if not (isinstance(rate, tuple) and len(rate) == 2 and rate[0] > 0 and rate[1] > 0):
            raise ValueError(f"invalid rate detected: {rate}, input: {args}")
        return rate

    return _wrapper


@functools.singledispatch
def parse_rate(rate: Any) -> tuple[int, int | float]:
    raise NotImplementedError


@parse_rate.register(str)
@functools.lru_cache
@_check_rate
def _(rate: str) -> tuple[int, int | float]:
    try:
        counter, _multiplier, period = cast("re.Match", _rate_regex.match(rate)).groups()
    except AttributeError:
        raise ValueError("invalid rate format") from None
    counter = int(counter)
    if _multiplier is None:
        multiplier = 1
    elif "." in _multiplier:
        multiplier = float(_multiplier)
    else:
        multiplier = int(_multiplier)
    return counter, multiplier * _PERIOD_MAP[period]


@parse_rate.register(list)
@_check_rate
def _(rate: list) -> tuple[int, int | float]:
    return tuple(rate)


@parse_rate.register(tuple)
@_check_rate
def _(rate: tuple) -> tuple[int, int | float]:
    return rate


@parse_rate.register(type(None))
def _(rate: None) -> tuple[int, int | float]:
    return _missing_rate_tuple  # type: ignore


def get_default_hash_algorithm() -> str:
    return getattr(lilya_settings, "LILYA_WAF_HASH_ALGORITHM", "sha256")


@functools.lru_cache(maxsize=64, typed=False)
def hardened_import_string(dotted_path: str) -> Any:
    """check also __all__ for intended imports"""
    module_path, fn_name = dotted_path.rsplit(".", 1)
    module = import_module(module_path)
    if hasattr(module, "__all__"):
        if fn_name not in module.__all__:
            raise ValueError(f"__all__ does not contain {fn_name}")
    elif fn_name.startswith("_"):
        raise ValueError("should not start with _ (except when in __all__)")
    return getattr(module, fn_name)


@functools.singledispatch
def _retrieve_key_func(
    key: Any,
) -> WafKeyFunction:
    raise ValueError("Key type is invalid")


@_retrieve_key_func.register(list)
@_retrieve_key_func.register(tuple)
def _(
    key: list | tuple,
) -> WafKeyFunction:
    if len(key) == 0:
        raise ValueError("key function could not be found")
    if callable(key[0]):
        fun = key[0]
    else:
        impname = f"lilya_waf.methods.{key[0]}" if "." not in key[0] else key[0]
        fun = hardened_import_string(impname)
    if len(key) > 1:
        return fun(*key[1:])
    if hasattr(fun, "dispatch"):
        fun = fun.dispatch(Connection)
    return fun


@_retrieve_key_func.register(str)
def _(
    key: str,
) -> WafKeyFunction:
    return _retrieve_key_func(key.split(":", 1))


_missing_sentinel = object()


def _require_obj(obj: Any, argument: str) -> Any:
    if obj is None:
        raise ValueError(f'Missing argument: "{argument}"')
    return obj


async def prepare_group(
    *, connection: Connection | None, action: Action, group: _group_arg
) -> str:
    if callable(group):
        group = group(connection, action)  # ty: ignore

    if isawaitable(group):
        group = await cast(Awaitable[str], group)
    _group = cast(str, group)
    if "," in _group or "*" in _group:
        raise ValueError("Group names cannot contain `,` or `*`")
    return _group


async def prepare_methods(
    *, connection: Connection | None, action: Action, group: str, methods: _method_arg
) -> Set[str]:
    if callable(methods):
        methods = methods(connection, group, action)  # ty: ignore

    if isawaitable(methods):
        methods = await methods
    assert connection or methods is ALL, "error: no connection but methods is not ALL"
    if isinstance(methods, str):
        methods = {methods}
    if not isinstance(methods, frozenset):
        methods = frozenset(cast(Iterable[str], methods))
    assert all(x.isupper() and isinstance(x, str) for x in methods), "error: method lowercase"
    return cast("Set[str]", methods)


def prepare_hash_context(
    *, rate: tuple[int, int | float], methods: Set[str], hash_algorithm: str
) -> Any:
    hashctx = _parse_parts(rate, methods, hash_algorithm).copy()
    return hashctx


async def _set_initial_key(
    *, cache: BaseCache, cache_key: str, cur_time: float, rate: tuple[int, int | float]
) -> bool:
    try:
        # raises ValueError when exist
        await cache.add(cache_key, 1, rate[1])
    except ValueError:
        return False
    await cache.set(f"{cache_key}_expire", cur_time + rate[1], rate[1])
    return True


async def _get_ratelimit(
    *,
    action: Action,
    _fail_count: int = 0,
    **kwargs: Unpack[_APPLY_RATELIMIT_INNER_KWARGS],
) -> RatelimitResult:
    """
    Get ratelimit information.
    """
    epoch = kwargs.get("epoch")
    connection = kwargs["connection"]
    key = kwargs["key"]
    rate = kwargs["rate"]
    empty_to = kwargs["empty_to"]
    hashctx = kwargs["hash_context"]
    group = kwargs["group"]
    cache = kwargs["cache"]
    if isinstance(key, (str, tuple, list)):
        key = _retrieve_key_func(key)

    if callable(key):
        key = cast(
            "WafKeyFunction",
            key,
        )(connection, group, action, None if rate is _missing_rate_tuple else rate)

    if isawaitable(key):
        key = await key

    if isinstance(key, str):
        key = key.encode("utf8")
    assert isinstance(empty_to, (bytes, int)), f"invalid type: {type(empty_to)}"

    if key == b"":
        key = empty_to

    # bool maps to int but make it future proof in case this changes
    assert key is True or isinstance(key, (bytes, int)), f"{key!r}: {type(key)}"
    # sidestep cache (bool maps to int)
    if key is not True and isinstance(key, int):
        return RatelimitResult(
            group=group,
            limit=rate[0],
            request_limit=key,
            end=time.time() + rate[1],
        )
    if rate[0] is _missing_rate_sentinel:
        raise MissingRate(
            "rate argument is missing or None and the key (function) doesn't sidestep cache"
        )
    # hash context is finished
    if key is not True:
        hashctx.update(key)

    cache_key = _get_cache_key(group, hashctx)
    expired = cast(float | None, await cache.get(f"{cache_key}_expire", None))
    is_expired = False
    # have some jitter yet, synchronize upcoming timestamps
    cur_time = time.time()
    if not expired or expired < cur_time:
        # something is in the cache
        if expired is not None:
            await asyncio.gather(*(cache.delete(x) for x in [cache_key, f"{cache_key}_expire"]))
        is_expired = True

    # use a fixed window counter algorithm
    if action == Action.INCREASE:
        epoch_call_count(epoch, cache_key)
        count: int = 1
        if not is_expired or not await _set_initial_key(
            cache=cache, cur_time=cur_time, rate=rate, cache_key=cache_key
        ):
            try:
                # incr does not extend cache duration
                count = cast(int, await cache.increment(cache_key))
            except ValueError as exc:
                # not in cache, but should be in cache, race condition
                if _fail_count >= 3:
                    raise ValueError("buggy cache or racing cache clear") from exc
                kwargs["key"] = key
                return await _get_ratelimit(
                    action=action,
                    **kwargs,
                    _fail_count=_fail_count + 1,
                )
    elif is_expired:
        # shortcut, we know the cache is now empty
        count = 0
    elif action == Action.RESET_EPOCH and epoch:
        count = cast(int, await cache.get(cache_key, default=0))
        await reset_epoch(epoch, cache, cache_key)
    else:
        count = cast(int, await cache.get(cache_key, default=0))
        if action == Action.RESET:
            await asyncio.gather(*(cache.delete(x) for x in [cache_key, f"{cache_key}_expire"]))

    return RatelimitResult(
        count=count,
        limit=rate[0],
        # block on race condition
        request_limit=1 if count > rate[0] else 0,
        end=cur_time + rate[1],
        group=group,
        cache=cache,
        cache_key=cache_key,
    )


async def apply_ratelimits(
    *,
    action: Action = Action.PEEK,
    **kwargs: (
        Unpack[APPLY_RATELIMIT_FULL_KWARGS]  # type: ignore
        | Unpack[APPLY_RATELIMIT_RULES_KWARGS]  # type: ignore
        | Unpack[APPLY_RATELIMIT_DB_KWARGS]  # type: ignore
    ),
) -> list[RatelimitResult]:
    if kwargs["connection"] == "retrieve":
        connection = lilya_waf_connection.get(None)
    else:
        connection = kwargs["connection"]
    if kwargs.get("epoch") is None:
        kwargs["epoch"] = connection
    hash_algorithm = get_default_hash_algorithm()
    if (
        kwargs.get("rules") is None
        and kwargs.get("cache") is None
        and kwargs.get("registry") is None
    ):
        kwargs.setdefault("registry", lilya_waf_registry.get(None))
    if registry := cast("edgy.Registry | None", kwargs.pop("registry", None)):
        assert kwargs.get("rules") is None, 'only one of "registry" or "rules"'
        async with registry:
            kwargs["rules"] = await cast(
                "type[RuleProtocol]", registry.get_model("WafRule")
            ).fetch_rules(connection)
    if (
        rules := cast(
            """Sequence[RuleProtocol]
        | Callable[[Connection | None], Sequence[RuleProtocol] | Awaitable[Sequence[RuleProtocol]]]
        | Awaitable[Sequence[RuleProtocol]]
        | None""",
            kwargs.pop("rules", None),
        )
    ) is not None:
        if callable(rules):
            rules = rules(connection)
        if isawaitable(rules):
            rules = await cast("Awaitable[Sequence[RuleProtocol]]", rules)
        # extract group first
        group = await prepare_group(connection=connection, action=action, group=kwargs["group"])
        all_ratelimits = []
        check_ops = []
        rlimits_seen: set[int] = set()
        for rule in cast("Sequence[RuleProtocol]", rules):
            # extract methods
            methods = rule.methods
            # shortcut when not matching
            if (connection and connection["method"] not in methods) or (
                not connection and methods is not ALL
            ):
                continue
            ratelimit_definitions = rule.get_ratelimits()
            if isawaitable(ratelimit_definitions):
                ratelimit_definitions = await ratelimit_definitions
            for ratelimit_def in cast("Sequence[RatelimitProtocol]", ratelimit_definitions):
                # only use ratelimits which group is matching
                if group not in ratelimit_def.groups:
                    continue
                rate = parse_rate(ratelimit_def.rate)
                hash_context = prepare_hash_context(
                    rate=rate, methods=methods, hash_algorithm=hash_algorithm
                )
                rlimit = await _get_ratelimit(
                    action=action,
                    group=group,
                    connection=connection,
                    rate=rate,
                    methods=methods,
                    cache=rule.cache,
                    key=ratelimit_def.key,
                    epoch=kwargs["epoch"],
                    hash_context=hash_context,
                    empty_to=b"",
                )
                rlimit = await rlimit.decorate_object_and_return_ratelimit(
                    kwargs["epoch"],
                    name=ratelimit_def.decorate_name,
                    replace=ratelimit_def.replace,
                )
                rlimit_id = id(rlimit)
                # idiom to not add ratelimits twice
                # when replaced, still the old ratelimit actions (block and wait) are executed
                if rlimit_id in rlimits_seen:
                    continue
                rlimits_seen.add(rlimit_id)
                all_ratelimits.append(rlimit)
                if ratelimit_def.wait or ratelimit_def.block:
                    check_ops.append(
                        rlimit.check(wait=ratelimit_def.wait, block=ratelimit_def.block)
                    )
            if rule.stop:
                break
        # no ratelimit found
        if not all_ratelimits:
            raise NoMatchingRatelimit()
        # collect exceptions to a an ExceptionGroup
        exceptions = []
        for result in await asyncio.gather(*check_ops, return_exceptions=True):
            if isinstance(result, Exception):
                exceptions.append(result)
            elif isinstance(result, BaseException):
                # interrupts raise instantly
                raise result
        if exceptions:
            raise ExceptionGroup("Some ratelimits raised", exceptions)

        return all_ratelimits
    else:
        rate = parse_rate(kwargs["rate"])
        group = await prepare_group(connection=connection, action=action, group=kwargs["group"])
        methods = await prepare_methods(
            connection=connection, group=group, action=action, methods=kwargs.pop("methods", ALL)
        )
        # shortcut allow
        if connection and connection["method"] not in methods:
            return [RatelimitResult(group=group, limit=rate[0])]
        if (hcontext := kwargs.get("hash_context")) is not None:
            # prevent corruption of cache keys
            hash_context = hcontext.copy()
        else:
            hash_context = prepare_hash_context(
                rate=rate, methods=methods, hash_algorithm=hash_algorithm
            )
        rlimit = await _get_ratelimit(
            action=action,
            group=group,
            connection=connection,
            rate=rate,
            methods=methods,
            empty_to=kwargs.get("empty_to", b""),
            hash_context=hash_context,
            epoch=kwargs.get("epoch"),
            prefix=kwargs.get("prefix", "waf:"),
            cache=kwargs["cache"],
            key=kwargs["key"],
        )
        try:
            rlimit = await rlimit.decorate_object_and_return_ratelimit(
                kwargs["epoch"],
                wait=kwargs.get("wait", False),
                block=kwargs.get("block", False),
                replace=kwargs.get("replace", False),
                name=kwargs.get("decorate_name", "False"),
            )
        except Exception as exc:
            raise ExceptionGroup("The ratelimit raised", [exc]) from None
        return [rlimit]


def o2g(obj: Any) -> str:
    """object to group name"""
    while True:
        if isinstance(obj, functools.partial):
            obj = obj.func
        elif hasattr(obj, "__func__"):
            obj = obj.__func__
        else:
            break
    if getattr(obj, "__module__", None):
        parts = [obj.__module__, obj.__qualname__]
    else:
        parts = [obj.__qualname__]
    result: str = ".".join(parts)
    assert "*" not in result and "," not in result, (
        "invalid object name, contains `,` or `*` (should not be possible)"
    )
    return result


def _prepare_context(context: APPLY_RATELIMIT_FULL_KWARGS_DECORATOR) -> None:
    if "methods" not in context:
        context["methods"] = ALL
    if not callable(context["methods"]):
        if isinstance(context["methods"], str):
            context["methods"] = {context["methods"]}
        if not isinstance(context["methods"], frozenset):
            context["methods"] = frozenset(cast(dict, context)["methods"])
    _rate = context.get("rate")
    if _rate is None:
        # we cannot use parse rate yet because of check_rate doesn't accept the sentinal
        context["rate"] = _rate
    elif not callable(_rate):
        # result is not callable too (tuple)
        context["rate"] = parse_rate(_rate)
    # rate is now set in context and can be used without issues
    if (
        "hashctx" not in context
        and context["rate"] is not None
        and not callable(context["methods"])
        and not callable(context["rate"])
    ):
        # internal copy for not polluting context
        context["hash_context"] = prepare_hash_context(
            rate=cast(Any, context["rate"]),
            methods=context["methods"],
            hash_algorithm=get_default_hash_algorithm(),
        )

    # prepare a hash for use in get_ratelimit
    if context.get("hash_context") and isinstance(context["key"], bytes):
        cast(dict, context)["hash_context"].update(context["key"])
        context["key"] = True
    if isinstance(context["key"], (str, tuple, list)):
        context["key"] = _retrieve_key_func(context["key"])


@overload
def decorate[DECO_CALLABLE, DECO_APPLY_RATELIMITS_INPUT](
    func: DECO_CALLABLE, /, **context: DECO_APPLY_RATELIMITS_INPUT
) -> DECO_CALLABLE: ...


@overload
def decorate[DECO_CALLABLE, DECO_APPLY_RATELIMITS_INPUT](
    func: None = None, /, **context: DECO_APPLY_RATELIMITS_INPUT
) -> Callable[[DECO_CALLABLE], DECO_CALLABLE]: ...


def decorate[DECO_CALLABLE, DECO_APPLY_RATELIMITS_INPUT](
    func: DECO_CALLABLE | None = None, /, **context: DECO_APPLY_RATELIMITS_INPUT
) -> DECO_CALLABLE | Callable[[DECO_CALLABLE], DECO_CALLABLE]:
    if "key" in context and "rate" in context and "cache" in context:
        _prepare_context(cast("APPLY_RATELIMIT_FULL_KWARGS_DECORATOR", context))

    def _decorate(fn: DECO_CALLABLE, /) -> DECO_CALLABLE:
        if context.get("group") is None:
            _context = context.copy()
            _context["group"] = o2g(fn)  # ty: ignore
        else:
            _context = context

        @functools.wraps(fn)  # ty: ignore
        async def _wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                await apply_ratelimits(
                    action=Action.INCREASE,
                    connection="retrieve",
                    **_context,
                )
            except NoMatchingRatelimit as exc:
                exc.continue_fn = partial(fn, *args, **kwargs)  # ty: ignore
                raise exc
            return await fn(*args, **kwargs)  # ty: ignore

        return cast("DECO_CALLABLE", _wrapper)

    if func:
        return _decorate(func)
    return _decorate


__all__ = ["decorate", "parse_rate", "o2g", "apply_ratelimits"]
