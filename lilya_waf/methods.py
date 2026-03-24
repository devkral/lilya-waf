from __future__ import annotations

import functools
import ipaddress
from collections.abc import Callable, Generator
from ipaddress import IPv6Network
from typing import TYPE_CHECKING, Any, Literal, cast

from lilya.requests import Connection

from .misc import SCOPE_NAME, Action, parse_ip_to_net

if TYPE_CHECKING:
    from .types import WafKeyFunction

__all__ = [
    "user_or_ip",
    "user_and_ip",
    "ip",
    "user",
    "get",
    "ip_exempt_user",
    "user_or_ip_exempt",
    "static",
    "allow",
    "reject",
]


def _ip_to_net(
    args: Literal[True] | None | str | list | tuple = None,
) -> Callable[[Connection], IPv6Network]:
    if not args or args is True:
        args = (128,)

    if isinstance(args, str):
        args = args.split("/")
    _args = cast(tuple[int, int], tuple(map(int, args)))
    del args
    assert len(_args) <= 2
    if len(_args) == 1:
        assert _args[0] >= 0
        assert _args[0] <= 128

        def _(connection: Connection, /) -> IPv6Network:
            net, is_ipv4 = parse_ip_to_net(connection.scope.get(SCOPE_NAME))
            return net.supernet(new_prefix=_args[0])

        return _

    else:
        # list
        assert _args[0] >= 0
        assert _args[0] <= 32
        assert _args[1] >= 0
        assert _args[1] <= 128

        def _(connection: Connection, /) -> ipaddress.IPv6Network:
            net, is_ipv4 = parse_ip_to_net(connection.scope.get(SCOPE_NAME))
            if is_ipv4:
                return net.supernet(new_prefix=96 + _args[0])

            else:
                return net.supernet(new_prefix=_args[1])

        return _


_ip_to_net_single = _ip_to_net()


def _get_user_identifier_as_str_or_none(connection: Connection | None, /) -> str | None:
    if not (_con := getattr(connection, "user", None)):
        return None

    if _con.user.is_authenticated and (identifier := _con.user.unique_identifier):
        return f"user:{identifier}"
    return None


@functools.singledispatch
def static(
    connection: Connection | None,
    group: str,
    action: Action,
    rate: tuple[int, int | float] | None,
    /,
    key: bytes | int = b"static",
) -> bytes | int:
    return key


allow = functools.partial(static, key=0)
reject = functools.partial(static, key=1)


@static.register(int)  # type: ignore
def _(key: int) -> WafKeyFunction:
    return functools.partial(static.dispatch(Connection), key=key)  # type: ignore


@static.register(str)
@static.register(bytes)  # type: ignore
def _(key: str | bytes) -> WafKeyFunction:
    if not isinstance(key, bytes):
        key = str(key).encode("utf8")
    return functools.partial(static.dispatch(Connection), key=key)  # type: ignore


@functools.singledispatch
def user_or_ip(
    connection: Connection | None,
    group: str,
    action: Action,
    rate: tuple[int, int | float] | None,
    /,
    ip_fn: Callable[[Connection], ipaddress.IPv6Network] = _ip_to_net_single,
) -> str | int:
    user = _get_user_identifier_as_str_or_none(connection)
    if user:
        return user
    if connection is None:
        return 1
    net = ip_fn(connection)
    return net.exploded


@user_or_ip.register(str)
@user_or_ip.register(list)
@user_or_ip.register(tuple)  # type: ignore
def _(netmask: str | list | tuple, /) -> WafKeyFunction:
    ip_fn = _ip_to_net(netmask)

    return cast("WafKeyFunction", functools.partial(user_or_ip.dispatch(Connection), ip_fn=ip_fn))


@functools.singledispatch
def user_or_ip_exempt(
    connection: Connection | None,
    group: str,
    action: Action,
    rate: tuple[int, int | float] | None,
    /,
    ip_fn: Callable[[Connection], IPv6Network] = _ip_to_net_single,
    user_ok: bool = False,
    use_user_pk: bool = True,
    invert: bool = False,
) -> str | int:
    if connection is None:
        return 1
    if (
        connection.user
        is not None
        == user_ok
        != bool(action in {Action.RESET, Action.RESET_EPOCH})
    ) != invert:
        return 0
    if use_user_pk:
        user = _get_user_identifier_as_str_or_none(connection)
        if user:
            return user
    net = ip_fn(connection)
    if not net:
        # block
        return 1
    return net.exploded


@user_or_ip_exempt.register(str)
@user_or_ip_exempt.register(list)
@user_or_ip_exempt.register(tuple)  # type: ignore
def _(args: str | list | tuple) -> WafKeyFunction[str | int]:
    if isinstance(args, str):
        args = args.split(",")
    netmask: str | Literal[True] | tuple = True
    permissions = []
    flags = set()
    for arg in args:
        if isinstance(arg, str):
            if arg.startswith("netmask:"):
                netmask = arg.split(":", 1)[-1]
            elif arg.startswith("permission:"):
                permissions.append(arg.split(":", 1)[-1])
            else:
                flags.add(arg.lower())
        elif isinstance(arg, (tuple, list)) and len(arg) >= 2:
            if arg[0] == "netmask":
                netmask = tuple(arg[1:])
            elif arg[0] == "permission":
                permissions.extend(arg[1:])
    if "not_use_ip" in flags:
        assert netmask is True, "setting netmask despite not using ip"

        def ip_fn(connection: Connection, /) -> None | ipaddress.IPv6Network:
            return None
    else:
        ip_fn = _ip_to_net(netmask)
    return cast(
        "WafKeyFunction",
        functools.partial(
            user_or_ip_exempt.dispatch(Connection),
            ip_fn=ip_fn,
            permissions=permissions,
            user_ok="user_ok" in flags,
            use_user_pk="not_use_user_pk" not in flags,
            invert="invert" in flags,
        ),
    )


ip_exempt_user = functools.singledispatch(
    cast(
        "WafKeyFunction[str | int] | Callable[..., WafKeyFunction[str | int]]",
        functools.partial(
            user_or_ip_exempt.dispatch(Connection),
            user_ok=True,
            use_user_pk=False,
        ),
    )
)


@ip_exempt_user.register(str)
@ip_exempt_user.register(list)
@ip_exempt_user.register(tuple)
def _(args: str | list | tuple) -> WafKeyFunction[str | int]:
    if isinstance(args, str):
        args = args.split(",")
    netmask = True
    invert = False
    for arg in args:
        if arg in {"true", "false"}:
            invert = arg == "true"
        else:
            netmask = arg
    ip_fn = _ip_to_net(netmask)
    return cast(
        "WafKeyFunction[str | int]",
        functools.partial(
            user_or_ip_exempt.dispatch(Connection),
            user_ok=True,
            use_user_pk=False,
            ip_fn=ip_fn,
            invert=invert,
        ),
    )


@functools.singledispatch
def get(
    _noarg: Any, group: str, action: Action, rate: tuple[int, int | float] | None
) -> WafKeyFunction[str]:
    raise ValueError("invalid argument")


@get.register(dict)
def _(config: dict) -> WafKeyFunction[str]:
    headers = set(config.get("HEADER", []))
    netmask = config.get("IP")
    # ipv4, ipv6, default ipv6 (ipv4 is too fragmented)
    if "REMOTE_ADDR" in headers:
        headers.remove("REMOTE_ADDR")
        if not netmask:
            netmask = True
    ip_fn = None
    if netmask:
        ip_fn = _ip_to_net(netmask)

    headers = sorted(headers)
    session_keys = sorted(set(config.get("SESSION", [])))
    get_set = set(config.get("GET", []))
    check_user = config.get("USER", False)
    assert isinstance(check_user, bool), "USER can only be boolean"

    def _generate_key(connection: Connection) -> Generator[str]:
        if ip_fn:
            ip = ip_fn(connection)
            yield ip.exploded
        if check_user:
            user = _get_user_identifier_as_str_or_none(connection)
            if user:
                yield f"u={user}"
        for arg in session_keys:
            if session_val := connection.session.get(arg):
                yield f"s={arg}:{connection.session[session_val]}"
        for arg in headers:
            if header := connection.session.get(arg):
                yield f"h={arg}:{header}"
        for arg in get_set:
            if param := connection.query_params.get(arg):
                yield f"g={arg}:{param}"

    if check_user:
        return lambda connection, group, action, rate: "".join(_generate_key(connection))
    else:
        return lambda connection, group, action, rate: "".join(_generate_key(connection))


@get.register(str)
def _(*args: Any) -> WafKeyFunction[str]:
    if len(args) == 1:
        args = args[0].split(",")
    g = {
        "IP": False,
        "USER": False,
        "SESSION": [],
        "HEADER": [],
        "GET": [],
    }
    for arg in args:
        # split argument in list
        s = arg if isinstance(arg, (tuple, list)) else str(arg).split(":", 1)
        uppername = s[0].upper()
        value = s[1] if len(s) > 1 else None
        if uppername in {"IP", "USER"}:
            g[uppername] = True if value is None else value
        elif uppername in {"SESSION", "HEADER", "GET, POST"}:
            # can be None
            cast(list[str | None], g[uppername]).append(value)
        elif value:
            raise ValueError(f"This key does not exist: {uppername}.")
    return get(g)


user_and_ip = functools.singledispatch(
    cast(
        "WafKeyFunction[str | int] | Callable[..., WafKeyFunction[str]]",
        get({"IP": True, "USER": True}),
    )
)


@user_and_ip.register(str)
def _(netmask: str, /) -> WafKeyFunction[str]:
    return get({"IP": netmask, "USER": True})


user = get({"USER": True})


ip = functools.singledispatch(
    cast("WafKeyFunction[str] | Callable[..., WafKeyFunction[str]]", get({"IP": True}))
)


@ip.register(str)
@ip.register(list)
@ip.register(tuple)
def _(netmask: str | tuple | list) -> WafKeyFunction[str]:
    return get({"IP": netmask})
