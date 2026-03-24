import ipaddress
import re
from typing import Any

from lilya.conf import settings as lilya_settings
from pydantic import ValidationError
from pydantic_core import PydanticCustomError


def validate_network(value: Any) -> str:
    try:
        ip_addr = ipaddress.ip_address(value)
        if getattr(ip_addr, "ipv4_mapped", None):
            raise PydanticCustomError(
                "value_error",
                "Mapped ip4 addresses are forbidden. Use ip4 address instead.",
            )
        # skip further checks, as every ip is also a network
        return value
    except ValueError:
        pass
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise PydanticCustomError(
            "value_error",
            'Enter a valid IPv4 or IPv6 network or "*".',
        ) from None
    return value


def validate_regex(value: Any) -> str:
    try:
        re.compile(value)
    except re.error:
        raise PydanticCustomError(
            "value_error", "Invalid regex: {value}", {"value": value}
        ) from None
    return value


_path_regex = re.compile(r"^/[^?#]*/?$")


def validate_path(value: Any) -> str:
    if not _path_regex.match(value):
        raise PydanticCustomError(
            "value_error", "Invalid path: {value}", {"value": value}
        ) from None
    return value


def min_length_1(value: Any) -> str:
    if not len(value) >= 1:
        raise PydanticCustomError("value_error", "Minimum length is 1")
    return value


def validate_ratelimit_key(value: Any) -> str:
    min_length_1(value)
    splitted = value.split(":", 1)
    if splitted[0] == "django_fast_iprestrict.apply_iprestrict":
        raise ValidationError(
            "insecure",
            "Ratelimit key would cause infinite recursion: {value}",
            {"value": value},
        )
    path_parts = splitted[0].split(".")
    if not all(x.isidentifier() for x in path_parts):
        raise PydanticCustomError(
            "invalid_key_fn_path", "not a key function path: {value}.", {"value": value}
        )
    if path_parts[-1].startswith("_"):
        raise PydanticCustomError(
            "insecure_key_fn_path", "insecure key function path: {value}.", {"value": value}
        )

    for prefix in getattr(lilya_settings, "LILYA_WAF_ALLOWED_FN_PREFIXES", ()):
        if value.startswith(prefix):
            return value
    if not value.isidentifier():
        raise PydanticCustomError(
            "invalid_key_fn_path", "not a key function path: {value}.", {"value": value}
        )
    return value


def validate_generator_fn(value: str) -> None:
    min_length_1(value)
    splitted = value.split(":", 1)
    path_parts = splitted[0].split(".")
    if not all(x.isidentifier() for x in path_parts):
        raise PydanticCustomError(
            "invalid_generator_fn_path", "not a generate_fn path: {value}.", {"value": value}
        )
    if path_parts[-1].startswith("_"):
        raise PydanticCustomError(
            "insecure_generator_fn", "not a safe generate_fn: {value}.", {"value": value}
        )

    for prefix in getattr(lilya_settings, "LILYA_WAF_ALLOWED_FN_PREFIXES", ()):
        if value.startswith(prefix):
            return
    raise PydanticCustomError(
        "insecure_generator_fn", "not a safe generate_fn: {value}.", {"value": value}
    )


_rate = re.compile(r"(\d+)/(\d+)?([smhdw])?")


def validate_rate(value: Any) -> None:
    if value in {"inherit", "none"}:
        return
    matched = _rate.match(value)
    if not matched:
        raise PydanticCustomError("invalid_value", "Invalid rate: {value}", {"value": value})
