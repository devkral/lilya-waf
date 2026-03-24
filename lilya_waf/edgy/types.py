from typing import Literal, NotRequired, Required, TypedDict


class ManagedRules(TypedDict):
    revision: Required[int]
    position: NotRequired[Literal["top", "bottom"]]
    managed_by: Required[tuple[str, bool]]
    name: Required[tuple[str, bool]]
    http_methods: NotRequired[tuple[str, bool]]
    note: NotRequired[tuple[str, bool]]
    ratelimit_cache: NotRequired[tuple[str, bool]]
    paths: NotRequired[tuple[list[dict[str, bool]], bool]]
    networks: NotRequired[tuple[list[dict[str, bool]], bool]]
    ratelimits: NotRequired[tuple[list[dict[str, bool]], bool]]
