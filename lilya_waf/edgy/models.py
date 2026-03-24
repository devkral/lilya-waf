# ty: ignore[invalid-assignment]

from __future__ import annotations

import ipaddress
import re
from collections.abc import Awaitable, Mapping
from functools import cached_property
from typing import TYPE_CHECKING, Annotated, Any, ClassVar, Self, cast

import aiocache
import edgy
from monkay import load
from pydantic import AfterValidator
from sqlalchemy import bindparam, sql

from lilya_waf.types import RatelimitProtocol

from ..misc import ALL, parse_ip_to_net
from .utils import validate_network

if TYPE_CHECKING:
    from lilya.requests import Connection
    from sqlalchemy.engine.interfaces import Connection as SQLAConnection

    from .types import ManagedRules


class MaybeManaged(edgy.Model):
    managed_name: str | None = edgy.CharField(max_length=50, null=True, default=None)

    class Meta:
        abstract = True


class ActivatableWithNote(edgy.Model):
    is_active: bool = edgy.BooleanField(blank=True, default=True)
    note: str = edgy.TextField(default="")

    class Meta:
        abstract = True


class WafRuleRatelimit(MaybeManaged, ActivatableWithNote):  # type: ignore
    rule = edgy.ForeignKey("WafRule", related_name="ratelimits", on_delete=edgy.CASCADE)
    key: str = edgy.TextField()
    rate: str = edgy.CharField(max_length=20)
    decorate_name: str = edgy.CharField(max_length=50, default="")
    matching_groups: str = edgy.CharField(max_length=100, default="*")
    block: bool = edgy.BooleanField(default=False)
    wait: bool = edgy.BooleanField(default=False)
    replace: bool = edgy.BooleanField(default=False)

    @cached_property
    def groups(self) -> frozenset[str]:
        if "*" in self.matching_groups:
            return ALL
        return frozenset(self.matching_groups.split(","))


class WafRulePath(MaybeManaged, ActivatableWithNote):  # type: ignore
    rule = edgy.ForeignKey("WafRule", related_name="paths", on_delete=edgy.CASCADE)
    path: str = edgy.TextField()
    is_regex: bool = edgy.BooleanField(default=False)

    def __str__(self) -> str:
        return self.path

    @cached_property
    def processed_path(self) -> str:
        return self.path if self.is_regex else re.escape(self.path)


class WafRuleNetwork(MaybeManaged, ActivatableWithNote):  # type: ignore
    rule = edgy.ForeignKey("WafRule", related_name="networks", on_delete=edgy.CASCADE)
    network: Annotated[str, AfterValidator(validate_network)] = edgy.CharField(max_length=50)

    @cached_property
    def processed_network(self) -> tuple[ipaddress.IPv6Network, bool]:
        return parse_ip_to_net(self.network)

    def __str__(self) -> str:
        return self.network


class WafRule(ActivatableWithNote):
    managed_by: str = edgy.CharField(max_length=100, default="")
    revision: int = edgy.SmallIntegerField(default=1, gte=1)
    name: str = edgy.CharField(max_length=50, unique=True)
    position: int | None = edgy.SmallIntegerField(unique=True, null=True, default=None)
    stop: bool = edgy.BooleanField(default=False)
    http_methods: str = edgy.CharField(
        max_length=100, title="methods", default="*", regex=r"^(?:(?:[A-Z]+,)*[A-Z]+)|\*$"
    )
    ratelimit_cache: str = edgy.CharField(max_length=100, title="cache")

    _rules_cache: ClassVar[tuple[WafRule, ...] | None] = None

    @cached_property
    def cache(self) -> aiocache.BaseCache:
        cache = load(self.ratelimit_cache)
        if not isinstance(cache, aiocache.BaseCache):
            raise RuntimeError(f"Invalid cache selected: {self.ratelimit_cache}")
        return cache

    @cached_property
    def methods(self) -> frozenset[str]:
        if "*" in self.http_methods:
            return ALL
        return frozenset(self.http_methods.split(","))

    @classmethod
    async def get_rules_cache(cls) -> tuple[WafRule, ...]:
        WafRuleRatelimit = cast(
            "WafRuleRatelimit",
            cast("edgy.Registry", cls.meta.registry).get_model("WafRuleRatelimit"),
        )
        if cls._rules_cache is None:
            query = (
                cls.query.order_by("position")
                .filter(is_active=True, position__isnull=False)
                .prefetch_related(
                    edgy.Prefetch(
                        related_name="networks",
                        to_attr="cached_networks",
                    ),
                    edgy.Prefetch(
                        related_name="paths",
                        to_attr="cached_paths",
                    ),
                    edgy.Prefetch(
                        related_name="ratelimits",
                        to_attr="active_ratelimits",
                        queryset=WafRuleRatelimit.query.filter(is_active=True),
                    ),
                )
            )
            result = await query
            cls._rules_cache = tuple(result)
        return cls._rules_cache

    @classmethod
    async def clear_rules_cache(cls, *, clear_caches: bool = False) -> None:
        rules_cache = cls._rules_cache
        if rules_cache is None:
            return
        cls._rules_cache = None
        if clear_caches:
            seen_caches: set[str] = set()
            for rule in rules_cache:
                if rule.ratelimit_cache in seen_caches:
                    continue
                if "cache" in rule.__dict__:
                    await rule.cache.clear()
                    seen_caches.add(rule.ratelimit_cache)

    async def get_ratelimits(self) -> list[RatelimitProtocol] | Awaitable[list[RatelimitProtocol]]:
        active_ratelimits: list[RatelimitProtocol] | None = getattr(
            self, "active_ratelimits", None
        )
        if active_ratelimits is not None:
            return active_ratelimits
        return self.ratelimits.all()

    @cached_property
    def path_matcher(self) -> re.Pattern | None:
        cached_paths = getattr(self, "cached_paths", None)
        if cached_paths is None:
            raise AttributeError("Only available in `get_rules_cache`")
        arr = [obj.processed_path for obj in cached_paths if obj.is_active]
        if not arr:
            return None
        return re.compile("|".join(arr))

    @classmethod
    async def fetch_rules(cls, connection: Connection | None, /) -> list[WafRule]:
        """Return effective rules in right position."""
        rules: list[WafRule] = []
        unchecked_rules = await cls.get_rules_cache()
        if connection is None:
            for rule in unchecked_rules:
                if not getattr(rule, "cached_networks", None) and not getattr(
                    rule, "cached_paths", None
                ):
                    rules.append(rule)
            return rules
        client_ip = parse_ip_to_net(connection.scope["real-clientip"])[0]
        client_path = connection.scope.get("path", None)
        for rule in unchecked_rules:
            cached_networks: list[WafRuleNetwork] | None = getattr(rule, "cached_networks", None)
            cached_paths: list[WafRuleNetwork] | None = getattr(rule, "cached_paths", None)
            if not cached_networks and not cached_paths:
                continue
            if cached_networks:
                success = False
                for _network in cached_networks:
                    if not _network.is_active:
                        continue
                    network, ipv4 = _network.processed_network
                    if client_ip.subnet_of(network):
                        success = True
                        break
                if not success:
                    continue
            if cached_paths:
                if client_path is None:
                    continue
                matcher = rule.path_matcher
                if matcher is None:
                    continue
                if not matcher.match(client_path):
                    continue
            rules.append(rule)

        return rules

    @staticmethod
    def _prepare_schema(schema: Mapping, *, update: bool) -> dict[str, Any]:
        removed_elements = {"ratelimits", "networks", "paths", "position"}
        result_dict: dict[str, Any] = {}
        for k, v in schema.items():
            if k in removed_elements:
                continue
            if k == "revision":
                result_dict[k] = v
                continue
            assert isinstance(v, tuple), f"`{k}`: `{v}` is not a tuple"
            if update and not v[1]:
                continue
            result_dict[k] = v[0]

        return result_dict

    @classmethod
    async def rule_from_schema(cls, schema_string: str, /) -> Self:
        tracked_elements = ("ratelimits", "networks", "paths")
        schema: ManagedRules = load(schema_string)
        assert isinstance(schema, dict), "Schema is not a dict holding the schema"
        base_def_rule: dict[str, Any] = cls._prepare_schema(schema, update=False)
        revision = base_def_rule.pop("revision", None)
        if not revision:
            raise ValueError("Schema lacks `revision`.")
        rule_name = base_def_rule.get("name")
        if not rule_name:
            raise ValueError("Schema lacks `name`.")
        tracked_elements_seen_names: dict[str, set[str]] = {}
        for tracked_element_name in tracked_elements:
            tracked_elements_seen_names[tracked_element_name] = seen_names = set()
            tracked_list_and_final = schema.get(tracked_element_name)
            if not tracked_list_and_final:
                continue
            for element in tracked_list_and_final[0]:
                managed_name = element.get("managed_name")
                if not managed_name:
                    raise ValueError(
                        f"`{rule_name}``{tracked_element_name}` schema lacks `managed_name`."
                    )
                elif managed_name in seen_names:
                    raise ValueError(
                        f"`{rule_name}``{tracked_element_name}` schema has duplicate `managed_name`: {managed_name}."
                    )
                seen_names.add(managed_name)

        # we can have an initial schema which changes after e.g. to a new path or that no schema is used later
        base_def_rule.setdefault("managed_by", schema_string)
        position = schema.get("position") or "bottom"
        rule, created = await cls.query.get_or_create(defaults=base_def_rule, name=rule_name)
        if rule.position is None:
            # own rule is last, because true == 1 is after last
            # highly special, not expressable by edgy
            lock_expression = (
                sql.select(cls.table.columns.id, cls.table.columns.position)
                .order_by(
                    cls.table.columns.id == rule.id,
                    cls.table.columns.position,
                    cls.table.columns.id,
                )
                .select_from(cls.table)
                .distinct()
                .with_for_update()
            )

            def _updater(con: SQLAConnection) -> None:
                pos = 2 if position == "top" else 1
                updated_values: list[dict[str, Any]] = []
                with con.execute(lock_expression) as cursor:
                    while row := cursor.fetchone():
                        # numerate rows
                        if row.id != rule.id or position != "top":
                            row_pos = pos
                            pos += 1
                        else:
                            row_pos = 1
                        if row_pos != row.position:
                            if position == "top" and row.id == rule.id:
                                updated_values.insert(0, {"__id": row.id, "position": row_pos})
                            else:
                                updated_values.append({"__id": row.id, "position": row_pos})
                    # highest position first, descending, so we extend to the new element
                    updated_values.reverse()
                    con.execute(
                        cls.table.update().where(cls.table.c.id == bindparam("__id")),
                        updated_values,
                    )

            async with cls.database.connection() as con, con.transaction(), con:
                await con.run_sync(_updater)
        if not created and rule.revision != revision:
            for tracked_element_name in tracked_elements:
                tracked_list_and_final: tuple[dict, bool] | None = schema.get(tracked_element_name)
                if not tracked_list_and_final:
                    continue
                tracked_manager = getattr(rule, tracked_element_name)
                deletion_query = tracked_manager.exclude(
                    managed_name__in=tracked_elements_seen_names[tracked_element_name]
                )
                if not tracked_list_and_final[1]:
                    deletion_query = deletion_query.exclude(managed_name=None)
                await deletion_query.delete()
                for element_dict in tracked_list_and_final:
                    element_schema_create = cls._prepare_schema(
                        cast(dict, element_dict), update=False
                    )
                    element, created = tracked_manager.get_or_create(
                        element_schema_create, managed_name=element_schema_create["managed_name"]
                    )
                    if not created:
                        await element.update(
                            cls._prepare_schema(cast(dict, element_dict), update=True)
                        )

            await rule.update(cls._prepare_schema(schema, update=True))

        return rule

    @cached_property
    def managed_registry(self) -> dict[str, dict[str, tuple[Any, bool]]] | None:
        return None if not self.managed_by else load(self.managed_by).get(self.name)
