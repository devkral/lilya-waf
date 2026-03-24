from __future__ import annotations

from collections.abc import AsyncGenerator, Collection, Generator, Iterable
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from typing import TYPE_CHECKING, cast

from lilya.middleware import DefineMiddleware
from lilya.middleware.clientip import ClientIPMiddleware
from lilya.requests import Connection
from lilya.routing import Include
from monkay.asgi import CMToASGIMiddleware

from .misc import lilya_waf_connection, lilya_waf_registry

if TYPE_CHECKING:
    from edgy import Database, DatabaseURL, Registry
    from lilya.types import ASGIApp, Scope

    from .types import WafASGIWrapper

migrations_path = Path(__file__).parent / "edgy" / "migrations"


def asgi_wrap(
    *,
    with_clientip_middleware: bool = True,
    trusted_proxies: Collection[str] | None = None,
    db: Database | str | DatabaseURL | None = None,
    install_schemas: Iterable[str] | None = None,
) -> WafASGIWrapper:
    middleware: list = []
    if with_clientip_middleware:
        middleware.append(DefineMiddleware(ClientIPMiddleware, trusted_proxies=trusted_proxies))
    if db:
        import edgy

        from lilya_waf.edgy import models as lilya_waf_models

        registry = edgy.Registry(
            db,
            automigrate_config=edgy.EdgySettings(
                migration_directory=migrations_path, allow_automigrations=True
            ),
        )
        Rule = lilya_waf_models.WafRule.copy_edgy_model(registry=registry)
        lilya_waf_models.WafRuleNetwork.copy_edgy_model(registry=registry)
        lilya_waf_models.WafRulePath.copy_edgy_model(registry=registry)
        lilya_waf_models.WafRuleRatelimit.copy_edgy_model(registry=registry)
        if install_schemas is not None:

            async def _installer() -> None:
                async with registry:
                    for schema_string in install_schemas:
                        await Rule.rule_from_schema(schema_string)
                    await Rule.clear_rules_cache()

            edgy.run_sync(_installer())

        if lilya_waf_registry.get(None) is None:
            lilya_waf_registry.set(registry)

        def _decorator(app: ASGIApp) -> ASGIApp:
            @asynccontextmanager
            async def _wrapper(scope: Scope) -> AsyncGenerator:
                token_connection = lilya_waf_connection.set(Connection(scope))
                token_registry = lilya_waf_registry.set(registry)
                try:
                    yield
                finally:
                    lilya_waf_registry.reset(token_registry)
                    lilya_waf_connection.reset(token_connection)

            app = CMToASGIMiddleware(app, cm=_wrapper)

            app = registry.asgi(app)
            return Include(
                "",
                app=app,
                middleware=middleware,
            )

        _decorator.registry = registry  # type: ignore
    else:

        def _decorator(app: ASGIApp) -> ASGIApp:
            @asynccontextmanager
            async def _wrapper(scope: Scope) -> AsyncGenerator:
                token_connection = lilya_waf_connection.set(Connection(scope))
                try:
                    yield
                finally:
                    lilya_waf_connection.reset(token_connection)

            app = CMToASGIMiddleware(app, cm=_wrapper)

            return Include(
                "",
                app=app,
                middleware=middleware,
            )

        _decorator.registry = None  # type: ignore

    return cast("WafASGIWrapper", _decorator)


def management(registry: Registry | None = None) -> ASGIApp:
    import edgy
    from edgy.contrib.admin import create_admin_app

    app = create_admin_app(
        registry=registry,
        settings=edgy.EdgySettings(
            migration_directory=migrations_path,
        ),
    )
    if registry is not None:
        return app

    @contextmanager
    def _wrapper(scope: Scope) -> Generator:
        waf_registry = lilya_waf_registry.get()

        assert waf_registry is not None, "registry is not set"
        with edgy.monkay.with_instance(
            instance=edgy.Instance(registry=waf_registry, app=app),
        ):
            yield

    return CMToASGIMiddleware(app, cm=_wrapper)


__all__ = ["management", "asgi_wrap"]
