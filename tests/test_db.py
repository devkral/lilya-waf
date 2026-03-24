from time import perf_counter

import aiocache
import pytest
from edgy.testclient import DatabaseTestClient
from lilya.responses import PlainText
from lilya.testclient import AsyncTestClient
from lilya.types import ASGIApp, Receive, Scope, Send

from lilya_waf import ALL, NoMatchingRatelimit, RatelimitExceeded, asgi_wrap, decorate
from lilya_waf.misc import lilya_waf_registry

database = DatabaseTestClient("sqlite:///test_db.sqlite3", drop_database=True, use_existing=False)
cache = aiocache.SimpleMemoryCache()


@pytest.fixture(autouse=True, scope="function")
async def reset_lilya_waf_registry():
    lilya_waf_registry.set(None)
    assert not database.ref_counter
    async with database:
        try:
            yield
        finally:
            lilya_waf_registry.set(None)
            await cache.clear()
    assert not database.ref_counter


class InjectClientIPMiddleware:
    def __init__(self, app: ASGIApp, *, client: tuple[str, int]) -> None:
        self.app = app
        self.client = client

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        scope["client"] = self.client
        await self.app(scope, receive, send)


async def test_ratelimit_rule_copying():
    wrapper = asgi_wrap(db=database)
    registry = lilya_waf_registry.get()
    assert registry is not None
    assert registry is wrapper.registry
    WafRule = registry.get_model("WafRule")
    assert WafRule.model_fields == WafRule.meta.fields

    WafRuleRatelimit = registry.get_model("WafRuleRatelimit")
    assert WafRuleRatelimit.model_fields == WafRuleRatelimit.meta.fields
    async with registry:
        WafRule = registry.get_model("WafRule")
        assert WafRule.model_fields == WafRule.meta.fields

        WafRuleRatelimit = registry.get_model("WafRuleRatelimit")
        assert WafRuleRatelimit.model_fields == WafRuleRatelimit.meta.fields


async def test_install_schema():
    wrapper = asgi_wrap(
        db=database,
        install_schemas=[
            "tests.rule_schema.schema2",
            "tests.rule_schema.schema1",
            "tests.rule_schema.schema_top",
        ],
    )
    registry = lilya_waf_registry.get()
    assert registry is wrapper.registry
    WafRule = registry.get_model("WafRule")
    rules = await WafRule.query.order_by("position")
    # moved to top
    assert rules[0].position == 1
    assert rules[0].name == "schema_top"
    assert rules[0].ratelimit_cache == "invalid.import"
    # bottom
    assert rules[1].position == 2
    assert rules[1].name == "schema2"
    assert rules[1].ratelimit_cache == "invalid.import"
    assert rules[2].position == 3
    assert rules[2].name == "schema1"
    assert rules[2].ratelimit_cache == "invalid.import"


async def test_ratelimit_rule_manual(faker, subtests):
    ip_client = faker.ipv4()
    ip_forward1 = faker.ipv6()
    ip_forward2 = faker.ipv4()

    @decorate()
    async def sub_app(scope: Scope, receive: Receive, send: Send):
        response = PlainText(scope.get("real-clientip"), status_code=200)
        await response(scope, receive, send)

    async def app(scope: Scope, receive: Receive, send: Send):
        try:
            await sub_app(scope, receive, send)
        except NoMatchingRatelimit as exc:
            if any(x == (b"x-continue", b"Continue") for x in scope["headers"]):
                assert exc.continue_fn is not None
                await exc.continue_fn()
            else:
                raise exc

    wrapped = asgi_wrap(trusted_proxies=[ip_forward2], db=database)(app)
    registry = lilya_waf_registry.get()
    assert registry is not None
    async with registry:
        WafRule = registry.get_model("WafRule")
        rule = await WafRule.query.create(
            name="rule_ratelimit manual",
            ratelimit_cache="tests.test_db.cache",
            http_methods="*",
            position=1,
        )
        await rule.paths.create(path="/test.*", is_regex=True)
        ratelimit = await rule.ratelimits.create(key="ip", rate="1/0.5s", wait=True, block=True)
        assert ratelimit.groups is ALL
        # await WafRule.clear_rules_cache()
        client = AsyncTestClient(InjectClientIPMiddleware(wrapped, client=(ip_forward2, 24843)))
        with subtests.test("Excluded paths"):
            should_work = False
            # confirm syntaxes for matching NoMatchingRatelimit
            try:
                await client.get("/b", headers={"forwarded": f"for={ip_client},for={ip_forward1}"})
            except* NoMatchingRatelimit:
                should_work = True
            assert should_work
            should_work = False
            try:
                await client.get("/b", headers={"forwarded": f"for={ip_client},for={ip_forward1}"})
            except NoMatchingRatelimit:
                should_work = True
            assert should_work
            result = await client.get(
                "/i",
                headers={
                    "forwarded": f"for={ip_client},for={ip_forward1}",
                    "x-continue": "Continue",
                },
            )
            assert result.text == ip_client

        with subtests.test("Included paths"):
            result = await client.get(
                "/test/foo", headers={"forwarded": f"for={ip_client},for={ip_forward1}"}
            )
            assert result.text == ip_client
            # we have wait active
            start = perf_counter()
            with pytest.RaisesGroup(pytest.RaisesExc(RatelimitExceeded)):
                await client.get(
                    "/test/bar", headers={"forwarded": f"for={ip_client},for={ip_forward1}"}
                )
            stop = perf_counter()
            assert stop - start >= 0.5


async def test_ratelimit_rule_stop(faker):
    ip_client = faker.ipv4()
    ip_forward1 = faker.ipv6()
    ip_forward2 = faker.ipv4()

    @decorate()
    async def app(scope: Scope, receive: Receive, send: Send):
        response = PlainText(scope.get("real-clientip"), status_code=200)
        await response(scope, receive, send)

    wrapped = asgi_wrap(trusted_proxies=[ip_forward2], db=database)(app)
    registry = lilya_waf_registry.get()
    client = AsyncTestClient(InjectClientIPMiddleware(wrapped, client=(ip_forward2, 24843)))
    assert registry is not None
    async with registry:
        WafRule = registry.get_model("WafRule")
        rule1 = await WafRule.query.create(
            name="allow stateless",
            ratelimit_cache="tests.test_db.cache",
            http_methods="HEAD,GET,TRACE",
            position=1,
            stop=True,
        )

        await rule1.paths.create(path=".*", is_regex=True)
        rule2 = await WafRule.query.create(
            name="disallow rest",
            ratelimit_cache="tests.test_db.cache",
            position=2,
        )

        await rule2.paths.create(path=".*", is_regex=True)
        await rule2.ratelimits.create(key="reject", rate="1/1s", wait=True, block=True)
        with pytest.raises(NoMatchingRatelimit):
            await client.get("/", headers={"forwarded": f"for={ip_client},for={ip_forward1}"})
        with pytest.RaisesGroup(pytest.RaisesExc(RatelimitExceeded)):
            await client.post("/", headers={"forwarded": f"for={ip_client},for={ip_forward1}"})


async def test_ratelimit_rule_stop_empty(faker, subtests):
    ip_client = faker.ipv4()
    ip_forward1 = faker.ipv6()
    ip_forward2 = faker.ipv4()

    @decorate()
    async def app(scope: Scope, receive: Receive, send: Send):
        response = PlainText(scope.get("real-clientip"), status_code=200)
        await response(scope, receive, send)

    wrapped = asgi_wrap(trusted_proxies=[ip_forward2], db=database)(app)
    registry = lilya_waf_registry.get()
    client = AsyncTestClient(InjectClientIPMiddleware(wrapped, client=(ip_forward2, 24843)))
    assert registry is not None
    async with registry:
        WafRule = registry.get_model("WafRule")
        rule1 = await WafRule.query.create(
            name="allow stateless",
            ratelimit_cache="tests.test_db.cache",
            http_methods="HEAD,GET,TRACE",
            position=1,
            stop=True,
        )

        await rule1.paths.create(path=".*", is_regex=True)
        await rule1.ratelimits.create(key="allow", rate="1/1s", wait=True, block=True)
        rule2 = await WafRule.query.create(
            name="disallow rest",
            ratelimit_cache="tests.test_db.cache",
            position=2,
        )

        await rule2.paths.create(path=".*", is_regex=True)
        await rule2.ratelimits.create(key="reject", rate="1/1s", wait=True, block=True)
        result = await client.get("/", headers={"forwarded": f"for={ip_client},for={ip_forward1}"})
        assert result.text == ip_client
        with pytest.RaisesGroup(pytest.RaisesExc(RatelimitExceeded)):
            await client.post("/", headers={"forwarded": f"for={ip_client},for={ip_forward1}"})
