from time import perf_counter

import aiocache
import pytest
from lilya.responses import PlainText
from lilya.testclient import AsyncTestClient
from lilya.types import ASGIApp, Receive, Scope, Send

from lilya_waf import RatelimitExceeded, asgi_wrap, decorate


class InjectClientIPMiddleware:
    def __init__(self, app: ASGIApp, *, client: tuple[str, int]) -> None:
        self.app = app
        self.client = client

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        scope["client"] = self.client
        await self.app(scope, receive, send)


async def test_plain_unix(faker, subtests):
    ip_forward1 = faker.ipv6()
    ip_forward2 = faker.ipv4()

    async def app(scope: Scope, receive: Receive, send: Send):
        response = PlainText(scope.get("real-clientip"), status_code=200)
        await response(scope, receive, send)

    with subtests.test("unix but wrong trusted proxies"):
        wrapped = asgi_wrap(trusted_proxies=[ip_forward2])(app)
        client = AsyncTestClient(wrapped)
        with pytest.raises(ValueError):
            await client.get("/", headers={"forwarded": f"for={ip_forward2},for={ip_forward1}"})

    with subtests.test("unix but no trusted proxies"):
        wrapped = asgi_wrap(trusted_proxies=[])(app)
        client = AsyncTestClient(wrapped)
        with pytest.raises(ValueError):
            await client.get("/", headers={"forwarded": f"for={ip_forward2},for={ip_forward1}"})

    with subtests.test("with unix default"):
        wrapped = asgi_wrap()(app)
        client = AsyncTestClient(wrapped)
        result = await client.get(
            "/", headers={"forwarded": f"for={ip_forward2},for={ip_forward1}"}
        )
        assert result.text == ip_forward2
    with subtests.test("with provided unix"):
        wrapped = asgi_wrap(trusted_proxies=["unix"])(app)
        client = AsyncTestClient(wrapped)
        result = await client.get(
            "/", headers={"forwarded": f"for={ip_forward2},for={ip_forward1}"}
        )
        assert result.text == ip_forward2


async def test_plain_ip(faker):
    ip_client = faker.ipv4()
    ip_forward1 = faker.ipv6()
    ip_forward2 = faker.ipv4()

    async def app(scope: Scope, receive: Receive, send: Send):
        response = PlainText(scope.get("real-clientip"), status_code=200)
        await response(scope, receive, send)

    wrapped = asgi_wrap(trusted_proxies=[])(app)
    client = AsyncTestClient(InjectClientIPMiddleware(wrapped, client=(ip_forward2, 24843)))
    result = await client.get("/", headers={"forwarded": f"for={ip_client},for={ip_forward1}"})
    assert result.text == ip_forward2

    wrapped = asgi_wrap(trusted_proxies=[ip_forward2])(app)
    client = AsyncTestClient(InjectClientIPMiddleware(wrapped, client=(ip_forward2, 24843)))
    result = await client.get("/", headers={"forwarded": f"for={ip_client},for={ip_forward1}"})
    assert result.text == ip_client

    wrapped = asgi_wrap(trusted_proxies=[ip_forward1])(app)
    client = AsyncTestClient(InjectClientIPMiddleware(wrapped, client=(ip_forward2, 24843)))
    result = await client.get("/", headers={"forwarded": f"for={ip_client},for={ip_forward1}"})
    assert result.text == ip_forward2


async def test_ratelimit(faker):
    cache = aiocache.SimpleMemoryCache()
    ip_client = faker.ipv4()
    ip_forward1 = faker.ipv6()
    ip_forward2 = faker.ipv4()

    @decorate(key="ip", rate="1/0.5s", block=True, wait=True, cache=cache)
    async def app(scope: Scope, receive: Receive, send: Send):
        response = PlainText(scope.get("real-clientip"), status_code=200)
        await response(scope, receive, send)

    wrapped = asgi_wrap(trusted_proxies=[ip_forward2])(app)
    client = AsyncTestClient(InjectClientIPMiddleware(wrapped, client=(ip_forward2, 24843)))
    result = await client.get("/", headers={"forwarded": f"for={ip_client},for={ip_forward1}"})
    assert result.text == ip_client
    start = perf_counter()
    with pytest.RaisesGroup(pytest.RaisesExc(RatelimitExceeded)):
        await client.get("/", headers={"forwarded": f"for={ip_client},for={ip_forward1}"})
    stop = perf_counter()
    assert stop - start >= 0.5
