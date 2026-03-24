import asyncio
import hashlib
import time

import aiocache
import pytest

import lilya_waf
from lilya_waf import Action, RatelimitExceeded, apply_ratelimits, decorate
from lilya_waf._core import _get_cache_key, _get_group_hash


async def test_action_compatibility():
    # will fail with plain Enum
    for value in lilya_waf.Action.__members__.values():
        assert value == value.value


async def test_key_length_limits():
    _get_group_hash.cache_clear()
    for hashgroup in ["md5", "sha256", "sha512", "sha3-512"]:
        h = hashlib.new(hashgroup)
        k = _get_cache_key("foo" * 255, h)
        assert len(k) < 200, f"{hashgroup}: {len(k)}"
        _get_group_hash.cache_clear()


@pytest.mark.parametrize("key", ["reject", ("static", 1)], ids=["func", "manual"])
async def test_apply_ratelimits_reject(key):
    cache = aiocache.SimpleMemoryCache()
    results = await apply_ratelimits(
        connection=None, cache=cache, rate=(1, 1), key=key, group="foo"
    )
    assert results[0].request_limit == 1
    assert not results[0].can_reset
    assert results[0].cache is None


@pytest.mark.parametrize("key", ["allow", ("static", 0)], ids=["func", "manual"])
async def test_apply_ratelimits_allow(key):
    cache = aiocache.SimpleMemoryCache()
    results = await apply_ratelimits(
        connection=None, cache=cache, rate=(1, 1), key=key, group="foo"
    )
    assert results[0].request_limit == 0
    assert not results[0].can_reset
    assert results[0].cache is None


@pytest.mark.parametrize(
    "rate",
    [(3, 0.5), "3/0.5s", "3/0.5"],
)
async def test_apply_ratelimits_valid_rate(rate):
    cache = aiocache.SimpleMemoryCache()
    start = time.time()
    rlimits = await apply_ratelimits(
        connection=None, cache=cache, rate=rate, key=["static", 0], group="foo"
    )
    assert rlimits[0].end >= start + 0.5
    assert rlimits[0].end < start + 0.6
    assert rlimits[0].limit == 3


@pytest.mark.parametrize(
    "rate",
    [(0, 0), (1, 0), (0, 1)],
    ids=["00", "10", "01"],
)
async def test_appy_ratelimits_invalid_rate(rate):
    cache = aiocache.SimpleMemoryCache()
    with pytest.raises(ValueError):
        await apply_ratelimits(
            connection=None, cache=cache, rate=rate, key=["static", 0], group="foo"
        )


@pytest.mark.parametrize("rate", ["0/s", "1/0s", "1/10.0.0s", "1.0/10s"])
async def test_appy_ratelimits_invalid_rate_str(rate):
    cache = aiocache.SimpleMemoryCache()
    with pytest.raises(ValueError):
        await apply_ratelimits(
            connection=None, cache=cache, rate=rate, key=["static", 0], group="foo"
        )


async def test_apply_ratelimits_normal_operation():
    cache = aiocache.SimpleMemoryCache()
    results = await apply_ratelimits(
        action=Action.INCREASE,
        connection=None,
        cache=cache,
        rate=(1, 1),
        key=b"static",
        group="foo",
    )
    assert results[0].request_limit == 0
    assert results[0].can_reset
    assert results[0].cache is cache
    results = await apply_ratelimits(
        action=Action.INCREASE,
        connection=None,
        cache=cache,
        rate=(1, 1),
        key=b"static",
        group="foo",
    )
    assert results[0].request_limit == 1
    assert results[0].can_reset
    assert results[0].cache is cache
    results = await apply_ratelimits(
        action=Action.INCREASE,
        connection=None,
        cache=cache,
        rate=(1, 1),
        key=b"static",
        group="foo",
    )
    assert results[0].request_limit == 1
    await results[0].reset()
    results = await apply_ratelimits(
        action=Action.INCREASE,
        connection=None,
        cache=cache,
        rate=(1, 1),
        key=b"static",
        group="foo",
    )
    assert results[0].request_limit == 0
    await asyncio.sleep(1.1)
    results = await apply_ratelimits(
        action=Action.INCREASE,
        connection=None,
        cache=cache,
        rate=(1, 1),
        key=b"static",
        group="foo",
    )
    assert results[0].request_limit == 0


async def test_apply_ratelimits_decorated():
    cache = aiocache.SimpleMemoryCache()

    @decorate(cache=cache, rate=(1, 1), key=b"static", block=True)
    async def foo():
        pass

    await foo()
    with pytest.RaisesGroup(pytest.RaisesExc(RatelimitExceeded)):
        await foo()
    results = await apply_ratelimits(
        action=Action.RESET,
        connection=None,
        cache=cache,
        rate=(1, 1),
        key=b"static",
        group=lilya_waf.o2g(foo),
    )
    assert results[0].request_limit == 1
    results = await apply_ratelimits(
        action=Action.PEEK,
        connection=None,
        cache=cache,
        rate=(1, 1),
        key=b"static",
        group=lilya_waf.o2g(foo),
    )
    assert results[0].request_limit == 0
    assert results[0].can_reset
    assert results[0].cache is cache
    await foo()
