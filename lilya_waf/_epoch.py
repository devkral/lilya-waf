"""
private helpers for epoch stuff
"""

from __future__ import annotations

import asyncio
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aiocache import BaseCache


def epoch_call_count(epoch: object | int, cache_key: str, delta: int = 1) -> int | None:
    if epoch is None or isinstance(epoch, int):
        return epoch
    if not hasattr(epoch, "_waf_ratelimit_dict_count"):
        epoch._waf_ratelimit_dict_count = {}  # ty: ignore
    counter_dict: dict[str, int] = epoch._waf_ratelimit_dict_count  # ty: ignore
    count = counter_dict.get(cache_key, 0) + delta
    if delta != 0:
        counter_dict[cache_key] = count
    return count


async def reset_epoch(epoch: object | int, cache: BaseCache, cache_key: str) -> int:
    call_count = epoch_call_count(epoch, cache_key, 0)
    assert call_count is not None
    expired = await cache.get(f"{cache_key}_expire", None)
    if not expired or expired < int(time.time()):
        await asyncio.gather(*(cache.delete(x) for x in [cache_key, f"{cache_key}_expire"]))
        count = 0
    else:
        try:
            # decr does not extend cache duration
            count = await cache.increment(cache_key, -call_count)
        except ValueError:
            # not in cache, no problem
            count = 0
    epoch_call_count(epoch, cache_key, -call_count)
    return count
