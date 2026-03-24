from typing import TYPE_CHECKING, cast

import edgy

from lilya_waf.misc import lilya_waf_registry

if TYPE_CHECKING:
    from lilya_waf.edgy.models import WafRule


async def clear_caches() -> None:
    registry = lilya_waf_registry.get(None)
    if registry is not None:
        with edgy.monkay.with_instance(edgy.Instance(registry=registry)):
            async with registry:
                Rule = cast("type[WafRule]", registry.get_model("WafRule"))
                await Rule.query.update(is_active=False)
                await Rule.clear_rules_cache(clear_caches=True)
