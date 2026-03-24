from typing import cast

import edgy

from lilya_waf.misc import lilya_waf_registry

from ..edgy.models import WafRule as WafRuleEdgy


async def unrestrict_all() -> None:
    """Emergency disable all rules and clear caches for reallowing login."""
    registry = lilya_waf_registry.get(None)
    if registry is not None:
        with edgy.monkay.with_instance(edgy.Instance(registry=registry)):
            async with registry:
                WafRule = cast("WafRuleEdgy", registry.get_model("WafRule"))
                await WafRule.clear_rules_cache(clear_caches=True)
    else:
        await WafRuleEdgy.clear_rules_cache(clear_caches=False)
