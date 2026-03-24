from typing import TYPE_CHECKING

from .middleware import management, migrations_path

if TYPE_CHECKING:
    from lilya.types import ASGIApp


def for_migrations() -> ASGIApp:
    import edgy

    if not edgy.monkay.instance:
        from lilya_waf.edgy import models as lilya_waf_models

        registry = edgy.Registry("sqlite:///test_db.sqlite3")
        lilya_waf_models.WafRule.copy_edgy_model().add_to_registry(registry)
        lilya_waf_models.WafRuleNetwork.copy_edgy_model().add_to_registry(registry)
        lilya_waf_models.WafRulePath.copy_edgy_model().add_to_registry(registry)
        lilya_waf_models.WafRuleRatelimit.copy_edgy_model().add_to_registry(registry)
        app = management(registry=registry)
        edgy.monkay.set_instance(edgy.Instance(registry, app=app))
        edgy.monkay.settings.migration_directory = migrations_path
    return app


for_migrations()
