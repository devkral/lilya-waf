schema1 = {
    "name": ("schema1", False),
    "revision": 1,
    "position": "bottom",
    "is_active": (True, True),
    "note": ("schema1 rule", False),
    "ratelimit_cache": ("invalid.import", False),
    "ratelimits": ([{"managed_name": ("1", True)}], True),
}

schema2 = {
    "name": ("schema2", False),
    "revision": 1,
    "position": "bottom",
    "is_active": (True, True),
    "note": ("schema2 rule", False),
    "ratelimit_cache": ("invalid.import", False),
    "ratelimits": ([{"managed_name": ("1", False)}], False),
}

schema_top = {
    "name": ("schema_top", False),
    "revision": 1,
    "position": "top",
    "is_active": (True, True),
    "note": ("schema_top rule", False),
    "ratelimit_cache": ("invalid.import", False),
    "ratelimits": ([{"managed_name": ("1", False)}], False),
}
