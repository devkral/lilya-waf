from edgy.testclient import DatabaseTestClient
from lilya.types import ASGIApp, Receive, Scope, Send

database = DatabaseTestClient(
    "sqlite:///./test_db.sqlite3", drop_database=True, use_existing=False
)


class InjectClientIPMiddleware:
    def __init__(self, app: ASGIApp, *, client: tuple[str, int]) -> None:
        self.app = app
        self.client = client

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        scope["client"] = self.client
        await self.app(scope, receive, send)


async def test_parallel_lilya():
    pass
