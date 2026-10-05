import unittest
from unittest.mock import patch

from app.scanner import (
    PublicOnlyResolver,
    UnsafeTargetError,
    scan_headers,
    validate_target_url,
)


class FakeResolver:
    def __init__(self, addresses: list[str]) -> None:
        self.addresses = addresses

    async def resolve(
        self, host: str, port: int, family: int
    ) -> list[dict[str, object]]:
        return [
            {"host": address, "hostname": host, "port": port, "family": family}
            for address in self.addresses
        ]

    async def close(self) -> None:
        pass


class TargetValidationTests(unittest.TestCase):
    def test_allows_public_http_url(self) -> None:
        validate_target_url("https://example.com")

    def test_rejects_loopback_and_private_ip_literals(self) -> None:
        for url in ("http://127.0.0.1", "http://[::1]", "http://10.0.0.1"):
            with self.subTest(url=url), self.assertRaises(UnsafeTargetError):
                validate_target_url(url)

    def test_rejects_unsupported_ports_and_credentials(self) -> None:
        for url in ("https://example.com:8080", "https://user:pass@example.com"):
            with self.subTest(url=url), self.assertRaises(UnsafeTargetError):
                validate_target_url(url)


class PublicResolverTests(unittest.IsolatedAsyncioTestCase):
    async def test_allows_public_dns_answers(self) -> None:
        resolver = PublicOnlyResolver(FakeResolver(["8.8.8.8"]))
        self.addAsyncCleanup(resolver.close)
        records = await resolver.resolve("example.com", 443)
        self.assertEqual(records[0]["host"], "8.8.8.8")

    async def test_rejects_private_dns_answers(self) -> None:
        resolver = PublicOnlyResolver(FakeResolver(["8.8.8.8", "192.168.1.10"]))
        self.addAsyncCleanup(resolver.close)
        with self.assertRaises(UnsafeTargetError):
            await resolver.resolve("example.com", 443)


class FakeResponse:
    def __init__(self, status: int, headers: dict[str, str]) -> None:
        self.status = status
        self.headers = headers

    async def __aenter__(self) -> "FakeResponse":
        return self

    async def __aexit__(self, *args: object) -> None:
        del args


class FakeSession:
    def __init__(self, responses: list[FakeResponse], requests: list[str]) -> None:
        self.responses = responses
        self.requests = requests

    async def __aenter__(self) -> "FakeSession":
        return self

    async def __aexit__(self, *args: object) -> None:
        del args

    def get(self, url: str, allow_redirects: bool) -> FakeResponse:
        self.requests.append(url)
        if allow_redirects:
            raise AssertionError("Redirects must be checked manually")
        return self.responses.pop(0)


class ScanBehaviorTests(unittest.IsolatedAsyncioTestCase):
    async def test_blocks_redirect_to_loopback_before_following_it(self) -> None:
        requests: list[str] = []
        session = FakeSession(
            [FakeResponse(302, {"Location": "http://127.0.0.1/admin"})],
            requests,
        )
        with (
            patch("app.scanner.aiohttp.TCPConnector", return_value=object()),
            patch("app.scanner.aiohttp.ClientSession", return_value=session),
        ):
            with self.assertRaises(UnsafeTargetError):
                await scan_headers("https://public.example")
        self.assertEqual(requests, ["https://public.example"])

    async def test_scores_current_header_set_and_ignores_http_hsts(self) -> None:
        requests: list[str] = []
        session = FakeSession(
            [FakeResponse(200, {
                "Content-Security-Policy": "default-src 'self'",
                "Strict-Transport-Security": "max-age=31536000",
            })],
            requests,
        )
        with (
            patch("app.scanner.aiohttp.TCPConnector", return_value=object()),
            patch("app.scanner.aiohttp.ClientSession", return_value=session),
        ):
            result = await scan_headers("http://public.example")
        self.assertEqual(result.security_score, 17)
        self.assertNotIn("Strict-Transport-Security", result.headers_found)
        self.assertEqual(len(result.headers_missing), 5)


if __name__ == "__main__":
    unittest.main()