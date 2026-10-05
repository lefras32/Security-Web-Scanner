import asyncio
import ipaddress
import socket
from typing import Any, NamedTuple
from urllib.parse import urljoin, urlsplit

import aiohttp

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
MAX_REDIRECTS = 5
ALLOWED_PORTS = {80, 443}


class UnsafeTargetError(ValueError):
    pass


class ScanTimeoutError(Exception):
    pass


class ScanRequestError(Exception):
    pass


class ScanResult(NamedTuple):
    headers_found: dict[str, str]
    headers_missing: list[str]
    security_score: int
    recommendations: list[str]


def validate_target_url(url: str) -> None:
    try:
        parts = urlsplit(url)
        hostname = parts.hostname
        port = parts.port
    except ValueError as exc:
        raise UnsafeTargetError("The target URL is malformed.") from exc

    if parts.scheme not in {"http", "https"} or not hostname:
        raise UnsafeTargetError("Only valid HTTP and HTTPS URLs can be scanned.")
    if parts.username is not None or parts.password is not None:
        raise UnsafeTargetError("URLs containing credentials cannot be scanned.")

    if port is not None and port not in ALLOWED_PORTS:
        raise UnsafeTargetError("Only ports 80 and 443 can be scanned.")

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        return
    if not address.is_global:
        raise UnsafeTargetError("Scanning local or non-public IP addresses is prohibited.")


class PublicOnlyResolver(aiohttp.abc.AbstractResolver):
    def __init__(self, resolver: aiohttp.abc.AbstractResolver | None = None) -> None:
        self._resolver = resolver or aiohttp.resolver.DefaultResolver()

    async def resolve(
        self, host: str, port: int = 0, family: int = socket.AF_INET
    ) -> list[dict[str, Any]]:
        records = await self._resolver.resolve(host, port, family)
        if not records:
            raise OSError("The target hostname did not resolve to an address.")

        for record in records:
            address = ipaddress.ip_address(record["host"].split("%", maxsplit=1)[0])
            if not address.is_global:
                raise UnsafeTargetError(
                    "The target hostname resolves to a non-public IP address."
                )
        return records

    async def close(self) -> None:
        await self._resolver.close()


async def scan_headers(url: str) -> ScanResult:
    current_url = url
    validate_target_url(current_url)
    timeout = aiohttp.ClientTimeout(total=5.0, connect=2.0, sock_read=3.0)

    try:
        connector = aiohttp.TCPConnector(
            resolver=PublicOnlyResolver(),
            use_dns_cache=False,
            limit=10,
        )
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            auto_decompress=False,
            trust_env=False,
        ) as client:
            for redirect_count in range(MAX_REDIRECTS + 1):
                validate_target_url(current_url)
                async with client.get(current_url, allow_redirects=False) as response:
                    if response.status not in REDIRECT_STATUSES:
                        response_headers = response.headers
                        break

                    location = response.headers.get("Location")
                    if not location:
                        response_headers = response.headers
                        break
                    if redirect_count == MAX_REDIRECTS:
                        raise ScanRequestError("The target exceeded the redirect limit.")

                    current_url = urljoin(current_url, location)
                    validate_target_url(current_url)

    except UnsafeTargetError:
        raise
    except asyncio.TimeoutError as exc:
        raise ScanTimeoutError("The target server did not respond in time.") from exc
    except aiohttp.ClientConnectorError as exc:
        if isinstance(exc.os_error, UnsafeTargetError):
            raise exc.os_error from exc
        raise ScanRequestError("Unable to connect to the target server.") from exc
    except aiohttp.ClientError as exc:
        raise ScanRequestError("The target server returned an invalid response.") from exc

    secure_response = urlsplit(current_url).scheme == "https"
    headers_found = {
        header: response_headers[header]
        for header in SECURITY_HEADERS
        if header in response_headers and response_headers[header]
        and (header != "Strict-Transport-Security" or secure_response)
    }
    headers_missing = [header for header in SECURITY_HEADERS if header not in headers_found]
    recommendations = [f"Missing security header: {header}" for header in headers_missing]
    score = round((len(headers_found) / len(SECURITY_HEADERS)) * 100)

    return ScanResult(headers_found, headers_missing, score, recommendations)