"""Fetch skill or prompt text from an http(s) URL, refusing private network targets."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

import httpx

MAX_REDIRECTS = 3
TIMEOUT_SECONDS = 15.0
ACCEPT = "text/markdown, text/plain;q=0.9, */*;q=0.1"


def is_url(value: str) -> bool:
    return value.strip().lower().startswith(("http://", "https://"))


def fetch_text(
    url: str, max_bytes: int = 1_000_000, allow_private: bool = False
) -> str:
    """Download ``url`` and return it as text, e.g. a SKILL.md or a prompt ``.md`` endpoint.

    Every hop, including redirects, must resolve to a public address unless
    ``allow_private`` is set, so a scan request cannot reach internal services.

    Raises:
        ValueError: unsupported URL, non-public host, too many redirects, oversized or binary content.
        httpx.HTTPError: network failure or an error HTTP status.
    """
    url = url.strip()
    with httpx.Client(timeout=TIMEOUT_SECONDS, follow_redirects=False) as client:
        for _ in range(MAX_REDIRECTS + 1):
            _check_target(url, allow_private)
            with client.stream("GET", url, headers={"Accept": ACCEPT}) as response:
                if response.is_redirect:
                    url = urljoin(url, response.headers["location"])
                    continue
                response.raise_for_status()
                data = bytearray()
                for chunk in response.iter_bytes():
                    data += chunk
                    if len(data) > max_bytes:
                        raise ValueError(f"{url} exceeds {max_bytes} bytes")
            if bytes([0]) in data[:8192]:
                raise ValueError(f"{url} is not a text document")
            return data.decode("utf-8", errors="replace")
    raise ValueError(f"too many redirects fetching {url}")


def _check_target(url: str, allow_private: bool) -> None:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError(f"unsupported URL: {url}")
    if allow_private:
        return
    port = parts.port or (443 if parts.scheme == "https" else 80)
    try:
        addresses = {
            info[4][0]
            for info in socket.getaddrinfo(
                parts.hostname, port, proto=socket.IPPROTO_TCP
            )
        }
    except socket.gaierror as exc:
        raise ValueError(f"cannot resolve {parts.hostname}: {exc}") from exc
    for address in addresses:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
        if not ip.is_global:
            raise ValueError(
                f"refusing to fetch {url}: {parts.hostname} resolves to non-public address {ip}"
            )
