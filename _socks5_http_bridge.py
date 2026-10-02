"""Loopback HTTP proxy bridge for authenticated SOCKS5 upstreams.

Playwright browsers accept SOCKS5 endpoints, but proxy credentials are only
supported for HTTP(S) proxies. This bridge keeps the configured SOCKS endpoint
unchanged and exposes a short-lived HTTP proxy on ``127.0.0.1``.
"""

from __future__ import annotations

import asyncio
import ipaddress
import struct
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote, urlparse, urlsplit


_HEADER_LIMIT = 64 * 1024
_CONNECT_TIMEOUT_SECONDS = 20.0
_SOCKS_REPLY_ERRORS = {
    1: "general SOCKS server failure",
    2: "connection not allowed by ruleset",
    3: "network unreachable",
    4: "host unreachable",
    5: "connection refused",
    6: "TTL expired",
    7: "command not supported",
    8: "address type not supported",
}


class Socks5BridgeError(RuntimeError):
    """SOCKS handshake or local HTTP bridge failure."""


@dataclass(frozen=True)
class _Socks5Upstream:
    host: str
    port: int
    username: str | None
    password: str | None


def needs_socks5_http_bridge(proxy_url: str | None) -> bool:
    """Return whether a browser proxy needs the authenticated SOCKS bridge."""
    if not proxy_url:
        return False
    parsed = urlparse(proxy_url)
    return parsed.scheme.casefold() in {"socks5", "socks5h"} and (
        parsed.username is not None or parsed.password is not None
    )


def _parse_upstream(proxy_url: str) -> _Socks5Upstream:
    parsed = urlparse(proxy_url)
    if parsed.scheme.casefold() not in {"socks5", "socks5h"}:
        raise ValueError("SOCKS bridge chỉ nhận socks5:// hoặc socks5h://")
    if not parsed.hostname or parsed.port is None:
        raise ValueError("SOCKS proxy thiếu host hoặc port")
    username = unquote(parsed.username) if parsed.username is not None else None
    password = unquote(parsed.password) if parsed.password is not None else None
    if username is not None or password is not None:
        user_bytes = (username or "").encode("utf-8")
        pass_bytes = (password or "").encode("utf-8")
        if len(user_bytes) > 255 or len(pass_bytes) > 255:
            raise ValueError("SOCKS username/password vượt quá 255 bytes")
    return _Socks5Upstream(
        host=parsed.hostname,
        port=parsed.port,
        username=username,
        password=password,
    )


def _parse_authority(authority: str, *, default_port: int) -> tuple[str, int]:
    authority = authority.strip()
    if authority.startswith("["):
        closing = authority.find("]")
        if closing < 0:
            raise Socks5BridgeError("IPv6 authority không hợp lệ")
        host = authority[1:closing]
        remainder = authority[closing + 1:]
        port = int(remainder[1:]) if remainder.startswith(":") else default_port
        return host, port
    if authority.count(":") == 1:
        host, raw_port = authority.rsplit(":", 1)
        return host, int(raw_port)
    return authority, default_port


def _socks_address(host: str) -> bytes:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        encoded = host.encode("idna")
        if not encoded or len(encoded) > 255:
            raise Socks5BridgeError("SOCKS target hostname không hợp lệ")
        return b"\x03" + bytes((len(encoded),)) + encoded
    if address.version == 4:
        return b"\x01" + address.packed
    return b"\x04" + address.packed


class Socks5HttpBridge:
    """Short-lived loopback HTTP proxy backed by one SOCKS5 upstream."""

    def __init__(self, upstream: _Socks5Upstream, *, log=None) -> None:
        self._upstream = upstream
        self._log = log
        self._server: Any | None = None
        self._client_tasks: set[asyncio.Task] = set()
        self._local_port: int | None = None

    @classmethod
    async def start(cls, proxy_url: str, *, log=None) -> "Socks5HttpBridge":
        bridge = cls(_parse_upstream(proxy_url), log=log)
        bridge._server = await asyncio.start_server(
            bridge._accept_client,
            host="127.0.0.1",
            port=0,
            limit=_HEADER_LIMIT,
        )
        sockets = bridge._server.sockets or []
        if not sockets:
            bridge._server.close()
            await bridge._server.wait_closed()
            raise Socks5BridgeError("không bind được HTTP bridge trên loopback")
        bridge._local_port = int(sockets[0].getsockname()[1])
        if log:
            log(
                "[proxy-bridge] authenticated SOCKS5 "
                f"{bridge._upstream.host}:{bridge._upstream.port} → "
                f"{bridge.proxy_url}"
            )
        return bridge

    @property
    def proxy_url(self) -> str:
        if self._local_port is None:
            raise Socks5BridgeError("HTTP bridge chưa được start")
        return f"http://127.0.0.1:{self._local_port}"

    def _accept_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        task = asyncio.create_task(self._handle_client(reader, writer))
        self._client_tasks.add(task)
        task.add_done_callback(self._client_tasks.discard)

    async def close(self) -> None:
        server = self._server
        self._server = None
        if server is not None:
            server.close()
            await server.wait_closed()
        tasks = list(self._client_tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        self._client_tasks.clear()
        if self._log:
            self._log("[proxy-bridge] stopped")

    async def _handle_client(
        self,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ) -> None:
        upstream_writer: asyncio.StreamWriter | None = None
        response_started = False
        try:
            header_block = await asyncio.wait_for(
                client_reader.readuntil(b"\r\n\r\n"),
                timeout=_CONNECT_TIMEOUT_SECONDS,
            )
            if len(header_block) > _HEADER_LIMIT:
                raise Socks5BridgeError("HTTP proxy header quá lớn")
            lines = header_block.split(b"\r\n")
            try:
                method, target, version = lines[0].decode("latin-1").split(" ", 2)
            except ValueError as exc:
                raise Socks5BridgeError("HTTP proxy request line không hợp lệ") from exc
            method_upper = method.upper()
            if method_upper == "CONNECT":
                target_host, target_port = _parse_authority(target, default_port=443)
                upstream_reader, upstream_writer = await self._open_socks_connection(
                    target_host,
                    target_port,
                )
                client_writer.write(
                    b"HTTP/1.1 200 Connection Established\r\n"
                    b"Proxy-Agent: local-socks5-bridge\r\n\r\n"
                )
                await client_writer.drain()
                response_started = True
            else:
                parsed_target = urlsplit(target)
                if parsed_target.scheme.casefold() != "http" or not parsed_target.hostname:
                    await self._send_error(client_writer, 400, "absolute HTTP URL required")
                    return
                target_host = parsed_target.hostname
                target_port = parsed_target.port or 80
                upstream_reader, upstream_writer = await self._open_socks_connection(
                    target_host,
                    target_port,
                )
                origin_target = parsed_target.path or "/"
                if parsed_target.query:
                    origin_target += f"?{parsed_target.query}"
                forwarded_headers: list[bytes] = []
                has_host = False
                for raw_header in lines[1:]:
                    if not raw_header or b":" not in raw_header:
                        continue
                    name = raw_header.split(b":", 1)[0].strip().lower()
                    if name in {b"proxy-authorization", b"proxy-connection", b"connection"}:
                        continue
                    if name == b"host":
                        has_host = True
                    forwarded_headers.append(raw_header)
                if not has_host:
                    forwarded_headers.append(f"Host: {parsed_target.netloc}".encode("latin-1"))
                # Disable keep-alive for plain HTTP so each absolute-form request
                # is parsed and routed independently by the bridge.
                forwarded_headers.append(b"Connection: close")
                upstream_writer.write(
                    f"{method_upper} {origin_target} {version}\r\n".encode("latin-1")
                    + b"\r\n".join(forwarded_headers)
                    + b"\r\n\r\n"
                )
                await upstream_writer.drain()
                response_started = True

            await self._relay_bidirectional(
                client_reader,
                client_writer,
                upstream_reader,
                upstream_writer,
            )
        except asyncio.CancelledError:
            raise
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        except Exception as exc:
            if not response_started:
                await self._send_error(client_writer, 502, "SOCKS upstream unavailable")
            if self._log:
                self._log(f"[proxy-bridge] connection failed: {type(exc).__name__}: {exc}")
        finally:
            if upstream_writer is not None:
                upstream_writer.close()
                try:
                    await upstream_writer.wait_closed()
                except Exception:
                    pass
            client_writer.close()
            try:
                await client_writer.wait_closed()
            except Exception:
                pass

    async def _open_socks_connection(
        self,
        target_host: str,
        target_port: int,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        upstream_reader, upstream_writer = await asyncio.wait_for(
            asyncio.open_connection(self._upstream.host, self._upstream.port),
            timeout=_CONNECT_TIMEOUT_SECONDS,
        )
        try:
            await asyncio.wait_for(
                self._socks_handshake(
                    upstream_reader,
                    upstream_writer,
                    target_host,
                    target_port,
                ),
                timeout=_CONNECT_TIMEOUT_SECONDS,
            )
        except BaseException:
            upstream_writer.close()
            try:
                await upstream_writer.wait_closed()
            except Exception:
                pass
            raise
        return upstream_reader, upstream_writer

    async def _socks_handshake(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target_host: str,
        target_port: int,
    ) -> None:
        has_auth = self._upstream.username is not None or self._upstream.password is not None
        writer.write(b"\x05\x01\x02" if has_auth else b"\x05\x01\x00")
        await writer.drain()
        version, method = await reader.readexactly(2)
        if version != 5 or method == 0xFF:
            raise Socks5BridgeError("SOCKS5 không chấp nhận authentication method")
        if method == 0x02:
            username = (self._upstream.username or "").encode("utf-8")
            password = (self._upstream.password or "").encode("utf-8")
            writer.write(
                b"\x01"
                + bytes((len(username),))
                + username
                + bytes((len(password),))
                + password
            )
            await writer.drain()
            auth_version, auth_status = await reader.readexactly(2)
            if auth_version != 1 or auth_status != 0:
                raise Socks5BridgeError("SOCKS5 username/password bị từ chối")
        elif method != 0x00:
            raise Socks5BridgeError(f"SOCKS5 auth method không hỗ trợ: {method}")

        writer.write(
            b"\x05\x01\x00"
            + _socks_address(target_host)
            + struct.pack("!H", target_port)
        )
        await writer.drain()
        version, reply, _reserved, address_type = await reader.readexactly(4)
        if version != 5:
            raise Socks5BridgeError("SOCKS5 response version không hợp lệ")
        if reply != 0:
            reason = _SOCKS_REPLY_ERRORS.get(reply, f"unknown error {reply}")
            raise Socks5BridgeError(f"SOCKS5 connect failed: {reason}")
        if address_type == 1:
            await reader.readexactly(4)
        elif address_type == 3:
            length = (await reader.readexactly(1))[0]
            await reader.readexactly(length)
        elif address_type == 4:
            await reader.readexactly(16)
        else:
            raise Socks5BridgeError("SOCKS5 bound address type không hợp lệ")
        await reader.readexactly(2)

    @staticmethod
    async def _relay_bidirectional(
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        upstream_reader: asyncio.StreamReader,
        upstream_writer: asyncio.StreamWriter,
    ) -> None:
        async def relay(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            while True:
                data = await reader.read(64 * 1024)
                if not data:
                    return
                writer.write(data)
                await writer.drain()

        tasks = {
            asyncio.create_task(relay(client_reader, upstream_writer)),
            asyncio.create_task(relay(upstream_reader, client_writer)),
        }
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*done, *pending, return_exceptions=True)

    @staticmethod
    async def _send_error(
        writer: asyncio.StreamWriter,
        status: int,
        message: str,
    ) -> None:
        reason = "Bad Request" if status == 400 else "Bad Gateway"
        body = message.encode("utf-8")
        try:
            writer.write(
                f"HTTP/1.1 {status} {reason}\r\n".encode("ascii")
                + b"Content-Type: text/plain; charset=utf-8\r\n"
                + f"Content-Length: {len(body)}\r\n".encode("ascii")
                + b"Connection: close\r\n\r\n"
                + body
            )
            await writer.drain()
        except Exception:
            pass
