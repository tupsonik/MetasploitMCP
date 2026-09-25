"""Metasploit RPC connection primitives.

This module keeps RPC configuration parsing and client construction separate
from the MCP server/tool layer.
"""

from dataclasses import dataclass
from typing import Any, Callable, Tuple, Type

from pymetasploit3.msfrpc import MsfRpcClient


@dataclass(frozen=True)
class RpcConfig:
    server: str
    port: int
    ssl: bool


def parse_rpc_config(server: str, port_text: str, ssl_text: str) -> RpcConfig:
    """Validate and normalize Metasploit RPC connection settings."""
    try:
        port = int(port_text)
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid MSF connection parameters") from exc

    if not 1 <= port <= 65535:
        raise ValueError("Invalid MSF connection parameters")

    ssl_value = str(ssl_text).strip().lower()
    if ssl_value not in {"true", "false"}:
        raise ValueError("Invalid MSF connection parameters")

    return RpcConfig(server=server, port=port, ssl=ssl_value == "true")


def create_rpc_client(
    password: str,
    config: RpcConfig,
    client_factory: Callable[..., Any] = MsfRpcClient,
) -> Any:
    """Construct an RPC client from validated settings."""
    if not password:
        raise ValueError("MSF password must be provided")
    return client_factory(
        password=password,
        server=config.server,
        port=config.port,
        ssl=config.ssl,
    )
