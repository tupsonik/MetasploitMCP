"""Input validation and capability controls for the MCP server."""

import ipaddress
import re
from typing import Any

MODULE_NAME_RE = re.compile(r"^[A-Za-z0-9_.+\-]+(?:/[A-Za-z0-9_.+\-]+)*$")
OPTION_KEY_RE = re.compile(r"^[A-Za-z0-9_.:+\-]+$")


def is_loopback_host(host: str) -> bool:
    normalized = host.strip().lower()
    if normalized == "localhost":
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def validate_module_name(module_name: str) -> str:
    if not isinstance(module_name, str):
        raise ValueError("Invalid Metasploit module name.")
    normalized = module_name.strip("/")
    if not MODULE_NAME_RE.fullmatch(normalized):
        raise ValueError("Invalid Metasploit module name.")
    return normalized


def validate_option_key(key: Any) -> str:
    key_str = str(key)
    if not OPTION_KEY_RE.fullmatch(key_str):
        raise ValueError(f"Invalid Metasploit option key: {key_str!r}")
    return key_str


def require_capability(
    capability: str,
    *,
    active_actions: bool,
    session_control: bool,
    payload_generation: bool,
    listener_control: bool,
) -> None:
    allowed = {
        "active_actions": active_actions,
        "session_control": session_control,
        "payload_generation": payload_generation,
        "listener_control": listener_control,
    }
    if not allowed.get(capability, False):
        raise PermissionError(
            f"Capability '{capability}' is disabled. "
            "Enable the corresponding MCP_* setting explicitly."
        )


def validate_timeout(timeout_seconds: int, max_timeout: int) -> int:
    if not 1 <= timeout_seconds <= max_timeout:
        raise ValueError(
            f"timeout_seconds must be between 1 and {max_timeout}."
        )
    return timeout_seconds


def validate_command(command: str, max_length: int) -> None:
    if not isinstance(command, str) or not command.strip():
        raise ValueError("Command must be a non-empty string.")
    if "\x00" in command:
        raise ValueError("Command contains a NUL byte.")
    if len(command) > max_length:
        raise ValueError(
            f"Command exceeds the configured maximum length of {max_length} characters."
        )
