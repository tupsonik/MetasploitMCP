"""Runtime configuration loaded from environment variables.

Keep this module side-effect free apart from reading environment variables so the
server entrypoint remains easy to import and test.
"""

import pathlib
import os


def _env_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.getenv(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise RuntimeError(f"{name} must be between {minimum} and {maximum}")
    return value


# Metasploit connection
MSF_PASSWORD = os.getenv("MSF_PASSWORD")
MSF_SERVER = os.getenv("MSF_SERVER", "127.0.0.1")
MSF_PORT_STR = os.getenv("MSF_PORT", "55553")
MSF_SSL_STR = os.getenv("MSF_SSL", "false")

# Server/runtime
PAYLOAD_SAVE_DIR = os.getenv(
    "PAYLOAD_SAVE_DIR",
    str(pathlib.Path.home() / "payloads"),
)
LOG_LEVEL = os.getenv("LOG_LEVEL", "info")

# High-impact capabilities are opt-in.
ALLOW_ACTIVE_ACTIONS = _env_bool("MCP_ALLOW_ACTIVE_ACTIONS", False)
ALLOW_SESSION_CONTROL = _env_bool("MCP_ALLOW_SESSION_CONTROL", False)
ALLOW_PAYLOAD_GENERATION = _env_bool("MCP_ALLOW_PAYLOAD_GENERATION", False)
ALLOW_LISTENER_CONTROL = _env_bool("MCP_ALLOW_LISTENER_CONTROL", False)

# Resource limits.
MAX_COMMAND_LENGTH = _env_int("MCP_MAX_COMMAND_LENGTH", 4096, 128, 65536)
MAX_TOOL_TIMEOUT = _env_int("MCP_MAX_TOOL_TIMEOUT", 300, 5, 3600)

# HTTP authentication.
MCP_AUTH_TOKEN = os.getenv("MCP_AUTH_TOKEN")
MCP_REQUIRE_AUTH = os.getenv("MCP_REQUIRE_AUTH", "auto").strip().lower()
