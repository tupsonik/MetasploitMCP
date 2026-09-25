"""Reusable helper functions for Metasploit module operations."""

import asyncio
from typing import Any, Callable, Dict, Union

from pymetasploit3.msfrpc import MsfRpcError

from security import validate_module_name, validate_option_key


def parse_options_gracefully(
    options: Union[Dict[str, Any], str, None],
    logger: Any,
) -> Dict[str, Any]:
    """Normalize dict/string option input while keeping values redacted in logs."""
    if options is None:
        return {}
    if isinstance(options, dict):
        return options
    if isinstance(options, str):
        if not options.strip():
            return {}
        logger.info("Converting string format options to dict; values redacted.")
        parsed_options: Dict[str, Any] = {}
        try:
            pairs = [pair.strip() for pair in options.split(",") if pair.strip()]
            for pair in pairs:
                if "=" not in pair:
                    raise ValueError(f"Invalid option syntax at pair {len(parsed_options) + 1}: expected key=value")
                key, value = pair.split("=", 1)
                key = key.strip()
                value = value.strip()
                if not key:
                    raise ValueError(f"Invalid option syntax at pair {len(parsed_options) + 1}: key is empty")
                if (value.startswith('"') and value.endswith('"')) or (
                    value.startswith("'") and value.endswith("'")
                ):
                    value = value[1:-1]
                if value.lower() in ("true", "false"):
                    value = value.lower() == "true"
                elif value.isdigit():
                    try:
                        value = int(value)
                    except ValueError:
                        pass
                parsed_options[key] = value
            logger.info(
                f"Successfully converted string options to dict with {len(parsed_options)} keys."
            )
            return parsed_options
        except Exception as exc:
            raise ValueError(
                f"Failed to parse options string: {exc}. "
                "Expected format: 'key=value,key2=value2' or dict {'key': 'value'}"
            ) from exc
    try:
        return dict(options)
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Options must be a dictionary or comma-separated string format "
            f"'key=value,key2=value2'. Got {type(options)}: {options}"
        ) from exc


async def get_module_object(
    module_type: str,
    module_name: str,
    get_client: Callable[[], Any],
    logger: Any,
) -> Any:
    """Resolve a Metasploit module name and return its RPC object."""
    client = get_client()
    normalized = validate_module_name(module_name)
    base_module_name = normalized
    if "/" in normalized:
        parts = normalized.split("/")
        if parts[0] in ("exploit", "payload", "post", "auxiliary", "encoder", "nop"):
            base_module_name = "/".join(parts[1:])
            if module_type != parts[0]:
                logger.warning(
                    f"Module type mismatch: expected '{module_type}', got path starting with "
                    f"'{parts[0]}'. Using provided type."
                )
    try:
        return await asyncio.to_thread(
            lambda: client.modules.use(module_type, base_module_name)
        )
    except (MsfRpcError, KeyError) as exc:
        error_str = str(exc).lower()
        if (
            "unknown module" in error_str
            or "invalid module" in error_str
            or isinstance(exc, KeyError)
        ):
            raise ValueError(
                f"Module '{normalized}' of type '{module_type}' not found."
            ) from exc
        raise MsfRpcError(
            f"Error retrieving module '{normalized}': {exc}"
        ) from exc


async def set_module_options(
    module_obj: Any,
    options: Dict[str, Any],
    logger: Any,
) -> None:
    """Set and normalize module options through the RPC module object."""
    for key, value in options.items():
        validate_option_key(key)
        if isinstance(value, str):
            if value.isdigit():
                try:
                    value = int(value)
                except ValueError:
                    pass
            elif value.lower() in ("true", "false"):
                value = value.lower() == "true"
        try:
            await asyncio.to_thread(
                lambda option_key=key, option_value=value:
                    module_obj.__setitem__(option_key, option_value)
            )
        except (MsfRpcError, KeyError, TypeError) as exc:
            logger.error(f"Failed to set option {key} on module: {exc}")
            raise ValueError(f"Failed to set option '{key}': {exc}") from exc
