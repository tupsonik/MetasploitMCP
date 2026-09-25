#!/usr/bin/env python3
"""Unit tests for security controls in MetasploitMCP."""

import pytest
from unittest.mock import patch

from MetasploitMCP import (
    _is_loopback_host,
    _require_capability,
    _validate_command,
    _validate_timeout,
)


class TestSecurityHelpers:
    def test_loopback_detection(self):
        assert _is_loopback_host("127.0.0.1") is True
        assert _is_loopback_host("localhost") is True
        assert _is_loopback_host("::1") is True
        assert _is_loopback_host("0.0.0.0") is False
        assert _is_loopback_host("192.168.1.10") is False

    def test_command_validation_accepts_normal_command(self):
        _validate_command("whoami")
        _validate_command("uname -a")

    def test_command_validation_rejects_empty(self):
        with pytest.raises(ValueError, match="non-empty"):
            _validate_command("   ")

    def test_command_validation_rejects_nul(self):
        with pytest.raises(ValueError, match="NUL"):
            _validate_command("whoami\x00")

    def test_command_validation_rejects_oversized(self):
        with patch("MetasploitMCP.MAX_COMMAND_LENGTH", 8):
            with pytest.raises(ValueError, match="maximum length"):
                _validate_command("123456789")

    def test_timeout_validation(self):
        assert _validate_timeout(5) == 5
        with pytest.raises(ValueError, match="between"):
            _validate_timeout(0)
        with patch("MetasploitMCP.MAX_TOOL_TIMEOUT", 10):
            with pytest.raises(ValueError, match="between"):
                _validate_timeout(11)

    @pytest.mark.parametrize(
        "flag,capability",
        [
            ("ALLOW_ACTIVE_ACTIONS", "active_actions"),
            ("ALLOW_SESSION_CONTROL", "session_control"),
            ("ALLOW_PAYLOAD_GENERATION", "payload_generation"),
            ("ALLOW_LISTENER_CONTROL", "listener_control"),
        ],
    )
    def test_capabilities_are_denied_by_default(self, flag, capability):
        with patch(f"MetasploitMCP.{flag}", False):
            with pytest.raises(PermissionError, match="disabled"):
                _require_capability(capability)

    def test_enabled_capability_is_allowed(self):
        with patch("MetasploitMCP.ALLOW_ACTIVE_ACTIONS", True):
            _require_capability("active_actions")
