#!/usr/bin/env python3
"""Shared pytest configuration and deterministic runtime dependency stubs."""

import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(__file__))
from tests.fakes import install_import_stubs  # noqa: E402

# Install before any test module imports MetasploitMCP. This prevents one test
# module from replacing mcp.* with a bare Mock and turning async tools into mocks.
install_import_stubs()


def pytest_configure(config):
    """Register project markers."""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line("markers", "integration: Integration tests")
    config.addinivalue_line("markers", "slow: Slow tests")
    config.addinivalue_line("markers", "network: Tests that require network access")


def pytest_collection_modifyitems(config, items):
    for item in items:
        if "test_options_parsing" in item.nodeid or "test_helpers" in item.nodeid:
            item.add_marker(pytest.mark.unit)
        if "test_tools_integration" in item.nodeid:
            item.add_marker(pytest.mark.integration)
        if "network" in item.name.lower():
            item.add_marker(pytest.mark.network)


@pytest.fixture(scope="session")
def mock_msf_environment():
    from tests.fakes import MockMsfRpcClient, MockMsfConsole, MockMsfRpcError

    yield {
        "client_class": MockMsfRpcClient,
        "console_class": MockMsfConsole,
        "error_class": MockMsfRpcError,
    }


@pytest.fixture
def mock_logger():
    with patch("MetasploitMCP.logger") as mock_log:
        yield mock_log


@pytest.fixture
def temp_payload_dir(tmp_path):
    payload_dir = tmp_path / "payloads"
    payload_dir.mkdir()
    with patch("MetasploitMCP.PAYLOAD_SAVE_DIR", str(payload_dir)):
        yield str(payload_dir)


@pytest.fixture
def mock_asyncio_to_thread():
    async def mock_to_thread(func, *args, **kwargs):
        return func(*args, **kwargs)

    with patch("asyncio.to_thread", side_effect=mock_to_thread):
        yield


@pytest.fixture
def capture_logs(caplog):
    import logging

    caplog.set_level(logging.DEBUG)
    return caplog


def pytest_addoption(parser):
    parser.addoption("--run-slow", action="store_true", default=False, help="Run slow tests")
    parser.addoption("--run-network", action="store_true", default=False, help="Run network tests")


def pytest_runtest_setup(item):
    if "slow" in item.keywords and not item.config.getoption("--run-slow"):
        pytest.skip("Skipping slow test (use --run-slow to run)")
    if "network" in item.keywords and not item.config.getoption("--run-network"):
        pytest.skip("Skipping network test (use --run-network to run)")


@pytest.fixture(autouse=True)
def enable_capabilities_for_tests():
    with patch.multiple(
        "MetasploitMCP",
        ALLOW_ACTIVE_ACTIONS=True,
        ALLOW_SESSION_CONTROL=True,
        ALLOW_PAYLOAD_GENERATION=True,
        ALLOW_LISTENER_CONTROL=True,
    ):
        yield


@pytest.fixture(autouse=True)
def reset_msf_client():
    with patch("MetasploitMCP._msf_client_instance", None):
        yield
