#!/usr/bin/env python3
"""Branch and error-path tests for the Metasploit MCP server."""

import asyncio
from unittest.mock import AsyncMock, Mock, patch

import pytest

import MetasploitMCP as app
from tests.fakes import MockMsfModule, MockMsfRpcClient, MockMsfRpcError, MockMsfConsole


@pytest.mark.asyncio
async def test_check_msf_connection_success():
    client = MockMsfRpcClient()
    with patch.object(app, "get_msf_client", return_value=client):
        result = await app.check_msf_connection()
    assert result["status"] == "connected"
    assert result["version"] == "6.3.0"


@pytest.mark.asyncio
async def test_check_msf_connection_timeout():
    with patch.object(app.asyncio, "to_thread", new_callable=AsyncMock, side_effect=asyncio.TimeoutError):
        result = await app.check_msf_connection()
    assert result["status"] == "timeout"


@pytest.mark.asyncio
async def test_check_msf_connection_not_initialized():
    with patch.object(app, "get_msf_client", side_effect=ConnectionError("not ready")):
        result = await app.check_msf_connection()
    assert result["status"] == "not_initialized"


@pytest.mark.asyncio
async def test_check_msf_connection_rpc_error():
    with patch.object(app, "get_msf_client", side_effect=MockMsfRpcError("rpc down")):
        result = await app.check_msf_connection()
    assert result["status"] == "rpc_error"


@pytest.mark.asyncio
async def test_check_msf_connection_unexpected_error():
    with patch.object(app, "get_msf_client", side_effect=RuntimeError("boom")):
        result = await app.check_msf_connection()
    assert result["status"] == "error"


def test_initialize_msf_client_missing_password():
    with patch.object(app, "_msf_client_instance", None), patch.object(app, "MSF_PASSWORD", None):
        with pytest.raises(RuntimeError, match="MSF_PASSWORD"):
            app.initialize_msf_client()


def test_initialize_msf_client_remote_warns_without_tls():
    client = MockMsfRpcClient()
    with (
        patch.object(app, "_msf_client_instance", None),
        patch.object(app, "MSF_PASSWORD", "test-password"),
        patch.object(app, "MSF_SERVER", "10.0.0.10"),
        patch.object(app, "MSF_PORT_STR", "55553"),
        patch.object(app, "MSF_SSL_STR", "false"),
        patch.object(app, "MsfRpcClient", return_value=client),
        patch.object(app.logger, "warning") as warning,
    ):
        result = app.initialize_msf_client()
    assert result is client
    warning.assert_called()


def test_initialize_msf_client_rpc_error():
    with (
        patch.object(app, "_msf_client_instance", None),
        patch.object(app, "MSF_PASSWORD", "test-password"),
        patch.object(app, "MsfRpcClient", side_effect=MockMsfRpcError("auth failed")),
    ):
        with pytest.raises(ConnectionError, match="Failed to connect"):
            app.initialize_msf_client()


def test_initialize_msf_client_unexpected_error():
    with (
        patch.object(app, "_msf_client_instance", None),
        patch.object(app, "MSF_PASSWORD", "test-password"),
        patch.object(app, "MsfRpcClient", side_effect=RuntimeError("boom")),
    ):
        with pytest.raises(RuntimeError, match="Unexpected error"):
            app.initialize_msf_client()


@pytest.mark.asyncio
async def test_run_command_safely_detects_buffer_prompt():
    console = Mock()
    console.write = Mock()
    console.read = Mock(return_value={
        "data": "done\n",
        "prompt": "",
        "busy": False,
    })
    with patch.object(app, "MSF_PROMPT_RE", __import__("re").compile(rb"done")):
        result = await app.run_command_safely(console, "help")
    assert "done" in result


@pytest.mark.asyncio
async def test_run_command_safely_overall_timeout():
    console = Mock()
    console.write = Mock()
    console.read = Mock(return_value={"data": "", "prompt": "", "busy": True})
    times = iter([0.0, 2.0])
    with (
        patch.object(app.asyncio.get_event_loop(), "time", side_effect=lambda: next(times)),
        patch.object(app, "DEFAULT_CONSOLE_READ_TIMEOUT", 1),
    ):
        result = await app.run_command_safely(console, "help")
    assert result == ""


@pytest.mark.asyncio
async def test_get_msf_console_invalid_object():
    client = Mock()
    client.consoles.console.return_value = object()
    with patch.object(app, "get_msf_client", return_value=client):
        with pytest.raises(MockMsfRpcError, match="Unexpected result"):
            async with app.get_msf_console():
                pass


@pytest.mark.asyncio
async def test_execute_module_rpc_auxiliary_success():
    client = MockMsfRpcClient()
    module = MockMsfModule("auxiliary/scanner/http/title")
    module.execute = Mock(return_value={"job_id": 12, "uuid": None, "error": False})
    with (
        patch.object(app, "get_msf_client", return_value=client),
        patch.object(app, "_get_module_object", new_callable=AsyncMock, return_value=module),
        patch.object(app, "_set_module_options", new_callable=AsyncMock),
    ):
        result = await app._execute_module_rpc(
            "auxiliary", "scanner/http/title", {"RHOSTS": "example.com"}
        )
    assert result["status"] == "success"
    assert result["job_id"] == 12


@pytest.mark.asyncio
async def test_execute_module_rpc_non_dict_result():
    client = MockMsfRpcClient()
    module = MockMsfModule("auxiliary/test")
    module.execute = Mock(return_value="bad-result")
    with (
        patch.object(app, "get_msf_client", return_value=client),
        patch.object(app, "_get_module_object", new_callable=AsyncMock, return_value=module),
        patch.object(app, "_set_module_options", new_callable=AsyncMock),
    ):
        result = await app._execute_module_rpc("auxiliary", "test", {})
    assert result["status"] == "error"
    assert "Unexpected result" in result["message"]


@pytest.mark.asyncio
async def test_execute_module_rpc_bind_error():
    client = MockMsfRpcClient()
    module = MockMsfModule("auxiliary/test")
    module.execute = Mock(return_value={"error": True, "error_message": "Could not bind address"})
    with (
        patch.object(app, "get_msf_client", return_value=client),
        patch.object(app, "_get_module_object", new_callable=AsyncMock, return_value=module),
        patch.object(app, "_set_module_options", new_callable=AsyncMock),
    ):
        result = await app._execute_module_rpc("auxiliary", "test", {})
    assert result["status"] == "error"
    assert "Address/Port" in result["message"]


@pytest.mark.asyncio
async def test_execute_module_rpc_no_job_id():
    client = MockMsfRpcClient()
    module = MockMsfModule("auxiliary/test")
    module.execute = Mock(return_value={"error": False})
    with (
        patch.object(app, "get_msf_client", return_value=client),
        patch.object(app, "_get_module_object", new_callable=AsyncMock, return_value=module),
        patch.object(app, "_set_module_options", new_callable=AsyncMock),
        patch.object(app.asyncio, "sleep", new_callable=AsyncMock),
    ):
        result = await app._execute_module_rpc("auxiliary", "test", {})
    assert result["status"] == "unknown"


@pytest.mark.asyncio
async def test_execute_module_rpc_exploit_finds_session():
    client = MockMsfRpcClient()
    module = MockMsfModule("exploit/test")
    module.execute = Mock(return_value={"job_id": 12, "uuid": "u1", "error": False})
    client.sessions.list = Mock(return_value={"3": {"exploit_uuid": "u1", "type": "shell"}})
    with (
        patch.object(app, "get_msf_client", return_value=client),
        patch.object(app, "_get_module_object", new_callable=AsyncMock, return_value=module),
        patch.object(app, "_set_module_options", new_callable=AsyncMock),
        patch.object(app, "EXPLOIT_SESSION_POLL_TIMEOUT", 1),
        patch.object(app, "EXPLOIT_SESSION_POLL_INTERVAL", 0),
    ):
        result = await app._execute_module_rpc("exploit", "test", {})
    assert result["status"] == "success"
    assert result["session_id"] == "3"


@pytest.mark.asyncio
async def test_execute_module_rpc_payload_setup_error():
    client = MockMsfRpcClient()
    module = MockMsfModule("exploit/test")
    with (
        patch.object(app, "get_msf_client", return_value=client),
        patch.object(app, "_get_module_object", new_callable=AsyncMock, side_effect=[
            module,
            ValueError("unknown module"),
        ]),
        patch.object(app, "_set_module_options", new_callable=AsyncMock),
    ):
        result = await app._execute_module_rpc(
            "exploit", "test", {}, {"name": "bad/payload", "options": {}}
        )
    assert result["status"] == "error"
    assert "prepare payload" in result["message"]


@pytest.mark.asyncio
async def test_execute_module_console_auxiliary_success():
    console = MockMsfConsole()
    outputs = iter(["", "", "HTTP result\nmsf6 > "])
    async def fake_command(*args, **kwargs):
        return next(outputs)
    with (
        patch.object(app, "get_msf_console", return_value=app._test_console_context(console)),
        patch.object(app, "run_command_safely", new=AsyncMock(side_effect=fake_command)),
    ):
        result = await app._execute_module_console(
            "auxiliary", "scanner/http/title", {"RHOSTS": "example.com"}, "run"
        )
    assert result["status"] == "success"
    assert "HTTP result" in result["module_output"]


@pytest.mark.asyncio
async def test_execute_module_console_setup_error():
    console = MockMsfConsole()
    calls = {"n": 0}
    async def fake_command(*args, **kwargs):
        calls["n"] += 1
        return "[-] Error setting option" if calls["n"] == 2 else ""
    with (
        patch.object(app, "get_msf_console", return_value=app._test_console_context(console)),
        patch.object(app, "run_command_safely", new=AsyncMock(side_effect=fake_command)),
    ):
        result = await app._execute_module_console(
            "auxiliary", "scanner/http/title", {"RHOSTS": "example.com"}, "run"
        )
    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_execute_module_console_invalid_payload_name():
    console = MockMsfConsole()
    with pytest.raises(ValueError, match="Invalid Metasploit module name"):
        await app._execute_module_console(
            "exploit", "test/module", {}, "exploit",
            {"name": "bad payload;exit", "options": {}},
        )


@pytest.mark.asyncio
async def test_run_exploit_check_aborts_on_negative():
    with (
        patch.object(app, "_execute_module_console", new_callable=AsyncMock, return_value={
            "status": "success", "module_output": "Target is not vulnerable"
        }),
        patch.object(app, "_execute_module_rpc", new_callable=AsyncMock) as rpc,
    ):
        result = await app.run_exploit("test/module", {}, check_vulnerability=True, run_as_job=True)
    assert result["status"] == "aborted"
    rpc.assert_not_called()


@pytest.mark.asyncio
async def test_run_exploit_check_positive_then_runs():
    with (
        patch.object(app, "_execute_module_console", new_callable=AsyncMock, return_value={
            "status": "success", "module_output": "Target appears vulnerable"
        }),
        patch.object(app, "_execute_module_rpc", new_callable=AsyncMock, return_value={"status": "success"}),
    ):
        result = await app.run_exploit("test/module", {}, check_vulnerability=True, run_as_job=True)
    assert result["status"] == "success"


@pytest.mark.asyncio
async def test_run_exploit_check_inconclusive_then_console():
    with (
        patch.object(app, "_execute_module_console", new_callable=AsyncMock, return_value={
            "status": "success", "module_output": "No definitive result"
        }),
    ):
        result = await app.run_exploit("test/module", {}, check_vulnerability=True, run_as_job=False)
    assert result["status"] == "success"


@pytest.mark.asyncio
async def test_run_post_module_missing_session():
    client = MockMsfRpcClient()
    client.sessions.list = Mock(return_value={})
    with patch.object(app, "get_msf_client", return_value=client):
        result = await app.run_post_module("test/module", 99, {})
    assert result["status"] == "error"
    assert "not found" in result["message"]


@pytest.mark.asyncio
async def test_run_post_module_job_path():
    client = MockMsfRpcClient()
    client.sessions.list = Mock(return_value={"7": {"type": "meterpreter"}})
    with (
        patch.object(app, "get_msf_client", return_value=client),
        patch.object(app, "_execute_module_rpc", new_callable=AsyncMock, return_value={"status": "success"}) as rpc,
    ):
        result = await app.run_post_module("test/module", 7, {}, run_as_job=True)
    assert result["status"] == "success"
    rpc.assert_called_once()


@pytest.mark.asyncio
async def test_run_auxiliary_check_negative():
    with patch.object(app, "_execute_module_console", new_callable=AsyncMock, return_value={
        "status": "success", "module_output": "Target is not reachable"
    }):
        result = await app.run_auxiliary_module("scanner/http/title", {}, check_target=True)
    assert result["status"] == "aborted"


@pytest.mark.asyncio
async def test_run_auxiliary_job_path():
    with patch.object(app, "_execute_module_rpc", new_callable=AsyncMock, return_value={"status": "success"}) as rpc:
        result = await app.run_auxiliary_module("scanner/http/title", {}, run_as_job=True)
    assert result["status"] == "success"
    rpc.assert_called_once()


@pytest.mark.asyncio
async def test_list_listeners_categorizes_jobs():
    client = MockMsfRpcClient()
    client.jobs.list = Mock(return_value={
        "1": {"name": "exploit/multi/handler", "info": "", "datastore": {"LHOST": "127.0.0.1", "LPORT": 4444}},
        "2": {"name": "portscan", "info": "", "datastore": {}},
    })
    with patch.object(app, "get_msf_client", return_value=client):
        result = await app.list_listeners()
    assert result["handler_count"] == 1
    assert result["other_job_count"] == 1


@pytest.mark.asyncio
async def test_list_listeners_rpc_error():
    client = MockMsfRpcClient()
    client.jobs.list = Mock(side_effect=MockMsfRpcError("down"))
    with patch.object(app, "get_msf_client", return_value=client):
        result = await app.list_listeners()
    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_send_session_command_shell():
    client = MockMsfRpcClient()
    session = Mock()
    session.write = Mock()
    session.read = Mock(side_effect=["data\n", "# "])
    session.run_with_output = Mock()
    client.sessions.list = Mock(return_value={"1": {"type": "shell"}})
    client.sessions.session = Mock(return_value=session)
    with patch.object(app, "get_msf_client", return_value=client), patch.object(app.asyncio, "sleep", new_callable=AsyncMock):
        result = await app.send_session_command(1, "whoami", timeout_seconds=1)
    assert result["status"] == "success"
    session.write.assert_called_once_with("whoami\n")


@pytest.mark.asyncio
async def test_send_session_command_exit_shell():
    client = MockMsfRpcClient()
    session = Mock()
    session.write = Mock()
    session.read = Mock(return_value="# ")
    client.sessions.list = Mock(return_value={"1": {"type": "shell"}})
    client.sessions.session = Mock(return_value=session)
    with patch.object(app, "get_msf_client", return_value=client), patch.object(app.asyncio, "sleep", new_callable=AsyncMock):
        result = await app.send_session_command(1, "exit")
    assert result["status"] == "success"


@pytest.mark.asyncio
async def test_send_session_command_unknown_type():
    client = MockMsfRpcClient()
    session = Mock()
    client.sessions.list = Mock(return_value={"1": {"type": "strange"}})
    client.sessions.session = Mock(return_value=session)
    with patch.object(app, "get_msf_client", return_value=client):
        result = await app.send_session_command(1, "id")
    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_send_session_command_session_object_missing():
    client = MockMsfRpcClient()
    client.sessions.list = Mock(return_value={"1": {"type": "shell"}})
    client.sessions.session = Mock(return_value=None)
    with patch.object(app, "get_msf_client", return_value=client):
        result = await app.send_session_command(1, "id")
    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_stop_job_not_found():
    client = MockMsfRpcClient()
    client.jobs.list = Mock(return_value={})
    with patch.object(app, "get_msf_client", return_value=client):
        result = await app.stop_job(10)
    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_terminate_session_warning():
    client = MockMsfRpcClient()
    session = Mock()
    client.sessions.list = Mock(side_effect=[
        {"1": {"type": "shell"}},
        {"1": {"type": "shell"}},
    ])
    client.sessions.session = Mock(return_value=session)
    session.stop = Mock()
    with patch.object(app, "get_msf_client", return_value=client), patch.object(app.asyncio, "sleep", new_callable=AsyncMock):
        result = await app.terminate_session(1)
    assert result["status"] == "warning"


@pytest.mark.asyncio
async def test_healthz_is_liveness_only():
    result = await app.healthz()
    assert result["status"] == "ok"


@pytest.mark.asyncio
async def test_health_check_success():
    client = MockMsfRpcClient()
    with patch.object(app, "get_msf_client", return_value=client):
        result = await app.health_check()
    assert result["status"] == "ok"
    assert result["msf_version"] == "6.3.0"


class _Context:
    def __init__(self, value):
        self.value = value

    async def __aenter__(self):
        return self.value

    async def __aexit__(self, exc_type, exc, tb):
        return False


# Keep context creation local to tests so production imports remain unchanged.
def _test_console_context(console):
    return _Context(console)


app._test_console_context = _test_console_context
