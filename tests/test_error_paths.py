#!/usr/bin/env python3
"""Additional coverage for error branches and option-driven behavior."""

import asyncio
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest

import MetasploitMCP as app
from tests.fakes import MockMsfRpcClient, MockMsfRpcError


@pytest.mark.asyncio
async def test_generate_payload_optional_flags_and_file():
    client = MockMsfRpcClient()
    payload = Mock()
    payload.runoptions = {}
    payload.payload_generate.return_value = b"payload"
    tmp = tempfile.TemporaryDirectory()
    try:
        with (
            patch.object(app, "get_msf_client", return_value=client),
            patch.object(app, "_get_module_object", new_callable=AsyncMock, return_value=payload),
            patch.object(app, "_set_module_options", new_callable=AsyncMock),
            patch.object(app, "PAYLOAD_SAVE_DIR", tmp.name),
        ):
            result = await app.generate_payload(
                "windows/x64/test", "exe", {"LHOST": "127.0.0.1"},
                encoder="x86/shikata_ga_nai", iterations=2, bad_chars="\x00",
                nop_sled_size=8, template_path="/tmp/template.exe",
                keep_template=True, force_encode=True, output_filename="../safe.exe",
            )
        assert result["status"] == "success"
        assert Path(result["server_save_path"]).exists()
        assert payload.runoptions["Format"] == "exe"
        assert payload.runoptions["Encoder"] == "x86/shikata_ga_nai"
        assert payload.runoptions["Iterations"] == 2
        assert payload.runoptions["BadChars"] == "\x00"
        assert payload.runoptions["NopSledSize"] == 8
        assert payload.runoptions["Template"] == "/tmp/template.exe"
    finally:
        tmp.cleanup()


@pytest.mark.asyncio
async def test_generate_payload_generation_dict_error():
    client = MockMsfRpcClient()
    payload = Mock()
    payload.runoptions = {}
    payload.payload_generate.return_value = {"error": True, "error_message": "generation failed"}
    with (
        patch.object(app, "get_msf_client", return_value=client),
        patch.object(app, "_get_module_object", new_callable=AsyncMock, return_value=payload),
        patch.object(app, "_set_module_options", new_callable=AsyncMock),
    ):
        result = await app.generate_payload("windows/test", "raw", {"LHOST": "127.0.0.1"})
    assert result["status"] == "error"
    assert "generation failed" in result["message"]


@pytest.mark.asyncio
async def test_generate_payload_makedir_error():
    client = MockMsfRpcClient()
    payload = Mock()
    payload.runoptions = {}
    payload.payload_generate.return_value = b"payload"
    with (
        patch.object(app, "get_msf_client", return_value=client),
        patch.object(app, "_get_module_object", new_callable=AsyncMock, return_value=payload),
        patch.object(app, "_set_module_options", new_callable=AsyncMock),
        patch.object(app.os, "makedirs", side_effect=OSError("disk error")),
    ):
        result = await app.generate_payload("windows/test", "raw", {"LHOST": "127.0.0.1"})
    assert result["status"] == "error"
    assert "could not create save directory" in result["message"]


@pytest.mark.asyncio
async def test_generate_payload_write_error():
    client = MockMsfRpcClient()
    payload = Mock()
    payload.runoptions = {}
    payload.payload_generate.return_value = b"payload"
    with (
        patch.object(app, "get_msf_client", return_value=client),
        patch.object(app, "_get_module_object", new_callable=AsyncMock, return_value=payload),
        patch.object(app, "_set_module_options", new_callable=AsyncMock),
        patch.object(app, "open", side_effect=IOError("disk full")),
        patch.object(app.os, "makedirs"),
    ):
        result = await app.generate_payload("windows/test", "raw", {"LHOST": "127.0.0.1"})
    assert result["status"] == "error"
    assert "failed to save" in result["message"].lower()


@pytest.mark.asyncio
async def test_generate_payload_invalid_module():
    client = MockMsfRpcClient()
    with (
        patch.object(app, "get_msf_client", return_value=client),
        patch.object(app, "_get_module_object", new_callable=AsyncMock, side_effect=ValueError("Invalid payload type")),
    ):
        result = await app.generate_payload("bad", "raw", {"LHOST": "127.0.0.1"})
    assert result["status"] == "error"
    assert "Invalid payload type" in result["message"]


@pytest.mark.asyncio
async def test_generate_payload_missing_generate_method():
    client = MockMsfRpcClient()
    payload = SimpleNamespace(runoptions={})
    with (
        patch.object(app, "get_msf_client", return_value=client),
        patch.object(app, "_get_module_object", new_callable=AsyncMock, return_value=payload),
        patch.object(app, "_set_module_options", new_callable=AsyncMock),
    ):
        result = await app.generate_payload("windows/test", "raw", {"LHOST": "127.0.0.1"})
    assert result["status"] == "error"
    assert "payload module doesn't have the payload_generate method" in result["message"]


@pytest.mark.asyncio
async def test_execute_module_console_quotes_string_option():
    """Console option values containing separators must be quoted."""
    console = Mock()
    console.write = Mock()
    console.read = Mock(return_value={
        "data": "msf6 > ",
        "prompt": "\x01\x02msf6\x01\x02 \x01\x02> \x01\x02",
        "busy": False,
    })
    calls = []

    async def fake_command(_console, command, execution_timeout=None):
        calls.append(command)
        return "msf6 > "

    with (
        patch.object(app, "get_msf_console", return_value=_Context(console)),
        patch.object(app, "run_command_safely", new_callable=AsyncMock, side_effect=fake_command),
        patch.object(app.asyncio, "sleep", new_callable=AsyncMock),
    ):
        result = await app._execute_module_console(
            "auxiliary", "scanner/http/title",
            {"RHOSTS": "example.com; echo SHOULD_NOT_EXECUTE"},
            "run",
        )

    assert result["status"] == "success"
    assert "set RHOSTS 'example.com; echo SHOULD_NOT_EXECUTE'" in calls


@pytest.mark.asyncio
async def test_run_exploit_check_exception_continues():
    with (
        patch.object(app, "_execute_module_console", new_callable=AsyncMock, side_effect=RuntimeError("check failed")),
        patch.object(app, "_execute_module_rpc", new_callable=AsyncMock, return_value={"status": "success"}),
    ):
        result = await app.run_exploit("test/module", {}, run_as_job=True, check_vulnerability=True)
    assert result["status"] == "success"


@pytest.mark.asyncio
async def test_run_exploit_check_error_aborts():
    with patch.object(app, "_execute_module_console", new_callable=AsyncMock, return_value={
        "status": "error", "message": "check command failed", "module_output": "check failed"
    }):
        result = await app.run_exploit("test/module", {}, check_vulnerability=True)
    assert result["status"] == "aborted"


@pytest.mark.asyncio
async def test_run_post_module_rpc_error_on_session_validation():
    client = MockMsfRpcClient()
    client.sessions.list = Mock(side_effect=MockMsfRpcError("session list failed"))
    with patch.object(app, "get_msf_client", return_value=client):
        result = await app.run_post_module("test/module", 7, {})
    assert result["status"] == "error"
    assert "validating session" in result["message"]


@pytest.mark.asyncio
async def test_run_post_module_console_path():
    client = MockMsfRpcClient()
    client.sessions.list = Mock(return_value={"7": {"type": "meterpreter"}})
    with (
        patch.object(app, "get_msf_client", return_value=client),
        patch.object(app, "_execute_module_console", new_callable=AsyncMock, return_value={"status": "success"}) as console,
    ):
        result = await app.run_post_module("test/module", 7, {}, run_as_job=False)
    assert result["status"] == "success"
    console.assert_called_once()


@pytest.mark.asyncio
async def test_run_auxiliary_check_positive_then_runs():
    with (
        patch.object(app, "_execute_module_console", new_callable=AsyncMock, side_effect=[
            {"status": "success", "module_output": "Target appears reachable"},
            {"status": "success"},
        ])
    ):
        result = await app.run_auxiliary_module("scanner/http/title", {}, check_target=True, run_as_job=False)
    assert result["status"] == "success"


@pytest.mark.asyncio
async def test_run_auxiliary_check_exception_continues():
    with (
        patch.object(app, "_execute_module_console", new_callable=AsyncMock, side_effect=RuntimeError("check failed")),
        patch.object(app, "_execute_module_rpc", new_callable=AsyncMock, return_value={"status": "success"}),
    ):
        result = await app.run_auxiliary_module("scanner/http/title", {}, check_target=True, run_as_job=True)
    assert result["status"] == "success"


@pytest.mark.asyncio
async def test_list_active_sessions_timeout():
    client = MockMsfRpcClient()
    with (
        patch.object(app, "get_msf_client", return_value=client),
        patch.object(app.asyncio, "to_thread", new_callable=AsyncMock, side_effect=asyncio.TimeoutError),
    ):
        result = await app.list_active_sessions()
    assert result["status"] == "error"
    assert "Timeout" in result["message"]


@pytest.mark.asyncio
async def test_list_active_sessions_rpc_error():
    client = MockMsfRpcClient()
    client.sessions.list = Mock(side_effect=MockMsfRpcError("rpc"))
    with patch.object(app, "get_msf_client", return_value=client):
        result = await app.list_active_sessions()
    assert result["status"] == "error"
    assert "RPC error" in result["message"]


@pytest.mark.asyncio
async def test_list_active_sessions_bad_type():
    client = MockMsfRpcClient()
    client.sessions.list = Mock(return_value=[])
    with patch.object(app, "get_msf_client", return_value=client):
        result = await app.list_active_sessions()
    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_send_session_command_meterpreter_error():
    client = MockMsfRpcClient()
    session = Mock()
    session.run_with_output.side_effect = MockMsfRpcError("command failed")
    client.sessions.list = Mock(return_value={"100": {"type": "meterpreter"}})
    client.sessions.session = Mock(return_value=session)
    with patch.object(app, "get_msf_client", return_value=client):
        result = await app.send_session_command(100, "id")
    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_send_session_command_shell_inactivity_success():
    client = MockMsfRpcClient()
    session = Mock()
    session.write = Mock()
    session.read = Mock(return_value="")
    client.sessions.list = Mock(return_value={"101": {"type": "shell"}})
    client.sessions.session = Mock(return_value=session)
    fake_loop = Mock()
    fake_loop.time = Mock(side_effect=[0.0, 1.0])
    with (
        patch.object(app, "get_msf_client", return_value=client),
        patch.object(app.asyncio, "get_event_loop", return_value=fake_loop),
        patch.object(app.asyncio, "sleep", new_callable=AsyncMock),
        patch.object(app, "SESSION_READ_INACTIVITY_TIMEOUT", 0),
    ):
        result = await app.send_session_command(101, "id", timeout_seconds=2)
    assert result["status"] == "success"


@pytest.mark.asyncio
async def test_send_session_command_invalid_session_id_rpc_error():
    client = MockMsfRpcClient()
    client.sessions.list = Mock(side_effect=MockMsfRpcError("Session ID is not valid"))
    with patch.object(app, "get_msf_client", return_value=client):
        result = await app.send_session_command(102, "id")
    assert result["status"] == "error"
    assert "not valid" in result["message"]


@pytest.mark.asyncio
async def test_list_listeners_timeout():
    client = MockMsfRpcClient()
    with (
        patch.object(app, "get_msf_client", return_value=client),
        patch.object(app.asyncio, "to_thread", new_callable=AsyncMock, side_effect=asyncio.TimeoutError),
    ):
        result = await app.list_listeners()
    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_list_listeners_bad_type():
    client = MockMsfRpcClient()
    client.jobs.list = Mock(return_value=[])
    with patch.object(app, "get_msf_client", return_value=client):
        result = await app.list_listeners()
    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_start_listener_parse_error():
    with patch.object(app, "_parse_options_gracefully", side_effect=ValueError("bad options")):
        result = await app.start_listener("windows/x64/test", "127.0.0.1", 4444, "bad")
    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_stop_job_still_present_after_stop():
    client = MockMsfRpcClient()
    client.jobs.list = Mock(side_effect=[
        {"1": {"name": "handler"}},
        {"1": {"name": "handler"}},
    ])
    client.jobs.stop = Mock(return_value="ok")
    with patch.object(app, "get_msf_client", return_value=client), patch.object(app.asyncio, "sleep", new_callable=AsyncMock):
        result = await app.stop_job(1)
    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_stop_job_rpc_error():
    client = MockMsfRpcClient()
    client.jobs.list = Mock(side_effect=MockMsfRpcError("rpc"))
    with patch.object(app, "get_msf_client", return_value=client):
        result = await app.stop_job(1)
    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_terminate_session_not_found():
    client = MockMsfRpcClient()
    client.sessions.list = Mock(return_value={})
    with patch.object(app, "get_msf_client", return_value=client):
        result = await app.terminate_session(1)
    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_terminate_session_rpc_error():
    client = MockMsfRpcClient()
    client.sessions.list = Mock(side_effect=MockMsfRpcError("rpc"))
    with patch.object(app, "get_msf_client", return_value=client):
        result = await app.terminate_session(1)
    assert result["status"] == "error"


@pytest.mark.asyncio
async def test_health_check_timeout():
    client = MockMsfRpcClient()
    with (
        patch.object(app, "get_msf_client", return_value=client),
        patch.object(app.asyncio, "to_thread", new_callable=AsyncMock, side_effect=asyncio.TimeoutError),
    ):
        with pytest.raises(app.HTTPException) as exc_info:
            await app.health_check()
    assert exc_info.value.status_code == 503


@pytest.mark.asyncio
async def test_health_check_connection_error():
    with patch.object(app, "get_msf_client", side_effect=ConnectionError("down")):
        with pytest.raises(app.HTTPException) as exc_info:
            await app.health_check()
    assert exc_info.value.status_code == 503


@pytest.mark.asyncio
async def test_health_check_generic_error():
    with patch.object(app, "get_msf_client", side_effect=RuntimeError("boom")):
        with pytest.raises(app.HTTPException) as exc_info:
            await app.health_check()
    assert exc_info.value.status_code == 500
