"""Deterministic test doubles for optional runtime dependencies."""

from contextlib import asynccontextmanager
from types import ModuleType
from unittest.mock import Mock
import sys

class MockMCPServer:
    async def run(self, *args, **kwargs):
        return None

    def create_initialization_options(self):
        return {}

class MockFastMCP:
    def __init__(self, *args, **kwargs):
        self._mcp_server = MockMCPServer()
        self.tools = {}

    def tool(self, *args, **kwargs):
        def decorator(func):
            self.tools[func.__name__] = func
            return func
        return decorator

    def run(self, *args, **kwargs):
        return None

class MockFastAPI:
    def __init__(self, *args, **kwargs):
        self.routes = []

    @staticmethod
    def _identity_decorator(func):
        return func

    def get(self, *args, **kwargs):
        return self._identity_decorator

    def middleware(self, *args, **kwargs):
        return self._identity_decorator

class MockHTTPException(Exception):
    def __init__(self, status_code=None, detail=None, *args, **kwargs):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)

class MockRequest:
    def __init__(self, *args, **kwargs):
        self.headers = kwargs.get('headers', {})
        self.url = kwargs.get('url')

class MockResponse:
    def __init__(self, content=None, status_code=200, media_type=None, *args, **kwargs):
        self.content = content
        self.status_code = status_code
        self.media_type = media_type

class MockSseServerTransport:
    def __init__(self, endpoint, *args, **kwargs):
        self.endpoint = endpoint

    @asynccontextmanager
    async def connect_sse(self, *args, **kwargs):
        yield None, None

    async def handle_post_message(self, *args, **kwargs):
        return None

class MockServerSession:
    async def _received_request(self, *args, **kwargs):
        return None

class MockRoute:
    def __init__(self, path, endpoint=None, methods=None, *args, **kwargs):
        self.path = path
        self.endpoint = endpoint
        self.methods = methods

class MockMount:
    def __init__(self, path, app=None, *args, **kwargs):
        self.path = path
        self.app = app

class MockRouter:
    def __init__(self, routes=None, *args, **kwargs):
        self.routes = list(routes or [])

class MockStarlette:
    def __init__(self, *args, **kwargs):
        self.routes = []

class MockMsfRpcError(Exception):
    pass

class MockMsfConsole:
    def __init__(self, cid='test-console-id'):
        self.cid = cid
        self._command_history = []

    def read(self):
        return {'data': 'msf6 > ', 'prompt': '\\x01\\x02msf6\\x01\\x02 \\x01\\x02> \\x01\\x02', 'busy': False}

    def write(self, command):
        self._command_history.append(command.strip())
        return True

class MockMsfModule:
    def __init__(self, fullname):
        self.fullname = fullname
        self.options = {}
        self.runoptions = {}
        self.missing_required = []

    def __setitem__(self, key, value):
        self.options[key] = value

    def execute(self, payload=None):
        return {'job_id': 1234, 'uuid': 'test-uuid-123', 'error': False}

    def payload_generate(self):
        return b'test_payload_bytes'

class MockMsfRpcClient:
    def __init__(self):
        self.modules = Mock()
        self.core = Mock()
        self.sessions = Mock()
        self.jobs = Mock()
        self.consoles = Mock()
        self.core.version = {'version': '6.3.0'}
        self.modules.exploits = ['windows/smb/ms17_010_eternalblue', 'unix/ftp/vsftpd_234_backdoor']
        self.modules.payloads = ['windows/meterpreter/reverse_tcp', 'linux/x86/shell/reverse_tcp']
        self.sessions.list = Mock(return_value={})
        self.jobs.list = Mock(return_value={})

def install_import_stubs():
    uvicorn = ModuleType('uvicorn')

    fastapi = ModuleType('fastapi')
    fastapi.FastAPI = MockFastAPI
    fastapi.HTTPException = MockHTTPException
    fastapi.Request = MockRequest
    fastapi.Response = MockResponse

    starlette = ModuleType('starlette')
    starlette_applications = ModuleType('starlette.applications')
    starlette_applications.Starlette = MockStarlette
    starlette_routing = ModuleType('starlette.routing')
    starlette_routing.Route = MockRoute
    starlette_routing.Mount = MockMount
    starlette_routing.Router = MockRouter
    starlette.applications = starlette_applications
    starlette.routing = starlette_routing

    mcp = ModuleType('mcp')
    mcp_server = ModuleType('mcp.server')
    mcp_fastmcp = ModuleType('mcp.server.fastmcp')
    mcp_fastmcp.FastMCP = MockFastMCP
    mcp_sse = ModuleType('mcp.server.sse')
    mcp_sse.SseServerTransport = MockSseServerTransport
    mcp_session = ModuleType('mcp.server.session')
    mcp_session.ServerSession = MockServerSession
    mcp.server = mcp_server
    mcp_server.fastmcp = mcp_fastmcp
    mcp_server.sse = mcp_sse
    mcp_server.session = mcp_session

    pymetasploit3 = ModuleType('pymetasploit3')
    msfrpc = ModuleType('pymetasploit3.msfrpc')
    msfrpc.MsfRpcClient = MockMsfRpcClient
    msfrpc.MsfConsole = MockMsfConsole
    msfrpc.MsfRpcError = MockMsfRpcError
    pymetasploit3.msfrpc = msfrpc

    sys.modules.update({
        'uvicorn': uvicorn,
        'fastapi': fastapi,
        'starlette': starlette,
        'starlette.applications': starlette_applications,
        'starlette.routing': starlette_routing,
        'mcp': mcp,
        'mcp.server': mcp_server,
        'mcp.server.fastmcp': mcp_fastmcp,
        'mcp.server.sse': mcp_sse,
        'mcp.server.session': mcp_session,
        'pymetasploit3': pymetasploit3,
        'pymetasploit3.msfrpc': msfrpc,
    })

install_import_stubs()