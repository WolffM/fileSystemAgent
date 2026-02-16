import json
import logging
from typing import Dict, List, Optional, Any

from mcp.client.session import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters
from mcp.types import CallToolResult


class MCPFileSystemOperations:
    """MCP-based file system operations wrapper"""

    def __init__(self, client_session: ClientSession):
        self.client = client_session
        self.logger = logging.getLogger(__name__)

    async def read_file(self, path: str, encoding: str = "utf-8") -> str:
        result = await self.client.call_tool("read_file", {
            "path": path,
            "encoding": encoding
        })

        if result.isError:
            raise Exception(f"MCP read_file error: {result.content[0].text}")

        return result.content[0].text

    async def write_file(self, path: str, content: str, encoding: str = "utf-8") -> bool:
        result = await self.client.call_tool("write_file", {
            "path": path,
            "content": content,
            "encoding": encoding
        })

        if result.isError:
            raise Exception(f"MCP write_file error: {result.content[0].text}")

        return True

    async def list_directory(self, path: str) -> List[Dict[str, Any]]:
        result = await self.client.call_tool("list_directory", {
            "path": path
        })

        if result.isError:
            raise Exception(f"MCP list_directory error: {result.content[0].text}")

        return json.loads(result.content[0].text)

    async def execute_command(self, command: str, args: List[str] = None, cwd: str = None) -> Dict[str, Any]:
        result = await self.client.call_tool("execute_command", {
            "command": command,
            "args": args or [],
            "cwd": cwd
        })

        return json.loads(result.content[0].text)

    async def create_directory(self, path: str, parents: bool = True) -> bool:
        result = await self.client.call_tool("create_directory", {
            "path": path,
            "parents": parents
        })

        if result.isError:
            raise Exception(f"MCP create_directory error: {result.content[0].text}")

        return True

    async def delete_file(self, path: str) -> bool:
        result = await self.client.call_tool("delete_file", {
            "path": path
        })

        if result.isError:
            raise Exception(f"MCP delete_file error: {result.content[0].text}")

        return True

    async def get_file_info(self, path: str) -> Dict[str, Any]:
        result = await self.client.call_tool("get_file_info", {
            "path": path
        })

        if result.isError:
            raise Exception(f"MCP get_file_info error: {result.content[0].text}")

        return json.loads(result.content[0].text)

    async def file_exists(self, path: str) -> bool:
        try:
            await self.get_file_info(path)
            return True
        except Exception:
            return False

    async def is_directory(self, path: str) -> bool:
        try:
            info = await self.get_file_info(path)
            return info.get("type") == "directory"
        except Exception:
            return False


class MCPFileSystemClient:
    """MCP client for file system operations"""

    def __init__(self, server_command: List[str] = None):
        self.server_command = server_command or ["python", "-m", "src.mcp_server"]
        self.client_session: Optional[ClientSession] = None
        self.operations: Optional[MCPFileSystemOperations] = None
        self._stdio_context = None
        self._session_context = None
        self.logger = logging.getLogger(__name__)

    async def __aenter__(self):
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.disconnect()

    async def connect(self):
        """Connect to MCP server"""
        try:
            self.logger.info("Connecting to MCP server")

            server_params = StdioServerParameters(
                command=self.server_command[0],
                args=self.server_command[1:]
            )

            # stdio_client is an async context manager
            self._stdio_context = stdio_client(server_params)
            read_stream, write_stream = await self._stdio_context.__aenter__()

            self._session_context = ClientSession(read_stream, write_stream)
            self.client_session = await self._session_context.__aenter__()

            await self.client_session.initialize()

            self.operations = MCPFileSystemOperations(self.client_session)
            self.logger.info("Connected to MCP server successfully")

        except Exception as e:
            self.logger.error(f"Failed to connect to MCP server: {e}")
            raise

    async def disconnect(self):
        """Disconnect from MCP server"""
        try:
            if self._session_context:
                await self._session_context.__aexit__(None, None, None)
            if self._stdio_context:
                await self._stdio_context.__aexit__(None, None, None)
            self.logger.info("Disconnected from MCP server")
        except Exception as e:
            self.logger.error(f"Error disconnecting from MCP server: {e}")

        self.client_session = None
        self.operations = None
        self._stdio_context = None
        self._session_context = None

    def is_connected(self) -> bool:
        return self.client_session is not None

    async def read_file(self, path: str, encoding: str = "utf-8") -> str:
        if not self.operations:
            raise RuntimeError("MCP client not connected")
        return await self.operations.read_file(path, encoding)

    async def write_file(self, path: str, content: str, encoding: str = "utf-8") -> bool:
        if not self.operations:
            raise RuntimeError("MCP client not connected")
        return await self.operations.write_file(path, content, encoding)

    async def list_directory(self, path: str) -> List[Dict[str, Any]]:
        if not self.operations:
            raise RuntimeError("MCP client not connected")
        return await self.operations.list_directory(path)

    async def execute_command(self, command: str, args: List[str] = None, cwd: str = None) -> Dict[str, Any]:
        if not self.operations:
            raise RuntimeError("MCP client not connected")
        return await self.operations.execute_command(command, args, cwd)

    async def create_directory(self, path: str, parents: bool = True) -> bool:
        if not self.operations:
            raise RuntimeError("MCP client not connected")
        return await self.operations.create_directory(path, parents)

    async def delete_file(self, path: str) -> bool:
        if not self.operations:
            raise RuntimeError("MCP client not connected")
        return await self.operations.delete_file(path)

    async def get_file_info(self, path: str) -> Dict[str, Any]:
        if not self.operations:
            raise RuntimeError("MCP client not connected")
        return await self.operations.get_file_info(path)

    async def file_exists(self, path: str) -> bool:
        if not self.operations:
            raise RuntimeError("MCP client not connected")
        return await self.operations.file_exists(path)

    async def is_directory(self, path: str) -> bool:
        if not self.operations:
            raise RuntimeError("MCP client not connected")
        return await self.operations.is_directory(path)
