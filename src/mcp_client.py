import asyncio
import json
import logging
from typing import Dict, List, Optional, Any, Union
from pathlib import Path
from dataclasses import dataclass

from mcp.client import ClientSession
from mcp.client.stdio import stdio_client
from mcp.types import CallToolResult

from .models import FileSystemEvent


@dataclass
class MCPFileSystemOperations:
    """MCP-based file system operations wrapper"""
    
    def __init__(self, client_session: ClientSession):
        self.client = client_session
        self.logger = logging.getLogger(__name__)
    
    async def read_file(self, path: str, encoding: str = "utf-8") -> str:
        """Read a file using MCP"""
        try:
            result = await self.client.call_tool("read_file", {
                "path": path,
                "encoding": encoding
            })
            
            if result.isError:
                raise Exception(f"MCP read_file error: {result.content[0].text}")
            
            return result.content[0].text
            
        except Exception as e:
            self.logger.error(f"MCP read_file failed for {path}: {e}")
            raise
    
    async def write_file(self, path: str, content: str, encoding: str = "utf-8") -> bool:
        """Write a file using MCP"""
        try:
            result = await self.client.call_tool("write_file", {
                "path": path,
                "content": content,
                "encoding": encoding
            })
            
            if result.isError:
                raise Exception(f"MCP write_file error: {result.content[0].text}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"MCP write_file failed for {path}: {e}")
            raise
    
    async def list_directory(self, path: str) -> List[Dict[str, Any]]:
        """List directory contents using MCP"""
        try:
            result = await self.client.call_tool("list_directory", {
                "path": path
            })
            
            if result.isError:
                raise Exception(f"MCP list_directory error: {result.content[0].text}")
            
            return json.loads(result.content[0].text)
            
        except Exception as e:
            self.logger.error(f"MCP list_directory failed for {path}: {e}")
            raise
    
    async def execute_command(self, command: str, args: List[str] = None, cwd: str = None) -> Dict[str, Any]:
        """Execute command using MCP"""
        try:
            result = await self.client.call_tool("execute_command", {
                "command": command,
                "args": args or [],
                "cwd": cwd
            })
            
            # Note: MCP execute_command returns result even on non-zero exit codes
            # The isError flag indicates if the command execution itself failed
            return json.loads(result.content[0].text)
            
        except Exception as e:
            self.logger.error(f"MCP execute_command failed for {command}: {e}")
            raise
    
    async def create_directory(self, path: str, parents: bool = True) -> bool:
        """Create directory using MCP"""
        try:
            result = await self.client.call_tool("create_directory", {
                "path": path,
                "parents": parents
            })
            
            if result.isError:
                raise Exception(f"MCP create_directory error: {result.content[0].text}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"MCP create_directory failed for {path}: {e}")
            raise
    
    async def delete_file(self, path: str) -> bool:
        """Delete file using MCP"""
        try:
            result = await self.client.call_tool("delete_file", {
                "path": path
            })
            
            if result.isError:
                raise Exception(f"MCP delete_file error: {result.content[0].text}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"MCP delete_file failed for {path}: {e}")
            raise
    
    async def get_file_info(self, path: str) -> Dict[str, Any]:
        """Get file info using MCP"""
        try:
            result = await self.client.call_tool("get_file_info", {
                "path": path
            })
            
            if result.isError:
                raise Exception(f"MCP get_file_info error: {result.content[0].text}")
            
            return json.loads(result.content[0].text)
            
        except Exception as e:
            self.logger.error(f"MCP get_file_info failed for {path}: {e}")
            raise
    
    async def file_exists(self, path: str) -> bool:
        """Check if file exists using MCP"""
        try:
            await self.get_file_info(path)
            return True
        except:
            return False
    
    async def is_directory(self, path: str) -> bool:
        """Check if path is directory using MCP"""
        try:
            info = await self.get_file_info(path)
            return info.get("type") == "directory"
        except:
            return False


class MCPFileSystemClient:
    """MCP client for file system operations"""
    
    def __init__(self, server_command: List[str] = None):
        self.server_command = server_command or ["python", "-m", "src.mcp_server"]
        self.client_session: Optional[ClientSession] = None
        self.operations: Optional[MCPFileSystemOperations] = None
        self.logger = logging.getLogger(__name__)
    
    async def __aenter__(self):
        """Async context manager entry"""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        await self.disconnect()
    
    async def connect(self):
        """Connect to MCP server"""
        try:
            self.logger.info("Connecting to MCP server")
            
            # Create stdio client
            self.client_session = await stdio_client(self.server_command)
            
            # Initialize operations wrapper
            self.operations = MCPFileSystemOperations(self.client_session)
            
            self.logger.info("Connected to MCP server successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to connect to MCP server: {e}")
            raise
    
    async def disconnect(self):
        """Disconnect from MCP server"""
        if self.client_session:
            try:
                await self.client_session.close()
                self.logger.info("Disconnected from MCP server")
            except Exception as e:
                self.logger.error(f"Error disconnecting from MCP server: {e}")
        
        self.client_session = None
        self.operations = None
    
    def is_connected(self) -> bool:
        """Check if connected to MCP server"""
        return self.client_session is not None
    
    async def read_file(self, path: str, encoding: str = "utf-8") -> str:
        """Read file via MCP"""
        if not self.operations:
            raise RuntimeError("MCP client not connected")
        return await self.operations.read_file(path, encoding)
    
    async def write_file(self, path: str, content: str, encoding: str = "utf-8") -> bool:
        """Write file via MCP"""
        if not self.operations:
            raise RuntimeError("MCP client not connected")
        return await self.operations.write_file(path, content, encoding)
    
    async def list_directory(self, path: str) -> List[Dict[str, Any]]:
        """List directory via MCP"""
        if not self.operations:
            raise RuntimeError("MCP client not connected")
        return await self.operations.list_directory(path)
    
    async def execute_command(self, command: str, args: List[str] = None, cwd: str = None) -> Dict[str, Any]:
        """Execute command via MCP"""
        if not self.operations:
            raise RuntimeError("MCP client not connected")
        return await self.operations.execute_command(command, args, cwd)
    
    async def create_directory(self, path: str, parents: bool = True) -> bool:
        """Create directory via MCP"""
        if not self.operations:
            raise RuntimeError("MCP client not connected")
        return await self.operations.create_directory(path, parents)
    
    async def delete_file(self, path: str) -> bool:
        """Delete file via MCP"""
        if not self.operations:
            raise RuntimeError("MCP client not connected")
        return await self.operations.delete_file(path)
    
    async def get_file_info(self, path: str) -> Dict[str, Any]:
        """Get file info via MCP"""
        if not self.operations:
            raise RuntimeError("MCP client not connected")
        return await self.operations.get_file_info(path)
    
    async def file_exists(self, path: str) -> bool:
        """Check if file exists via MCP"""
        if not self.operations:
            raise RuntimeError("MCP client not connected")
        return await self.operations.file_exists(path)
    
    async def is_directory(self, path: str) -> bool:
        """Check if path is directory via MCP"""
        if not self.operations:
            raise RuntimeError("MCP client not connected")
        return await self.operations.is_directory(path)