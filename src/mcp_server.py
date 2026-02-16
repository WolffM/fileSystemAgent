import logging
import subprocess
import json
from typing import Dict, List, Optional, Any
from pathlib import Path
from dataclasses import dataclass

from mcp.server import Server
from mcp.types import (
    TextContent,
    CallToolResult
)
import mcp.server.stdio

from .models import FileSystemEvent


@dataclass
class MCPConfig:
    enabled: bool = True
    allowed_paths: Optional[List[str]] = None
    max_file_size: int = 100 * 1024 * 1024  # 100MB
    allowed_commands: Optional[List[str]] = None
    security_mode: str = "strict"  # strict, permissive


class FileSystemMCPServer:
    def __init__(self, config: MCPConfig):
        self.config = config
        self.server = Server("filesystem-agent")
        self.logger = logging.getLogger(__name__)
        self.allowed_paths = [Path(p).resolve() for p in (config.allowed_paths or [])]
        self.allowed_commands = set(config.allowed_commands or [
            "python", "pip", "git", "curl", "wget", "ls", "cat", "grep", "find"
        ])
        self.events: List[FileSystemEvent] = []
        
        self._setup_tools()
    
    def _setup_tools(self):
        """Setup MCP tools for file system operations"""
        
        @self.server.call_tool()
        async def read_file(path: str, encoding: str = "utf-8") -> CallToolResult:
            """Read a file from the filesystem"""
            try:
                if not self._is_path_allowed(path):
                    raise PermissionError(f"Access denied to path: {path}")
                
                file_path = Path(path).resolve()
                
                if not file_path.exists():
                    raise FileNotFoundError(f"File not found: {path}")
                
                if file_path.stat().st_size > self.config.max_file_size:
                    raise ValueError(f"File too large: {file_path.stat().st_size} bytes")
                
                with open(file_path, 'r', encoding=encoding) as f:
                    content = f.read()
                
                self._log_event("read_file", str(file_path), {"size": len(content)})
                
                return CallToolResult(
                    content=[TextContent(type="text", text=content)],
                    isError=False
                )
                
            except Exception as e:
                self.logger.error(f"Error reading file {path}: {e}")
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Error: {str(e)}")],
                    isError=True
                )
        
        @self.server.call_tool()
        async def write_file(path: str, content: str, encoding: str = "utf-8") -> CallToolResult:
            """Write content to a file"""
            try:
                if not self._is_path_allowed(path):
                    raise PermissionError(f"Access denied to path: {path}")
                
                file_path = Path(path).resolve()
                
                # Create parent directories if they don't exist
                file_path.parent.mkdir(parents=True, exist_ok=True)
                
                with open(file_path, 'w', encoding=encoding) as f:
                    f.write(content)
                
                self._log_event("write_file", str(file_path), {"size": len(content)})
                
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Successfully wrote {len(content)} characters to {path}")],
                    isError=False
                )
                
            except Exception as e:
                self.logger.error(f"Error writing file {path}: {e}")
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Error: {str(e)}")],
                    isError=True
                )
        
        @self.server.call_tool()
        async def list_directory(path: str) -> CallToolResult:
            """List contents of a directory"""
            try:
                if not self._is_path_allowed(path):
                    raise PermissionError(f"Access denied to path: {path}")
                
                dir_path = Path(path).resolve()
                
                if not dir_path.exists():
                    raise FileNotFoundError(f"Directory not found: {path}")
                
                if not dir_path.is_dir():
                    raise NotADirectoryError(f"Not a directory: {path}")
                
                items = []
                for item in dir_path.iterdir():
                    stat = item.stat()
                    items.append({
                        "name": item.name,
                        "path": str(item),
                        "type": "directory" if item.is_dir() else "file",
                        "size": stat.st_size,
                        "modified": stat.st_mtime
                    })
                
                self._log_event("list_directory", str(dir_path), {"count": len(items)})
                
                return CallToolResult(
                    content=[TextContent(type="text", text=json.dumps(items, indent=2))],
                    isError=False
                )
                
            except Exception as e:
                self.logger.error(f"Error listing directory {path}: {e}")
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Error: {str(e)}")],
                    isError=True
                )
        
        @self.server.call_tool()
        async def execute_command(command: str, args: List[str] = None, cwd: str = None) -> CallToolResult:
            """Execute a system command"""
            try:
                if not self._is_command_allowed(command):
                    raise PermissionError(f"Command not allowed: {command}")
                
                if cwd and not self._is_path_allowed(cwd):
                    raise PermissionError(f"Access denied to working directory: {cwd}")
                
                cmd_args = [command] + (args or [])
                
                # Execute command
                result = subprocess.run(
                    cmd_args,
                    cwd=cwd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                self._log_event("execute_command", " ".join(cmd_args), {
                    "returncode": result.returncode,
                    "cwd": cwd
                })
                
                output = {
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }
                
                return CallToolResult(
                    content=[TextContent(type="text", text=json.dumps(output, indent=2))],
                    isError=result.returncode != 0
                )
                
            except Exception as e:
                self.logger.error(f"Error executing command {command}: {e}")
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Error: {str(e)}")],
                    isError=True
                )
        
        @self.server.call_tool()
        async def create_directory(path: str, parents: bool = True) -> CallToolResult:
            """Create a directory"""
            try:
                if not self._is_path_allowed(path):
                    raise PermissionError(f"Access denied to path: {path}")
                
                dir_path = Path(path).resolve()
                dir_path.mkdir(parents=parents, exist_ok=True)
                
                self._log_event("create_directory", str(dir_path), {"parents": parents})
                
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Successfully created directory: {path}")],
                    isError=False
                )
                
            except Exception as e:
                self.logger.error(f"Error creating directory {path}: {e}")
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Error: {str(e)}")],
                    isError=True
                )
        
        @self.server.call_tool()
        async def delete_file(path: str) -> CallToolResult:
            """Delete a file or directory"""
            try:
                if not self._is_path_allowed(path):
                    raise PermissionError(f"Access denied to path: {path}")
                
                file_path = Path(path).resolve()
                
                if not file_path.exists():
                    raise FileNotFoundError(f"Path not found: {path}")
                
                if file_path.is_dir():
                    import shutil
                    shutil.rmtree(file_path)
                    operation = "delete_directory"
                else:
                    file_path.unlink()
                    operation = "delete_file"
                
                self._log_event(operation, str(file_path), {})
                
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Successfully deleted: {path}")],
                    isError=False
                )
                
            except Exception as e:
                self.logger.error(f"Error deleting {path}: {e}")
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Error: {str(e)}")],
                    isError=True
                )
        
        @self.server.call_tool()
        async def get_file_info(path: str) -> CallToolResult:
            """Get file information"""
            try:
                if not self._is_path_allowed(path):
                    raise PermissionError(f"Access denied to path: {path}")
                
                file_path = Path(path).resolve()
                
                if not file_path.exists():
                    raise FileNotFoundError(f"Path not found: {path}")
                
                stat = file_path.stat()
                info = {
                    "path": str(file_path),
                    "name": file_path.name,
                    "type": "directory" if file_path.is_dir() else "file",
                    "size": stat.st_size,
                    "created": stat.st_ctime,
                    "modified": stat.st_mtime,
                    "permissions": oct(stat.st_mode)[-3:]
                }
                
                self._log_event("get_file_info", str(file_path), info)
                
                return CallToolResult(
                    content=[TextContent(type="text", text=json.dumps(info, indent=2))],
                    isError=False
                )
                
            except Exception as e:
                self.logger.error(f"Error getting file info for {path}: {e}")
                return CallToolResult(
                    content=[TextContent(type="text", text=f"Error: {str(e)}")],
                    isError=True
                )
    
    def _is_path_allowed(self, path: str) -> bool:
        """Check if path is allowed based on configuration"""
        if self.config.security_mode == "permissive":
            return True
        
        if not self.allowed_paths:
            return True
        
        try:
            path_obj = Path(path).resolve()
            for allowed_path in self.allowed_paths:
                if path_obj.is_relative_to(allowed_path):
                    return True
        except Exception:
            return False
        
        return False
    
    def _is_command_allowed(self, command: str) -> bool:
        """Check if command is allowed based on configuration"""
        if self.config.security_mode == "permissive":
            return True
        
        return command in self.allowed_commands
    
    def _log_event(self, event_type: str, file_path: str, metadata: Dict[str, Any]):
        """Log file system event"""
        event = FileSystemEvent(
            event_type=event_type,
            file_path=file_path,
            metadata=metadata
        )
        self.events.append(event)
        self.logger.info(f"MCP Event: {event_type} - {file_path}")
    
    def get_events(self) -> List[FileSystemEvent]:
        """Get all logged events"""
        return self.events.copy()
    
    async def run(self):
        """Run the MCP server"""
        self.logger.info("Starting MCP FileSystem server")

        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await self.server.run(read_stream, write_stream)