#!/usr/bin/env python3
"""
MCP Server entry point for FileSystem Agent
"""
import asyncio
import sys
from pathlib import Path

# Add parent directory to path to import src modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.mcp_server import FileSystemMCPServer, MCPConfig

async def main():
    """Run the MCP server"""
    config = MCPConfig(
        enabled=True,
        allowed_paths=[
            "./data",
            "./scripts", 
            "./logs",
            "./config.yaml"
        ],
        max_file_size=100 * 1024 * 1024,  # 100MB
        allowed_commands=[
            "python", "pip", "git", "curl", "wget", "ls", "cat", "grep", "find"
        ],
        security_mode="strict"
    )
    
    server = FileSystemMCPServer(config)
    await server.run()

if __name__ == "__main__":
    asyncio.run(main())