#!/usr/bin/env python3
"""
MCP Server entry point for FileSystem Agent

Usage: python -m src
"""
import asyncio

from .mcp_server import FileSystemMCPServer, MCPConfig


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
