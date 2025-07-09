#!/usr/bin/env python3
"""
FileSystem Agent Entry Point
"""
import sys
import os
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from src.cli import cli

if __name__ == '__main__':
    cli()