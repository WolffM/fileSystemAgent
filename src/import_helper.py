#!/usr/bin/env python3
"""
Import helper for cross-platform compatibility
Handles both relative and absolute imports for the fileSystemAgent
"""

import sys
import os
from pathlib import Path

def setup_imports():
    """Set up Python path for proper imports"""
    # Get the project root directory
    current_file = Path(__file__)
    src_dir = current_file.parent
    project_root = src_dir.parent
    
    # Add paths to sys.path if not already there
    paths_to_add = [
        str(src_dir),
        str(project_root),
        str(project_root / 'src'),
        str(Path.cwd()),
    ]
    
    for path in paths_to_add:
        if path not in sys.path:
            sys.path.insert(0, path)

def safe_import(module_name, relative_name=None):
    """
    Safely import a module with fallback options
    
    Args:
        module_name: The module name for absolute import
        relative_name: The relative module name (optional)
    
    Returns:
        The imported module
    """
    setup_imports()
    
    # Try relative import first if provided
    if relative_name:
        try:
            return __import__(relative_name, fromlist=[''])
        except ImportError:
            pass
    
    # Try absolute import
    try:
        return __import__(module_name, fromlist=[''])
    except ImportError:
        pass
    
    # Try with src prefix
    try:
        return __import__(f'src.{module_name}', fromlist=[''])
    except ImportError:
        pass
    
    # Final fallback - try importing from current directory
    try:
        current_dir = Path(__file__).parent
        sys.path.insert(0, str(current_dir))
        return __import__(module_name, fromlist=[''])
    except ImportError as e:
        raise ImportError(f"Could not import {module_name}: {e}")

# Set up imports when this module is loaded
setup_imports()