import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field

from .models import AgentConfig


class ConfigManager:
    def __init__(self, config_path: str = "config.yaml"):
        self.config_path = Path(config_path)
        self.config: Optional[AgentConfig] = None
        self.load_config()
    
    def load_config(self) -> AgentConfig:
        """Load configuration from file"""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
        
        with open(self.config_path, 'r') as f:
            config_data = yaml.safe_load(f)
        
        # Merge with environment variables
        config_data = self._merge_env_vars(config_data)
        
        # Create agent config
        agent_config = config_data.get('agent', {})
        self.config = AgentConfig(**agent_config)
        
        # Store additional sections
        for key, value in config_data.items():
            if key != 'agent':
                setattr(self.config, key, value)
        
        return self.config
    
    def _merge_env_vars(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """Merge environment variables with configuration"""
        env_prefix = "FSA_"
        
        for key, value in os.environ.items():
            if key.startswith(env_prefix):
                config_key = key[len(env_prefix):].lower()
                
                # Handle nested keys (e.g., FSA_AGENT_LOG_LEVEL)
                if '_' in config_key:
                    parts = config_key.split('_')
                    section = parts[0]
                    nested_key = '_'.join(parts[1:])
                    
                    if section not in config_data:
                        config_data[section] = {}
                    
                    config_data[section][nested_key] = value
                else:
                    config_data[config_key] = value
        
        return config_data
    
    def get_config(self) -> AgentConfig:
        """Get current configuration"""
        if self.config is None:
            self.load_config()
        return self.config
    
    def get_section(self, section: str) -> Dict[str, Any]:
        """Get a specific configuration section"""
        if self.config is None:
            self.load_config()
        return getattr(self.config, section, {})
    
    def update_config(self, updates: Dict[str, Any]):
        """Update configuration"""
        if self.config is None:
            self.load_config()
        
        # Update the configuration object
        for key, value in updates.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
        
        # Save to file
        self.save_config()
    
    def save_config(self):
        """Save configuration to file"""
        if self.config is None:
            return
        
        config_dict = self.config.dict()
        
        with open(self.config_path, 'w') as f:
            yaml.dump(config_dict, f, default_flow_style=False)
    
    def create_directories(self):
        """Create necessary directories based on configuration"""
        if self.config is None:
            return
        
        dirs_to_create = [
            self.config.data_dir,
            self.config.scripts_dir,
            self.config.logs_dir
        ]
        
        for dir_path in dirs_to_create:
            Path(dir_path).mkdir(parents=True, exist_ok=True)