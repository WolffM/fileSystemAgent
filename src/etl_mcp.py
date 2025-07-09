import os
import json
import csv
import pandas as pd
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from concurrent.futures import ThreadPoolExecutor
import logging
from datetime import datetime

from .models import ETLJob, JobStatus, ETLOperationType
from .mcp_client import MCPFileSystemClient


class MCPETLEngine:
    """ETL Engine with MCP file system operations"""
    
    def __init__(self, max_workers: int = 4, chunk_size: int = 10000, use_mcp: bool = False):
        self.max_workers = max_workers
        self.chunk_size = chunk_size
        self.use_mcp = use_mcp
        self.logger = logging.getLogger(__name__)
        self.mcp_client: Optional[MCPFileSystemClient] = None
        
        self.supported_formats = {
            'csv': self._read_csv,
            'json': self._read_json,
            'xml': self._read_xml,
            'parquet': self._read_parquet,
            'excel': self._read_excel
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        if self.use_mcp:
            self.mcp_client = MCPFileSystemClient()
            await self.mcp_client.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.mcp_client:
            await self.mcp_client.disconnect()
            self.mcp_client = None
    
    async def execute_job(self, job: ETLJob) -> ETLJob:
        """Execute an ETL job with optional MCP support"""
        job.status = JobStatus.RUNNING
        job.started_at = datetime.now()
        
        try:
            if job.operation_type == ETLOperationType.EXTRACT:
                await self._extract(job)
            elif job.operation_type == ETLOperationType.TRANSFORM:
                await self._transform(job)
            elif job.operation_type == ETLOperationType.LOAD:
                await self._load(job)
            elif job.operation_type == ETLOperationType.FULL_ETL:
                await self._full_etl(job)
            
            job.status = JobStatus.COMPLETED
            job.progress = 100.0
            
        except Exception as e:
            job.status = JobStatus.FAILED
            job.error_message = str(e)
            self.logger.error(f"ETL job {job.id} failed: {e}")
        
        finally:
            job.completed_at = datetime.now()
            
        return job
    
    async def _extract(self, job: ETLJob):
        """Extract data from source"""
        if not await self._file_exists(job.source_path):
            raise FileNotFoundError(f"Source file not found: {job.source_path}")
        
        source_path = Path(job.source_path)
        file_ext = source_path.suffix.lower().lstrip('.')
        
        if file_ext not in self.supported_formats:
            raise ValueError(f"Unsupported file format: {file_ext}")
        
        # Read data using appropriate method
        data = await self.supported_formats[file_ext](source_path, job.parameters)
        
        # Save extracted data
        if job.destination_path:
            await self._save_data(data, job.destination_path, job.parameters)
        
        job.progress = 100.0
    
    async def _transform(self, job: ETLJob):
        """Transform data using provided script"""
        if not job.transform_script:
            raise ValueError("Transform script not provided")
        
        # Load data
        data = await self._load_data(job.source_path, job.parameters)
        
        # Execute transformation script
        transformed_data = await self._execute_transform_script(
            data, job.transform_script, job.parameters
        )
        
        # Save transformed data
        if job.destination_path:
            await self._save_data(transformed_data, job.destination_path, job.parameters)
        
        job.progress = 100.0
    
    async def _load(self, job: ETLJob):
        """Load data to destination"""
        data = await self._load_data(job.source_path, job.parameters)
        await self._save_data(data, job.destination_path, job.parameters)
        job.progress = 100.0
    
    async def _full_etl(self, job: ETLJob):
        """Execute full ETL pipeline"""
        # Extract
        job.progress = 10.0
        data = await self._load_data(job.source_path, job.parameters)
        
        # Transform
        job.progress = 50.0
        if job.transform_script:
            data = await self._execute_transform_script(
                data, job.transform_script, job.parameters
            )
        
        # Load
        job.progress = 90.0
        if job.destination_path:
            await self._save_data(data, job.destination_path, job.parameters)
        
        job.progress = 100.0
    
    async def _read_csv(self, file_path: Path, params: Dict[str, Any]) -> pd.DataFrame:
        """Read CSV file"""
        if self.use_mcp and self.mcp_client:
            content = await self.mcp_client.read_file(str(file_path))
            from io import StringIO
            return pd.read_csv(
                StringIO(content),
                chunksize=params.get('chunk_size', self.chunk_size),
                **params.get('csv_options', {})
            )
        else:
            return pd.read_csv(
                file_path,
                chunksize=params.get('chunk_size', self.chunk_size),
                **params.get('csv_options', {})
            )
    
    async def _read_json(self, file_path: Path, params: Dict[str, Any]) -> Union[Dict, List]:
        """Read JSON file"""
        if self.use_mcp and self.mcp_client:
            content = await self.mcp_client.read_file(str(file_path))
            return json.loads(content)
        else:
            with open(file_path, 'r') as f:
                return json.load(f)
    
    async def _read_xml(self, file_path: Path, params: Dict[str, Any]) -> ET.Element:
        """Read XML file"""
        if self.use_mcp and self.mcp_client:
            content = await self.mcp_client.read_file(str(file_path))
            return ET.fromstring(content)
        else:
            tree = ET.parse(file_path)
            return tree.getroot()
    
    async def _read_parquet(self, file_path: Path, params: Dict[str, Any]) -> pd.DataFrame:
        """Read Parquet file"""
        if self.use_mcp and self.mcp_client:
            # For binary formats like Parquet, we need to handle differently
            # This is a limitation - MCP text-based operations don't work well with binary formats
            self.logger.warning("Parquet files not fully supported with MCP - falling back to direct file access")
            return pd.read_parquet(file_path, **params.get('parquet_options', {}))
        else:
            return pd.read_parquet(file_path, **params.get('parquet_options', {}))
    
    async def _read_excel(self, file_path: Path, params: Dict[str, Any]) -> pd.DataFrame:
        """Read Excel file"""
        if self.use_mcp and self.mcp_client:
            # Similar limitation for Excel files
            self.logger.warning("Excel files not fully supported with MCP - falling back to direct file access")
            return pd.read_excel(file_path, **params.get('excel_options', {}))
        else:
            return pd.read_excel(file_path, **params.get('excel_options', {}))
    
    async def _load_data(self, file_path: str, params: Dict[str, Any]) -> Any:
        """Load data from file"""
        source_path = Path(file_path)
        file_ext = source_path.suffix.lower().lstrip('.')
        
        if file_ext not in self.supported_formats:
            raise ValueError(f"Unsupported file format: {file_ext}")
        
        return await self.supported_formats[file_ext](source_path, params)
    
    async def _save_data(self, data: Any, file_path: str, params: Dict[str, Any]):
        """Save data to file"""
        dest_path = Path(file_path)
        
        # Create parent directories
        if self.use_mcp and self.mcp_client:
            await self.mcp_client.create_directory(str(dest_path.parent))
        else:
            dest_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_ext = dest_path.suffix.lower().lstrip('.')
        
        if isinstance(data, pd.DataFrame):
            if file_ext == 'csv':
                content = data.to_csv(index=False, **params.get('csv_options', {}))
                if self.use_mcp and self.mcp_client:
                    await self.mcp_client.write_file(str(dest_path), content)
                else:
                    with open(dest_path, 'w') as f:
                        f.write(content)
            elif file_ext == 'json':
                content = data.to_json(**params.get('json_options', {}))
                if self.use_mcp and self.mcp_client:
                    await self.mcp_client.write_file(str(dest_path), content)
                else:
                    with open(dest_path, 'w') as f:
                        f.write(content)
            elif file_ext == 'parquet':
                # Binary format - use direct file access
                data.to_parquet(dest_path, **params.get('parquet_options', {}))
            elif file_ext == 'excel':
                # Binary format - use direct file access
                data.to_excel(dest_path, index=False, **params.get('excel_options', {}))
        else:
            if file_ext == 'json':
                content = json.dumps(data, indent=2)
                if self.use_mcp and self.mcp_client:
                    await self.mcp_client.write_file(str(dest_path), content)
                else:
                    with open(dest_path, 'w') as f:
                        f.write(content)
    
    async def _execute_transform_script(self, data: Any, script_path: str, params: Dict[str, Any]) -> Any:
        """Execute transformation script"""
        if not await self._file_exists(script_path):
            raise FileNotFoundError(f"Transform script not found: {script_path}")
        
        # Read script content
        if self.use_mcp and self.mcp_client:
            script_content = await self.mcp_client.read_file(script_path)
        else:
            with open(script_path, 'r') as f:
                script_content = f.read()
        
        # Create a safe execution environment
        namespace = {
            'data': data,
            'params': params,
            'pd': pd,
            'json': json,
            'datetime': datetime
        }
        
        exec(script_content, namespace)
        
        # Return the transformed data
        return namespace.get('result', data)
    
    async def _file_exists(self, path: str) -> bool:
        """Check if file exists"""
        if self.use_mcp and self.mcp_client:
            return await self.mcp_client.file_exists(path)
        else:
            return Path(path).exists()
    
    async def _is_directory(self, path: str) -> bool:
        """Check if path is directory"""
        if self.use_mcp and self.mcp_client:
            return await self.mcp_client.is_directory(path)
        else:
            return Path(path).is_dir()