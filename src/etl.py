import os
import json
import csv
import pandas as pd
import defusedxml.ElementTree as ET
from xml.etree.ElementTree import Element
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from concurrent.futures import ThreadPoolExecutor
import logging
from datetime import datetime

from .models import ETLJob, JobStatus, ETLOperationType


class ETLEngine:
    def __init__(self, max_workers: int = 4, chunk_size: int = 10000):
        self.max_workers = max_workers
        self.chunk_size = chunk_size
        self.logger = logging.getLogger(__name__)
        self.supported_formats = {
            'csv': self._read_csv,
            'json': self._read_json,
            'xml': self._read_xml,
            'parquet': self._read_parquet,
            'excel': self._read_excel
        }
        
    def execute_job(self, job: ETLJob) -> ETLJob:
        """Execute an ETL job"""
        job.status = JobStatus.RUNNING
        job.started_at = datetime.now()
        
        try:
            if job.operation_type == ETLOperationType.EXTRACT:
                self._extract(job)
            elif job.operation_type == ETLOperationType.TRANSFORM:
                self._transform(job)
            elif job.operation_type == ETLOperationType.LOAD:
                self._load(job)
            elif job.operation_type == ETLOperationType.FULL_ETL:
                self._full_etl(job)
            
            job.status = JobStatus.COMPLETED
            job.progress = 100.0
            
        except Exception as e:
            job.status = JobStatus.FAILED
            job.error_message = str(e)
            self.logger.error(f"ETL job {job.id} failed: {e}")
        
        finally:
            job.completed_at = datetime.now()
            
        return job
    
    def _extract(self, job: ETLJob):
        """Extract data from source"""
        source_path = Path(job.source_path)
        if not source_path.exists():
            raise FileNotFoundError(f"Source file not found: {job.source_path}")
        
        file_ext = source_path.suffix.lower().lstrip('.')
        if file_ext not in self.supported_formats:
            raise ValueError(f"Unsupported file format: {file_ext}")
        
        # Read data using appropriate method
        data = self.supported_formats[file_ext](source_path, job.parameters)
        
        # Save extracted data
        if job.destination_path:
            self._save_data(data, job.destination_path, job.parameters)
        
        job.progress = 100.0
        
    def _transform(self, job: ETLJob):
        """Transform data using provided script"""
        if not job.transform_script:
            raise ValueError("Transform script not provided")
        
        # Load data
        data = self._load_data(job.source_path, job.parameters)
        
        # Execute transformation script
        transformed_data = self._execute_transform_script(
            data, job.transform_script, job.parameters
        )
        
        # Save transformed data
        if job.destination_path:
            self._save_data(transformed_data, job.destination_path, job.parameters)
        
        job.progress = 100.0
        
    def _load(self, job: ETLJob):
        """Load data to destination"""
        data = self._load_data(job.source_path, job.parameters)
        self._save_data(data, job.destination_path, job.parameters)
        job.progress = 100.0
        
    def _full_etl(self, job: ETLJob):
        """Execute full ETL pipeline"""
        # Extract
        job.progress = 10.0
        data = self._load_data(job.source_path, job.parameters)
        
        # Transform
        job.progress = 50.0
        if job.transform_script:
            data = self._execute_transform_script(
                data, job.transform_script, job.parameters
            )
        
        # Load
        job.progress = 90.0
        if job.destination_path:
            self._save_data(data, job.destination_path, job.parameters)
        
        job.progress = 100.0
    
    def _read_csv(self, file_path: Path, params: Dict[str, Any]) -> pd.DataFrame:
        """Read CSV file"""
        return pd.read_csv(
            file_path,
            chunksize=params.get('chunk_size', self.chunk_size),
            **params.get('csv_options', {})
        )
    
    def _read_json(self, file_path: Path, params: Dict[str, Any]) -> Union[Dict, List]:
        """Read JSON file"""
        with open(file_path, 'r') as f:
            return json.load(f)
    
    def _read_xml(self, file_path: Path, params: Dict[str, Any]) -> Element:
        """Read XML file"""
        tree = ET.parse(file_path)
        return tree.getroot()
    
    def _read_parquet(self, file_path: Path, params: Dict[str, Any]) -> pd.DataFrame:
        """Read Parquet file"""
        return pd.read_parquet(file_path, **params.get('parquet_options', {}))
    
    def _read_excel(self, file_path: Path, params: Dict[str, Any]) -> pd.DataFrame:
        """Read Excel file"""
        return pd.read_excel(file_path, **params.get('excel_options', {}))
    
    def _load_data(self, file_path: str, params: Dict[str, Any]) -> Any:
        """Load data from file"""
        source_path = Path(file_path)
        file_ext = source_path.suffix.lower().lstrip('.')
        
        if file_ext not in self.supported_formats:
            raise ValueError(f"Unsupported file format: {file_ext}")
        
        return self.supported_formats[file_ext](source_path, params)
    
    def _save_data(self, data: Any, file_path: str, params: Dict[str, Any]):
        """Save data to file"""
        dest_path = Path(file_path)
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_ext = dest_path.suffix.lower().lstrip('.')
        
        if isinstance(data, pd.DataFrame):
            if file_ext == 'csv':
                data.to_csv(dest_path, index=False, **params.get('csv_options', {}))
            elif file_ext == 'json':
                data.to_json(dest_path, **params.get('json_options', {}))
            elif file_ext == 'parquet':
                data.to_parquet(dest_path, **params.get('parquet_options', {}))
            elif file_ext == 'excel':
                data.to_excel(dest_path, index=False, **params.get('excel_options', {}))
        else:
            if file_ext == 'json':
                with open(dest_path, 'w') as f:
                    json.dump(data, f, indent=2)
    
    def _execute_transform_script(self, data: Any, script_path: str, params: Dict[str, Any]) -> Any:
        """Execute transformation script"""
        script_file = Path(script_path)
        if not script_file.exists():
            raise FileNotFoundError(f"Transform script not found: {script_path}")
        
        # Create a safe execution environment
        namespace = {
            'data': data,
            'params': params,
            'pd': pd,
            'json': json,
            'datetime': datetime
        }
        
        with open(script_file, 'r') as f:
            script_content = f.read()
        
        exec(script_content, namespace)
        
        # Return the transformed data
        return namespace.get('result', data)