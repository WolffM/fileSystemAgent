import os
import json
import asyncio
import sys
import pandas as pd
import defusedxml.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
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
        if self.use_mcp:
            self.mcp_client = MCPFileSystemClient()
            await self.mcp_client.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
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
        if not await self._file_exists(job.source_path):
            raise FileNotFoundError(f"Source file not found: {job.source_path}")

        source_path = Path(job.source_path)
        file_ext = source_path.suffix.lower().lstrip('.')

        if file_ext not in self.supported_formats:
            raise ValueError(f"Unsupported file format: {file_ext}")

        data = await self.supported_formats[file_ext](source_path, job.parameters)

        if job.destination_path:
            await self._save_data(data, job.destination_path, job.parameters)

        job.progress = 100.0

    async def _transform(self, job: ETLJob):
        if not job.transform_script:
            raise ValueError("Transform script not provided")

        data = await self._load_data(job.source_path, job.parameters)
        transformed_data = await self._execute_transform_script(
            data, job.transform_script, job.parameters
        )

        if job.destination_path:
            await self._save_data(transformed_data, job.destination_path, job.parameters)

        job.progress = 100.0

    async def _load(self, job: ETLJob):
        data = await self._load_data(job.source_path, job.parameters)
        await self._save_data(data, job.destination_path, job.parameters)
        job.progress = 100.0

    async def _full_etl(self, job: ETLJob):
        job.progress = 10.0
        data = await self._load_data(job.source_path, job.parameters)

        job.progress = 50.0
        if job.transform_script:
            data = await self._execute_transform_script(
                data, job.transform_script, job.parameters
            )

        job.progress = 90.0
        if job.destination_path:
            await self._save_data(data, job.destination_path, job.parameters)

        job.progress = 100.0

    async def _read_csv(self, file_path: Path, params: Dict[str, Any]) -> pd.DataFrame:
        if self.use_mcp and self.mcp_client:
            content = await self.mcp_client.read_file(str(file_path))
            from io import StringIO
            return pd.read_csv(
                StringIO(content),
                chunksize=params.get('chunk_size', self.chunk_size),
                **params.get('csv_options', {})
            )
        return pd.read_csv(
            file_path,
            chunksize=params.get('chunk_size', self.chunk_size),
            **params.get('csv_options', {})
        )

    async def _read_json(self, file_path: Path, params: Dict[str, Any]) -> Union[Dict, List]:
        if self.use_mcp and self.mcp_client:
            content = await self.mcp_client.read_file(str(file_path))
            return json.loads(content)
        with open(file_path, 'r') as f:
            return json.load(f)

    async def _read_xml(self, file_path: Path, params: Dict[str, Any]):
        if self.use_mcp and self.mcp_client:
            content = await self.mcp_client.read_file(str(file_path))
            return ET.fromstring(content)
        tree = ET.parse(file_path)
        return tree.getroot()

    async def _read_parquet(self, file_path: Path, params: Dict[str, Any]) -> pd.DataFrame:
        return pd.read_parquet(file_path, **params.get('parquet_options', {}))

    async def _read_excel(self, file_path: Path, params: Dict[str, Any]) -> pd.DataFrame:
        return pd.read_excel(file_path, **params.get('excel_options', {}))

    async def _load_data(self, file_path: str, params: Dict[str, Any]) -> Any:
        source_path = Path(file_path)
        file_ext = source_path.suffix.lower().lstrip('.')

        if file_ext not in self.supported_formats:
            raise ValueError(f"Unsupported file format: {file_ext}")

        return await self.supported_formats[file_ext](source_path, params)

    async def _save_data(self, data: Any, file_path: str, params: Dict[str, Any]):
        dest_path = Path(file_path)

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
                data.to_parquet(dest_path, **params.get('parquet_options', {}))
            elif file_ext == 'excel':
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
        if not await self._file_exists(script_path):
            raise FileNotFoundError(f"Transform script not found: {script_path}")

        import tempfile
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as data_file:
            if isinstance(data, pd.DataFrame):
                data.to_json(data_file.name, orient='records')
            else:
                json.dump(data, data_file)
            data_path = data_file.name

        result_path = data_path + '.result'

        try:
            env = {
                **dict(os.environ),
                'TRANSFORM_DATA_PATH': data_path,
                'TRANSFORM_RESULT_PATH': result_path,
                'TRANSFORM_PARAMS': json.dumps(params),
            }

            process = await asyncio.create_subprocess_exec(
                sys.executable, str(script_path),
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=300)

            if process.returncode != 0:
                raise RuntimeError(f"Transform script failed: {stderr.decode()}")

            if Path(result_path).exists():
                with open(result_path, 'r') as f:
                    return json.load(f)

            return data

        finally:
            Path(data_path).unlink(missing_ok=True)
            Path(result_path).unlink(missing_ok=True)

    async def _file_exists(self, path: str) -> bool:
        if self.use_mcp and self.mcp_client:
            return await self.mcp_client.file_exists(path)
        return Path(path).exists()
