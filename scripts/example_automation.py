#!/usr/bin/env python3
"""
Example automation script for the FileSystem Agent
This script demonstrates how to create an automation script that runs on a schedule
"""
import os
import sys
import json
import time
from datetime import datetime
from pathlib import Path

# Get job parameters from environment
job_id = os.environ.get('JOB_ID', 'unknown')
job_name = os.environ.get('JOB_NAME', 'unknown')
job_params = json.loads(os.environ.get('JOB_PARAMS', '{}'))

print(f"Starting automation job: {job_name} (ID: {job_id})")
print(f"Parameters: {job_params}")
print(f"Started at: {datetime.now()}")

try:
    # Example automation tasks
    
    # Task 1: File system maintenance
    data_dir = Path(job_params.get('data_dir', './data'))
    if data_dir.exists():
        files = list(data_dir.glob('*'))
        print(f"Found {len(files)} files in {data_dir}")
        
        # Clean up old files (example)
        cleanup_days = job_params.get('cleanup_days', 30)
        current_time = time.time()
        
        for file_path in files:
            if file_path.is_file():
                file_age = (current_time - file_path.stat().st_mtime) / (24 * 3600)
                if file_age > cleanup_days:
                    print(f"Would delete old file: {file_path.name} (age: {file_age:.1f} days)")
                    # file_path.unlink()  # Uncomment to actually delete
    
    # Task 2: System health check
    import psutil
    
    cpu_percent = psutil.cpu_percent(interval=1)
    memory_percent = psutil.virtual_memory().percent
    
    print(f"System health check:")
    print(f"  CPU: {cpu_percent}%")
    print(f"  Memory: {memory_percent}%")
    
    # Task 3: Log rotation (example)
    logs_dir = Path(job_params.get('logs_dir', './logs'))
    if logs_dir.exists():
        log_files = list(logs_dir.glob('*.log'))
        print(f"Found {len(log_files)} log files")
        
        for log_file in log_files:
            size_mb = log_file.stat().st_size / (1024 * 1024)
            if size_mb > job_params.get('max_log_size_mb', 100):
                print(f"Log file {log_file.name} is {size_mb:.1f}MB (rotation needed)")
    
    # Task 4: Send status report
    status_report = {
        'job_id': job_id,
        'job_name': job_name,
        'completed_at': datetime.now().isoformat(),
        'status': 'success',
        'metrics': {
            'cpu_percent': cpu_percent,
            'memory_percent': memory_percent,
            'files_processed': len(files) if 'files' in locals() else 0
        }
    }
    
    print(f"Status report: {json.dumps(status_report, indent=2)}")
    
    print(f"Automation job {job_name} completed successfully")
    
except Exception as e:
    print(f"Error in automation job {job_name}: {str(e)}")
    sys.exit(1)