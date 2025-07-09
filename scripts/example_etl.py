#!/usr/bin/env python3
"""
Example ETL transformation script
This script demonstrates how to create a transformation script for the FileSystem Agent
"""
import os
import sys
import json
import pandas as pd
from datetime import datetime

# Get job parameters from environment
job_id = os.environ.get('JOB_ID', 'unknown')
job_name = os.environ.get('JOB_NAME', 'unknown')
job_params = json.loads(os.environ.get('JOB_PARAMS', '{}'))

print(f"Starting ETL job: {job_name} (ID: {job_id})")
print(f"Parameters: {job_params}")

try:
    # Example transformation: data cleaning and processing
    # In a real transformation script, you would:
    # 1. Read data from the source
    # 2. Apply transformations
    # 3. Return the result
    
    # This is just an example - actual transformation depends on your data
    if isinstance(data, pd.DataFrame):
        # Example transformations
        result = data.copy()
        
        # Remove null values
        result = result.dropna()
        
        # Add timestamp column
        result['processed_at'] = datetime.now()
        
        # Apply any custom transformations based on parameters
        if 'filter_column' in params and 'filter_value' in params:
            result = result[result[params['filter_column']] == params['filter_value']]
        
        print(f"Processed {len(result)} rows")
    
    else:
        # Handle non-DataFrame data
        result = data
    
    print(f"ETL job {job_name} completed successfully")
    
except Exception as e:
    print(f"Error in ETL job {job_name}: {str(e)}")
    sys.exit(1)