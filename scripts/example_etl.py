#!/usr/bin/env python3
"""
Example ETL transformation script.

Transform scripts receive data via environment variables:
  TRANSFORM_DATA_PATH  - Path to JSON file containing input data
  TRANSFORM_RESULT_PATH - Path to write JSON result to
  TRANSFORM_PARAMS - JSON-encoded parameters
"""
import os
import sys
import json
import pandas as pd
from datetime import datetime

data_path = os.environ.get('TRANSFORM_DATA_PATH')
result_path = os.environ.get('TRANSFORM_RESULT_PATH')
params = json.loads(os.environ.get('TRANSFORM_PARAMS', '{}'))

if not data_path:
    print("Error: TRANSFORM_DATA_PATH not set", file=sys.stderr)
    sys.exit(1)

print(f"Starting transform with params: {params}")

try:
    with open(data_path, 'r') as f:
        raw = json.load(f)

    data = pd.DataFrame(raw) if isinstance(raw, list) else raw

    if isinstance(data, pd.DataFrame):
        result = data.dropna()
        result['processed_at'] = datetime.now().isoformat()

        if 'filter_column' in params and 'filter_value' in params:
            result = result[result[params['filter_column']] == params['filter_value']]

        print(f"Processed {len(result)} rows")
        output = result.to_dict(orient='records')
    else:
        output = data

    if result_path:
        with open(result_path, 'w') as f:
            json.dump(output, f)

    print("Transform completed successfully")

except Exception as e:
    print(f"Transform error: {e}", file=sys.stderr)
    sys.exit(1)
