#!/usr/bin/env python3
"""
Duplicate Detection Example using File Indexing System
This script demonstrates how to use the indexing system for duplicate detection.
"""

import os
import sys
import json
from pathlib import Path

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from file_indexing_system import FileIndexingSystem
from template_models import HashAlgorithm


def main():
    """Example of duplicate detection using the indexing system"""
    
    print("=== File Indexing and Duplicate Detection Example ===")
    
    # Initialize indexing system
    index_path = "/tmp/file_index_example"
    indexer = FileIndexingSystem(index_path, HashAlgorithm.SHA256)
    
    # Example 1: Index a directory
    print("\n1. Indexing directory...")
    
    # Use a safe directory for example - current directory
    directory_to_index = Path(".")
    
    stats = indexer.index_directory(
        directory_to_index,
        recursive=True,
        include_hash=True,
        max_workers=4
    )
    
    print(f"Indexing complete:")
    print(f"  Total files: {stats['total_files']}")
    print(f"  Indexed files: {stats['indexed_files']}")
    print(f"  Failed files: {stats['failed_files']}")
    
    # Example 2: Find duplicates
    print("\n2. Finding duplicates...")
    
    duplicates = indexer.find_duplicates(min_size=1024)  # Only files >= 1KB
    
    if duplicates:
        print(f"Found {len(duplicates)} duplicate groups:")
        
        total_wasted_space = 0
        for i, group in enumerate(duplicates[:5]):  # Show first 5 groups
            print(f"\nGroup {i+1}:")
            print(f"  Hash: {group.hash_value[:16]}...")
            print(f"  File size: {group.file_size:,} bytes")
            print(f"  File count: {group.file_count}")
            print(f"  Wasted space: {group.total_wasted_space:,} bytes")
            print(f"  Files:")
            
            for file_meta in group.files:
                print(f"    - {file_meta.file_path}")
                print(f"      Modified: {file_meta.modified_time}")
            
            total_wasted_space += group.total_wasted_space
        
        print(f"\nTotal wasted space: {total_wasted_space:,} bytes")
        
        if len(duplicates) > 5:
            print(f"... and {len(duplicates) - 5} more groups")
    else:
        print("No duplicates found!")
    
    # Example 3: Generate duplicate report
    print("\n3. Generating duplicate report...")
    
    report = indexer.generate_duplicate_report(str(directory_to_index))
    
    print(f"Duplicate Report:")
    print(f"  Scan path: {report.scan_path}")
    print(f"  Total files scanned: {report.total_files_scanned:,}")
    print(f"  Total size scanned: {report.total_size_scanned:,} bytes")
    print(f"  Duplicate groups: {len(report.duplicate_groups)}")
    print(f"  Total duplicates: {report.total_duplicates}")
    print(f"  Total wasted space: {report.total_wasted_space:,} bytes")
    print(f"  Duplicate percentage: {report.duplicate_percentage:.2f}%")
    
    # Example 4: Search files
    print("\n4. Searching files...")
    
    # Search by name
    search_results = indexer.search_files("example", "name")
    print(f"Files with 'example' in name: {len(search_results)}")
    
    for result in search_results[:3]:  # Show first 3 results
        print(f"  - {result.file_name} ({result.file_size:,} bytes)")
    
    # Search by extension
    py_files = indexer.search_files("*.py", "name")
    print(f"Python files found: {len(py_files)}")
    
    # Example 5: Export index
    print("\n5. Exporting index...")
    
    # Export to JSON
    json_export_path = "/tmp/file_index_export.json"
    indexer.export_index(json_export_path, "json")
    print(f"Index exported to: {json_export_path}")
    
    # Export to CSV
    csv_export_path = "/tmp/file_index_export.csv"
    indexer.export_index(csv_export_path, "csv")
    print(f"Index exported to: {csv_export_path}")
    
    # Example 6: Advanced duplicate analysis
    print("\n6. Advanced duplicate analysis...")
    
    # Group duplicates by size
    size_groups = {}
    for group in duplicates:
        size = group.file_size
        if size not in size_groups:
            size_groups[size] = []
        size_groups[size].append(group)
    
    print(f"Duplicates grouped by size:")
    for size in sorted(size_groups.keys(), reverse=True)[:3]:  # Top 3 sizes
        groups = size_groups[size]
        total_files = sum(g.file_count for g in groups)
        total_wasted = sum(g.total_wasted_space for g in groups)
        print(f"  Size {size:,} bytes: {len(groups)} groups, {total_files} files, {total_wasted:,} bytes wasted")
    
    # Example 7: Cleanup recommendations
    print("\n7. Cleanup recommendations...")
    
    if duplicates:
        print("Recommended cleanup actions:")
        
        # Sort by wasted space (descending)
        sorted_duplicates = sorted(duplicates, key=lambda x: x.total_wasted_space, reverse=True)
        
        for i, group in enumerate(sorted_duplicates[:3]):  # Top 3 space wasters
            print(f"\nGroup {i+1} (Priority: High)")
            print(f"  Wasted space: {group.total_wasted_space:,} bytes")
            print(f"  Files: {group.file_count}")
            print(f"  Recommendation: Keep newest file, remove others")
            
            # Sort files by modification time (newest first)
            sorted_files = sorted(group.files, key=lambda x: x.modified_time, reverse=True)
            
            print(f"  Keep: {sorted_files[0].file_path}")
            print(f"  Remove:")
            for file_meta in sorted_files[1:]:
                print(f"    - {file_meta.file_path}")
    
    # Example 8: Performance statistics
    print("\n8. Performance statistics...")
    
    total_files = indexer.get_total_files()
    total_size = indexer.get_total_size()
    
    print(f"Index statistics:")
    print(f"  Total files indexed: {total_files:,}")
    print(f"  Total size indexed: {total_size:,} bytes ({total_size / 1024 / 1024:.1f} MB)")
    print(f"  Average file size: {total_size // total_files if total_files > 0 else 0:,} bytes")
    
    # Cleanup
    print("\n9. Cleanup...")
    
    # Remove stale entries (files that no longer exist)
    removed_count = indexer.cleanup_stale_entries()
    print(f"Removed {removed_count} stale entries")
    
    print("\nExample completed successfully!")


if __name__ == "__main__":
    main()