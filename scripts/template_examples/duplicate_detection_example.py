#!/usr/bin/env python3
"""
Duplicate Detection Example using File Indexing System
This script demonstrates how to use the indexing system for duplicate detection.

Usage:
    python -m scripts.template_examples.duplicate_detection_example
    (run from project root)
"""

import sys
import tempfile
from pathlib import Path

# Ensure project root is on path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from src.file_indexing_system import FileIndexingSystem
from src.template_models import HashAlgorithm


def main():
    """Example of duplicate detection using the indexing system"""

    print("=== File Indexing and Duplicate Detection Example ===")

    # Initialize indexing system with a temp directory
    tmp_dir = Path(tempfile.mkdtemp(prefix="file_index_"))
    index_path = str(tmp_dir / "file_index_example")
    indexer = FileIndexingSystem(index_path, HashAlgorithm.SHA256)

    # Index a directory (current directory as example)
    print("\n1. Indexing directory...")
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

    # Find duplicates
    print("\n2. Finding duplicates...")
    duplicates = indexer.find_duplicates(min_size=1024)

    if duplicates:
        print(f"Found {len(duplicates)} duplicate groups:")

        total_wasted_space = 0
        for i, group in enumerate(duplicates[:5]):
            print(f"\nGroup {i+1}:")
            print(f"  Hash: {group.hash_value[:16]}...")
            print(f"  File size: {group.file_size:,} bytes")
            print(f"  File count: {group.file_count}")
            print(f"  Wasted space: {group.total_wasted_space:,} bytes")
            print(f"  Files:")

            for file_meta in group.files:
                print(f"    - {file_meta.file_path}")

            total_wasted_space += group.total_wasted_space

        print(f"\nTotal wasted space: {total_wasted_space:,} bytes")
    else:
        print("No duplicates found!")

    # Generate duplicate report
    print("\n3. Generating duplicate report...")
    report = indexer.generate_duplicate_report(str(directory_to_index))

    print(f"Duplicate Report:")
    print(f"  Total files scanned: {report.total_files_scanned:,}")
    print(f"  Total size scanned: {report.total_size_scanned:,} bytes")
    print(f"  Duplicate groups: {len(report.duplicate_groups)}")
    print(f"  Total wasted space: {report.total_wasted_space:,} bytes")
    print(f"  Duplicate percentage: {report.duplicate_percentage:.2f}%")

    # Export index
    print("\n4. Exporting index...")
    json_export = str(tmp_dir / "file_index_export.json")
    indexer.export_index(json_export, "json")
    print(f"Index exported to: {json_export}")

    # Performance statistics
    print("\n5. Performance statistics...")
    total_files = indexer.get_total_files()
    total_size = indexer.get_total_size()

    print(f"  Total files indexed: {total_files:,}")
    print(f"  Total size indexed: {total_size:,} bytes ({total_size / 1024 / 1024:.1f} MB)")

    # Cleanup stale entries
    removed_count = indexer.cleanup_stale_entries()
    print(f"  Removed {removed_count} stale entries")

    print(f"\nTemp files in: {tmp_dir}")
    print("Example completed successfully!")


if __name__ == "__main__":
    main()
