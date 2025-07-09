#!/usr/bin/env python3
"""
Test migration script for civitai directory
This script will copy files from G:\n\gen7\manual_ingestion\civitai to a test directory
and generate media fingerprints for duplicate detection.
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime

# Add src directory to path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from file_migration_template import FileMigrationTemplate
from template_models import ETLTemplateConfig, PathMapping, FileFilter, ConflictResolution, FileOperation
from media_fingerprinting import MediaFingerprintEngine
from file_indexing_system import FileIndexingSystem


def main():
    """Test migration and fingerprinting of civitai directory"""
    
    print("=== Civitai Directory Test Migration ===")
    print(f"Started at: {datetime.now()}")
    
    # Source and destination paths
    source_path = r"G:\n\gen7\manual_ingestion\civitai"
    destination_path = r"G:\test_migration\civitai_test"
    
    # Verify source exists
    if not Path(source_path).exists():
        print(f"❌ Source directory not found: {source_path}")
        print("Please verify the path and try again.")
        return
    
    print(f"📁 Source: {source_path}")
    print(f"📁 Destination: {destination_path}")
    
    # Create path mapping
    path_mapping = PathMapping(
        source_path=source_path,
        destination_path=destination_path,
        preserve_structure=True,
        create_directories=True
    )
    
    # Create file filter for media files
    file_filter = FileFilter(
        include_patterns=[
            "*.jpg", "*.jpeg", "*.png", "*.gif", "*.bmp", "*.tiff", "*.webp",
            "*.mp4", "*.avi", "*.mov", "*.wmv", "*.mkv", "*.webm",
            "*.pdf", "*.txt", "*.json"  # Include some other file types
        ],
        exclude_patterns=[
            "*.tmp", "*.log", "*.cache", "Thumbs.db", ".DS_Store"
        ],
        min_size=1024,  # 1KB minimum
        ignore_hidden=True,
        ignore_system=True
    )
    
    # Create ETL configuration
    config = ETLTemplateConfig(
        template_name="Civitai Test Migration",
        template_version="1.0",
        description="Test migration of civitai directory with media fingerprinting",
        path_mappings=[path_mapping],
        operation=FileOperation.COPY,
        conflict_resolution=ConflictResolution.SKIP,
        file_filter=file_filter,
        indexing_mode="full",
        hash_algorithm="sha256",
        verify_integrity=True,
        preserve_timestamps=True,
        preserve_permissions=True,
        max_workers=4,
        batch_size=100,  # Smaller batches for testing
        max_retries=3,
        retry_delay=1.0,
        continue_on_error=True,
        dry_run=True,  # Start with dry run for safety
        log_level="INFO",
        index_output_path=str(Path(destination_path).parent / "civitai_index.json"),
        detailed_logging=True
    )
    
    # Create and execute migration template
    print(f"\n🔄 Creating migration template...")
    template = FileMigrationTemplate(config)
    
    # Set up progress callback
    def progress_callback(progress):
        if progress.total_files > 0:
            percent = (progress.processed_files / progress.total_files) * 100
            print(f"📊 Progress: {percent:.1f}% ({progress.processed_files}/{progress.total_files})")
            if progress.current_file:
                print(f"   Current: {Path(progress.current_file).name}")
    
    template.set_progress_callback(progress_callback)
    
    # Execute migration
    print(f"\n🚀 Starting migration (DRY RUN)...")
    result = template.execute()
    
    # Display results
    print(f"\n📈 Migration Results:")
    print(f"   Status: {result.status}")
    print(f"   Duration: {result.duration:.2f} seconds" if result.duration else "N/A")
    print(f"   Total files found: {result.progress.total_files}")
    print(f"   Processed: {result.progress.processed_files}")
    print(f"   Successful: {result.progress.successful_files}")
    print(f"   Failed: {result.progress.failed_files}")
    print(f"   Skipped: {result.progress.skipped_files}")
    
    if result.progress.errors:
        print(f"   Errors: {len(result.progress.errors)}")
        for error in result.progress.errors[:5]:  # Show first 5 errors
            print(f"      - {error}")
    
    # Show file type breakdown
    if result.file_index and result.file_index.files:
        print(f"\n📊 File Type Analysis:")
        
        file_types = {}
        image_files = []
        video_files = []
        
        for file_path, metadata in result.file_index.files.items():
            # Get file extension
            ext = Path(file_path).suffix.lower()
            file_types[ext] = file_types.get(ext, 0) + 1
            
            # Categorize media files
            if ext in {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp'}:
                image_files.append(file_path)
            elif ext in {'.mp4', '.avi', '.mov', '.wmv', '.mkv', '.webm'}:
                video_files.append(file_path)
        
        # Show top file types
        sorted_types = sorted(file_types.items(), key=lambda x: x[1], reverse=True)
        for ext, count in sorted_types[:10]:
            print(f"   {ext}: {count} files")
        
        print(f"\n🖼️  Image files found: {len(image_files)}")
        print(f"🎬 Video files found: {len(video_files)}")
    
    # Ask if user wants to proceed with actual migration
    print(f"\n❓ Dry run completed. Proceed with actual migration? (y/N): ", end="")
    response = input().lower().strip()
    
    if response == 'y':
        print(f"\n🔄 Starting actual migration...")
        
        # Update config for actual run
        config.dry_run = False
        
        # Create new template and execute
        template = FileMigrationTemplate(config)
        template.set_progress_callback(progress_callback)
        
        result = template.execute()
        
        print(f"\n✅ Migration completed!")
        print(f"   Status: {result.status}")
        print(f"   Files copied: {result.progress.successful_files}")
        print(f"   Duration: {result.duration:.2f} seconds" if result.duration else "N/A")
        
        # Now perform media fingerprinting
        if result.status == "completed" and result.progress.successful_files > 0:
            print(f"\n🔍 Starting media fingerprinting...")
            
            # Initialize media fingerprinting
            fingerprint_engine = MediaFingerprintEngine(
                hash_size=8,  # 64-bit hashes
                enable_image_hashing=True,
                enable_video_hashing=True,
                preferred_image_hash="dhash"
            )
            
            # Process media files
            fingerprints = []
            media_files = []
            
            # Find media files in destination
            dest_path = Path(destination_path)
            if dest_path.exists():
                for file_path in dest_path.rglob('*'):
                    if file_path.is_file() and fingerprint_engine.is_supported_media(file_path):
                        media_files.append(file_path)
            
            print(f"📊 Found {len(media_files)} media files to fingerprint")
            
            # Generate fingerprints
            for i, file_path in enumerate(media_files):
                print(f"🔍 Processing {i+1}/{len(media_files)}: {file_path.name}")
                
                fingerprint = fingerprint_engine.generate_fingerprint(file_path)
                fingerprints.append(fingerprint)
                
                if fingerprint.error_message:
                    print(f"   ⚠️  Warning: {fingerprint.error_message}")
            
            # Find duplicates
            print(f"\n🔍 Analyzing for duplicates...")
            duplicates = fingerprint_engine.find_duplicates(fingerprints, similarity_threshold=0.95)
            
            if duplicates:
                print(f"📋 Found {len(duplicates)} duplicate groups:")
                
                total_duplicates = 0
                total_wasted_space = 0
                
                for i, group in enumerate(duplicates):
                    print(f"\n   Group {i+1}: {len(group)} files")
                    
                    for fp in group:
                        print(f"      - {Path(fp.file_path).name} ({fp.file_size:,} bytes)")
                        if fp.dhash:
                            print(f"        dhash: {fp.dhash}")
                    
                    # Calculate wasted space (keep one, remove others)
                    group_size = group[0].file_size
                    wasted = group_size * (len(group) - 1)
                    total_wasted_space += wasted
                    total_duplicates += len(group) - 1
                    
                    print(f"      Wasted space: {wasted:,} bytes")
                
                print(f"\n📊 Duplicate Summary:")
                print(f"   Total duplicate files: {total_duplicates}")
                print(f"   Total wasted space: {total_wasted_space:,} bytes ({total_wasted_space/1024/1024:.1f} MB)")
                
                # Save fingerprints and duplicates
                fingerprint_data = {
                    'timestamp': datetime.now().isoformat(),
                    'source_path': source_path,
                    'destination_path': destination_path,
                    'total_files': len(fingerprints),
                    'duplicate_groups': len(duplicates),
                    'total_duplicates': total_duplicates,
                    'total_wasted_space': total_wasted_space,
                    'fingerprints': [
                        {
                            'file_path': fp.file_path,
                            'file_type': fp.file_type,
                            'file_size': fp.file_size,
                            'sha256_hash': fp.sha256_hash,
                            'dhash': fp.dhash,
                            'phash': fp.phash,
                            'video_hash': fp.video_hash,
                            'error_message': fp.error_message
                        }
                        for fp in fingerprints
                    ]
                }
                
                fingerprint_file = Path(destination_path).parent / "civitai_fingerprints.json"
                with open(fingerprint_file, 'w') as f:
                    json.dump(fingerprint_data, f, indent=2)
                
                print(f"💾 Fingerprints saved to: {fingerprint_file}")
                
            else:
                print(f"✅ No duplicates found!")
    
    else:
        print(f"🛑 Migration cancelled.")
    
    print(f"\n🎯 Test completed at: {datetime.now()}")


if __name__ == "__main__":
    main()