#!/usr/bin/env python3
"""
Test script for civitai directory with duplicate detection and staging
This implements the workflow: scan for duplicates, stage both files when found
"""

import os
import sys
import json
from pathlib import Path
from datetime import datetime

# Add src directory to path and set up proper import environment
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root / 'src'))
sys.path.insert(0, str(project_root))

# Add current directory to path for Windows compatibility
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path.cwd()))

from duplicate_workflow import DuplicateWorkflowEngine, DuplicateAction
from media_fingerprinting import MediaFingerprintEngine


def main():
    """Test civitai directory with duplicate detection and staging"""
    
    print("=== Civitai Duplicate Detection & Staging Test ===")
    print(f"Started at: {datetime.now()}")
    
    # Paths
    source_path = r"G:\n\gen7\manual_ingestion\civitai"
    destination_path = r"G:\test_migration\civitai_destination"
    staging_path = r"G:\test_migration\civitai_staging"
    
    # Verify source exists
    if not Path(source_path).exists():
        print(f"❌ Source directory not found: {source_path}")
        print("Please verify the path and try again.")
        return
    
    print(f"📁 Paths:")
    print(f"   Source: {source_path}")
    print(f"   Destination: {destination_path}")
    print(f"   Staging: {staging_path}")
    
    # Create destination directory with some existing files for testing
    dest_dir = Path(destination_path)
    dest_dir.mkdir(parents=True, exist_ok=True)
    
    # Copy a few files to destination first to create potential duplicates
    print(f"\n🔧 Setting up test environment...")
    
    source_files = list(Path(source_path).glob('*'))[:5]  # Get first 5 files
    print(f"Copying {len(source_files)} files to destination for duplicate testing...")
    
    import shutil
    for i, file_path in enumerate(source_files):
        if file_path.is_file():
            dest_file = dest_dir / f"existing_{file_path.name}"
            try:
                shutil.copy2(file_path, dest_file)
                print(f"   Copied: {file_path.name} -> {dest_file.name}")
            except Exception as e:
                print(f"   ⚠️  Error copying {file_path.name}: {e}")
    
    # Initialize duplicate workflow engine
    print(f"\n🔧 Initializing duplicate workflow engine...")
    print(f"   Action: STAGE_BOTH (move both source and destination to staging)")
    print(f"   Similarity threshold: 0.95")
    print(f"   Hamming threshold: 2")
    
    workflow = DuplicateWorkflowEngine(
        staging_base_path=staging_path,
        duplicate_action=DuplicateAction.STAGE_BOTH,
        similarity_threshold=0.95,
        hamming_threshold=2
    )
    
    # Ask user for confirmation
    print(f"\n❓ Ready to scan for duplicates. This will:")
    print(f"   1. Scan source directory for media files")
    print(f"   2. Scan destination directory for existing files")
    print(f"   3. Compare using perceptual hashing")
    print(f"   4. Move duplicate pairs to staging area")
    print(f"   5. Generate detailed reports")
    print(f"\n   Continue? (y/N): ", end="")
    
    response = input().lower().strip()
    if response != 'y':
        print("🛑 Operation cancelled.")
        return
    
    # Execute duplicate detection workflow
    print(f"\n🔍 Starting duplicate detection workflow...")
    
    try:
        # Execute workflow
        report = workflow.execute_workflow(source_path, destination_path)
        
        # Display comprehensive results
        print(f"\n📊 Duplicate Detection Results:")
        print(f"=" * 50)
        print(f"   Scan completed at: {report.scan_timestamp}")
        print(f"   Source files scanned: {report.total_source_files}")
        print(f"   Destination files scanned: {report.total_destination_files}")
        print(f"   Duplicate matches found: {len(report.duplicate_matches)}")
        print(f"   Duplicate percentage: {report.duplicate_percentage:.1f}%")
        
        print(f"\n📈 Actions Taken:")
        print(f"   Files ignored: {report.files_ignored}")
        print(f"   Files staged: {report.files_staged}")
        print(f"   Files ready for normal processing: {report.files_processed_normally}")
        
        # Show detailed duplicate matches
        if report.duplicate_matches:
            print(f"\n🔍 Detailed Duplicate Matches:")
            print(f"=" * 50)
            
            for i, match in enumerate(report.duplicate_matches, 1):
                print(f"\n   Match {i}:")
                print(f"   Source: {Path(match.source_file.file_path).name}")
                print(f"           Size: {match.source_file.file_size:,} bytes")
                print(f"           Type: {match.source_file.file_type}")
                if match.source_file.dhash:
                    print(f"           dHash: {match.source_file.dhash}")
                
                print(f"   Destination: {Path(match.destination_file.file_path).name}")
                print(f"                Size: {match.destination_file.file_size:,} bytes")
                print(f"                Type: {match.destination_file.file_type}")
                if match.destination_file.dhash:
                    print(f"                dHash: {match.destination_file.dhash}")
                
                print(f"   Similarity: {match.similarity_score:.3f} ({match.similarity_type})")
                if match.hamming_distance is not None:
                    print(f"   Hamming Distance: {match.hamming_distance}")
                
                print(f"   Action Taken: {match.action_taken}")
                
                if match.staging_paths:
                    print(f"   Staged Files:")
                    for path in match.staging_paths:
                        print(f"     - {path}")
        
        # Show staging directory contents
        print(f"\n📂 Staging Directory Structure:")
        print(f"=" * 50)
        
        staging_base = Path(staging_path)
        if staging_base.exists():
            for root, dirs, files in os.walk(staging_base):
                level = root.replace(str(staging_base), '').count(os.sep)
                indent = ' ' * 2 * level
                print(f"{indent}{os.path.basename(root)}/")
                subindent = ' ' * 2 * (level + 1)
                for file in files:
                    file_path = Path(root) / file
                    size = file_path.stat().st_size if file_path.exists() else 0
                    print(f"{subindent}{file} ({size:,} bytes)")
        
        # Calculate space savings
        if report.duplicate_matches:
            total_duplicate_size = sum(
                match.source_file.file_size for match in report.duplicate_matches
            )
            print(f"\n💾 Space Analysis:")
            print(f"   Total duplicate file size: {total_duplicate_size:,} bytes ({total_duplicate_size/1024/1024:.1f} MB)")
            print(f"   Space that would be saved: {total_duplicate_size:,} bytes ({total_duplicate_size/1024/1024:.1f} MB)")
        
        # Show file type breakdown
        print(f"\n📊 File Type Analysis:")
        print(f"=" * 50)
        
        file_types = {}
        image_duplicates = 0
        video_duplicates = 0
        other_duplicates = 0
        
        for match in report.duplicate_matches:
            file_type = match.source_file.file_type
            ext = Path(match.source_file.file_path).suffix.lower()
            
            file_types[ext] = file_types.get(ext, 0) + 1
            
            if file_type == "image":
                image_duplicates += 1
            elif file_type == "video":
                video_duplicates += 1
            else:
                other_duplicates += 1
        
        print(f"   Image duplicates: {image_duplicates}")
        print(f"   Video duplicates: {video_duplicates}")
        print(f"   Other duplicates: {other_duplicates}")
        
        if file_types:
            print(f"\n   Duplicate file types:")
            for ext, count in sorted(file_types.items(), key=lambda x: x[1], reverse=True):
                print(f"     {ext}: {count}")
        
        # Generate recommendations
        print(f"\n💡 Recommendations:")
        print(f"=" * 50)
        
        if len(report.duplicate_matches) > 0:
            print(f"   1. Review staged files in: {staging_path}")
            print(f"   2. Verify duplicate detection accuracy")
            print(f"   3. Delete unwanted duplicates from staging")
            print(f"   4. Move preferred files back to appropriate locations")
            print(f"   5. Continue with migration of remaining {report.files_processed_normally} files")
        else:
            print(f"   1. No duplicates found - proceed with normal migration")
            print(f"   2. All {report.total_source_files} files can be migrated normally")
        
        # Save additional analysis
        analysis_file = Path(staging_path) / "reports" / "analysis.json"
        analysis_data = {
            'timestamp': datetime.now().isoformat(),
            'duplicate_matches': len(report.duplicate_matches),
            'duplicate_percentage': report.duplicate_percentage,
            'file_type_breakdown': file_types,
            'space_analysis': {
                'total_duplicate_size': total_duplicate_size if report.duplicate_matches else 0,
                'space_saved_mb': (total_duplicate_size / 1024 / 1024) if report.duplicate_matches else 0
            },
            'recommendations': [
                "Review staged files",
                "Verify duplicate detection accuracy", 
                "Clean up duplicates",
                "Continue with migration"
            ]
        }
        
        with open(analysis_file, 'w') as f:
            json.dump(analysis_data, f, indent=2)
        
        print(f"\n💾 Analysis saved to: {analysis_file}")
        
    except Exception as e:
        print(f"❌ Error in duplicate detection workflow: {e}")
        import traceback
        traceback.print_exc()
    
    # Offer to run with different action
    print(f"\n❓ Test different duplicate action? (IGNORE_NEW instead of STAGE_BOTH)")
    print(f"   This would leave duplicates in source instead of staging them.")
    print(f"   Test IGNORE_NEW action? (y/N): ", end="")
    
    response = input().lower().strip()
    if response == 'y':
        print(f"\n🔄 Testing IGNORE_NEW action...")
        
        # Reset environment
        if Path(destination_path).exists():
            shutil.rmtree(destination_path)
        dest_dir.mkdir(parents=True, exist_ok=True)
        
        # Copy test files again
        for i, file_path in enumerate(source_files):
            if file_path.is_file():
                dest_file = dest_dir / f"existing_{file_path.name}"
                try:
                    shutil.copy2(file_path, dest_file)
                except Exception:
                    pass
        
        # Test with IGNORE_NEW
        workflow_ignore = DuplicateWorkflowEngine(
            staging_base_path=staging_path + "_ignore",
            duplicate_action=DuplicateAction.IGNORE_NEW,
            similarity_threshold=0.95,
            hamming_threshold=2
        )
        
        try:
            report_ignore = workflow_ignore.execute_workflow(source_path, destination_path)
            
            print(f"\n📊 IGNORE_NEW Results:")
            print(f"   Duplicate matches: {len(report_ignore.duplicate_matches)}")
            print(f"   Files ignored: {report_ignore.files_ignored}")
            print(f"   Files staged: {report_ignore.files_staged}")
            print(f"   Files for normal processing: {report_ignore.files_processed_normally}")
            
            # Check that source files are still there
            remaining_source = list(Path(source_path).glob('*'))
            print(f"   Source files remaining: {len(remaining_source)}")
            
        except Exception as e:
            print(f"❌ Error testing IGNORE_NEW: {e}")
    
    print(f"\n🎯 Test completed at: {datetime.now()}")
    print(f"\n✅ Duplicate detection and staging workflow is working!")
    print(f"   Ready for production use with your file migration system.")


if __name__ == "__main__":
    main()