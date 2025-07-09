#!/usr/bin/env python3
"""
Standalone duplicate detection test script for Windows
This script contains all necessary components without relative imports
"""

import os
import sys
import json
import shutil
import hashlib
import mimetypes
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import logging

# Try to import the image/video processing libraries
try:
    import imagehash
    from PIL import Image, ImageFile
    ImageFile.LOAD_TRUNCATED_IMAGES = True
    IMAGE_HASHING_AVAILABLE = True
except ImportError:
    IMAGE_HASHING_AVAILABLE = False

try:
    from videohash import VideoHash
    VIDEO_HASHING_AVAILABLE = True
except ImportError:
    VIDEO_HASHING_AVAILABLE = False

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class DuplicateAction(str, Enum):
    IGNORE_NEW = "ignore_new"        # Skip source file, leave in origin
    STAGE_BOTH = "stage_both"        # Move both to staging area
    KEEP_NEWEST = "keep_newest"      # Keep newest, stage older
    KEEP_LARGEST = "keep_largest"    # Keep largest, stage smaller
    MANUAL_REVIEW = "manual_review"  # Mark for manual review


@dataclass
class MediaFingerprint:
    """Media fingerprint containing multiple hash types"""
    file_path: str
    file_type: str  # 'image' or 'video'
    file_size: int
    mime_type: str
    
    # Traditional hash
    sha256_hash: str
    
    # Perceptual hashes for images
    dhash: Optional[str] = None
    phash: Optional[str] = None
    ahash: Optional[str] = None
    whash: Optional[str] = None
    
    # Video hash
    video_hash: Optional[str] = None
    
    # Metadata
    created_at: datetime = datetime.now()
    error_message: Optional[str] = None


@dataclass
class DuplicateMatch:
    """Represents a duplicate match between source and destination files"""
    source_file: MediaFingerprint
    destination_file: MediaFingerprint
    similarity_score: float
    similarity_type: str  # 'exact', 'perceptual', 'hash'
    hamming_distance: Optional[int] = None
    action_taken: Optional[DuplicateAction] = None
    staging_paths: List[str] = None
    
    def __post_init__(self):
        if self.staging_paths is None:
            self.staging_paths = []


@dataclass
class DuplicateReport:
    """Comprehensive duplicate detection report"""
    scan_timestamp: datetime
    source_path: str
    destination_path: str
    staging_path: str
    
    total_source_files: int
    total_destination_files: int
    duplicate_matches: List[DuplicateMatch]
    
    files_ignored: int = 0
    files_staged: int = 0
    files_processed_normally: int = 0
    
    def __post_init__(self):
        # Calculate summary statistics
        self.files_ignored = sum(1 for match in self.duplicate_matches if match.action_taken == DuplicateAction.IGNORE_NEW)
        self.files_staged = sum(1 for match in self.duplicate_matches if match.action_taken == DuplicateAction.STAGE_BOTH)
        self.files_processed_normally = self.total_source_files - len(self.duplicate_matches)
    
    @property
    def duplicate_percentage(self) -> float:
        """Calculate percentage of source files that are duplicates"""
        if self.total_source_files == 0:
            return 0.0
        return (len(self.duplicate_matches) / self.total_source_files) * 100


class MediaFingerprintEngine:
    """Engine for generating perceptual fingerprints of images and videos"""
    
    def __init__(self, 
                 hash_size: int = 8,
                 enable_image_hashing: bool = True,
                 enable_video_hashing: bool = True,
                 preferred_image_hash: str = "dhash"):
        self.hash_size = hash_size
        self.enable_image_hashing = enable_image_hashing
        self.enable_video_hashing = enable_video_hashing
        self.preferred_image_hash = preferred_image_hash
        self.logger = logging.getLogger(__name__)
        
        # Supported media types
        self.image_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif',
            '.webp', '.svg', '.ico', '.psd', '.raw', '.cr2', '.nef',
            '.orf', '.sr2', '.arw', '.dng', '.heic', '.heif'
        }
        
        self.video_extensions = {
            '.mp4', '.avi', '.mov', '.wmv', '.flv', '.webm', '.mkv',
            '.m4v', '.3gp', '.3g2', '.mts', '.m2ts', '.ts', '.vob',
            '.ogv', '.dv', '.rm', '.rmvb', '.asf', '.amv', '.mpg',
            '.mpeg', '.mpv', '.m2v', '.m4v', '.f4v', '.f4p', '.f4a', '.f4b'
        }
        
        # Check library availability
        if enable_image_hashing and not IMAGE_HASHING_AVAILABLE:
            self.logger.warning("Image hashing disabled: imagehash library not available")
            self.enable_image_hashing = False
        
        if enable_video_hashing and not VIDEO_HASHING_AVAILABLE:
            self.logger.warning("Video hashing disabled: videohash library not available")
            self.enable_video_hashing = False
    
    def is_supported_media(self, file_path: Path) -> bool:
        """Check if file is supported media type"""
        extension = file_path.suffix.lower()
        return extension in self.image_extensions or extension in self.video_extensions
    
    def get_media_type(self, file_path: Path) -> Optional[str]:
        """Determine media type (image/video) from file extension"""
        extension = file_path.suffix.lower()
        
        if extension in self.image_extensions:
            return "image"
        elif extension in self.video_extensions:
            return "video"
        else:
            return None
    
    def calculate_traditional_hash(self, file_path: Path) -> str:
        """Calculate traditional SHA256 hash"""
        try:
            hash_func = hashlib.sha256()
            with open(file_path, 'rb') as f:
                while chunk := f.read(8192):
                    hash_func.update(chunk)
            return hash_func.hexdigest()
        except Exception as e:
            self.logger.error(f"Error calculating traditional hash for {file_path}: {e}")
            return ""
    
    def calculate_image_hashes(self, image_path: Path) -> Dict[str, str]:
        """Calculate perceptual hashes for images"""
        if not self.enable_image_hashing:
            return {}
        
        try:
            # Open image with PIL
            with Image.open(image_path) as img:
                # Convert to RGB if necessary
                if img.mode in ('RGBA', 'LA', 'P'):
                    img = img.convert('RGB')
                
                hashes = {}
                
                # Calculate different hash types
                if self.preferred_image_hash == "dhash" or "dhash" in self.preferred_image_hash:
                    hashes['dhash'] = str(imagehash.dhash(img, hash_size=self.hash_size))
                
                if self.preferred_image_hash == "phash" or "phash" in self.preferred_image_hash:
                    hashes['phash'] = str(imagehash.phash(img, hash_size=self.hash_size))
                
                if self.preferred_image_hash == "ahash" or "ahash" in self.preferred_image_hash:
                    hashes['ahash'] = str(imagehash.average_hash(img, hash_size=self.hash_size))
                
                if self.preferred_image_hash == "whash" or "whash" in self.preferred_image_hash:
                    hashes['whash'] = str(imagehash.whash(img, hash_size=self.hash_size))
                
                # Always calculate the preferred hash if not already done
                if self.preferred_image_hash not in hashes:
                    if self.preferred_image_hash == "dhash":
                        hashes['dhash'] = str(imagehash.dhash(img, hash_size=self.hash_size))
                    elif self.preferred_image_hash == "phash":
                        hashes['phash'] = str(imagehash.phash(img, hash_size=self.hash_size))
                    elif self.preferred_image_hash == "ahash":
                        hashes['ahash'] = str(imagehash.average_hash(img, hash_size=self.hash_size))
                    elif self.preferred_image_hash == "whash":
                        hashes['whash'] = str(imagehash.whash(img, hash_size=self.hash_size))
                
                return hashes
                
        except Exception as e:
            self.logger.error(f"Error calculating image hashes for {image_path}: {e}")
            return {}
    
    def calculate_video_hash(self, video_path: Path) -> Optional[str]:
        """Calculate perceptual hash for videos"""
        if not self.enable_video_hashing:
            return None
        
        try:
            # Use VideoHash class to generate perceptual hash
            video_hash_obj = VideoHash(path=str(video_path))
            video_hash_value = str(video_hash_obj)  # This returns the hash string
            return video_hash_value
            
        except Exception as e:
            self.logger.error(f"Error calculating video hash for {video_path}: {e}")
            return None
    
    def generate_fingerprint(self, file_path: Path) -> MediaFingerprint:
        """Generate comprehensive media fingerprint"""
        try:
            # Basic file info
            stat_info = file_path.stat()
            mime_type = mimetypes.guess_type(str(file_path))[0] or 'application/octet-stream'
            media_type = self.get_media_type(file_path)
            
            # Calculate traditional hash
            sha256_hash = self.calculate_traditional_hash(file_path)
            
            # Initialize fingerprint
            fingerprint = MediaFingerprint(
                file_path=str(file_path),
                file_type=media_type or 'unknown',
                file_size=stat_info.st_size,
                mime_type=mime_type,
                sha256_hash=sha256_hash
            )
            
            # Generate perceptual hashes based on media type
            if media_type == "image":
                image_hashes = self.calculate_image_hashes(file_path)
                fingerprint.dhash = image_hashes.get('dhash')
                fingerprint.phash = image_hashes.get('phash')
                fingerprint.ahash = image_hashes.get('ahash')
                fingerprint.whash = image_hashes.get('whash')
                
            elif media_type == "video":
                fingerprint.video_hash = self.calculate_video_hash(file_path)
            
            self.logger.debug(f"Generated fingerprint for {file_path}")
            return fingerprint
            
        except Exception as e:
            error_msg = f"Error generating fingerprint for {file_path}: {e}"
            self.logger.error(error_msg)
            
            return MediaFingerprint(
                file_path=str(file_path),
                file_type='unknown',
                file_size=0,
                mime_type='application/octet-stream',
                sha256_hash='',
                error_message=error_msg
            )


class DuplicateWorkflowEngine:
    """Engine for handling duplicate detection workflow before file migration"""
    
    def __init__(self, 
                 staging_base_path: str,
                 duplicate_action: DuplicateAction = DuplicateAction.STAGE_BOTH,
                 similarity_threshold: float = 0.95,
                 hamming_threshold: int = 2):
        self.staging_base_path = Path(staging_base_path)
        self.duplicate_action = duplicate_action
        self.similarity_threshold = similarity_threshold
        self.hamming_threshold = hamming_threshold
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.fingerprint_engine = MediaFingerprintEngine(
            hash_size=8,
            enable_image_hashing=True,
            enable_video_hashing=True,
            preferred_image_hash="dhash"
        )
        
        # Create staging directories
        self._create_staging_directories()
    
    def _create_staging_directories(self):
        """Create staging directory structure"""
        staging_dirs = [
            self.staging_base_path / "duplicates",
            self.staging_base_path / "duplicates" / "source",
            self.staging_base_path / "duplicates" / "destination", 
            self.staging_base_path / "duplicates" / "manual_review",
            self.staging_base_path / "reports"
        ]
        
        for dir_path in staging_dirs:
            dir_path.mkdir(parents=True, exist_ok=True)
            self.logger.info(f"Created staging directory: {dir_path}")
    
    def scan_directory(self, directory_path: Path, recursive: bool = True) -> List[MediaFingerprint]:
        """Scan directory and generate fingerprints for all supported media files"""
        fingerprints = []
        
        self.logger.info(f"Scanning directory: {directory_path}")
        
        # Find all media files
        media_files = []
        if recursive:
            for file_path in directory_path.rglob('*'):
                if file_path.is_file() and self.fingerprint_engine.is_supported_media(file_path):
                    media_files.append(file_path)
        else:
            for file_path in directory_path.iterdir():
                if file_path.is_file() and self.fingerprint_engine.is_supported_media(file_path):
                    media_files.append(file_path)
        
        self.logger.info(f"Found {len(media_files)} media files to fingerprint")
        
        # Generate fingerprints
        for i, file_path in enumerate(media_files):
            if i % 100 == 0:
                self.logger.info(f"Processing file {i+1}/{len(media_files)}: {file_path.name}")
            
            fingerprint = self.fingerprint_engine.generate_fingerprint(file_path)
            fingerprints.append(fingerprint)
        
        self.logger.info(f"Generated {len(fingerprints)} fingerprints")
        return fingerprints
    
    def find_duplicates(self, source_fingerprints: List[MediaFingerprint],
                       destination_fingerprints: List[MediaFingerprint]) -> List[DuplicateMatch]:
        """Find duplicate matches between source and destination files"""
        matches = []
        
        self.logger.info(f"Comparing {len(source_fingerprints)} source files with {len(destination_fingerprints)} destination files")
        
        for source_fp in source_fingerprints:
            for dest_fp in destination_fingerprints:
                # Skip if different file types
                if source_fp.file_type != dest_fp.file_type:
                    continue
                
                # Check for exact match first (SHA256)
                if source_fp.sha256_hash == dest_fp.sha256_hash and source_fp.sha256_hash:
                    match = DuplicateMatch(
                        source_file=source_fp,
                        destination_file=dest_fp,
                        similarity_score=1.0,
                        similarity_type='exact'
                    )
                    matches.append(match)
                    continue
        
        self.logger.info(f"Found {len(matches)} duplicate matches")
        return matches
    
    def handle_duplicates(self, matches: List[DuplicateMatch], 
                         action: Optional[DuplicateAction] = None) -> List[DuplicateMatch]:
        """Handle duplicate matches according to specified action"""
        if action is None:
            action = self.duplicate_action
        
        self.logger.info(f"Handling {len(matches)} duplicates with action: {action}")
        
        for match in matches:
            try:
                if action == DuplicateAction.IGNORE_NEW:
                    self._handle_ignore_new(match)
                elif action == DuplicateAction.STAGE_BOTH:
                    self._handle_stage_both(match)
                
                match.action_taken = action
                
            except Exception as e:
                self.logger.error(f"Error handling duplicate match: {e}")
                match.action_taken = None
        
        return matches
    
    def _handle_ignore_new(self, match: DuplicateMatch):
        """Handle duplicate by ignoring new file (leave in source)"""
        self.logger.info(f"Ignoring new file: {match.source_file.file_path}")
        # No action needed - file stays in source location
    
    def _handle_stage_both(self, match: DuplicateMatch):
        """Handle duplicate by staging both files"""
        source_path = Path(match.source_file.file_path)
        dest_path = Path(match.destination_file.file_path)
        
        # Create unique staging paths
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Stage source file
        source_staging = self.staging_base_path / "duplicates" / "source" / f"{timestamp}_{source_path.name}"
        source_staging = self._get_unique_path(source_staging)
        
        # Stage destination file
        dest_staging = self.staging_base_path / "duplicates" / "destination" / f"{timestamp}_{dest_path.name}"
        dest_staging = self._get_unique_path(dest_staging)
        
        # Copy files to staging (don't move original files during testing)
        if source_path.exists():
            shutil.copy2(str(source_path), str(source_staging))
        if dest_path.exists():
            shutil.copy2(str(dest_path), str(dest_staging))
        
        match.staging_paths = [str(source_staging), str(dest_staging)]
        
        self.logger.info(f"Staged duplicate files:")
        self.logger.info(f"  Source: {source_path} -> {source_staging}")
        self.logger.info(f"  Destination: {dest_path} -> {dest_staging}")
    
    def _get_unique_path(self, path: Path) -> Path:
        """Get unique path by adding counter if file exists"""
        if not path.exists():
            return path
        
        base = path.stem
        suffix = path.suffix
        parent = path.parent
        counter = 1
        
        while True:
            new_path = parent / f"{base}_{counter}{suffix}"
            if not new_path.exists():
                return new_path
            counter += 1
    
    def execute_workflow(self, source_path: str, destination_path: str) -> DuplicateReport:
        """Execute complete duplicate detection workflow"""
        source_path = Path(source_path)
        destination_path = Path(destination_path)
        
        self.logger.info(f"Starting duplicate detection workflow")
        self.logger.info(f"Source: {source_path}")
        self.logger.info(f"Destination: {destination_path}")
        
        # Phase 1: Scan directories
        source_fingerprints = self.scan_directory(source_path)
        destination_fingerprints = []
        
        if destination_path.exists():
            destination_fingerprints = self.scan_directory(destination_path)
        
        # Phase 2: Find duplicates
        matches = self.find_duplicates(source_fingerprints, destination_fingerprints)
        
        # Phase 3: Handle duplicates
        processed_matches = self.handle_duplicates(matches)
        
        # Generate report
        report = DuplicateReport(
            scan_timestamp=datetime.now(),
            source_path=str(source_path),
            destination_path=str(destination_path),
            staging_path=str(self.staging_base_path),
            total_source_files=len(source_fingerprints),
            total_destination_files=len(destination_fingerprints),
            duplicate_matches=processed_matches
        )
        
        # Save report
        self.save_report(report)
        
        return report
    
    def save_report(self, report: DuplicateReport):
        """Save duplicate detection report"""
        timestamp = report.scan_timestamp.strftime("%Y%m%d_%H%M%S")
        report_file = self.staging_base_path / "reports" / f"duplicate_report_{timestamp}.json"
        
        report_data = {
            'scan_timestamp': report.scan_timestamp.isoformat(),
            'source_path': report.source_path,
            'destination_path': report.destination_path,
            'staging_path': report.staging_path,
            'total_source_files': report.total_source_files,
            'total_destination_files': report.total_destination_files,
            'files_ignored': report.files_ignored,
            'files_staged': report.files_staged,
            'files_processed_normally': report.files_processed_normally,
            'duplicate_percentage': report.duplicate_percentage,
            'duplicate_matches': [
                {
                    'source_file': match.source_file.file_path,
                    'destination_file': match.destination_file.file_path,
                    'similarity_score': match.similarity_score,
                    'similarity_type': match.similarity_type,
                    'hamming_distance': match.hamming_distance,
                    'action_taken': match.action_taken,
                    'staging_paths': match.staging_paths
                }
                for match in report.duplicate_matches
            ]
        }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        self.logger.info(f"Duplicate report saved: {report_file}")


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
    print(f"   3. Compare using SHA256 hashes")
    print(f"   4. Stage duplicate pairs to staging area")
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
                
                print(f"   Destination: {Path(match.destination_file.file_path).name}")
                print(f"                Size: {match.destination_file.file_size:,} bytes")
                print(f"                Type: {match.destination_file.file_type}")
                
                print(f"   Similarity: {match.similarity_score:.3f} ({match.similarity_type})")
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
        
        print(f"\n📊 Summary:")
        print(f"   Total files processed: {report.total_source_files + report.total_destination_files}")
        print(f"   Duplicates found: {len(report.duplicate_matches)}")
        print(f"   Duplicate rate: {report.duplicate_percentage:.1f}%")
        print(f"   Files ready for migration: {report.files_processed_normally}")
        
    except Exception as e:
        print(f"❌ Error in duplicate detection workflow: {e}")
        import traceback
        traceback.print_exc()
    
    print(f"\n🎯 Test completed at: {datetime.now()}")
    print(f"✅ Duplicate detection and staging workflow tested successfully!")


if __name__ == "__main__":
    main()