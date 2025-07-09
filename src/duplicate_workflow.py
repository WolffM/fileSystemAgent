import os
import json
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import logging

try:
    from .media_fingerprinting import MediaFingerprintEngine, MediaFingerprint
    from .file_indexing_system import FileIndexingSystem
    from .template_models import HashAlgorithm
except ImportError:
    # Fallback for direct execution
    from media_fingerprinting import MediaFingerprintEngine, MediaFingerprint
    from file_indexing_system import FileIndexingSystem
    from template_models import HashAlgorithm


class DuplicateAction(str, Enum):
    IGNORE_NEW = "ignore_new"        # Skip source file, leave in origin
    STAGE_BOTH = "stage_both"        # Move both to staging area
    KEEP_NEWEST = "keep_newest"      # Keep newest, stage older
    KEEP_LARGEST = "keep_largest"    # Keep largest, stage smaller
    MANUAL_REVIEW = "manual_review"  # Mark for manual review


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


class DuplicateWorkflowEngine:
    """Engine for handling duplicate detection workflow before file migration"""
    
    def __init__(self, 
                 staging_base_path: str,
                 duplicate_action: DuplicateAction = DuplicateAction.STAGE_BOTH,
                 similarity_threshold: float = 0.95,
                 hamming_threshold: int = 2):
        """
        Initialize duplicate workflow engine
        
        Args:
            staging_base_path: Base path for staging duplicate files
            duplicate_action: Default action for handling duplicates
            similarity_threshold: Similarity threshold for perceptual duplicates
            hamming_threshold: Hamming distance threshold for image duplicates
        """
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
                
                # Check perceptual similarity
                similarities = self.fingerprint_engine.calculate_similarity(source_fp, dest_fp)
                
                # Find best similarity score
                best_similarity = 0.0
                best_type = None
                hamming_dist = None
                
                for sim_type, score in similarities.items():
                    if score > best_similarity:
                        best_similarity = score
                        best_type = sim_type
                
                # Check if it meets threshold
                if best_similarity >= self.similarity_threshold:
                    # For image hashes, calculate Hamming distance
                    if source_fp.file_type == "image" and best_type in ['dhash', 'phash', 'ahash', 'whash']:
                        try:
                            from imagehash import hex_to_hash
                            hash1 = getattr(source_fp, best_type)
                            hash2 = getattr(dest_fp, best_type)
                            
                            if hash1 and hash2:
                                img_hash1 = hex_to_hash(hash1)
                                img_hash2 = hex_to_hash(hash2)
                                hamming_dist = img_hash1 - img_hash2
                        except Exception:
                            pass
                    
                    match = DuplicateMatch(
                        source_file=source_fp,
                        destination_file=dest_fp,
                        similarity_score=best_similarity,
                        similarity_type=best_type,
                        hamming_distance=hamming_dist
                    )
                    matches.append(match)
        
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
                elif action == DuplicateAction.KEEP_NEWEST:
                    self._handle_keep_newest(match)
                elif action == DuplicateAction.KEEP_LARGEST:
                    self._handle_keep_largest(match)
                elif action == DuplicateAction.MANUAL_REVIEW:
                    self._handle_manual_review(match)
                
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
        
        # Move files to staging
        shutil.move(str(source_path), str(source_staging))
        shutil.move(str(dest_path), str(dest_staging))
        
        match.staging_paths = [str(source_staging), str(dest_staging)]
        
        self.logger.info(f"Staged duplicate files:")
        self.logger.info(f"  Source: {source_path} -> {source_staging}")
        self.logger.info(f"  Destination: {dest_path} -> {dest_staging}")
    
    def _handle_keep_newest(self, match: DuplicateMatch):
        """Handle duplicate by keeping newest file, staging older"""
        source_path = Path(match.source_file.file_path)
        dest_path = Path(match.destination_file.file_path)
        
        # Compare modification times
        source_mtime = source_path.stat().st_mtime
        dest_mtime = dest_path.stat().st_mtime
        
        if source_mtime > dest_mtime:
            # Source is newer, stage destination
            self._stage_file(dest_path, "destination")
            match.staging_paths = [str(dest_path)]
        else:
            # Destination is newer, stage source
            self._stage_file(source_path, "source")
            match.staging_paths = [str(source_path)]
    
    def _handle_keep_largest(self, match: DuplicateMatch):
        """Handle duplicate by keeping largest file, staging smaller"""
        source_path = Path(match.source_file.file_path)
        dest_path = Path(match.destination_file.file_path)
        
        if match.source_file.file_size > match.destination_file.file_size:
            # Source is larger, stage destination
            self._stage_file(dest_path, "destination")
            match.staging_paths = [str(dest_path)]
        else:
            # Destination is larger, stage source
            self._stage_file(source_path, "source")
            match.staging_paths = [str(source_path)]
    
    def _handle_manual_review(self, match: DuplicateMatch):
        """Handle duplicate by marking for manual review"""
        review_dir = self.staging_base_path / "duplicates" / "manual_review"
        
        # Create review info file
        review_info = {
            'source_file': match.source_file.file_path,
            'destination_file': match.destination_file.file_path,
            'similarity_score': match.similarity_score,
            'similarity_type': match.similarity_type,
            'hamming_distance': match.hamming_distance,
            'created_at': datetime.now().isoformat()
        }
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        review_file = review_dir / f"review_{timestamp}.json"
        
        with open(review_file, 'w') as f:
            json.dump(review_info, f, indent=2)
        
        match.staging_paths = [str(review_file)]
        
        self.logger.info(f"Marked for manual review: {review_file}")
    
    def _stage_file(self, file_path: Path, category: str):
        """Stage a single file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        staging_path = self.staging_base_path / "duplicates" / category / f"{timestamp}_{file_path.name}"
        staging_path = self._get_unique_path(staging_path)
        
        shutil.move(str(file_path), str(staging_path))
        self.logger.info(f"Staged file: {file_path} -> {staging_path}")
    
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
        
        # Also save summary
        summary_file = self.staging_base_path / "reports" / f"duplicate_summary_{timestamp}.txt"
        with open(summary_file, 'w') as f:
            f.write(f"Duplicate Detection Summary\n")
            f.write(f"=" * 50 + "\n")
            f.write(f"Scan Date: {report.scan_timestamp}\n")
            f.write(f"Source Path: {report.source_path}\n")
            f.write(f"Destination Path: {report.destination_path}\n")
            f.write(f"Staging Path: {report.staging_path}\n\n")
            
            f.write(f"File Counts:\n")
            f.write(f"  Source Files: {report.total_source_files}\n")
            f.write(f"  Destination Files: {report.total_destination_files}\n")
            f.write(f"  Duplicate Matches: {len(report.duplicate_matches)}\n")
            f.write(f"  Duplicate Percentage: {report.duplicate_percentage:.1f}%\n\n")
            
            f.write(f"Actions Taken:\n")
            f.write(f"  Files Ignored: {report.files_ignored}\n")
            f.write(f"  Files Staged: {report.files_staged}\n")
            f.write(f"  Files Processed Normally: {report.files_processed_normally}\n\n")
            
            f.write(f"Duplicate Matches:\n")
            for i, match in enumerate(report.duplicate_matches, 1):
                f.write(f"  {i}. {Path(match.source_file.file_path).name}\n")
                f.write(f"     vs {Path(match.destination_file.file_path).name}\n")
                f.write(f"     Similarity: {match.similarity_score:.3f} ({match.similarity_type})\n")
                if match.hamming_distance is not None:
                    f.write(f"     Hamming Distance: {match.hamming_distance}\n")
                f.write(f"     Action: {match.action_taken}\n\n")
        
        self.logger.info(f"Duplicate summary saved: {summary_file}")
    
    def get_files_to_process(self, report: DuplicateReport) -> List[str]:
        """Get list of source files that should be processed normally (not duplicates)"""
        duplicate_source_files = {match.source_file.file_path for match in report.duplicate_matches}
        
        # This would need to be called with the original source fingerprints
        # For now, return empty list - this method needs the original fingerprint data
        return []