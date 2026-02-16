import json
import sqlite3
import hashlib
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

from .template_models import (
    FileMetadata, DuplicateGroup, DuplicateReport,
    HashAlgorithm
)


class FileIndexingSystem:
    """Advanced file indexing system with SQLite backend for performance"""
    
    def __init__(self, index_path: str = "file_index.db", hash_algorithm: HashAlgorithm = HashAlgorithm.SHA256):
        self.index_path = Path(index_path)
        self.hash_algorithm = hash_algorithm
        self.logger = logging.getLogger(__name__)
        self.db_path = self.index_path.with_suffix('.db')
        
        # Initialize database
        self._init_database()
    
    def _init_database(self):
        """Initialize SQLite database for file indexing"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create tables
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT UNIQUE NOT NULL,
                    file_name TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    created_time TIMESTAMP NOT NULL,
                    modified_time TIMESTAMP NOT NULL,
                    accessed_time TIMESTAMP,
                    file_hash TEXT,
                    hash_algorithm TEXT,
                    mime_type TEXT,
                    permissions TEXT,
                    owner_name TEXT,
                    group_name TEXT,
                    is_directory BOOLEAN NOT NULL,
                    is_symlink BOOLEAN NOT NULL,
                    target_path TEXT,
                    indexed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    custom_metadata TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS file_indices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    index_id TEXT UNIQUE NOT NULL,
                    index_path TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL,
                    updated_at TIMESTAMP NOT NULL,
                    total_files INTEGER DEFAULT 0,
                    total_size INTEGER DEFAULT 0,
                    hash_algorithm TEXT NOT NULL
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS duplicate_groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hash_value TEXT NOT NULL,
                    hash_algorithm TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    file_count INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS duplicate_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    group_id INTEGER NOT NULL,
                    file_path TEXT NOT NULL,
                    FOREIGN KEY (group_id) REFERENCES duplicate_groups (id)
                )
            ''')
            
            # Create indexes for performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_files_hash ON files(file_hash)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_files_path ON files(file_path)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_files_size ON files(file_size)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_files_modified ON files(modified_time)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_duplicates_hash ON duplicate_groups(hash_value)')
            
            conn.commit()
    
    def calculate_file_hash(self, file_path: Path, algorithm: HashAlgorithm = None) -> str:
        """Calculate file hash with progress tracking for large files"""
        if algorithm is None:
            algorithm = self.hash_algorithm
        
        hash_func = getattr(hashlib, algorithm.value)()
        
        try:
            chunk_size = 8192
            
            with open(file_path, 'rb') as f:
                while chunk := f.read(chunk_size):
                    hash_func.update(chunk)
            
            return hash_func.hexdigest()
            
        except Exception as e:
            self.logger.error(f"Error calculating hash for {file_path}: {e}")
            return ""
    
    def get_file_metadata(self, file_path: Path, include_hash: bool = True) -> FileMetadata:
        """Get comprehensive file metadata"""
        try:
            stat_info = file_path.stat()
            
            metadata = FileMetadata(
                file_path=str(file_path),
                file_name=file_path.name,
                file_size=stat_info.st_size,
                created_time=datetime.fromtimestamp(stat_info.st_ctime),
                modified_time=datetime.fromtimestamp(stat_info.st_mtime),
                accessed_time=datetime.fromtimestamp(stat_info.st_atime),
                is_directory=file_path.is_dir(),
                is_symlink=file_path.is_symlink(),
                permissions=oct(stat_info.st_mode)[-3:],
            )
            
            # Add hash for files
            if include_hash and not metadata.is_directory:
                metadata.file_hash = self.calculate_file_hash(file_path)
                metadata.hash_algorithm = self.hash_algorithm
            
            # Add MIME type
            if not metadata.is_directory:
                import mimetypes
                metadata.mime_type = mimetypes.guess_type(str(file_path))[0]
            
            # Add symlink target
            if metadata.is_symlink:
                try:
                    metadata.target_path = str(file_path.readlink())
                except Exception:
                    pass
            
            # Add owner info (Unix-like systems)
            try:
                import pwd, grp
                metadata.owner = pwd.getpwuid(stat_info.st_uid).pw_name
                metadata.group = grp.getgrgid(stat_info.st_gid).gr_name
            except (ImportError, KeyError, OSError):
                pass
            
            return metadata
            
        except Exception as e:
            self.logger.error(f"Error getting metadata for {file_path}: {e}")
            raise
    
    def index_file(self, file_path: Path, include_hash: bool = True) -> bool:
        """Index a single file"""
        try:
            metadata = self.get_file_metadata(file_path, include_hash)
            
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Insert or update file record
                cursor.execute('''
                    INSERT OR REPLACE INTO files (
                        file_path, file_name, file_size, created_time, modified_time,
                        accessed_time, file_hash, hash_algorithm, mime_type, permissions,
                        owner_name, group_name, is_directory, is_symlink, target_path,
                        custom_metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    str(file_path), metadata.file_name, metadata.file_size,
                    metadata.created_time, metadata.modified_time, metadata.accessed_time,
                    metadata.file_hash, metadata.hash_algorithm.value if metadata.hash_algorithm else None,
                    metadata.mime_type, metadata.permissions, metadata.owner, metadata.group,
                    metadata.is_directory, metadata.is_symlink, metadata.target_path,
                    json.dumps(metadata.custom_metadata) if metadata.custom_metadata else None
                ))
                
                conn.commit()
                return True
                
        except Exception as e:
            self.logger.error(f"Error indexing {file_path}: {e}")
            return False
    
    def index_directory(self, directory_path: Path, recursive: bool = True, 
                       include_hash: bool = True, max_workers: int = 4) -> Dict[str, int]:
        """Index entire directory with threading"""
        stats = {
            'total_files': 0,
            'indexed_files': 0,
            'failed_files': 0,
            'skipped_files': 0
        }
        
        # Collect all files
        files_to_index = []
        
        if recursive:
            for file_path in directory_path.rglob('*'):
                if file_path.is_file():
                    files_to_index.append(file_path)
        else:
            for file_path in directory_path.iterdir():
                if file_path.is_file():
                    files_to_index.append(file_path)
        
        stats['total_files'] = len(files_to_index)
        
        # Process files with threading
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_file = {
                executor.submit(self.index_file, file_path, include_hash): file_path
                for file_path in files_to_index
            }
            
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    success = future.result()
                    if success:
                        stats['indexed_files'] += 1
                    else:
                        stats['failed_files'] += 1
                except Exception as e:
                    self.logger.error(f"Error processing {file_path}: {e}")
                    stats['failed_files'] += 1
        
        self.logger.info(f"Directory indexing complete: {stats}")
        return stats
    
    def find_duplicates(self, min_size: int = 0) -> List[DuplicateGroup]:
        """Find duplicate files based on hash"""
        duplicates = []
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Clear existing duplicate records
            cursor.execute('DELETE FROM duplicate_groups')
            cursor.execute('DELETE FROM duplicate_files')
            
            # Find files with same hash
            cursor.execute('''
                SELECT file_hash, hash_algorithm, file_size, COUNT(*) as count
                FROM files 
                WHERE file_hash IS NOT NULL 
                AND file_hash != '' 
                AND file_size >= ?
                AND is_directory = 0
                GROUP BY file_hash, hash_algorithm, file_size
                HAVING count > 1
                ORDER BY file_size DESC
            ''', (min_size,))
            
            for row in cursor.fetchall():
                hash_value, hash_algorithm, file_size, count = row
                
                # Get all files with this hash
                cursor.execute('''
                    SELECT file_path, file_name, created_time, modified_time
                    FROM files 
                    WHERE file_hash = ? AND hash_algorithm = ?
                    ORDER BY modified_time
                ''', (hash_value, hash_algorithm))
                
                files = []
                for file_row in cursor.fetchall():
                    file_path, file_name, created, modified = file_row
                    try:
                        metadata = self.get_file_metadata(Path(file_path), include_hash=False)
                        files.append(metadata)
                    except Exception as e:
                        self.logger.warning(f"Could not get metadata for {file_path}: {e}")
                        continue
                
                if len(files) > 1:
                    # Create duplicate group
                    duplicate_group = DuplicateGroup(
                        hash_value=hash_value,
                        hash_algorithm=HashAlgorithm(hash_algorithm),
                        file_size=file_size,
                        file_count=len(files),
                        files=files
                    )
                    duplicates.append(duplicate_group)
                    
                    # Store in database
                    cursor.execute('''
                        INSERT INTO duplicate_groups (hash_value, hash_algorithm, file_size, file_count)
                        VALUES (?, ?, ?, ?)
                    ''', (hash_value, hash_algorithm, file_size, len(files)))
                    
                    group_id = cursor.lastrowid
                    
                    # Store individual files
                    for file_metadata in files:
                        cursor.execute('''
                            INSERT INTO duplicate_files (group_id, file_path)
                            VALUES (?, ?)
                        ''', (group_id, file_metadata.file_path))
            
            conn.commit()
        
        return duplicates
    
    def generate_duplicate_report(self, scan_path: str) -> DuplicateReport:
        """Generate comprehensive duplicate report"""
        duplicates = self.find_duplicates()
        
        # Calculate statistics
        total_files = self.get_total_files()
        total_size = self.get_total_size()
        total_duplicates = sum(group.file_count for group in duplicates)
        total_wasted_space = sum(group.total_wasted_space for group in duplicates)
        
        report = DuplicateReport(
            scan_path=scan_path,
            total_files_scanned=total_files,
            total_size_scanned=total_size,
            duplicate_groups=duplicates,
            total_duplicates=total_duplicates,
            total_wasted_space=total_wasted_space,
            hash_algorithm=self.hash_algorithm
        )
        
        return report
    
    def get_total_files(self) -> int:
        """Get total number of indexed files"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM files WHERE is_directory = 0')
            return cursor.fetchone()[0]
    
    def get_total_size(self) -> int:
        """Get total size of indexed files"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT SUM(file_size) FROM files WHERE is_directory = 0')
            result = cursor.fetchone()[0]
            return result if result else 0
    
    def search_files(self, query: str, search_type: str = "name") -> List[FileMetadata]:
        """Search indexed files"""
        results = []
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            if search_type == "name":
                cursor.execute('''
                    SELECT * FROM files 
                    WHERE file_name LIKE ? 
                    ORDER BY file_name
                ''', (f'%{query}%',))
            elif search_type == "path":
                cursor.execute('''
                    SELECT * FROM files 
                    WHERE file_path LIKE ? 
                    ORDER BY file_path
                ''', (f'%{query}%',))
            elif search_type == "hash":
                cursor.execute('''
                    SELECT * FROM files 
                    WHERE file_hash = ?
                ''', (query,))
            elif search_type == "size":
                try:
                    size = int(query)
                    cursor.execute('''
                        SELECT * FROM files 
                        WHERE file_size = ?
                        ORDER BY file_name
                    ''', (size,))
                except ValueError:
                    return results
            
            for row in cursor.fetchall():
                try:
                    metadata = self._row_to_metadata(row)
                    results.append(metadata)
                except Exception as e:
                    self.logger.warning(f"Error converting row to metadata: {e}")
        
        return results
    
    def _row_to_metadata(self, row) -> FileMetadata:
        """Convert database row to FileMetadata"""
        (id, file_path, file_name, file_size, created_time, modified_time,
         accessed_time, file_hash, hash_algorithm, mime_type, permissions,
         owner_name, group_name, is_directory, is_symlink, target_path,
         indexed_at, custom_metadata) = row
        
        # Parse custom metadata
        custom_meta = {}
        if custom_metadata:
            try:
                custom_meta = json.loads(custom_metadata)
            except json.JSONDecodeError:
                pass
        
        return FileMetadata(
            file_path=file_path,
            file_name=file_name,
            file_size=file_size,
            created_time=datetime.fromisoformat(created_time) if created_time else None,
            modified_time=datetime.fromisoformat(modified_time) if modified_time else None,
            accessed_time=datetime.fromisoformat(accessed_time) if accessed_time else None,
            file_hash=file_hash,
            hash_algorithm=HashAlgorithm(hash_algorithm) if hash_algorithm else None,
            mime_type=mime_type,
            permissions=permissions,
            owner=owner_name,
            group=group_name,
            is_directory=bool(is_directory),
            is_symlink=bool(is_symlink),
            target_path=target_path,
            custom_metadata=custom_meta
        )
    
    def export_index(self, output_path: str, format: str = "json"):
        """Export file index to various formats"""
        if format == "json":
            self._export_json(output_path)
        elif format == "csv":
            self._export_csv(output_path)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def _export_json(self, output_path: str):
        """Export index to JSON format"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM files ORDER BY file_path')
            
            files = []
            for row in cursor.fetchall():
                metadata = self._row_to_metadata(row)
                files.append(metadata.model_dump())
            
            with open(output_path, 'w') as f:
                json.dump(files, f, indent=2, default=str)
    
    def _export_csv(self, output_path: str):
        """Export index to CSV format"""
        import csv
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM files ORDER BY file_path')
            
            with open(output_path, 'w', newline='') as csvfile:
                fieldnames = [
                    'file_path', 'file_name', 'file_size', 'created_time',
                    'modified_time', 'file_hash', 'mime_type', 'permissions',
                    'is_directory', 'is_symlink'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                
                for row in cursor.fetchall():
                    metadata = self._row_to_metadata(row)
                    writer.writerow({
                        'file_path': metadata.file_path,
                        'file_name': metadata.file_name,
                        'file_size': metadata.file_size,
                        'created_time': metadata.created_time,
                        'modified_time': metadata.modified_time,
                        'file_hash': metadata.file_hash,
                        'mime_type': metadata.mime_type,
                        'permissions': metadata.permissions,
                        'is_directory': metadata.is_directory,
                        'is_symlink': metadata.is_symlink
                    })
    
    def cleanup_stale_entries(self):
        """Remove entries for files that no longer exist"""
        removed_count = 0
        
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT file_path FROM files')
            
            for (file_path,) in cursor.fetchall():
                if not Path(file_path).exists():
                    cursor.execute('DELETE FROM files WHERE file_path = ?', (file_path,))
                    removed_count += 1
            
            conn.commit()
        
        self.logger.info(f"Removed {removed_count} stale entries")
        return removed_count