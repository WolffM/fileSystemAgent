import hashlib
import mimetypes
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import logging

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
    
    # Fix for PIL.Image compatibility issues with newer Pillow versions
    try:
        from PIL import Image
        # Add missing attributes for compatibility
        if not hasattr(Image, 'ANTIALIAS'):
            Image.ANTIALIAS = Image.LANCZOS
        if not hasattr(Image, 'CUBIC'):
            Image.CUBIC = Image.BICUBIC
        if not hasattr(Image, 'LINEAR'):
            Image.LINEAR = Image.BILINEAR
    except ImportError:
        pass
        
except ImportError:
    VIDEO_HASHING_AVAILABLE = False


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
    created_at: datetime = field(default_factory=datetime.now)
    error_message: Optional[str] = None


class MediaFingerprintEngine:
    """Engine for generating perceptual fingerprints of images and videos"""
    
    def __init__(self, 
                 hash_size: int = 8,
                 enable_image_hashing: bool = True,
                 enable_video_hashing: bool = True,
                 preferred_image_hash: str = "dhash"):
        """
        Initialize media fingerprinting engine
        
        Args:
            hash_size: Size of perceptual hash (8 = 64-bit, 16 = 256-bit)
            enable_image_hashing: Enable image perceptual hashing
            enable_video_hashing: Enable video perceptual hashing
            preferred_image_hash: Primary hash algorithm (dhash, phash, ahash, whash)
        """
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

        hash_funcs = {
            'dhash': lambda img: str(imagehash.dhash(img, hash_size=self.hash_size)),
            'phash': lambda img: str(imagehash.phash(img, hash_size=self.hash_size)),
            'ahash': lambda img: str(imagehash.average_hash(img, hash_size=self.hash_size)),
            'whash': lambda img: str(imagehash.whash(img, hash_size=self.hash_size)),
        }

        try:
            with Image.open(image_path) as img:
                if img.mode in ('RGBA', 'LA', 'P'):
                    img = img.convert('RGB')

                hashes = {}

                # Always calculate the preferred hash
                if self.preferred_image_hash in hash_funcs:
                    hashes[self.preferred_image_hash] = hash_funcs[self.preferred_image_hash](img)

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
    
    def calculate_similarity(self, fingerprint1: MediaFingerprint, fingerprint2: MediaFingerprint) -> Dict[str, float]:
        """Calculate similarity between two media fingerprints"""
        similarities = {}
        
        # Check if same file type
        if fingerprint1.file_type != fingerprint2.file_type:
            return similarities
        
        # Traditional hash similarity (exact match)
        if fingerprint1.sha256_hash and fingerprint2.sha256_hash:
            similarities['sha256'] = 1.0 if fingerprint1.sha256_hash == fingerprint2.sha256_hash else 0.0
        
        # Image perceptual hash similarities
        if fingerprint1.file_type == "image":
            hash_types = ['dhash', 'phash', 'ahash', 'whash']
            
            for hash_type in hash_types:
                hash1 = getattr(fingerprint1, hash_type)
                hash2 = getattr(fingerprint2, hash_type)
                
                if hash1 and hash2:
                    try:
                        # Convert hex strings back to imagehash objects for comparison
                        img_hash1 = imagehash.hex_to_hash(hash1)
                        img_hash2 = imagehash.hex_to_hash(hash2)
                        
                        # Calculate Hamming distance
                        hamming_distance = img_hash1 - img_hash2
                        
                        # Convert to similarity score (0-1, where 1 is identical)
                        max_distance = len(hash1) * 4  # 4 bits per hex char
                        similarity = 1.0 - (hamming_distance / max_distance)
                        similarities[hash_type] = max(0.0, similarity)
                        
                    except Exception as e:
                        self.logger.warning(f"Error calculating {hash_type} similarity: {e}")
        
        # Video hash similarity
        elif fingerprint1.file_type == "video":
            if fingerprint1.video_hash and fingerprint2.video_hash:
                try:
                    # Video hashes are typically compared as strings
                    # VideoHash uses a different similarity calculation
                    similarities['video_hash'] = 1.0 if fingerprint1.video_hash == fingerprint2.video_hash else 0.0
                    
                except Exception as e:
                    self.logger.warning(f"Error calculating video hash similarity: {e}")
        
        return similarities
    
    def find_duplicates(self, fingerprints: List[MediaFingerprint], 
                       similarity_threshold: float = 0.9,
                       hash_type: str = "dhash") -> List[List[MediaFingerprint]]:
        """Find duplicate media based on perceptual hashes"""
        if not fingerprints:
            return []
        
        duplicates = []
        processed = set()
        
        for i, fp1 in enumerate(fingerprints):
            if i in processed:
                continue
            
            duplicate_group = [fp1]
            processed.add(i)
            
            for j, fp2 in enumerate(fingerprints[i+1:], i+1):
                if j in processed:
                    continue
                
                similarities = self.calculate_similarity(fp1, fp2)
                
                # Check if similar enough to be considered duplicate
                if hash_type in similarities and similarities[hash_type] >= similarity_threshold:
                    duplicate_group.append(fp2)
                    processed.add(j)
            
            # Only add groups with actual duplicates
            if len(duplicate_group) > 1:
                duplicates.append(duplicate_group)
        
        return duplicates
    
    def get_preferred_hash(self, fingerprint: MediaFingerprint) -> Optional[str]:
        """Get the preferred hash for a media fingerprint"""
        if fingerprint.file_type == "image":
            return getattr(fingerprint, self.preferred_image_hash)
        elif fingerprint.file_type == "video":
            return fingerprint.video_hash
        else:
            return None
    
    def is_duplicate(self, fingerprint1: MediaFingerprint, fingerprint2: MediaFingerprint,
                    hamming_threshold: int = 2) -> bool:
        """Quick duplicate check using recommended thresholds"""
        if fingerprint1.file_type != fingerprint2.file_type:
            return False
        
        # Check traditional hash first (exact match)
        if fingerprint1.sha256_hash == fingerprint2.sha256_hash:
            return True
        
        # Check perceptual hashes
        if fingerprint1.file_type == "image":
            hash1 = self.get_preferred_hash(fingerprint1)
            hash2 = self.get_preferred_hash(fingerprint2)
            
            if hash1 and hash2:
                try:
                    img_hash1 = imagehash.hex_to_hash(hash1)
                    img_hash2 = imagehash.hex_to_hash(hash2)
                    hamming_distance = img_hash1 - img_hash2
                    
                    # Use recommended threshold: <= 2 for duplicates
                    return hamming_distance <= hamming_threshold
                except Exception:
                    return False
        
        elif fingerprint1.file_type == "video":
            return fingerprint1.video_hash == fingerprint2.video_hash
        
        return False