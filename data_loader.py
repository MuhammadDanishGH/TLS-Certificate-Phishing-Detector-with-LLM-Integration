"""
Extension-agnostic certificate file loader.
Handles files without extensions by inspecting content.
"""
import os
import re
from pathlib import Path
from typing import List, Tuple, Optional, Dict
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

logger = logging.getLogger(__name__)


class CertificateLoader:
    """Load certificate files regardless of extension."""
    
    # Common certificate file patterns
    PEM_START = b"-----BEGIN CERTIFICATE-----"
    PEM_END = b"-----END CERTIFICATE-----"
    OPENSSL_PATTERNS = [
        b"Certificate chain",
        b"Server certificate",
        b"subject=",
        b"issuer=",
        b"CONNECTED(",
    ]
    
    def __init__(self, max_workers: int = 4):
        """
        Initialize loader.
        
        Args:
            max_workers: Number of parallel workers for file loading
        """
        self.max_workers = max_workers
    
    def detect_file_type(self, file_path: str) -> str:
        """
        Detect certificate file type by content inspection.
        
        Args:
            file_path: Path to file
            
        Returns:
            File type: "pem", "der", "openssl_text", "unknown"
        """
        try:
            # Read first 8KB for detection
            with open(file_path, 'rb') as f:
                header = f.read(8192)
            
            # Check for PEM format
            if self.PEM_START in header:
                return "pem"
            
            # Check for OpenSSL text dump
            for pattern in self.OPENSSL_PATTERNS:
                if pattern in header:
                    return "openssl_text"
            
            # Check if it's mostly ASCII text (likely OpenSSL or malformed)
            try:
                text = header.decode('utf-8', errors='ignore')
                ascii_ratio = sum(c.isascii() for c in text) / len(text)
                if ascii_ratio > 0.9:
                    return "openssl_text"
            except:
                pass
            
            # Check for DER format (binary certificate)
            # DER certificates typically start with 0x30 (SEQUENCE)
            if header[0:1] == b'\x30' and len(header) > 100:
                return "der"
            
            return "unknown"
            
        except Exception as e:
            logger.warning(f"Error detecting file type for {file_path}: {e}")
            return "unknown"
    
    def read_certificate_file(self, file_path: str) -> Tuple[str, str, str]:
        """
        Read certificate file and return raw content, type, and label.
        
        Args:
            file_path: Path to certificate file
            
        Returns:
            Tuple of (raw_content, file_type, label)
        """
        file_type = self.detect_file_type(file_path)
        
        # Determine label from directory structure
        label = "unknown"
        path_parts = Path(file_path).parts
        if "phishing" in path_parts:
            label = "phishing"
        elif "benign" in path_parts:
            label = "benign"
        
        try:
            if file_type == "der":
                # Read as binary
                with open(file_path, 'rb') as f:
                    raw_content = f.read()
                return raw_content, file_type, label
            else:
                # Read as text with fallback encoding
                encodings = ['utf-8', 'latin-1', 'cp1252']
                for encoding in encodings:
                    try:
                        with open(file_path, 'r', encoding=encoding, errors='replace') as f:
                            raw_content = f.read()
                        return raw_content, file_type, label
                    except UnicodeDecodeError:
                        continue
                
                # If all encodings fail, read as binary and decode with replacement
                with open(file_path, 'rb') as f:
                    raw_content = f.read().decode('utf-8', errors='replace')
                return raw_content, file_type, label
                
        except Exception as e:
            logger.error(f"Error reading file {file_path}: {e}")
            return "", "error", label
    
    def load_directory(
        self,
        directory: str,
        label: Optional[str] = None,
        sample_size: Optional[int] = None,
        recursive: bool = True
    ) -> List[Dict[str, str]]:
        """
        Load all certificate files from directory.
        
        Args:
            directory: Root directory to scan
            label: Override label (if not inferring from path)
            sample_size: Limit number of files (per subdirectory if None)
            recursive: Recursively scan subdirectories
            
        Returns:
            List of dicts with keys: file_path, file_name, raw_content, file_type, label
        """
        # Collect all files
        pattern = "**/*" if recursive else "*"
        all_files = []
        
        for file_path in Path(directory).glob(pattern):
            if file_path.is_file():
                all_files.append(str(file_path))
        
        logger.info(f"Found {len(all_files)} files in {directory}")
        
        # Apply sampling if requested
        if sample_size and sample_size < len(all_files):
            import random
            random.seed(42)
            all_files = random.sample(all_files, sample_size)
            logger.info(f"Sampled {len(all_files)} files")
        
        # Load files in parallel
        results = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_file = {
                executor.submit(self.read_certificate_file, fp): fp
                for fp in all_files
            }
            
            for future in tqdm(as_completed(future_to_file), total=len(all_files), desc="Loading files"):
                file_path = future_to_file[future]
                try:
                    raw_content, file_type, inferred_label = future.result()
                    
                    # Use provided label if available, otherwise use inferred
                    final_label = label if label is not None else inferred_label
                    
                    results.append({
                        'file_path': file_path,
                        'file_name': Path(file_path).name,
                        'raw_content': raw_content,
                        'file_type': file_type,
                        'label': final_label
                    })
                except Exception as e:
                    logger.warning(f"Failed to load {file_path}: {e}")
        
        logger.info(f"Successfully loaded {len(results)} files")
        return results
    
    def load_dataset(
        self,
        data_dir: str,
        sample_size_per_class: Optional[int] = None
    ) -> Tuple[List[Dict], List[Dict]]:
        """
        Load complete dataset with benign and phishing subdirectories.
        
        Args:
            data_dir: Root directory containing benign/ and phishing/ subdirs
            sample_size_per_class: Limit files per class
            
        Returns:
            Tuple of (benign_data, phishing_data)
        """
        benign_dir = Path(data_dir) / "benign"
        phishing_dir = Path(data_dir) / "phishing"
        
        benign_data = []
        phishing_data = []
        
        if benign_dir.exists():
            logger.info(f"Loading benign certificates from {benign_dir}")
            benign_data = self.load_directory(
                str(benign_dir),
                label="benign",
                sample_size=sample_size_per_class
            )
        else:
            logger.warning(f"Benign directory not found: {benign_dir}")
        
        if phishing_dir.exists():
            logger.info(f"Loading phishing certificates from {phishing_dir}")
            phishing_data = self.load_directory(
                str(phishing_dir),
                label="phishing",
                sample_size=sample_size_per_class
            )
        else:
            logger.warning(f"Phishing directory not found: {phishing_dir}")
        
        logger.info(f"Dataset loaded: {len(benign_data)} benign, {len(phishing_data)} phishing")
        return benign_data, phishing_data


def load_single_file(file_path: str) -> Dict[str, str]:
    """
    Convenience function to load a single certificate file.
    
    Args:
        file_path: Path to certificate file
        
    Returns:
        Dict with file metadata and content
    """
    loader = CertificateLoader(max_workers=1)
    raw_content, file_type, label = loader.read_certificate_file(file_path)
    
    return {
        'file_path': file_path,
        'file_name': Path(file_path).name,
        'raw_content': raw_content,
        'file_type': file_type,
        'label': label
    }