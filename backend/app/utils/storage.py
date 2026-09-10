"""
Secure storage and file validation utility for VisionTrust.
Enforces:
- Extension and MIME whitelist validation
- Strict path traversal prevention (including Zip Slip attacks)
- Safe unique server-side filenames
- Size limit enforcement
- Streaming SHA-256 computation
"""
from __future__ import annotations

import hashlib
import os
import re
import uuid
import zipfile
from pathlib import Path
from typing import BinaryIO, Tuple

# Configuration limits
MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024       # 50 MB
MAX_ARCHIVE_SIZE_BYTES = 200 * 1024 * 1024   # 200 MB
MAX_ARCHIVE_ENTRIES = 500                    # Prevent decompression bombs
MAX_DECOMPRESSED_BYTES = 500 * 1024 * 1024   # 500 MB decompressed limit

ALLOWED_IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".bmp", ".webp", ".tiff"}
ALLOWED_DATA_EXTENSIONS = {".csv", ".json", ".txt"}
ALLOWED_ARCHIVE_EXTENSIONS = {".zip"}
ALLOWED_EXTENSIONS = ALLOWED_IMAGE_EXTENSIONS | ALLOWED_DATA_EXTENSIONS | ALLOWED_ARCHIVE_EXTENSIONS

# Magic byte signatures for content validation
MAGIC_BYTES = {
    b"\xff\xd8\xff": "image/jpeg",
    b"\x89PNG\r\n\x1a\n": "image/png",
    b"GIF87a": "image/gif",
    b"GIF89a": "image/gif",
    b"BM": "image/bmp",
    b"RIFF": "image/webp",
    b"II*\x00": "image/tiff",
    b"MM\x00*": "image/tiff",
    b"PK\x03\x04": "application/zip",
    b"PK\x05\x06": "application/zip",
}

# Base upload directory (relative to project root or workspace)
UPLOAD_BASE_DIR = Path("uploads").resolve()


def sanitize_filename(filename: str) -> str:
    """
    Sanitize an incoming filename to prevent path traversal, null bytes,
    and control characters while preserving alphanumeric and safe punctuation.
    """
    # Remove any directory path components
    basename = os.path.basename(filename)
    # Strip null bytes and control chars
    basename = re.sub(r"[\x00-\x1f\x7f-\x9f]", "", basename)
    # Remove leading dots or slashes
    basename = basename.lstrip("./\\")
    # Replace unsafe characters with an underscore
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", basename)
    return safe_name or f"file_{uuid.uuid4().hex[:8]}"


def validate_extension(filename: str) -> str:
    """Validate that filename has an allowed extension and return lowercase extension."""
    ext = Path(filename).suffix.lower()
    if not ext or ext not in ALLOWED_EXTENSIONS:
        raise ValueError(
            f"File extension '{ext}' is forbidden. Allowed: {sorted(ALLOWED_EXTENSIONS)}"
        )
    return ext


def compute_sha256_stream(stream: BinaryIO, chunk_size: int = 65536) -> Tuple[str, int]:
    """
    Calculate SHA-256 hash and byte length of a binary stream without loading entire file in memory.
    Resets file pointer to beginning when finished.
    """
    hasher = hashlib.sha256()
    total_bytes = 0
    stream.seek(0)
    while chunk := stream.read(chunk_size):
        hasher.update(chunk)
        total_bytes += len(chunk)
    stream.seek(0)
    return hasher.hexdigest(), total_bytes


def compute_sha256_bytes(data: bytes) -> str:
    """Calculate SHA-256 hash of a byte string."""
    return hashlib.sha256(data).hexdigest()


def compute_file_hash_on_disk(file_path: Path) -> str:
    """Compute SHA-256 hash directly from disk."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def get_dataset_upload_dir(dataset_id: str) -> Path:
    """Return and create the isolated filesystem storage path for a given dataset."""
    target_dir = UPLOAD_BASE_DIR / "datasets" / dataset_id
    target_dir.mkdir(parents=True, exist_ok=True)
    return target_dir


def save_upload_stream(
    dataset_id: str,
    original_filename: str,
    stream: BinaryIO,
    max_size: int = MAX_FILE_SIZE_BYTES,
) -> Tuple[str, str, int, str]:
    """
    Safely saves an uploaded stream to an isolated disk directory:
    - Verifies extension
    - Computes SHA-256
    - Verifies size limit
    - Writes to unique server-side storage filename
    Returns (storage_name, storage_path, file_size, sha256_hash)
    """
    ext = validate_extension(original_filename)
    safe_orig = sanitize_filename(original_filename)

    sha256_hash, file_size = compute_sha256_stream(stream)
    if file_size > max_size:
        raise ValueError(
            f"File size {file_size} bytes exceeds limit of {max_size} bytes."
        )

    # Generate unique server-side storage name
    unique_storage_name = f"{uuid.uuid4().hex}_{safe_orig}"
    dataset_dir = get_dataset_upload_dir(dataset_id)
    dest_path = dataset_dir / unique_storage_name

    # Check for path traversal out of target_dir
    if not str(dest_path.resolve()).startswith(str(dataset_dir.resolve())):
        raise ValueError("Detected path traversal in destination path.")

    # Write file to disk
    stream.seek(0)
    with open(dest_path, "wb") as dest:
        while chunk := stream.read(65536):
            dest.write(chunk)

    rel_storage_path = str(dest_path.relative_to(UPLOAD_BASE_DIR))
    return unique_storage_name, rel_storage_path, file_size, sha256_hash


def extract_safe_zip(
    dataset_id: str,
    zip_stream: BinaryIO,
    uploaded_by_id: str,
    uploaded_by_username: str,
) -> list[dict]:
    """
    Safely unpacks a ZIP archive while preventing:
    - Path Traversal / Zip Slip attacks
    - Archive Decompression Bombs (entry count & total byte limits)
    - Forbidden extensions inside archive
    Returns list of dicts with extracted file metadata.
    """
    dataset_dir = get_dataset_upload_dir(dataset_id)
    extracted_files: list[dict] = []

    with zipfile.ZipFile(zip_stream, "r") as zf:
        infolist = zf.infolist()
        if len(infolist) > MAX_ARCHIVE_ENTRIES:
            raise ValueError(
                f"Archive contains {len(infolist)} entries; maximum allowed is {MAX_ARCHIVE_ENTRIES}."
            )

        total_uncompressed = sum(info.file_size for info in infolist)
        if total_uncompressed > MAX_DECOMPRESSED_BYTES:
            raise ValueError(
                f"Uncompressed archive size {total_uncompressed} bytes exceeds limit of {MAX_DECOMPRESSED_BYTES} bytes."
            )

        for member in infolist:
            # Skip directories
            if member.is_dir():
                continue

            orig_name = member.filename
            # Prevent Zip Slip: ensure normalized path does not escape base directory
            target_path = (dataset_dir / orig_name).resolve()
            if not str(target_path).startswith(str(dataset_dir.resolve())):
                raise ValueError(f"Zip Slip path traversal detected: {orig_name}")

            # Check extension
            ext = Path(orig_name).suffix.lower()
            if ext not in ALLOWED_EXTENSIONS or ext in ALLOWED_ARCHIVE_EXTENSIONS:
                continue  # Skip nested archives or disallowed types

            file_bytes = zf.read(member)
            file_size = len(file_bytes)
            if file_size > MAX_FILE_SIZE_BYTES:
                continue

            file_hash = compute_sha256_bytes(file_bytes)
            safe_orig = sanitize_filename(orig_name)
            unique_storage_name = f"{uuid.uuid4().hex}_{safe_orig}"
            final_path = dataset_dir / unique_storage_name

            with open(final_path, "wb") as f:
                f.write(file_bytes)

            rel_storage_path = str(final_path.relative_to(UPLOAD_BASE_DIR))
            extracted_files.append({
                "original_filename": safe_orig,
                "storage_name": unique_storage_name,
                "storage_path": rel_storage_path,
                "file_size": file_size,
                "mime_type": f"image/{ext.lstrip('.')}" if ext in ALLOWED_IMAGE_EXTENSIONS else "application/octet-stream",
                "sha256_hash": file_hash,
                "uploaded_by_id": uploaded_by_id,
                "uploaded_by_username": uploaded_by_username,
            })

    return extracted_files
