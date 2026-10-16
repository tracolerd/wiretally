import os
MAX_FILE_SIZE_MB = 100  # Default limit to prevent memory exhaustion
class ValidationError(Exception):
    """Custom exception for file validation errors."""
    pass
def validate_capture_file(filepath: str, max_size_mb: int = MAX_FILE_SIZE_MB) -> bool:
    """Validates the capture file size, type, and availability."""
    if not os.path.exists(filepath):
        raise ValidationError(f"File not found: '{filepath}'")
    if not os.path.isfile(filepath):
        raise ValidationError(f"Path is not a regular file: '{filepath}'")
    ext = os.path.splitext(filepath)[1].lower()
    if ext not in ['.pcap', '.pcapng']:
        raise ValidationError(f"Unsupported file type '{ext}'. Only .pcap and .pcapng are supported.")
    file_size_bytes = os.path.getsize(filepath)
    if file_size_bytes == 0:
        raise ValidationError(f"File is empty (0 bytes): '{filepath}'")
    max_bytes = max_size_mb * 1024 * 1024
    if file_size_bytes > max_bytes:
        raise ValidationError(f"File exceeds maximum allowed size of {max_size_mb}MB (Found: {file_size_bytes / (1024*1024):.2f}MB).")
    return True
