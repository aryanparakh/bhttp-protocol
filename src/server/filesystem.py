"""Filesystem operations for the BHTTP server.

Implements path security (SPEC §12) and file serving.
"""

import os
from typing import Tuple, Optional

from ..protocol.constants import MIME_TYPES, DEFAULT_MIME_TYPE


class PathSecurityError(Exception):
    """Raised when a path violates security constraints (§12)."""
    pass


class FileNotFoundError_(Exception):
    """Raised when the requested file does not exist."""
    pass


def resolve_path(doc_root: str, request_path: str) -> str:
    """Safely resolve a request path to a filesystem path.

    Implements all path security rules from SPEC §12:
    1. Path must start with '/'.
    2. Path must not contain '..' components.
    3. Path must not be/start with a Windows drive letter.
    4. Resolved path must be under the document root.

    Args:
        doc_root: Absolute path to the document root directory.
        request_path: The request path (e.g., "/index.html").

    Returns:
        Absolute filesystem path to the requested file.

    Raises:
        PathSecurityError: If the path violates security constraints.
        FileNotFoundError_: If the file does not exist.
    """
    if not request_path.startswith('/'):
        raise PathSecurityError("Path must start with '/'")

    # Check for directory traversal components
    # Normalize separators for cross-platform safety
    normalized = request_path.replace('\\', '/')
    parts = normalized.split('/')
    for part in parts:
        if part == '..':
            raise PathSecurityError(
                "Path contains '..' component (directory traversal)"
            )

    # Check for Windows drive letters (e.g., "C:" or "/C:")
    stripped = request_path.lstrip('/')
    if len(stripped) >= 2 and stripped[1] == ':' and stripped[0].isalpha():
        raise PathSecurityError("Path contains drive letter")

    # Map '/' to '/index.html'
    if request_path == '/':
        request_path = '/index.html'

    # Build the filesystem path
    # request_path starts with '/', so strip it for os.path.join
    relative = request_path.lstrip('/')
    candidate = os.path.normpath(os.path.join(doc_root, relative))

    # Final safety check: resolved path must be under doc_root
    doc_root_real = os.path.realpath(doc_root)
    candidate_real = os.path.realpath(candidate)
    if not candidate_real.startswith(doc_root_real + os.sep) and \
       candidate_real != doc_root_real:
        raise PathSecurityError(
            f"Resolved path escapes document root: {candidate_real}"
        )

    if not os.path.isfile(candidate_real):
        raise FileNotFoundError_(f"File not found: {request_path}")

    return candidate_real


def read_file(path: str) -> bytes:
    """Read a file's contents as bytes.

    Args:
        path: Absolute filesystem path.

    Returns:
        File contents as bytes.
    """
    with open(path, 'rb') as f:
        return f.read()


def get_mime_type(path: str) -> str:
    """Determine MIME type from file extension.

    Args:
        path: Filesystem path.

    Returns:
        MIME type string.
    """
    _, ext = os.path.splitext(path)
    return MIME_TYPES.get(ext.lower(), DEFAULT_MIME_TYPE)
