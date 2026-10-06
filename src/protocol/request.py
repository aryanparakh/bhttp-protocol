"""BHTTP request payload encoding and decoding.

Implements REQUEST frame payload format defined in SPEC.md §11.
"""

import struct
from dataclasses import dataclass, field
from typing import List, Tuple

from .constants import (
    FRAME_REQUEST, METHOD_GET, STATUS_NONE,
    MAX_PATH_LENGTH, FLAG_CONN_CLOSE,
)
from .frame import FrameHeader, FrameError, encode_header
from .headers import HeaderList, encode_headers, decode_headers


@dataclass
class Request:
    """Parsed BHTTP request."""
    method: int
    path: str
    headers: HeaderList = field(default_factory=list)
    conn_close: bool = False


def encode_request(path: str, headers: HeaderList = None,
                   method: int = METHOD_GET,
                   conn_close: bool = False) -> bytes:
    """Encode a complete BHTTP REQUEST frame (header + payload).

    Args:
        path: Request path (e.g., "/index.html"). Must start with '/'.
        headers: Optional list of (name, value) header pairs.
        method: Request method (default: GET = 0x01).
        conn_close: If True, set CONN_CLOSE flag.

    Returns:
        Complete frame bytes (12-byte header + payload).
    """
    if headers is None:
        headers = []

    path_bytes = path.encode('utf-8')
    if len(path_bytes) == 0 or len(path_bytes) > MAX_PATH_LENGTH:
        raise ValueError(
            f"Path length {len(path_bytes)} out of range 1–{MAX_PATH_LENGTH}"
        )
    if not path.startswith('/'):
        raise ValueError("Path must start with '/'")

    # Build payload: method(1) + path_len(2) + path + headers
    payload_parts = []
    payload_parts.append(struct.pack('>B', method))
    payload_parts.append(struct.pack('>H', len(path_bytes)))
    payload_parts.append(path_bytes)
    payload_parts.append(encode_headers(headers))

    payload = b''.join(payload_parts)

    flags = FLAG_CONN_CLOSE if conn_close else 0x00

    # Build frame header
    header = encode_header(
        frame_type=FRAME_REQUEST,
        flags=flags,
        status=STATUS_NONE,  # REQUEST status MUST be 0 (§5)
        payload_length=len(payload),
    )

    return header + payload


def decode_request(header: FrameHeader, payload: bytes) -> Request:
    """Decode a REQUEST frame payload.

    Args:
        header: Already-parsed frame header.
        payload: Payload bytes (payload_length bytes after the header).

    Returns:
        Parsed Request object.

    Raises:
        FrameError: If the request payload is malformed.
    """
    # §15 rule 5: status in REQUEST must be 0
    if header.status != STATUS_NONE:
        raise FrameError(
            f"REQUEST frame has non-zero status 0x{header.status:04X}"
        )

    if len(payload) < 4:
        # Minimum: method(1) + path_len(2) + header_count(1) = 4,
        # but path_len >= 1 so actually minimum is 5
        raise FrameError("REQUEST payload too short")

    offset = 0

    # Method: 1 byte
    method = payload[offset]
    offset += 1
    if method != METHOD_GET:
        raise FrameError(f"Unsupported method 0x{method:02X}")

    # Path length: 2 bytes, big-endian
    path_len = struct.unpack('>H', payload[offset:offset + 2])[0]
    offset += 2

    if path_len == 0 or path_len > MAX_PATH_LENGTH:
        raise FrameError(
            f"Path length {path_len} out of range 1–{MAX_PATH_LENGTH}"
        )
    if offset + path_len > len(payload):
        raise FrameError("Path extends past payload boundary")

    # Path: path_len bytes, UTF-8
    try:
        path = payload[offset:offset + path_len].decode('utf-8')
    except UnicodeDecodeError:
        raise FrameError("Path is not valid UTF-8")
    if '\x00' in path:
        raise FrameError("Path contains NUL byte")
    if not path.startswith('/'):
        raise FrameError("Path must start with '/'")
    offset += path_len

    # Headers
    headers, offset = decode_headers(payload, offset)

    # §11 payload consistency: all payload bytes must be consumed
    if offset != len(payload):
        raise FrameError(
            f"REQUEST payload has {len(payload) - offset} unconsumed bytes "
            f"(offset={offset}, payload_length={len(payload)})"
        )

    return Request(
        method=method,
        path=path,
        headers=headers,
        conn_close=header.conn_close,
    )
