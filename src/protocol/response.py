"""BHTTP response payload encoding and decoding.

Implements RESPONSE and ERROR frame payload formats defined in SPEC.md §13.
"""

import struct
from dataclasses import dataclass, field
from typing import List, Tuple

from .constants import (
    FRAME_RESPONSE, FRAME_ERROR, FLAG_CONN_CLOSE,
    STATUS_OK, STATUS_BAD_REQUEST, STATUS_NOT_FOUND, STATUS_INTERNAL_ERROR,
    MAX_BODY_SIZE,
)
from .frame import FrameHeader, FrameError, encode_header
from .headers import HeaderList, encode_headers, decode_headers


@dataclass
class Response:
    """Parsed BHTTP response."""
    status: int
    headers: HeaderList = field(default_factory=list)
    body: bytes = b''
    conn_close: bool = False
    frame_type: int = FRAME_RESPONSE


def encode_response(status: int, headers: HeaderList = None,
                    body: bytes = b'', conn_close: bool = False,
                    is_error: bool = False) -> bytes:
    """Encode a complete BHTTP RESPONSE or ERROR frame.

    Args:
        status: Status code (e.g., STATUS_OK, STATUS_NOT_FOUND).
        headers: Optional list of (name, value) header pairs.
        body: Response body bytes. Must be empty for ERROR frames.
        conn_close: If True, set CONN_CLOSE flag.
        is_error: If True, encode as ERROR frame instead of RESPONSE.

    Returns:
        Complete frame bytes (12-byte header + payload).
    """
    if headers is None:
        headers = []

    if is_error and len(body) > 0:
        raise ValueError("ERROR frames must have zero-length body (SPEC §13)")

    if len(body) > MAX_BODY_SIZE:
        raise ValueError(
            f"Body size {len(body)} exceeds MAX_BODY_SIZE {MAX_BODY_SIZE}"
        )

    frame_type = FRAME_ERROR if is_error else FRAME_RESPONSE
    flags = FLAG_CONN_CLOSE if conn_close else 0x00

    # Build payload: header_count(1) + headers + body_len(4) + body
    headers_encoded = encode_headers(headers)
    body_len_encoded = struct.pack('>I', len(body))

    payload = headers_encoded + body_len_encoded + body

    # Build frame header
    header = encode_header(
        frame_type=frame_type,
        flags=flags,
        status=status,
        payload_length=len(payload),
    )

    return header + payload


def decode_response(header: FrameHeader, payload: bytes) -> Response:
    """Decode a RESPONSE or ERROR frame payload.

    Args:
        header: Already-parsed frame header.
        payload: Payload bytes.

    Returns:
        Parsed Response object.

    Raises:
        FrameError: If the response payload is malformed.
    """
    if len(payload) < 5:
        # Minimum: header_count(1) + body_len(4) = 5
        raise FrameError("RESPONSE payload too short")

    offset = 0

    # Decode headers (includes the 1-byte count)
    headers, offset = decode_headers(payload, offset)

    # Body length: 4 bytes big-endian
    if offset + 4 > len(payload):
        raise FrameError("Body length extends past payload boundary")
    body_len = struct.unpack('>I', payload[offset:offset + 4])[0]
    offset += 4

    if body_len > MAX_BODY_SIZE:
        raise FrameError(
            f"Body length {body_len} exceeds MAX_BODY_SIZE {MAX_BODY_SIZE}"
        )

    # ERROR frames must have body_length = 0 (§13)
    if header.frame_type == FRAME_ERROR and body_len != 0:
        raise FrameError("ERROR frame must have zero-length body")

    if offset + body_len > len(payload):
        raise FrameError("Body extends past payload boundary")

    body = payload[offset:offset + body_len]
    offset += body_len

    # Payload consistency check (§13)
    if offset != len(payload):
        raise FrameError(
            f"RESPONSE payload has {len(payload) - offset} unconsumed bytes"
        )

    return Response(
        status=header.status,
        headers=headers,
        body=body,
        conn_close=header.conn_close,
        frame_type=header.frame_type,
    )
