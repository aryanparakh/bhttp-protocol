"""BHTTP frame header encoding and decoding.

Implements the 12-byte fixed frame header defined in SPEC.md §5.
"""

import struct
from dataclasses import dataclass
from typing import Optional

from .constants import (
    MAGIC, VERSION, FRAME_HEADER_SIZE, FRAME_HEADER_FMT,
    MAX_PAYLOAD_SIZE, FRAME_REQUEST, STATUS_NONE,
)


@dataclass
class FrameHeader:
    """Represents a parsed BHTTP fixed frame header (12 bytes)."""
    version: int
    frame_type: int
    flags: int
    reserved: int
    status: int
    payload_length: int

    @property
    def conn_close(self) -> bool:
        """True if CONN_CLOSE flag (bit 0) is set."""
        return bool(self.flags & 0x01)

    @property
    def total_frame_size(self) -> int:
        """total_frame_size = 12 + payload_length (SPEC §5)."""
        return FRAME_HEADER_SIZE + self.payload_length


class FrameError(Exception):
    """Raised when frame header validation fails."""
    def __init__(self, message: str, fatal: bool = False):
        super().__init__(message)
        # Fatal errors require connection closure (invalid magic, bad version,
        # oversized payload). Non-fatal errors allow a 400 response on the
        # same connection.
        self.fatal = fatal


def encode_header(frame_type: int, flags: int, status: int,
                  payload_length: int) -> bytes:
    """Encode a 12-byte BHTTP frame header.

    Args:
        frame_type: Frame type (FRAME_REQUEST, FRAME_RESPONSE, FRAME_ERROR).
        flags: Flags byte (bit 0 = CONN_CLOSE).
        status: Status code (0 for REQUEST frames).
        payload_length: Number of bytes following this header.

    Returns:
        12-byte header as bytes.

    Raises:
        ValueError: If any parameter is out of range.
    """
    if payload_length > MAX_PAYLOAD_SIZE:
        raise ValueError(
            f"payload_length {payload_length} exceeds MAX_PAYLOAD_SIZE "
            f"{MAX_PAYLOAD_SIZE}"
        )
    if not (0 <= frame_type <= 0xFF):
        raise ValueError(f"frame_type {frame_type} out of uint8 range")
    if not (0 <= flags <= 0xFF):
        raise ValueError(f"flags {flags} out of uint8 range")
    if not (0 <= status <= 0xFFFF):
        raise ValueError(f"status {status} out of uint16 range")

    return struct.pack(
        FRAME_HEADER_FMT,
        MAGIC,          # 2 bytes
        VERSION,        # 1 byte
        frame_type,     # 1 byte
        flags,          # 1 byte
        0x00,           # reserved, sender MUST transmit 0 (§5)
        status,         # 2 bytes
        payload_length, # 4 bytes
    )


def decode_header(data: bytes) -> FrameHeader:
    """Decode a 12-byte BHTTP frame header.

    Args:
        data: Exactly 12 bytes of header data.

    Returns:
        Parsed FrameHeader.

    Raises:
        FrameError: If header validation fails.
    """
    if len(data) != FRAME_HEADER_SIZE:
        raise FrameError(
            f"Header data is {len(data)} bytes, expected {FRAME_HEADER_SIZE}",
            fatal=True
        )

    magic, version, frame_type, flags, reserved, status, payload_length = \
        struct.unpack(FRAME_HEADER_FMT, data)

    # §15 rule 1: validate magic
    if magic != MAGIC:
        raise FrameError(
            f"Invalid magic: 0x{magic.hex()} (expected 0x{MAGIC.hex()})",
            fatal=True
        )

    # §15 rule 2: validate version
    if version != VERSION:
        raise FrameError(
            f"Unsupported version: {version} (expected {VERSION})",
            fatal=True
        )

    # §15 rule 3: validate payload length
    if payload_length > MAX_PAYLOAD_SIZE:
        raise FrameError(
            f"Payload length {payload_length} exceeds MAX_PAYLOAD_SIZE "
            f"{MAX_PAYLOAD_SIZE}",
            fatal=True
        )

    # §5: reserved byte is ignored on receipt (no validation)
    # §5: unknown flag bits are ignored on receipt (no validation)

    return FrameHeader(
        version=version,
        frame_type=frame_type,
        flags=flags,
        reserved=reserved,
        status=status,
        payload_length=payload_length,
    )
