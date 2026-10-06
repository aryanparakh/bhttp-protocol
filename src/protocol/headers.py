"""BHTTP header encoding and decoding.

Implements the header wire format defined in SPEC.md §9.
"""

import struct
from typing import List, Tuple

from .constants import (
    HEADER_TAG_INDEXED, HEADER_TAG_LITERAL,
    HEADER_NAME_TABLE, HEADER_NAME_INDEX,
    MAX_HEADER_COUNT, MAX_HEADER_NAME_LEN, MAX_HEADER_VALUE_LEN,
)
from .frame import FrameError


# Type alias: list of (name, value) pairs, both strings
HeaderList = List[Tuple[str, str]]


def encode_headers(headers: HeaderList) -> bytes:
    """Encode a list of (name, value) header pairs into BHTTP wire format.

    Uses indexed names for entries in the static table (§9.1), literal names
    for all others.

    Args:
        headers: List of (name, value) tuples.

    Returns:
        Encoded bytes: 1-byte count + encoded header entries.

    Raises:
        ValueError: If header count or field sizes exceed limits.
    """
    if len(headers) > MAX_HEADER_COUNT:
        raise ValueError(
            f"Header count {len(headers)} exceeds MAX_HEADER_COUNT "
            f"{MAX_HEADER_COUNT}"
        )

    parts = []
    # Header count: 1 byte (§11, §13)
    parts.append(struct.pack('>B', len(headers)))

    for name, value in headers:
        value_bytes = value.encode('utf-8')
        if len(value_bytes) > MAX_HEADER_VALUE_LEN:
            raise ValueError(
                f"Header value length {len(value_bytes)} exceeds "
                f"MAX_HEADER_VALUE_LEN {MAX_HEADER_VALUE_LEN}"
            )

        # Check if name is in the static table
        name_lower = name.lower()
        if name_lower in HEADER_NAME_INDEX:
            # Indexed name: tag(1) + id(1)
            idx = HEADER_NAME_INDEX[name_lower]
            parts.append(struct.pack('>BB', HEADER_TAG_INDEXED, idx))
        else:
            # Literal name: tag(1) + name_len(1) + name_bytes
            name_bytes = name.encode('utf-8')
            if len(name_bytes) == 0 or len(name_bytes) > MAX_HEADER_NAME_LEN:
                raise ValueError(
                    f"Header name length {len(name_bytes)} out of range "
                    f"1–{MAX_HEADER_NAME_LEN}"
                )
            parts.append(struct.pack('>BB', HEADER_TAG_LITERAL, len(name_bytes)))
            parts.append(name_bytes)

        # Value: value_len(2) + value_bytes
        parts.append(struct.pack('>H', len(value_bytes)))
        parts.append(value_bytes)

    return b''.join(parts)


def decode_headers(data: bytes, offset: int) -> Tuple[HeaderList, int]:
    """Decode headers from a payload buffer starting at the given offset.

    Args:
        data: The full payload buffer.
        offset: Starting byte offset within data.

    Returns:
        Tuple of (header list, new offset after all headers).

    Raises:
        FrameError: If header data is malformed.
    """
    if offset >= len(data):
        raise FrameError("Header count extends past payload boundary")

    header_count = data[offset]
    offset += 1

    if header_count > MAX_HEADER_COUNT:
        raise FrameError(
            f"Header count {header_count} exceeds MAX_HEADER_COUNT "
            f"{MAX_HEADER_COUNT}"
        )

    headers: HeaderList = []

    for i in range(header_count):
        # Parse name tag
        if offset >= len(data):
            raise FrameError(
                f"Header {i}: name tag extends past payload boundary"
            )
        name_tag = data[offset]
        offset += 1

        if name_tag == HEADER_TAG_INDEXED:
            # Indexed name: read 1-byte ID
            if offset >= len(data):
                raise FrameError(
                    f"Header {i}: indexed name ID extends past payload boundary"
                )
            name_id = data[offset]
            offset += 1

            if name_id >= len(HEADER_NAME_TABLE):
                raise FrameError(
                    f"Header {i}: indexed name ID {name_id} out of range "
                    f"0–{len(HEADER_NAME_TABLE) - 1}"
                )
            name = HEADER_NAME_TABLE[name_id]

        elif name_tag == HEADER_TAG_LITERAL:
            # Literal name: read 1-byte length + name bytes
            if offset >= len(data):
                raise FrameError(
                    f"Header {i}: literal name length extends past payload "
                    f"boundary"
                )
            name_len = data[offset]
            offset += 1

            if name_len == 0 or name_len > MAX_HEADER_NAME_LEN:
                raise FrameError(
                    f"Header {i}: name length {name_len} out of range "
                    f"1–{MAX_HEADER_NAME_LEN}"
                )
            if offset + name_len > len(data):
                raise FrameError(
                    f"Header {i}: name bytes extend past payload boundary"
                )
            try:
                name = data[offset:offset + name_len].decode('utf-8')
            except UnicodeDecodeError:
                raise FrameError(f"Header {i}: name is not valid UTF-8")
            if '\x00' in name:
                raise FrameError(f"Header {i}: name contains NUL byte")
            offset += name_len

        else:
            raise FrameError(
                f"Header {i}: invalid name tag 0x{name_tag:02X} "
                f"(expected 0x00 or 0x01)"
            )

        # Parse value: 2-byte length + value bytes
        if offset + 2 > len(data):
            raise FrameError(
                f"Header {i}: value length extends past payload boundary"
            )
        value_len = struct.unpack('>H', data[offset:offset + 2])[0]
        offset += 2

        if value_len > MAX_HEADER_VALUE_LEN:
            raise FrameError(
                f"Header {i}: value length {value_len} exceeds "
                f"MAX_HEADER_VALUE_LEN {MAX_HEADER_VALUE_LEN}"
            )
        if offset + value_len > len(data):
            raise FrameError(
                f"Header {i}: value bytes extend past payload boundary"
            )
        try:
            value = data[offset:offset + value_len].decode('utf-8')
        except UnicodeDecodeError:
            raise FrameError(f"Header {i}: value is not valid UTF-8")
        offset += value_len

        headers.append((name, value))

    return headers, offset
