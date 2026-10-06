"""Hex dump formatting for verbose mode.

Produces annotated hex dumps of BHTTP frames for debugging.
Format matches the project requirement: offset | hex bytes | ASCII
"""

import sys
from typing import Optional

from ..protocol.constants import (
    MAGIC, FRAME_HEADER_SIZE, FRAME_REQUEST, FRAME_RESPONSE, FRAME_ERROR,
    STATUS_NAMES, METHOD_GET, HEADER_TAG_INDEXED, HEADER_TAG_LITERAL,
    HEADER_NAME_TABLE,
)


# Frame type names for display
FRAME_TYPE_NAMES = {
    FRAME_REQUEST:  "REQUEST",
    FRAME_RESPONSE: "RESPONSE",
    FRAME_ERROR:    "ERROR",
}


def hexdump(data: bytes, label: str = "", file=sys.stderr) -> None:
    """Print a formatted hex dump of raw bytes.

    Output format:
        offset  hex bytes                                 ASCII
        0000    B7 48 01 01 00 00 00 00 00 00 00 0F       .H..........

    Args:
        data: Bytes to dump.
        label: Optional label printed before the dump.
        file: Output stream (default stderr, to avoid mixing with body output).
    """
    if label:
        print(f"\n{'=' * 60}", file=file)
        print(f"  {label}", file=file)
        print(f"{'=' * 60}", file=file)

    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = ' '.join(f'{b:02X}' for b in chunk)
        ascii_part = ''.join(
            chr(b) if 32 <= b < 127 else '.' for b in chunk
        )
        print(f"  {i:04X}    {hex_part:<48s}  {ascii_part}", file=file)

    print(file=file)


def annotated_frame_dump(data: bytes, direction: str,
                         file=sys.stderr) -> None:
    """Print an annotated hex dump of a BHTTP frame.

    Decodes the fixed header fields and labels them in the output.

    Args:
        data: Complete frame bytes (header + payload).
        direction: "SEND" or "RECV" for labeling.
        file: Output stream.
    """
    if len(data) < FRAME_HEADER_SIZE:
        hexdump(data, f"{direction} (TRUNCATED FRAME)", file=file)
        return

    import struct
    from ..protocol.constants import FRAME_HEADER_FMT

    magic = data[0:2]
    version = data[2]
    frame_type = data[3]
    flags = data[4]
    reserved = data[5]
    status = (data[6] << 8) | data[7]
    payload_length = struct.unpack('>I', data[8:12])[0]

    type_name = FRAME_TYPE_NAMES.get(frame_type, f"UNKNOWN(0x{frame_type:02X})")
    status_name = STATUS_NAMES.get(status, f"0x{status:04X}")

    print(f"\n{'=' * 60}", file=file)
    print(f"  {direction} {type_name} FRAME  "
          f"({len(data)} bytes total)", file=file)
    print(f"{'=' * 60}", file=file)

    # Annotated header
    print(f"  Fixed Header (12 bytes):", file=file)
    print(f"    0000  {data[0]:02X} {data[1]:02X}"
          f"                        Magic: 0x{magic.hex().upper()}", file=file)
    print(f"    0002  {version:02X}"
          f"                           Version: {version}", file=file)
    print(f"    0003  {frame_type:02X}"
          f"                           Frame Type: {type_name}", file=file)
    print(f"    0004  {flags:02X}"
          f"                           Flags: 0x{flags:02X}"
          f"{' [CONN_CLOSE]' if flags & 0x01 else ''}", file=file)
    print(f"    0005  {reserved:02X}"
          f"                           Reserved", file=file)
    print(f"    0006  {data[6]:02X} {data[7]:02X}"
          f"                        Status: {status_name}", file=file)
    print(f"    0008  {data[8]:02X} {data[9]:02X} {data[10]:02X} {data[11]:02X}"
          f"                    Payload Length: {payload_length}", file=file)

    # Raw payload hex dump
    if payload_length > 0:
        payload = data[FRAME_HEADER_SIZE:]
        print(f"  Payload ({len(payload)} bytes):", file=file)
        for i in range(0, len(payload), 16):
            chunk = payload[i:i + 16]
            hex_part = ' '.join(f'{b:02X}' for b in chunk)
            ascii_part = ''.join(
                chr(b) if 32 <= b < 127 else '.' for b in chunk
            )
            offset = FRAME_HEADER_SIZE + i
            print(f"    {offset:04X}  {hex_part:<48s}  {ascii_part}", file=file)

    print(file=file)
