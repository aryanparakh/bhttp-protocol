# BHTTP protocol constants
# All values defined in SPEC.md §5–§14

import struct

# --- Magic ---
MAGIC = b'\xB7\x48'

# --- Version ---
VERSION = 0x01

# --- Frame Types (§6) ---
FRAME_REQUEST  = 0x01
FRAME_RESPONSE = 0x02
FRAME_ERROR    = 0x03

# --- Flags (§7) ---
FLAG_CONN_CLOSE = 0x01  # bit 0

# --- Methods (§11) ---
METHOD_GET = 0x01

# --- Status Codes (§8) ---
STATUS_NONE           = 0x0000  # Used in REQUEST frames
STATUS_OK             = 0x00C8  # 200
STATUS_BAD_REQUEST    = 0x0190  # 400
STATUS_NOT_FOUND      = 0x0194  # 404
STATUS_INTERNAL_ERROR = 0x01F4  # 500

# Human-readable status names for logging
STATUS_NAMES = {
    STATUS_NONE:           "(none)",
    STATUS_OK:             "200 OK",
    STATUS_BAD_REQUEST:    "400 Bad Request",
    STATUS_NOT_FOUND:      "404 Not Found",
    STATUS_INTERNAL_ERROR: "500 Internal Server Error",
}

# --- Header Name Static Table (§9.1) ---
HEADER_NAME_TABLE = [
    "content-type",      # 0
    "content-length",    # 1
    "connection",        # 2
    "host",              # 3
    "accept",            # 4
    "server",            # 5
    "date",              # 6
    "last-modified",     # 7
    "cache-control",     # 8
    "etag",              # 9
]

# Reverse lookup: name string -> index
HEADER_NAME_INDEX = {name: idx for idx, name in enumerate(HEADER_NAME_TABLE)}

# Header name tags (§9.2)
HEADER_TAG_INDEXED = 0x00
HEADER_TAG_LITERAL = 0x01

# --- Limits (§14) ---
FRAME_HEADER_SIZE    = 12                # Fixed header: 12 bytes
MAX_PAYLOAD_SIZE     = 16_777_216        # 2^24 = 16 MiB
MAX_PATH_LENGTH      = 4096
MAX_HEADER_COUNT     = 32
MAX_HEADER_NAME_LEN  = 255
MAX_HEADER_VALUE_LEN = 8192
MAX_BODY_SIZE        = MAX_PAYLOAD_SIZE  # Body cannot exceed payload

# --- Struct format for frame header ---
# Magic(2) + Version(1) + Type(1) + Flags(1) + Reserved(1) + Status(2) + PayloadLen(4) = 12
FRAME_HEADER_FMT = '>2sBBBBHI'
FRAME_HEADER_PACK_SIZE = struct.calcsize(FRAME_HEADER_FMT)

assert FRAME_HEADER_PACK_SIZE == FRAME_HEADER_SIZE, \
    f"Header struct size mismatch: {FRAME_HEADER_PACK_SIZE} != {FRAME_HEADER_SIZE}"

# --- MIME types (§ implementation detail) ---
MIME_TYPES = {
    '.html': 'text/html',
    '.htm':  'text/html',
    '.txt':  'text/plain',
    '.css':  'text/css',
    '.js':   'application/javascript',
    '.json': 'application/json',
    '.png':  'image/png',
    '.jpg':  'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.gif':  'image/gif',
    '.pdf':  'application/pdf',
    '.svg':  'image/svg+xml',
    '.ico':  'image/x-icon',
    '.xml':  'application/xml',
}
DEFAULT_MIME_TYPE = 'application/octet-stream'
