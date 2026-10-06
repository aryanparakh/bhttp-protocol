# BHTTP — Binary Hypertext Transport Protocol Specification v1

## 1  Overview

BHTTP is a binary application-layer protocol carried over TCP.  A client sends
a REQUEST frame; the server replies with a RESPONSE (or ERROR) frame.
Connections are persistent by default: multiple request/response exchanges may
occur on one TCP connection.

## 2  Design Goals

| # | Goal | Mechanism |
|---|------|-----------|
| 1 | Compact framing | 12-byte fixed header, indexed header names |
| 2 | Safe parsing | Every variable-length field is length-prefixed; all lengths validated before read |
| 3 | Forward compatibility | Unknown frame types are skipped using the payload-length field |
| 4 | HTTP-like semantics | Familiar status codes, headers, and request paths |

## 3  Transport

BHTTP runs over a single TCP connection.  The client connects; the server
accepts.  All data is a contiguous stream of BHTTP frames.  TCP is a byte
stream; implementations MUST handle partial reads and writes.

## 4  Byte Order and Encoding

All multi-byte integers are **unsigned, big-endian** (network byte order).
All strings are **UTF-8**.  All length fields count **bytes**, not characters.
Strings MUST NOT contain the NUL byte (0x00).

## 5  Fixed Frame Header

Every BHTTP frame begins with a 12-byte fixed header.  The header contains all
information required to determine frame boundaries and to skip unknown frames
without parsing the payload.

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Magic  (0xB7 0x48)      |    Version    |   Frame Type  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Flags     |   Reserved    |          Status Code          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Payload Length                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Offset | Size | Field | Encoding | Valid Values | Meaning |
|--------|------|-------|----------|-------------|---------|
| 0 | 2 | Magic | octets | `0xB7 0x48` | Protocol discriminator.  Enables a receiver to immediately reject non-BHTTP data.  Chosen as `0xB748` — a non-ASCII pair unlikely to appear at the start of any text-based protocol. Not a security mechanism; it is a framing aid. |
| 2 | 1 | Version | uint8 | `0x01` | Protocol version.  Current version is 1.  Receivers MUST reject frames whose version they do not support. |
| 3 | 1 | Frame Type | uint8 | `0x01`–`0x03` defined | Identifies the frame kind.  See §6.  Unknown types MUST be skipped (§10). |
| 4 | 1 | Flags | uint8 bitfield | See §7 | Per-frame boolean options.  Undefined bits MUST be sent as 0 and MUST be ignored on receipt. |
| 5 | 1 | Reserved | uint8 | — | Reserved for future versions.  Sender MUST transmit `0x00`.  Receiver MUST ignore this byte (MUST NOT reject non-zero values). |
| 6 | 2 | Status Code | uint16 BE | See §8 | Meaningful in RESPONSE/ERROR frames.  In REQUEST frames, MUST be `0x0000`.  A receiver receiving a REQUEST with non-zero status MUST treat it as malformed (400). |
| 8 | 4 | Payload Length | uint32 BE | `0` – `16,777,216` | Number of bytes **immediately following** this 12-byte header that belong to this frame.  `total_frame_size = 12 + payload_length`.  Values above `MAX_PAYLOAD_SIZE` (16,777,216 = 2²⁴ = 16 MiB) MUST be rejected. |

## 6  Frame Types

| Value | Name | Direction | Description |
|-------|------|-----------|-------------|
| `0x01` | REQUEST | Client → Server | Resource request: method, path, headers |
| `0x02` | RESPONSE | Server → Client | Resource response: status, headers, body |
| `0x03` | ERROR | Server → Client | Error response: status, optional headers, no body |
| `0x04`–`0xFF` | *(reserved)* | — | Unknown; MUST be skipped per §10 |

## 7  Flags

| Bit | Name | Meaning |
|-----|------|---------|
| 0 (LSB) | CONN_CLOSE | Sender requests connection closure. |
| 1–7 | *(reserved)* | MUST be sent as 0.  MUST be ignored on receipt. |

**On a REQUEST:** if CONN_CLOSE is set, the server MUST close the TCP connection
after sending the corresponding response.  The server MUST NOT read further
frames.

**On a RESPONSE / ERROR:** if CONN_CLOSE is set, the client MUST NOT send
further requests on this connection.  The client SHOULD close after processing
the frame.

If neither side sets CONN_CLOSE, the connection remains open for additional
request/response exchanges.  Either side may close the TCP connection at any
time; the peer MUST handle unexpected EOF gracefully.

## 8  Status Codes

| Code | Hex | Name | Body? | Meaning |
|------|-----|------|-------|---------|
| 200 | `0x00C8` | OK | Yes | Resource served successfully |
| 400 | `0x0190` | Bad Request | Optional | Malformed frame or invalid field |
| 404 | `0x0194` | Not Found | Optional | Valid request; resource does not exist |
| 500 | `0x01F4` | Internal Error | Optional | Server-side failure |

**Invalid status values:** A client receiving an unrecognized status code MUST
treat codes 0x0190–0x01F3 as 400, 0x01F4–0x0257 as 500, and any other
unrecognized code as an error.  The client MUST exit non-zero for any status
≥ 0x0190.

## 9  Header Encoding

### 9.1  Static Name Table

| ID | Header Name |
|----|-------------|
| 0 | content-type |
| 1 | content-length |
| 2 | connection |
| 3 | host |
| 4 | accept |
| 5 | server |
| 6 | date |
| 7 | last-modified |
| 8 | cache-control |
| 9 | etag |

Header names in the static table are **case-sensitive lowercase**.

### 9.2  Header Entry Wire Format

```
+--------------------+
| Name Tag  (1 byte) |   0x00 = indexed, 0x01 = literal
+--------------------+
|  [indexed path]    |   Name ID (1 byte, uint8, 0–9)
|    — OR —          |
|  [literal path]    |   Name Length (1 byte, uint8, 1–255)
|                    |   Name Bytes (Name Length bytes, UTF-8)
+--------------------+
| Value Length (2 B)  |   uint16 BE, 0–8192
+--------------------+
| Value Bytes (var)  |   Value Length bytes, UTF-8
+--------------------+
```

**Indexed name (tag `0x00`):** 1 byte tag + 1 byte ID + 2 byte value-length + value.
Minimum size: 4 bytes (zero-length value).  Name ID MUST be 0–9; other IDs are
malformed.

**Literal name (tag `0x01`):** 1 byte tag + 1 byte name-length + name + 2 byte
value-length + value.  Name length MUST be 1–255.

**Any other tag value** is malformed; the receiver MUST respond with status 400.

### 9.3  Header Constraints

| Limit | Value | Rationale |
|-------|-------|-----------|
| Max header count | 32 | 1-byte count field; practical ceiling |
| Max header name length | 255 bytes | 1-byte length field |
| Max header value length | 8,192 bytes | 2-byte length field, capped |
| Header value > 8192 | Malformed | Receiver MUST reject |
| Name tag ∉ {0x00, 0x01} | Malformed | Receiver MUST reject |
| Indexed ID > 9 | Malformed | Receiver MUST reject |

**Duplicate headers:** Permitted.  If a header name appears more than once, the
receiver MUST use the **last** occurrence.  This allows headers to override
earlier values.

**All header data MUST fit within the frame's payload_length.**  If parsing a
header would read beyond the payload boundary, the frame is malformed.

## 10  Unknown Frame Type Handling

A receiver encountering a frame type it does not recognize MUST:

1. Read the 12-byte fixed header.
2. Validate magic, version, and payload-length ≤ MAX_PAYLOAD_SIZE.
3. Read and **discard** exactly `payload_length` bytes.
4. Continue reading the next frame.

The receiver MUST NOT close the connection solely because of an unknown frame
type.  This rule enables forward compatibility: a future BHTTP v1.x may
introduce new frame types that v1.0 receivers can safely ignore.

## 11  REQUEST Payload

```
+---------------------+
| Method    (1 byte)  |   0x01 = GET
+---------------------+
| Path Length (2 B)   |   uint16 BE, 1–4096
+---------------------+
| Path      (var)     |   Path Length bytes, UTF-8
+---------------------+
| Header Count (1 B)  |   uint8, 0–32
+---------------------+
| Headers   (var)     |   Header Count entries (§9.2)
+---------------------+
```

| Field | Size | Encoding | Constraints |
|-------|------|----------|-------------|
| Method | 1 | uint8 | `0x01` = GET.  Other values: server MUST respond 400. |
| Path Length | 2 | uint16 BE | 1–4096.  0 or > 4096: malformed. |
| Path | var | UTF-8 | MUST start with `/`.  No NUL bytes.  See §12 for security. |
| Header Count | 1 | uint8 | 0–32.  > 32: malformed. |
| Headers | var | §9.2 | MUST NOT exceed remaining payload bytes. |

**Payload consistency:** `payload_length` MUST equal
`1 + 2 + path_length + 1 + total_headers_size`.  A mismatch is malformed.

## 12  Path Security

The server maps the request path to a filesystem path relative to the
configured document root.

1. The path MUST start with `/`.
2. The path MUST NOT contain the component `..` (directory traversal).
3. The path MUST NOT be or start with a Windows drive letter (e.g., `C:\`).
4. The server MUST resolve the final path and verify it is a descendant of the
   document root.  If not, respond 400.
5. Percent-encoding is NOT supported in BHTTP v1.  Paths are literal byte
   sequences.
6. The path `/` MAY be mapped to `/index.html` by the server (implementation
   choice, not protocol requirement).

## 13  RESPONSE Payload

```
+---------------------+
| Header Count (1 B)  |   uint8, 0–32
+---------------------+
| Headers   (var)     |   Header Count entries (§9.2)
+---------------------+
| Body Length (4 B)    |   uint32 BE, 0 – MAX_PAYLOAD_SIZE
+---------------------+
| Body      (var)     |   Body Length bytes, raw octets
+---------------------+
```

**Payload consistency:** `payload_length` MUST equal
`1 + total_headers_size + 4 + body_length`.  A mismatch is malformed.

**ERROR frames** (`0x03`) use the same payload format as RESPONSE, but body
length MUST be 0.

## 14  Limits Summary

| Limit | Value | Width |
|-------|-------|-------|
| MAX_PAYLOAD_SIZE | 16,777,216 (2²⁴, 16 MiB) | 4 bytes |
| MAX_PATH_LENGTH | 4,096 | 2 bytes |
| MAX_HEADER_COUNT | 32 | 1 byte |
| MAX_HEADER_NAME_LEN | 255 | 1 byte |
| MAX_HEADER_VALUE_LEN | 8,192 | 2 bytes |
| MAX_BODY_SIZE | ≤ MAX_PAYLOAD_SIZE | 4 bytes |

## 15  Validation Rules

A receiver MUST validate every field **before** reading dependent data:

1. **Magic** ≠ `0xB748` → reject (400), close connection.
2. **Version** ≠ `0x01` → reject (400), close connection.
3. **Payload Length** > MAX_PAYLOAD_SIZE → reject (400), close connection.
4. **Frame Type** unknown → skip frame (§10), do NOT reject.
5. **Status** in REQUEST ≠ 0 → malformed (400).
6. **Method** not recognized → respond 400.
7. **Path Length** = 0 or > 4096 → respond 400.
8. **Path** does not start with `/` → respond 400.
9. **Path** contains `..` component → respond 400.
10. **Header Count** > 32 → respond 400.
11. **Name Tag** ∉ {0x00, 0x01} → respond 400.
12. **Indexed Name ID** > 9 → respond 400.
13. **Header Value Length** > 8192 → respond 400.
14. **Header data exceeds payload boundary** → respond 400.
15. **Body length + headers size ≠ payload_length** → respond 400.
16. **TCP EOF mid-frame** → close connection.

## 16  Design Rationale

| Decision | Rationale |
|----------|-----------|
| 2-byte magic `0xB748` | Protocol discriminator / framing aid.  Two non-ASCII bytes immediately distinguish BHTTP from text protocols.  Not a security mechanism. |
| 1-byte version | Supports 256 versions; no realistic protocol needs more. |
| 1-byte frame type | 256 types; enables unknown-frame skipping for forward compatibility. |
| 1-byte flags | 8 boolean options; only bit 0 defined in v1, rest reserved. |
| 1-byte reserved | Future expansion without breaking v1 parsers (ignored on receipt). |
| 2-byte status | Accommodates all HTTP status codes (100–599) directly, allowing instant recognition in hex dumps. |
| 4-byte payload length | Supports payloads up to 16 MiB (capped below uint32 max to prevent DoS). This is the key field enabling unknown-frame skipping: read 12 bytes, skip payload_length bytes. |
| 12-byte header total | Compact fixed header containing every field needed for safe frame parsing and unknown-frame skipping: protocol identity, version, type, flags, status, and payload length. |
| Indexed header names | Saves 10+ bytes per common header vs. sending the full name string. |
| Literal header fallback | Extensibility: any header name can be sent without protocol changes. |
| Big-endian integers | Universal network convention (RFC 1700); eliminates byte-order ambiguity. |
| Persistent connections | Avoids TCP handshake overhead for multiple resources. CONN_CLOSE flag provides explicit opt-out. |
| body_length inside payload | Separates headers from body unambiguously; redundancy with payload_length enables corruption detection. |
