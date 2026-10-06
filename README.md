# BHTTP — Binary Hypertext Transport Protocol

A custom, robust, binary application-layer protocol designed and implemented from scratch over raw TCP sockets. Includes an independent multi-threaded server (`bserve`), an HTTP-like client (`bcurl`), comprehensive test coverage, and complete protocol specifications.

---

## 1. Project Overview

Modern web protocols (such as HTTP/2 and HTTP/3) moved away from ASCII text framing (HTTP/1.1) to structured binary framing to achieve determinism, eliminate delimiter parsing ambiguity, lower serialization overhead, and improve parsing efficiency. 

**BHTTP (Binary Hypertext Transport Protocol)** is a clean, academic binary protocol that maps core HTTP semantics (resources, methods, headers, status codes, bodies) onto fixed and length-prefixed binary frames.

### Key Capabilities
- **Fixed 12-Byte Header**: Frame demarcation occurs entirely in the first 12 bytes; frame boundaries are determined without parsing payloads.
- **Forward Compatibility**: Unknown frame types are cleanly skipped using `payload_length` without terminating the connection.
- **Robust Framing**: Length-prefixed variable fields with bounded caps prevent unbounded memory allocation and buffer overrun vulnerabilities.
- **Indexed Header Table**: Standard static table indexes frequent header names to 2-byte descriptors, falling back gracefully to literal names.
- **Reliable TCP Stream Processing**: Transparent handling of TCP stream fragmentation, partial writes, and socket aggregation.
- **Persistent Connections**: Multiple request-response cycles on a single TCP connection by default, with deterministic `CONN_CLOSE` teardown.
- **Path Security**: Canonicalization and descent validation preventing directory traversal attacks (`..`) and Windows volume escapes.

---

## 2. Architecture

```text
+-----------------------------------------------------------------------+
|                              Application                              |
|          bserve (src.server.main)    |    bcurl (src.client.main)      |
+-----------------------------------------------------------------------+
|                           Protocol Layer                              |
|   frame.py (12-byte header)         | headers.py (indexed / literal)  |
|   request.py (Request codec)        | response.py (Response codec)    |
|   constants.py (limits, opcodes, tables, status definitions)          |
+-----------------------------------------------------------------------+
|                          Common I/O Layer                             |
|   tcp.py (read_exact, write_all, discard_bytes)                       |
|   hexdump.py (annotated framing inspector)                            |
+-----------------------------------------------------------------------+
|                           Operating System                            |
|                          TCP/IP Socket Stack                          |
+-----------------------------------------------------------------------+
```

### Module Responsibilities
- **`src/protocol/constants.py`**: Protocol limits (`MAX_PAYLOAD_SIZE = 16 MiB`, `MAX_PATH_LENGTH = 4096`), magic bytes (`0xB748`), status codes, and the static header name table.
- **`src/protocol/frame.py`**: Packing and unpacking of the 12-byte fixed header. Enforces magic, version, and payload bounds.
- **`src/protocol/headers.py`**: Codec for indexed (tag `0x00`) and literal (tag `0x01`) header entries.
- **`src/protocol/request.py`**: Serializes and deserializes client request frames.
- **`src/protocol/response.py`**: Serializes and deserializes server response and error frames.
- **`src/common/tcp.py`**: Low-level stream synchronization. Guarantees complete buffer delivery/receipt regardless of TCP segmentation.
- **`src/common/hexdump.py`**: Hexadecimal stream visualizer displaying field boundaries in verbose mode (`-v`).
- **`src/server/filesystem.py`**: Sanitizes paths, enforces document root isolation, and maps MIME types.
- **`src/server/connection.py`**: Multi-threaded connection handler loop managing persistent TCP sessions and error dispatching.

---

## 3. Protocol Summary

### Fixed 12-Byte Header Wire Format

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Magic (0xB7 0x48)        |    Version    |   Frame Type  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Flags     |   Reserved    |          Status Code          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Payload Length                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Offset | Width | Field | Description |
|---|---|---|---|
| `0` | 2 bytes | **Magic** | `0xB748`: Protocol discriminator. Immediate rejection of foreign protocols. |
| `2` | 1 byte | **Version** | `0x01`: Version 1. Non-matching versions rejected with status 400. |
| `3` | 1 byte | **Frame Type** | `0x01` = REQUEST, `0x02` = RESPONSE, `0x03` = ERROR. Types ≥ `0x04` skipped. |
| `4` | 1 byte | **Flags** | Bit 0: `CONN_CLOSE` (`0x01`). Indicates connection termination after frame. |
| `5` | 1 byte | **Reserved** | Transmitted as `0x00`; ignored on receipt for forward compatibility. |
| `6` | 2 bytes | **Status Code** | `0x0000` on REQUEST; `0x00C8` (200), `0x0190` (400), `0x0194` (404), `0x01F4` (500) on RESPONSE. |
| `8` | 4 bytes | **Payload Length** | Big-endian uint32. Length in bytes of the payload immediately following the header. |

Total Frame Size = `12 + Payload Length`.

### Request Payload Layout
```text
[Method: 1B] [Path Length: 2B BE] [Path Bytes: var] [Header Count: 1B] [Headers: var]
```

### Response Payload Layout
```text
[Header Count: 1B] [Headers: var] [Body Length: 4B BE] [Body Bytes: var]
```

---

## 4. Build & Run Instructions

### Prerequisites
- Python 3.10+ (tested on Python 3.12.6)
- Windows / Linux / macOS (standard library only; zero third-party dependencies)

### Launcher Scripts (Windows)
Launcher scripts are provided in the project root:
- `bserve.bat <document_root> <port>`
- `bcurl.bat [-v] <host>:<port>/<path>`

---

## 5. Server Usage

Start the server pointing to a document root directory:

```bash
# Using the Windows batch launcher:
bserve.bat ./www 9000

# Or invoking Python directly:
python -m src.server.main ./www 9000
```

Console output:
```text
[bserve] Listening on 0.0.0.0:9000
[bserve] Document root: C:\Users\...\Network-Architecture-Project\www
```

---

## 6. Client Usage

Fetch resources from a running server:

```bash
# Using the Windows batch launcher:
bcurl.bat localhost:9000/index.html

# Fetch a plain text file:
bcurl.bat localhost:9000/test.txt

# Inspect frame exchange with verbose hex dump:
bcurl.bat -v localhost:9000/test.txt
```

### Exit Codes
- `0`: Success (HTTP-like 2xx response received).
- `1`: Client-side error (malformed URL, network failure, or protocol parse error).
- `2`: Server-side error (4xx or 5xx status returned).

---

## 7. Testing Instructions & Results

The project includes an automated test suite featuring protocol unit tests, path traversal security tests, and integration tests across real TCP sockets.

### Running the Test Suite

```bash
python -m unittest discover tests
```

### Test Coverage Highlights
47 automated test cases verifying:
1. **Header validation**: Magic verification, version checking, payload bounds enforcement.
2. **Payload consistency**: Variable length bounds checking, UTF-8 integrity, trailing byte detection.
3. **Path security**: Traversal injection (`../`), drive letter checks (`C:`), outside document root isolation.
4. **Persistent connections**: Back-to-back requests across single TCP connections.
5. **Stream handling**: 1-byte chunked delivery, multiple frames packed in single socket reads.
6. **Unknown frames**: Clean payload skipping of unsupported opcodes without socket termination.
7. **Client CLI**: Return code correctness (0, 1, 2) and verbose output formatting.

### Test Results
```text
Ran 47 tests in 0.727s

OK
```

---

## 8. Real Hex Dump Walkthrough

An annotated breakdown of actual captured wire bytes for a request and response is located in:
- [`examples/annotated-hexdump.md`](examples/annotated-hexdump.md)
- [`examples/request.hex`](examples/request.hex)
- [`examples/response.hex`](examples/response.hex)

---

## 9. Design Rationale

| Decision | Rationale |
|---|---|
| **12-Byte Fixed Header** | Contains all necessary fields (magic, version, frame type, flags, status, payload length) needed to delimit frames and safely skip unknown frames without parsing bodies. |
| **Non-ASCII Magic (`0xB748`)** | Prevents misinterpreting arbitrary text protocols (like HTTP/1.1 or Telnet) as BHTTP. |
| **Explicit `MAX_PAYLOAD_SIZE` (16 MiB)** | Prevents unbounded memory allocation denial-of-service (DoS) attacks from corrupt length headers. |
| **Indexed Name Table** | Eliminates redundant transmission of ubiquitous headers (`content-type`, `content-length`, `host`, `server`), saving significant bandwidth. |
| **Big-Endian Encoding** | Follows standard network byte order conventions (RFC 1700), eliminating endianness confusion across heterogenous architectures. |
| **Persistent by Default** | Amortizes TCP three-way handshake and connection setup overhead across multiple resource requests. |

---

## 10. Security & Path Handling

BHTTP addresses filesystem security at the boundary:
1. **Leading Slash Requirement**: Paths must start with `/`.
2. **Component Traversal Rejection**: Any path containing `..` path elements is rejected before filesystem access.
3. **Volume / Drive Isolation**: Paths with Windows drive prefixes (e.g. `/C:/`) are blocked.
4. **Descent Canonicalization**: Realpath resolution guarantees the target file exists strictly within the document root subtree.

---

## 11. Known Limitations & Future Work

- **Multiplexing**: While connections are persistent, frames are serialized sequentially. Future versions (v2) could introduce stream IDs for concurrent request multiplexing.
- **Compression**: Payloads are transmitted uncompressed. Header dictionary compression or gzip body encoding could be introduced in a future specification extension.
- **TLS**: Transport runs over raw TCP. Production deployments would encapsulate BHTTP inside TLS sockets.
