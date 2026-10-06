#!/usr/bin/env python3
"""BHTTP client entry point (bcurl).

Usage:
    python -m src.client.main [-v] <host>:<port>/<path>
    ./bcurl [-v] <host>:<port>/<path>

Example:
    ./bcurl -v localhost:9000/index.html

Flags:
    -v  Verbose mode: print annotated hex dumps of every frame to stderr.

Exit codes:
    0   Success (2xx response)
    1   Client-side error (bad arguments, connection failure, malformed response)
    2   Server returned 4xx or 5xx status
"""

import os
import sys
import socket
import struct
import re

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from src.protocol.constants import (
    FRAME_HEADER_SIZE, FRAME_REQUEST, FRAME_RESPONSE, FRAME_ERROR,
    STATUS_OK, STATUS_BAD_REQUEST, STATUS_NAMES, FLAG_CONN_CLOSE,
)
from src.protocol.frame import FrameHeader, FrameError, decode_header
from src.protocol.request import encode_request
from src.protocol.response import Response, decode_response
from src.common.tcp import read_exact, write_all, discard_bytes, ConnectionClosed
from src.common.hexdump import annotated_frame_dump


def parse_url(url: str) -> tuple:
    """Parse a bcurl-style URL: host:port/path

    Args:
        url: URL string like "localhost:9000/index.html"

    Returns:
        (host, port, path) tuple

    Raises:
        ValueError: If the URL format is invalid.
    """
    # Match host:port/path — path is optional (defaults to /)
    match = re.match(r'^([^:/]+):(\d+)(/.*)?$', url)
    if not match:
        raise ValueError(
            f"Invalid URL format: '{url}'. "
            f"Expected: host:port/path (e.g., localhost:9000/index.html)"
        )

    host = match.group(1)
    port = int(match.group(2))
    path = match.group(3) or '/'

    if not (1 <= port <= 65535):
        raise ValueError(f"Port must be 1–65535, got {port}")

    return host, port, path


def run_client(host: str, port: int, path: str, verbose: bool) -> int:
    """Execute a single BHTTP request and print the response body.

    Uses exactly ONE TCP connection for the entire operation.

    Args:
        host: Server hostname or IP.
        port: Server port.
        path: Request path (e.g., "/index.html").
        verbose: If True, print hex dumps to stderr.

    Returns:
        Exit code: 0 for success, 1 for client error, 2 for server error.
    """
    # --- Build request frame ---
    try:
        request_frame = encode_request(path=path)
    except (ValueError, Exception) as e:
        print(f"bcurl: error building request: {e}", file=sys.stderr)
        return 1

    # --- Connect (single TCP connection) ---
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)  # 30-second timeout for all operations
        sock.connect((host, port))
    except (socket.error, OSError) as e:
        print(f"bcurl: connection failed: {e}", file=sys.stderr)
        return 1

    try:
        # --- Send request ---
        if verbose:
            annotated_frame_dump(request_frame, "SEND")

        try:
            write_all(sock, request_frame)
        except ConnectionClosed as e:
            print(f"bcurl: failed to send request: {e}", file=sys.stderr)
            return 1

        # --- Read response ---
        response, response_frame = _read_response(sock, verbose)
        if response is None:
            return 1

        # --- Output body to stdout ---
        if response.body:
            sys.stdout.buffer.write(response.body)
            sys.stdout.buffer.flush()

        # --- Determine exit code based on status ---
        if response.status >= 0x0190:  # >= 400
            status_name = STATUS_NAMES.get(
                response.status, f"0x{response.status:04X}"
            )
            print(f"bcurl: server returned {status_name}", file=sys.stderr)
            return 2
        else:
            return 0

    finally:
        sock.close()


def _read_response(sock: socket.socket,
                   verbose: bool) -> tuple:
    """Read a BHTTP response from the server, skipping unknown frame types.

    Implements the unknown-frame skipping rule (SPEC §10): if we receive
    a frame type we don't understand, read and discard its payload, then
    continue reading the next frame.

    Args:
        sock: Connected socket.
        verbose: Whether to print hex dumps.

    Returns:
        (Response, raw_frame_bytes) or (None, None) on error.
    """
    while True:
        # --- Read 12-byte fixed header ---
        try:
            header_data = read_exact(sock, FRAME_HEADER_SIZE)
        except ConnectionClosed as e:
            print(f"bcurl: connection closed while reading response header: "
                  f"{e}", file=sys.stderr)
            return None, None

        # --- Decode header ---
        try:
            header = decode_header(header_data)
        except FrameError as e:
            print(f"bcurl: malformed response header: {e}", file=sys.stderr)
            if verbose:
                annotated_frame_dump(header_data, "RECV (MALFORMED)")
            return None, None

        # --- Read payload ---
        try:
            payload = read_exact(sock, header.payload_length)
        except ConnectionClosed as e:
            print(f"bcurl: truncated response: {e}", file=sys.stderr)
            return None, None

        full_frame = header_data + payload

        # --- Handle unknown frame types (SPEC §10) ---
        if header.frame_type not in (FRAME_RESPONSE, FRAME_ERROR):
            if verbose:
                print(f"bcurl: skipping unknown frame type "
                      f"0x{header.frame_type:02X} "
                      f"({header.payload_length} bytes payload)",
                      file=sys.stderr)
                annotated_frame_dump(full_frame, "RECV (UNKNOWN, SKIPPED)")
            continue

        # --- Verbose dump ---
        if verbose:
            annotated_frame_dump(full_frame, "RECV")

        # --- Decode response payload ---
        try:
            response = decode_response(header, payload)
        except FrameError as e:
            print(f"bcurl: malformed response payload: {e}", file=sys.stderr)
            return None, None

        return response, full_frame


def main() -> None:
    args = sys.argv[1:]

    if not args:
        print("Usage: bcurl [-v] host:port/path", file=sys.stderr)
        sys.exit(1)

    verbose = False
    url = None

    for arg in args:
        if arg == '-v':
            verbose = True
        elif arg.startswith('-'):
            print(f"bcurl: unknown option '{arg}'", file=sys.stderr)
            sys.exit(1)
        else:
            if url is not None:
                print("bcurl: too many arguments", file=sys.stderr)
                sys.exit(1)
            url = arg

    if url is None:
        print("bcurl: missing URL argument", file=sys.stderr)
        print("Usage: bcurl [-v] host:port/path", file=sys.stderr)
        sys.exit(1)

    try:
        host, port, path = parse_url(url)
    except ValueError as e:
        print(f"bcurl: {e}", file=sys.stderr)
        sys.exit(1)

    exit_code = run_client(host, port, path, verbose)
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
