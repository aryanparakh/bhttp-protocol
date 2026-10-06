"""BHTTP server — connection handler.

Handles a single TCP connection: reads frames, processes requests,
sends responses, and manages connection lifecycle per SPEC §7.
"""

import sys
import socket
import traceback
from typing import Optional

from ..protocol.constants import (
    FRAME_HEADER_SIZE, FRAME_REQUEST, FRAME_RESPONSE, FRAME_ERROR,
    STATUS_OK, STATUS_BAD_REQUEST, STATUS_NOT_FOUND, STATUS_INTERNAL_ERROR,
    FLAG_CONN_CLOSE,
)
from ..protocol.frame import FrameHeader, FrameError, decode_header
from ..protocol.request import Request, decode_request
from ..protocol.response import encode_response
from ..common.tcp import read_exact, write_all, discard_bytes, ConnectionClosed
from .filesystem import (
    resolve_path, read_file, get_mime_type,
    PathSecurityError, FileNotFoundError_,
)


def handle_connection(conn: socket.socket, addr: tuple,
                      doc_root: str) -> None:
    """Handle a single BHTTP client connection.

    Reads frames in a loop until the connection closes or CONN_CLOSE
    is signaled. Implements persistent connection semantics (SPEC §7).

    Args:
        conn: Connected client socket.
        addr: Client address tuple (host, port).
        doc_root: Absolute path to the document root.
    """
    print(f"[server] Connection from {addr[0]}:{addr[1]}", file=sys.stderr)

    try:
        while True:
            # --- Read fixed frame header (12 bytes) ---
            try:
                header_data = read_exact(conn, FRAME_HEADER_SIZE)
            except ConnectionClosed:
                # Clean EOF: client disconnected between frames
                print(f"[server] Client {addr[0]}:{addr[1]} disconnected",
                      file=sys.stderr)
                return

            # --- Decode frame header ---
            try:
                header = decode_header(header_data)
            except FrameError as e:
                # Fatal header errors: send error response, close connection
                print(f"[server] Frame header error: {e}", file=sys.stderr)
                _send_error(conn, STATUS_BAD_REQUEST, str(e), conn_close=True)
                return

            # --- Handle unknown frame types (SPEC §10) ---
            if header.frame_type not in (FRAME_REQUEST, FRAME_RESPONSE,
                                          FRAME_ERROR):
                print(f"[server] Unknown frame type 0x{header.frame_type:02X}, "
                      f"skipping {header.payload_length} bytes",
                      file=sys.stderr)
                try:
                    discard_bytes(conn, header.payload_length)
                except ConnectionClosed:
                    return
                continue

            # --- Server only expects REQUEST frames ---
            if header.frame_type != FRAME_REQUEST:
                print(f"[server] Unexpected frame type "
                      f"0x{header.frame_type:02X} from client",
                      file=sys.stderr)
                # Skip the payload and send 400
                try:
                    discard_bytes(conn, header.payload_length)
                except ConnectionClosed:
                    return
                _send_error(conn, STATUS_BAD_REQUEST,
                           "Server expected REQUEST frame")
                if header.conn_close:
                    return
                continue

            # --- Read payload ---
            try:
                payload = read_exact(conn, header.payload_length)
            except ConnectionClosed as e:
                # Truncated frame — can't send response, just close
                print(f"[server] Truncated frame: {e}", file=sys.stderr)
                return

            # --- Decode request ---
            try:
                request = decode_request(header, payload)
            except FrameError as e:
                print(f"[server] Malformed request: {e}", file=sys.stderr)
                _send_error(conn, STATUS_BAD_REQUEST, str(e),
                           conn_close=header.conn_close)
                if header.conn_close:
                    return
                continue

            # --- Process request ---
            should_close = request.conn_close
            try:
                _process_request(conn, request, doc_root, should_close)
            except ConnectionClosed:
                print(f"[server] Connection lost while sending response",
                      file=sys.stderr)
                return
            except Exception as e:
                # Internal server error — try to send 500
                print(f"[server] Internal error: {e}", file=sys.stderr)
                traceback.print_exc(file=sys.stderr)
                try:
                    _send_error(conn, STATUS_INTERNAL_ERROR, str(e),
                               conn_close=True)
                except ConnectionClosed:
                    pass
                return

            # Close connection if CONN_CLOSE was set on request (§7)
            if should_close:
                print(f"[server] CONN_CLOSE set, closing connection",
                      file=sys.stderr)
                return

    finally:
        conn.close()
        print(f"[server] Connection closed: {addr[0]}:{addr[1]}",
              file=sys.stderr)


def _process_request(conn: socket.socket, request: Request,
                     doc_root: str, conn_close: bool) -> None:
    """Process a valid request and send the response.

    Args:
        conn: Client socket.
        request: Parsed request.
        doc_root: Document root path.
        conn_close: Whether to set CONN_CLOSE on the response.
    """
    print(f"[server] GET {request.path}", file=sys.stderr)

    # Resolve path with security checks (§12)
    try:
        file_path = resolve_path(doc_root, request.path)
    except PathSecurityError as e:
        print(f"[server] Path security violation: {e}", file=sys.stderr)
        response = encode_response(
            status=STATUS_BAD_REQUEST,
            headers=[],
            body=str(e).encode('utf-8'),
            conn_close=conn_close,
        )
        write_all(conn, response)
        return
    except FileNotFoundError_ as e:
        print(f"[server] 404: {request.path}", file=sys.stderr)
        response = encode_response(
            status=STATUS_NOT_FOUND,
            headers=[],
            body=b'Not Found',
            conn_close=conn_close,
        )
        write_all(conn, response)
        return

    # Read file and determine content type
    try:
        body = read_file(file_path)
    except Exception as e:
        print(f"[server] Error reading file: {e}", file=sys.stderr)
        response = encode_response(
            status=STATUS_INTERNAL_ERROR,
            headers=[],
            body=b'Internal Server Error',
            conn_close=True,
        )
        write_all(conn, response)
        return

    mime_type = get_mime_type(file_path)

    # Build response headers
    headers = [
        ('content-type', mime_type),
        ('content-length', str(len(body))),
        ('server', 'bserve/1.0'),
    ]

    # Build and send response
    response = encode_response(
        status=STATUS_OK,
        headers=headers,
        body=body,
        conn_close=conn_close,
    )
    write_all(conn, response)
    print(f"[server] 200 OK {request.path} ({len(body)} bytes)",
          file=sys.stderr)


def _send_error(conn: socket.socket, status: int, message: str,
                conn_close: bool = False) -> None:
    """Send an ERROR frame to the client.

    Args:
        conn: Client socket.
        status: Error status code.
        message: Error message (used as body for RESPONSE, since ERROR
                 frames have no body, we use RESPONSE for errors with
                 optional body content).
        conn_close: Whether to set CONN_CLOSE flag.
    """
    try:
        response = encode_response(
            status=status,
            headers=[],
            body=message.encode('utf-8'),
            conn_close=conn_close,
        )
        write_all(conn, response)
    except (ConnectionClosed, OSError):
        # Can't send the error — connection is already broken
        pass
