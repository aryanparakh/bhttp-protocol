#!/usr/bin/env python3
"""BHTTP server entry point.

Usage:
    python -m src.server.main <document_root> <port>
    ./bserve <document_root> <port>

Example:
    ./bserve ./www 9000
"""

import os
import sys
import socket
import signal
import threading

# Ensure project root is on the path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

from src.server.connection import handle_connection


def main() -> None:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <document_root> <port>", file=sys.stderr)
        sys.exit(1)

    doc_root = sys.argv[1]
    try:
        port = int(sys.argv[2])
    except ValueError:
        print(f"Error: port must be an integer, got '{sys.argv[2]}'",
              file=sys.stderr)
        sys.exit(1)

    if not (1 <= port <= 65535):
        print(f"Error: port must be 1–65535, got {port}", file=sys.stderr)
        sys.exit(1)

    # Resolve document root to absolute path
    doc_root = os.path.abspath(doc_root)
    if not os.path.isdir(doc_root):
        print(f"Error: document root '{doc_root}' is not a directory",
              file=sys.stderr)
        sys.exit(1)

    # Create TCP server socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_sock.bind(('0.0.0.0', port))
    except OSError as e:
        print(f"Error: cannot bind to port {port}: {e}", file=sys.stderr)
        sys.exit(1)

    server_sock.listen(16)
    print(f"[bserve] Listening on 0.0.0.0:{port}", file=sys.stderr)
    print(f"[bserve] Document root: {doc_root}", file=sys.stderr)

    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        print(f"\n[bserve] Shutting down...", file=sys.stderr)
        server_sock.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)

    try:
        while True:
            try:
                conn, addr = server_sock.accept()
            except OSError:
                # Socket closed during accept (shutdown)
                break

            # Handle each connection in a new thread for concurrent clients
            t = threading.Thread(
                target=handle_connection,
                args=(conn, addr, doc_root),
                daemon=True,
            )
            t.start()
    finally:
        server_sock.close()


if __name__ == '__main__':
    main()
