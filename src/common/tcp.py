"""Reliable TCP I/O helpers.

TCP is a byte stream — one send() does not correspond to one recv().
These helpers ensure complete reads and writes across segment boundaries.
"""

import socket


class ConnectionClosed(Exception):
    """Raised when the peer closes the connection mid-read."""
    pass


def read_exact(sock: socket.socket, n: int) -> bytes:
    """Read exactly n bytes from a TCP socket.

    Handles partial reads by looping until all bytes are received.

    Args:
        sock: Connected TCP socket.
        n: Number of bytes to read.

    Returns:
        Exactly n bytes.

    Raises:
        ConnectionClosed: If the peer closes before n bytes are available.
    """
    if n == 0:
        return b''

    chunks = []
    remaining = n
    while remaining > 0:
        try:
            chunk = sock.recv(min(remaining, 65536))
        except (ConnectionResetError, ConnectionAbortedError, OSError):
            raise ConnectionClosed("Connection reset during read")

        if not chunk:
            # Peer closed the connection
            if remaining == n:
                # No bytes read yet — clean EOF
                raise ConnectionClosed("Connection closed by peer")
            else:
                # Partial read — truncated frame
                raise ConnectionClosed(
                    f"Connection closed mid-read: got {n - remaining} of "
                    f"{n} bytes"
                )
        chunks.append(chunk)
        remaining -= len(chunk)

    return b''.join(chunks)


def write_all(sock: socket.socket, data: bytes) -> None:
    """Write all bytes to a TCP socket.

    Handles partial writes by looping until all data is sent.

    Args:
        sock: Connected TCP socket.
        data: Bytes to send.

    Raises:
        ConnectionClosed: If the connection is broken during write.
    """
    if not data:
        return

    total_sent = 0
    while total_sent < len(data):
        try:
            sent = sock.send(data[total_sent:])
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError,
                OSError):
            raise ConnectionClosed("Connection broken during write")

        if sent == 0:
            raise ConnectionClosed("Socket send returned 0")
        total_sent += sent


def discard_bytes(sock: socket.socket, n: int) -> None:
    """Read and discard exactly n bytes from a socket.

    Used for unknown-frame skipping (SPEC §10).
    """
    remaining = n
    while remaining > 0:
        try:
            chunk = sock.recv(min(remaining, 65536))
        except (ConnectionResetError, ConnectionAbortedError, OSError):
            raise ConnectionClosed("Connection reset while discarding bytes")
        if not chunk:
            raise ConnectionClosed(
                f"Connection closed while discarding: {remaining} bytes remain"
            )
        remaining -= len(chunk)
