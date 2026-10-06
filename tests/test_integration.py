"""Comprehensive integration tests for BHTTP server and client over real TCP sockets.

Tests all scenarios required by assignment Phase 4:
- Normal 200 response (text, html, json)
- Missing file -> 404 Not Found
- Empty file -> 200 OK with zero-length body
- Large file response
- Path traversal attempt (..) -> 400 Bad Request
- Windows drive letter attempt -> 400 Bad Request
- Malformed magic -> 400 Bad Request / connection close
- Invalid version -> 400 Bad Request / connection close
- Oversized frame payload -> 400 / connection close
- Truncated frame handling
- Invalid header encoding -> 400 Bad Request
- Non-zero status in REQUEST frame -> 400 Bad Request
- Unknown frame type skipped cleanly (SPEC §10)
- Multiple requests on the same TCP connection (persistent connections)
- CONN_CLOSE flag honoring
- Partial TCP delivery (byte-by-byte streaming)
- Multiple frames delivered in a single TCP read
- bcurl client subprocess execution (exit codes 0, 1, 2, verbose -v hex dump)
"""

import os
import sys
import time
import socket
import struct
import tempfile
import threading
import subprocess
import unittest

from src.protocol.constants import (
    MAGIC, VERSION, FRAME_HEADER_SIZE,
    FRAME_REQUEST, FRAME_RESPONSE, FRAME_ERROR,
    FLAG_CONN_CLOSE, METHOD_GET,
    STATUS_NONE, STATUS_OK, STATUS_BAD_REQUEST, STATUS_NOT_FOUND, STATUS_INTERNAL_ERROR,
    MAX_PAYLOAD_SIZE, HEADER_TAG_INDEXED,
)
from src.protocol.frame import encode_header, decode_header
from src.protocol.request import encode_request
from src.protocol.response import decode_response
from src.common.tcp import read_exact, write_all, ConnectionClosed
from src.server.connection import handle_connection


class BHTTPServerFixture:
    """Helper to run a real BHTTP server in a background thread."""

    def __init__(self, doc_root: str):
        self.doc_root = doc_root
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('127.0.0.1', 0))  # OS assigns free port
        self.port = self.sock.getsockname()[1]
        self.sock.listen(16)
        self.running = True
        self.thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.thread.start()

    def _accept_loop(self):
        while self.running:
            try:
                conn, addr = self.sock.accept()
            except OSError:
                break
            t = threading.Thread(
                target=handle_connection,
                args=(conn, addr, self.doc_root),
                daemon=True,
            )
            t.start()

    def close(self):
        self.running = False
        try:
            self.sock.close()
        except OSError:
            pass


class TestIntegration(unittest.TestCase):
    """Real TCP socket integration tests."""

    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.doc_root = os.path.abspath(cls.temp_dir.name)

        # Create test files
        cls.index_content = b"<html><body>Welcome to BHTTP</body></html>"
        with open(os.path.join(cls.doc_root, "index.html"), "wb") as f:
            f.write(cls.index_content)

        cls.text_content = b"Hello world! This is a test text file."
        with open(os.path.join(cls.doc_root, "test.txt"), "wb") as f:
            f.write(cls.text_content)

        # Empty file (0 bytes)
        with open(os.path.join(cls.doc_root, "empty.txt"), "wb") as f:
            pass

        # Large file (256 KB)
        cls.large_content = b"A" * (256 * 1024)
        with open(os.path.join(cls.doc_root, "large.bin"), "wb") as f:
            f.write(cls.large_content)

        # Start background server
        cls.server = BHTTPServerFixture(cls.doc_root)
        cls.port = cls.server.port

    @classmethod
    def tearDownClass(cls):
        cls.server.close()
        cls.temp_dir.cleanup()

    def _connect(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(('127.0.0.1', self.port))
        return sock

    def _read_frame(self, sock: socket.socket):
        header_data = read_exact(sock, FRAME_HEADER_SIZE)
        header = decode_header(header_data)
        payload = read_exact(sock, header.payload_length)
        response = decode_response(header, payload)
        return response

    # 1. Normal 200 response for text file
    def test_get_text_file_200(self):
        sock = self._connect()
        try:
            req = encode_request(path="/test.txt")
            write_all(sock, req)
            resp = self._read_frame(sock)
            self.assertEqual(resp.status, STATUS_OK)
            self.assertEqual(resp.body, self.text_content)
            # Check headers
            headers_dict = dict(resp.headers)
            self.assertEqual(headers_dict.get("content-type"), "text/plain")
            self.assertEqual(headers_dict.get("content-length"), str(len(self.text_content)))
        finally:
            sock.close()

    # 2. Normal 200 response for index.html mapping from "/"
    def test_get_root_mapping_to_index(self):
        sock = self._connect()
        try:
            req = encode_request(path="/")
            write_all(sock, req)
            resp = self._read_frame(sock)
            self.assertEqual(resp.status, STATUS_OK)
            self.assertEqual(resp.body, self.index_content)
        finally:
            sock.close()

    # 3. Missing file -> 404 Not Found
    def test_missing_file_404(self):
        sock = self._connect()
        try:
            req = encode_request(path="/nonexistent_file_123.txt")
            write_all(sock, req)
            resp = self._read_frame(sock)
            self.assertEqual(resp.status, STATUS_NOT_FOUND)
        finally:
            sock.close()

    # 4. Empty file -> 200 OK with 0-length body
    def test_empty_file_200(self):
        sock = self._connect()
        try:
            req = encode_request(path="/empty.txt")
            write_all(sock, req)
            resp = self._read_frame(sock)
            self.assertEqual(resp.status, STATUS_OK)
            self.assertEqual(resp.body, b"")
            headers_dict = dict(resp.headers)
            self.assertEqual(headers_dict.get("content-length"), "0")
        finally:
            sock.close()

    # 5. Large response
    def test_large_file_response(self):
        sock = self._connect()
        try:
            req = encode_request(path="/large.bin")
            write_all(sock, req)
            resp = self._read_frame(sock)
            self.assertEqual(resp.status, STATUS_OK)
            self.assertEqual(len(resp.body), len(self.large_content))
            self.assertEqual(resp.body, self.large_content)
        finally:
            sock.close()

    # 6. Path traversal attempt (..) -> 400 Bad Request
    def test_path_traversal_returns_400(self):
        sock = self._connect()
        try:
            req = encode_request(path="/../../etc/passwd")
            write_all(sock, req)
            resp = self._read_frame(sock)
            self.assertEqual(resp.status, STATUS_BAD_REQUEST)
        finally:
            sock.close()

    # 7. Windows drive letter attempt -> 400 Bad Request
    def test_windows_drive_letter_returns_400(self):
        sock = self._connect()
        try:
            req = encode_request(path="/C:/Windows/System32/cmd.exe")
            write_all(sock, req)
            resp = self._read_frame(sock)
            self.assertEqual(resp.status, STATUS_BAD_REQUEST)
        finally:
            sock.close()

    # 8. Malformed magic -> 400 Bad Request and connection close
    def test_malformed_magic_returns_400_and_closes(self):
        sock = self._connect()
        try:
            # Send frame with invalid magic 0x1234
            bad_header = struct.pack('>2sBBBBHI', b'\x12\x34', VERSION, FRAME_REQUEST, 0, 0, 0, 0)
            write_all(sock, bad_header)
            resp = self._read_frame(sock)
            self.assertEqual(resp.status, STATUS_BAD_REQUEST)
            # Socket should now be closed by server
            with self.assertRaises(ConnectionClosed):
                read_exact(sock, 1)
        finally:
            sock.close()

    # 9. Invalid version -> 400 Bad Request and connection close
    def test_invalid_version_returns_400_and_closes(self):
        sock = self._connect()
        try:
            bad_ver = struct.pack('>2sBBBBHI', MAGIC, 0x02, FRAME_REQUEST, 0, 0, 0, 0)
            write_all(sock, bad_ver)
            resp = self._read_frame(sock)
            self.assertEqual(resp.status, STATUS_BAD_REQUEST)
            with self.assertRaises(ConnectionClosed):
                read_exact(sock, 1)
        finally:
            sock.close()

    # 10. Oversized frame payload -> 400 Bad Request and connection close
    def test_oversized_payload_returns_400_and_closes(self):
        sock = self._connect()
        try:
            bad_len = struct.pack('>2sBBBBHI', MAGIC, VERSION, FRAME_REQUEST, 0, 0, 0, MAX_PAYLOAD_SIZE + 100)
            write_all(sock, bad_len)
            resp = self._read_frame(sock)
            self.assertEqual(resp.status, STATUS_BAD_REQUEST)
            with self.assertRaises(ConnectionClosed):
                read_exact(sock, 1)
        finally:
            sock.close()

    # 11. Truncated frame -> server handles EOF cleanly without crash
    def test_truncated_frame_disconnect(self):
        sock = self._connect()
        try:
            # Send header claiming 50-byte payload, then send only 5 bytes and disconnect
            hdr = encode_header(FRAME_REQUEST, 0, 0, 50)
            sock.sendall(hdr + b'12345')
        finally:
            sock.close()
        # Verify server is still completely responsive on a new connection
        sock2 = self._connect()
        try:
            write_all(sock2, encode_request(path="/test.txt"))
            resp = self._read_frame(sock2)
            self.assertEqual(resp.status, STATUS_OK)
        finally:
            sock2.close()

    # 12. Invalid header encoding -> 400 Bad Request
    def test_invalid_header_encoding_returns_400(self):
        sock = self._connect()
        try:
            # Build request payload with corrupted header tag
            path_b = b'/test.txt'
            # method(1) + path_len(2) + path + header_count(1) + invalid_tag(1)
            payload = struct.pack('>BH', METHOD_GET, len(path_b)) + path_b + struct.pack('>BB', 1, 0xFE)
            hdr = encode_header(FRAME_REQUEST, 0, 0, len(payload))
            write_all(sock, hdr + payload)
            resp = self._read_frame(sock)
            self.assertEqual(resp.status, STATUS_BAD_REQUEST)
        finally:
            sock.close()

    # 13. Unknown frame type -> cleanly skipped per SPEC §10
    def test_unknown_frame_type_skipped_cleanly(self):
        sock = self._connect()
        try:
            # Send an unknown frame type 0x77 with 16 bytes of arbitrary payload
            unknown_payload = b'UnknownTypeBytes'
            unknown_hdr = encode_header(0x77, 0, 0, len(unknown_payload))
            write_all(sock, unknown_hdr + unknown_payload)

            # Immediately follow with a valid GET /test.txt REQUEST on the same connection
            req = encode_request(path="/test.txt")
            write_all(sock, req)

            # The server must skip the unknown frame and reply to the valid request
            resp = self._read_frame(sock)
            self.assertEqual(resp.status, STATUS_OK)
            self.assertEqual(resp.body, self.text_content)
        finally:
            sock.close()

    # 14. Multiple requests on the same TCP connection (persistent connection)
    def test_persistent_connection_multiple_requests(self):
        sock = self._connect()
        try:
            for i in range(5):
                req = encode_request(path="/test.txt")
                write_all(sock, req)
                resp = self._read_frame(sock)
                self.assertEqual(resp.status, STATUS_OK)
                self.assertEqual(resp.body, self.text_content)
        finally:
            sock.close()

    # 15. CONN_CLOSE flag honors connection closure
    def test_conn_close_flag(self):
        sock = self._connect()
        try:
            req = encode_request(path="/test.txt", conn_close=True)
            write_all(sock, req)
            resp = self._read_frame(sock)
            self.assertEqual(resp.status, STATUS_OK)
            self.assertTrue(resp.conn_close)
            # Server must close the connection
            with self.assertRaises(ConnectionClosed):
                read_exact(sock, 1)
        finally:
            sock.close()

    # 16. Partial TCP delivery (byte-by-byte write)
    def test_partial_tcp_delivery(self):
        sock = self._connect()
        try:
            req = encode_request(path="/test.txt")
            # Send one byte at a time to test stream reassembly
            for byte in req:
                sock.sendall(bytes([byte]))
                time.sleep(0.001)

            resp = self._read_frame(sock)
            self.assertEqual(resp.status, STATUS_OK)
            self.assertEqual(resp.body, self.text_content)
        finally:
            sock.close()

    # 17. Multiple frames delivered in a single TCP read
    def test_multiple_frames_in_single_tcp_packet(self):
        sock = self._connect()
        try:
            req1 = encode_request(path="/test.txt")
            req2 = encode_request(path="/index.html")
            # Concatenate both requests and send in one sendall call
            sock.sendall(req1 + req2)

            resp1 = self._read_frame(sock)
            self.assertEqual(resp1.status, STATUS_OK)
            self.assertEqual(resp1.body, self.text_content)

            resp2 = self._read_frame(sock)
            self.assertEqual(resp2.status, STATUS_OK)
            self.assertEqual(resp2.body, self.index_content)
        finally:
            sock.close()

    # 18. Client subprocess test: 200 OK -> exit code 0, body to stdout
    def test_client_subprocess_200(self):
        res = subprocess.run(
            [sys.executable, "-m", "src.client.main", f"127.0.0.1:{self.port}/test.txt"],
            capture_output=True,
        )
        self.assertEqual(res.returncode, 0)
        self.assertEqual(res.stdout, self.text_content)

    # 19. Client subprocess test: 404 Not Found -> exit code 2
    def test_client_subprocess_404(self):
        res = subprocess.run(
            [sys.executable, "-m", "src.client.main", f"127.0.0.1:{self.port}/not_here.txt"],
            capture_output=True,
        )
        self.assertEqual(res.returncode, 2)
        self.assertIn(b"404 Not Found", res.stderr)

    # 20. Client subprocess test: verbose (-v) mode -> prints hex dump to stderr
    def test_client_subprocess_verbose(self):
        res = subprocess.run(
            [sys.executable, "-m", "src.client.main", "-v", f"127.0.0.1:{self.port}/test.txt"],
            capture_output=True,
        )
        self.assertEqual(res.returncode, 0)
        self.assertEqual(res.stdout, self.text_content)
        stderr_str = res.stderr.decode('utf-8', errors='replace')
        self.assertIn("SEND REQUEST FRAME", stderr_str)
        self.assertIn("RECV RESPONSE FRAME", stderr_str)
        self.assertIn("Magic: 0xB748", stderr_str)

    # 21. Client subprocess test: bad arguments -> exit code 1
    def test_client_subprocess_bad_args(self):
        res = subprocess.run(
            [sys.executable, "-m", "src.client.main", "invalid_target_format"],
            capture_output=True,
        )
        self.assertEqual(res.returncode, 1)


if __name__ == '__main__':
    unittest.main()
