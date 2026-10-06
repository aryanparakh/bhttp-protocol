"""Unit tests for BHTTP protocol framing, header encoding, request/response codecs."""

import unittest
import struct

from src.protocol.constants import (
    MAGIC, VERSION, FRAME_HEADER_SIZE,
    FRAME_REQUEST, FRAME_RESPONSE, FRAME_ERROR,
    FLAG_CONN_CLOSE, METHOD_GET,
    STATUS_NONE, STATUS_OK, STATUS_BAD_REQUEST, STATUS_NOT_FOUND, STATUS_INTERNAL_ERROR,
    MAX_PAYLOAD_SIZE, MAX_PATH_LENGTH, MAX_HEADER_COUNT, MAX_HEADER_NAME_LEN, MAX_HEADER_VALUE_LEN,
    HEADER_NAME_TABLE, HEADER_TAG_INDEXED, HEADER_TAG_LITERAL,
)
from src.protocol.frame import FrameHeader, FrameError, encode_header, decode_header
from src.protocol.headers import encode_headers, decode_headers
from src.protocol.request import Request, encode_request, decode_request
from src.protocol.response import Response, encode_response, decode_response


class TestFrameHeader(unittest.TestCase):
    """Test 12-byte fixed frame header per SPEC §5."""

    def test_encode_decode_header_valid(self):
        hdr_bytes = encode_header(
            frame_type=FRAME_REQUEST,
            flags=FLAG_CONN_CLOSE,
            status=STATUS_NONE,
            payload_length=42,
        )
        self.assertEqual(len(hdr_bytes), FRAME_HEADER_SIZE)
        self.assertEqual(len(hdr_bytes), 12)

        parsed = decode_header(hdr_bytes)
        self.assertEqual(parsed.version, VERSION)
        self.assertEqual(parsed.frame_type, FRAME_REQUEST)
        self.assertEqual(parsed.flags, FLAG_CONN_CLOSE)
        self.assertTrue(parsed.conn_close)
        self.assertEqual(parsed.reserved, 0x00)
        self.assertEqual(parsed.status, STATUS_NONE)
        self.assertEqual(parsed.payload_length, 42)
        self.assertEqual(parsed.total_frame_size, 12 + 42)

    def test_invalid_magic_rejected(self):
        bad_magic = b'\x00\x00' + struct.pack('>BBBBHI', VERSION, FRAME_REQUEST, 0, 0, 0, 10)
        with self.assertRaises(FrameError) as ctx:
            decode_header(bad_magic)
        self.assertTrue(ctx.exception.fatal)
        self.assertIn("Invalid magic", str(ctx.exception))

    def test_invalid_version_rejected(self):
        bad_ver = struct.pack('>2sBBBBHI', MAGIC, 0x02, FRAME_REQUEST, 0, 0, 0, 10)
        with self.assertRaises(FrameError) as ctx:
            decode_header(bad_ver)
        self.assertTrue(ctx.exception.fatal)
        self.assertIn("Unsupported version", str(ctx.exception))

    def test_oversized_payload_rejected(self):
        oversized = MAX_PAYLOAD_SIZE + 1
        # Test encode raises ValueError
        with self.assertRaises(ValueError):
            encode_header(FRAME_REQUEST, 0, 0, oversized)

        # Test decode raises fatal FrameError
        bad_len = struct.pack('>2sBBBBHI', MAGIC, VERSION, FRAME_REQUEST, 0, 0, 0, oversized)
        with self.assertRaises(FrameError) as ctx:
            decode_header(bad_len)
        self.assertTrue(ctx.exception.fatal)
        self.assertIn("exceeds MAX_PAYLOAD_SIZE", str(ctx.exception))

    def test_reserved_byte_ignored_on_receipt(self):
        # SPEC §5: receiver MUST ignore reserved byte
        raw = struct.pack('>2sBBBBHI', MAGIC, VERSION, FRAME_REQUEST, 0, 0xFF, 0, 10)
        parsed = decode_header(raw)
        self.assertEqual(parsed.reserved, 0xFF)

    def test_header_length_short(self):
        with self.assertRaises(FrameError):
            decode_header(b'\xB7\x48\x01')


class TestHeaders(unittest.TestCase):
    """Test header encoding and decoding per SPEC §9."""

    def test_indexed_and_literal_headers(self):
        headers = [
            ("content-type", "text/html"),  # indexed ID 0
            ("server", "bserve/1.0"),       # indexed ID 5
            ("x-custom-header", "custom-value"),  # literal
        ]
        encoded = encode_headers(headers)
        decoded, offset = decode_headers(encoded, 0)
        self.assertEqual(offset, len(encoded))
        self.assertEqual(len(decoded), 3)
        self.assertEqual(decoded[0], ("content-type", "text/html"))
        self.assertEqual(decoded[1], ("server", "bserve/1.0"))
        self.assertEqual(decoded[2], ("x-custom-header", "custom-value"))

    def test_max_header_count_enforced(self):
        headers = [(f"x-hdr-{i}", "val") for i in range(MAX_HEADER_COUNT + 1)]
        with self.assertRaises(ValueError):
            encode_headers(headers)

    def test_invalid_header_tag_rejected(self):
        # 1 header, tag = 0x05 (invalid)
        corrupt = struct.pack('>BB', 1, 0x05) + b'\x00\x00'
        with self.assertRaises(FrameError) as ctx:
            decode_headers(corrupt, 0)
        self.assertIn("invalid name tag", str(ctx.exception))

    def test_out_of_range_indexed_id_rejected(self):
        # 1 header, indexed tag 0x00, id 50 (valid is 0-9)
        corrupt = struct.pack('>BBB', 1, HEADER_TAG_INDEXED, 50) + struct.pack('>H', 0)
        with self.assertRaises(FrameError) as ctx:
            decode_headers(corrupt, 0)
        self.assertIn("indexed name ID 50 out of range", str(ctx.exception))

    def test_value_exceeding_max_rejected(self):
        # Value > 8192 bytes
        oversized_val = "A" * (MAX_HEADER_VALUE_LEN + 1)
        with self.assertRaises(ValueError):
            encode_headers([("host", oversized_val)])


class TestRequestCodec(unittest.TestCase):
    """Test REQUEST encoding and decoding per SPEC §11."""

    def test_roundtrip_request(self):
        frame = encode_request(
            path="/index.html",
            headers=[("host", "localhost:9000"), ("accept", "text/html")],
            conn_close=True,
        )
        self.assertGreater(len(frame), 12)
        hdr = decode_header(frame[:12])
        self.assertEqual(hdr.frame_type, FRAME_REQUEST)
        self.assertTrue(hdr.conn_close)
        self.assertEqual(hdr.status, STATUS_NONE)
        self.assertEqual(hdr.payload_length, len(frame) - 12)

        req = decode_request(hdr, frame[12:])
        self.assertEqual(req.method, METHOD_GET)
        self.assertEqual(req.path, "/index.html")
        self.assertTrue(req.conn_close)
        self.assertEqual(len(req.headers), 2)
        self.assertEqual(req.headers[0], ("host", "localhost:9000"))
        self.assertEqual(req.headers[1], ("accept", "text/html"))

    def test_request_status_nonzero_rejected(self):
        frame = encode_request(path="/index.html")
        # Tamper with status field at offset 6-7
        tampered_header = bytearray(frame[:12])
        struct.pack_into('>H', tampered_header, 6, 0x00C8)
        hdr = decode_header(bytes(tampered_header))
        with self.assertRaises(FrameError) as ctx:
            decode_request(hdr, frame[12:])
        self.assertIn("non-zero status", str(ctx.exception))

    def test_request_missing_leading_slash(self):
        with self.assertRaises(ValueError):
            encode_request(path="index.html")

    def test_request_nul_byte_rejected(self):
        # Construct payload with NUL byte in path
        path_bytes = b'/index\x00.html'
        payload = struct.pack('>BH', METHOD_GET, len(path_bytes)) + path_bytes + struct.pack('>B', 0)
        hdr = encode_header(FRAME_REQUEST, 0, 0, len(payload))
        parsed_hdr = decode_header(hdr)
        with self.assertRaises(FrameError) as ctx:
            decode_request(parsed_hdr, payload)
        self.assertIn("NUL byte", str(ctx.exception))

    def test_request_unconsumed_bytes_rejected(self):
        frame = encode_request(path="/test.txt")
        hdr = decode_header(frame[:12])
        # Append extra garbage bytes to payload
        corrupted_payload = frame[12:] + b'extra_bytes'
        with self.assertRaises(FrameError) as ctx:
            decode_request(hdr, corrupted_payload)
        self.assertIn("unconsumed bytes", str(ctx.exception))


class TestResponseCodec(unittest.TestCase):
    """Test RESPONSE and ERROR encoding and decoding per SPEC §13."""

    def test_roundtrip_response_with_body(self):
        body = b"Hello, BHTTP Protocol!"
        frame = encode_response(
            status=STATUS_OK,
            headers=[("content-type", "text/plain"), ("content-length", str(len(body)))],
            body=body,
            conn_close=False,
        )
        hdr = decode_header(frame[:12])
        self.assertEqual(hdr.frame_type, FRAME_RESPONSE)
        self.assertEqual(hdr.status, STATUS_OK)
        self.assertFalse(hdr.conn_close)

        resp = decode_response(hdr, frame[12:])
        self.assertEqual(resp.status, STATUS_OK)
        self.assertEqual(resp.body, body)
        self.assertEqual(len(resp.headers), 2)
        self.assertEqual(resp.headers[0], ("content-type", "text/plain"))

    def test_error_frame_zero_length_body(self):
        # ERROR frame with 0 body is valid
        frame = encode_response(
            status=STATUS_BAD_REQUEST,
            headers=[],
            body=b"",
            is_error=True,
        )
        hdr = decode_header(frame[:12])
        self.assertEqual(hdr.frame_type, FRAME_ERROR)
        resp = decode_response(hdr, frame[12:])
        self.assertEqual(resp.status, STATUS_BAD_REQUEST)
        self.assertEqual(resp.body, b"")

        # ERROR frame with non-zero body must raise ValueError on encode
        with self.assertRaises(ValueError):
            encode_response(
                status=STATUS_BAD_REQUEST,
                headers=[],
                body=b"not empty",
                is_error=True,
            )


if __name__ == '__main__':
    unittest.main()
