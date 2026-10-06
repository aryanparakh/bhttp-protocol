"""Unit tests for server filesystem operations and path security per SPEC §12."""

import os
import tempfile
import unittest

from src.server.filesystem import (
    resolve_path, read_file, get_mime_type,
    PathSecurityError, FileNotFoundError_,
)


class TestFilesystem(unittest.TestCase):
    """Test filesystem mapping and security rules."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.doc_root = os.path.abspath(self.temp_dir.name)

        # Create test files
        with open(os.path.join(self.doc_root, "index.html"), "w", encoding="utf-8") as f:
            f.write("<h1>Root Index</h1>")
        with open(os.path.join(self.doc_root, "hello.txt"), "w", encoding="utf-8") as f:
            f.write("Hello world!")
        
        # Subdirectory
        sub = os.path.join(self.doc_root, "subdir")
        os.makedirs(sub, exist_ok=True)
        with open(os.path.join(sub, "sub.txt"), "w", encoding="utf-8") as f:
            f.write("Nested file")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_root_maps_to_index_html(self):
        resolved = resolve_path(self.doc_root, "/")
        self.assertEqual(resolved, os.path.join(self.doc_root, "index.html"))

    def test_valid_file_resolved(self):
        resolved = resolve_path(self.doc_root, "/hello.txt")
        self.assertEqual(resolved, os.path.join(self.doc_root, "hello.txt"))
        content = read_file(resolved)
        self.assertEqual(content, b"Hello world!")

    def test_nested_file_resolved(self):
        resolved = resolve_path(self.doc_root, "/subdir/sub.txt")
        self.assertEqual(resolved, os.path.join(self.doc_root, "subdir", "sub.txt"))

    def test_missing_file_raises_404(self):
        with self.assertRaises(FileNotFoundError_):
            resolve_path(self.doc_root, "/nonexistent.html")

    def test_path_must_start_with_slash(self):
        with self.assertRaises(PathSecurityError) as ctx:
            resolve_path(self.doc_root, "hello.txt")
        self.assertIn("must start with '/'", str(ctx.exception))

    def test_path_traversal_dotdot_blocked(self):
        # Traversal attempts: /../secret, /subdir/../../secret
        with self.assertRaises(PathSecurityError):
            resolve_path(self.doc_root, "/../secret.txt")
        with self.assertRaises(PathSecurityError):
            resolve_path(self.doc_root, "/subdir/../../secret.txt")
        with self.assertRaises(PathSecurityError):
            resolve_path(self.doc_root, "/subdir/..")

    def test_windows_drive_letter_blocked(self):
        # /C:/Windows/System32
        with self.assertRaises(PathSecurityError):
            resolve_path(self.doc_root, "/C:/windows/system32/cmd.exe")

    def test_mime_type_resolution(self):
        self.assertEqual(get_mime_type("file.html"), "text/html")
        self.assertEqual(get_mime_type("file.txt"), "text/plain")
        self.assertEqual(get_mime_type("file.css"), "text/css")
        self.assertEqual(get_mime_type("file.json"), "application/json")
        self.assertEqual(get_mime_type("file.unknown_xyz"), "application/octet-stream")


if __name__ == '__main__':
    unittest.main()
