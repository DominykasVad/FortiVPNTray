import tempfile
import unittest
from pathlib import Path

import check_files


class CheckFilesTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)

    def tearDown(self):
        self.directory.cleanup()

    def problems(self, files):
        for name, content in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content if isinstance(content, bytes) else content.encode())
        return check_files.check_repository(self.root, list(files))

    def assertOne(self, files, fragment):
        problems = self.problems(files)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn(fragment, problems[0])

    def test_clean_files_pass(self):
        self.assertEqual(self.problems({
            "a.txt": "one\ntwo\n",
            "empty.txt": "",
            "data.json": '{"a": [1, 2]}\n',
            "ci.yml": "on:\n  push:\n    branches: [main]\n",
            "Info.plist": '<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict><key>a</key><string>b</string></dict></plist>\n',
            "image.png": b"\x89PNG\0\0 \n trailing \0",
            "docs/guide.md": "See [the text](../a.txt), [site](https://example.com) and [top](#top).\n",
        }), [])

    def test_trailing_whitespace(self):
        self.assertOne({"a.txt": "one \ntwo\n"}, "a.txt:1: trailing whitespace")
        self.assertOne({"b.txt": "one\n\ttwo\t\n"}, "b.txt:2: trailing whitespace")

    def test_missing_final_newline(self):
        self.assertOne({"a.txt": "one\ntwo"}, "no newline at end of file")

    def test_crlf(self):
        self.assertOne({"a.txt": "one\r\ntwo\n"}, "a.txt:1: CRLF")

    def test_conflict_markers(self):
        for marker in ("<" * 7 + " HEAD", ">" * 7 + " branch", "|" * 7 + " base", "<" * 7):
            self.assertOne({"a.txt": f"one\n{marker}\ntwo\n"}, "a.txt:2: merge conflict marker")
        # A Markdown heading underline or a longer run is not a marker.
        self.assertEqual(self.problems({"b.md": "Title\n=======\n\n" + "<" * 8 + "\n"}), [])

    def test_invalid_json(self):
        self.assertOne({"a.json": '{"a": 1,}\n'}, "a.json: invalid json")

    def test_invalid_plist(self):
        self.assertOne({"a.plist": "<plist><dict><key>a</key></plist>\n"}, "a.plist: invalid plist")

    def test_invalid_yaml(self):
        self.assertOne({"a.yml": "a: [1, 2\nb: 3\n"}, "a.yml: invalid YAML")
        self.assertOne({"b.yaml": "a:\n  - 1\n - 2\n"}, "b.yaml: invalid YAML")

    def test_size_guard(self):
        limit = check_files.MAX_BYTES
        self.assertEqual(self.problems({"ok.bin": b"\0" * limit}), [])
        self.assertOne({"big.bin": b"\0" * (limit + 1)}, "larger than")

    def test_not_utf8(self):
        self.assertOne({"a.txt": b"caf\xe9\n"}, "not valid UTF-8")

    def test_broken_markdown_links(self):
        self.assertOne({"README.md": "See [guide](docs/missing.md).\n"}, "README.md:1: broken link: docs/missing.md")
        self.assertOne({"docs/a.md": "x\n\n![shot](shots/a.png)\n"}, "docs/a.md:3: broken link")
        self.assertOne({"b.md": "[up](../../etc/passwd)\n"}, "link leaves the repository")

    def test_markdown_links_resolve_relative_to_the_file(self):
        self.assertEqual(self.problems({
            "docs/signing.md": "text\n",
            "native/README.md": "[signing](../docs/signing.md#rules), [dir](../docs/), [root](/docs/signing.md), [sp](<../docs/signing.md>)\n",
        }), [])

    def test_markdown_code_is_not_a_link(self):
        self.assertEqual(self.problems({
            "a.md": "Use `[x](missing.md)` like this:\n\n```\n[y](also-missing.md)\n```\n",
        }), [])


if __name__ == "__main__":
    unittest.main()
