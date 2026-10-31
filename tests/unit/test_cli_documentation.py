"""Public module examples match the supported CLI parser, without dispatch."""
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class CLIDocumentationTests(unittest.TestCase):
    def test_module_examples_parse_against_current_cli(self):
        import contextlib
        import io
        import shlex
        from html.parser import HTMLParser

        from shadow313.cli.main import build_parser

        class Text(HTMLParser):
            def __init__(self):
                super().__init__()
                self.parts = []

            def handle_data(self, data):
                self.parts.append(data)

        paths = list((ROOT / "platform").glob("*.html"))
        paths.append(ROOT / "docs/quickstart.html")
        examples = 0
        for path in paths:
            page = Text()
            page.feed(path.read_text())
            for line in "\n".join(page.parts).splitlines():
                line = line.strip()
                if not line.startswith("shadow313 "):
                    continue
                examples += 1
                with self.subTest(page=path.name, command=line):
                    try:
                        with contextlib.redirect_stdout(io.StringIO()):
                            build_parser().parse_args(shlex.split(line)[1:])
                    except SystemExit as error:
                        self.assertEqual(error.code, 0)
        self.assertGreaterEqual(examples, 9)


if __name__ == "__main__":
    unittest.main()
