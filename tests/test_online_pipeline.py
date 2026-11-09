import json
import tempfile
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from app.cli import build_parser, main
from tests.helpers import FIXTURES


class OnlineCliTests(unittest.TestCase):
    def test_legacy_cli_flags_and_new_subcommand_are_both_available(self):
        parser = build_parser()
        old = parser.parse_args(["--input", "in.jsonl", "--output", "out.jsonl"])
        online = parser.parse_args(["online-assess", "--input", "in.jsonl", "--output", "out.jsonl"])
        self.assertIsNone(old.command)
        self.assertEqual(old.input, "in.jsonl")
        self.assertEqual(online.command, "online-assess")
        self.assertIn("--input", parser.format_help())

    def test_legacy_m2_execution_still_uses_old_output_contract(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "legacy.jsonl"
            result = main(["--input", str(FIXTURES / "fixture_ssh.json"), "--output", str(output)])
            self.assertEqual(result, 0)
            row = json.loads(output.read_text(encoding="utf-8").splitlines()[0])
            self.assertEqual(row["outcome"], "matched")
            self.assertNotIn("schema_version", row)

    def test_online_cli_fails_safely_without_key(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "input.jsonl"
            source.write_text("{}\n", encoding="utf-8")
            output = Path(temp) / "online.jsonl"
            stderr = StringIO()
            with patch("app.vulnerability.nvd.pipeline.load_api_key", return_value=None), redirect_stderr(stderr):
                result = main(["online-assess", "--input", str(source), "--output", str(output)])
            self.assertEqual(result, 2)
            self.assertIn("NVD_API_KEY is required", stderr.getvalue())
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
