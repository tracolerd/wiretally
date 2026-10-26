"""Tests for bounded TShark execution."""

import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from wiretally.parser import (  # noqa: E402
    DEFAULT_TSHARK_TIMEOUT_SECONDS,
    ParserError,
    extract_packet_metadata,
)


class ParserTimeoutTests(unittest.TestCase):
    @patch(
        "wiretally.parser.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="tshark", timeout=2),
    )
    def test_timeout_is_reported_as_parser_error(self, run_mock):
        with self.assertRaisesRegex(ParserError, "2-second timeout"):
            extract_packet_metadata("tshark", "sample.pcap", timeout_seconds=2)
        run_mock.assert_called_once()
        self.assertEqual(run_mock.call_args.kwargs["timeout"], 2)

    @patch(
        "wiretally.parser.subprocess.run",
        return_value=subprocess.CompletedProcess(
            args=["tshark"], returncode=0, stdout="[]", stderr=""
        ),
    )
    def test_default_timeout_is_passed_to_subprocess(self, run_mock):
        self.assertEqual(extract_packet_metadata("tshark", "sample.pcap"), [])
        self.assertEqual(
            run_mock.call_args.kwargs["timeout"],
            DEFAULT_TSHARK_TIMEOUT_SECONDS,
        )

    def test_non_positive_timeout_is_rejected_before_execution(self):
        with patch("wiretally.parser.subprocess.run") as run_mock:
            with self.assertRaisesRegex(ValueError, "greater than zero"):
                extract_packet_metadata("tshark", "sample.pcap", timeout_seconds=0)
            run_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
