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
        with self.assertRaisesRegex(ParserError, "2-second timeout") as raised:
            extract_packet_metadata("tshark", "sample.pcap", timeout_seconds=2)
        self.assertEqual(raised.exception.code, "tshark_timeout")
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

    @patch(
        "wiretally.parser.subprocess.run",
        return_value=subprocess.CompletedProcess(
            args=["tshark"], returncode=0, stdout="[]", stderr=""
        ),
    )
    def test_capture_path_is_passed_as_one_argument_without_shell(self, run_mock):
        capture_path = "/tmp/capture folder/strange;name.pcap"
        self.assertEqual(extract_packet_metadata("tshark", capture_path), [])

        command = run_mock.call_args.args[0]
        self.assertIsInstance(command, list)
        self.assertEqual(command[0:3], ["tshark", "-r", capture_path])
        self.assertNotIn("shell", run_mock.call_args.kwargs)

    @patch(
        "wiretally.parser.subprocess.run",
        return_value=subprocess.CompletedProcess(
            args=["tshark"], returncode=2, stdout="[]", stderr="bad file at /private/path"
        ),
    )
    def test_nonzero_tshark_exit_rejects_partial_output_without_leaking_stderr(self, run_mock):
        with self.assertRaisesRegex(ParserError, "exit code 2") as raised:
            extract_packet_metadata("tshark", "sample.pcap")
        self.assertEqual(raised.exception.code, "tshark_failed")
        self.assertNotIn("/private/path", str(raised.exception))

    @patch(
        "wiretally.parser.subprocess.run",
        return_value=subprocess.CompletedProcess(
            args=["tshark"], returncode=0, stdout="{broken", stderr=""
        ),
    )
    def test_invalid_json_has_a_stable_error_code(self, run_mock):
        with self.assertRaises(ParserError) as raised:
            extract_packet_metadata("tshark", "sample.pcap")
        self.assertEqual(raised.exception.code, "tshark_invalid_json")

    def test_non_positive_timeout_is_rejected_before_execution(self):
        with patch("wiretally.parser.subprocess.run") as run_mock:
            with self.assertRaisesRegex(ValueError, "greater than zero"):
                extract_packet_metadata("tshark", "sample.pcap", timeout_seconds=0)
            run_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
