"""DNS report observation tests."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from wiretally.models import PacketMetadata  # noqa: E402
from wiretally.reporting import extract_dns_query_names  # noqa: E402


class DNSReportingTests(unittest.TestCase):
    def test_extracts_unique_normalized_dns_names_deterministically(self):
        packets = [
            PacketMetadata(frame_number=1, time_epoch=1.0, frame_len=60, dns_query_name="Internal.Example."),
            PacketMetadata(frame_number=2, time_epoch=2.0, frame_len=60, dns_query_name="internal.example"),
            PacketMetadata(frame_number=3, time_epoch=3.0, frame_len=60, dns_query_name="api.example"),
            PacketMetadata(frame_number=4, time_epoch=4.0, frame_len=60),
        ]

        self.assertEqual(
            extract_dns_query_names(packets),
            ["api.example", "internal.example"],
        )

    def test_empty_names_are_omitted(self):
        packets = [
            PacketMetadata(frame_number=1, time_epoch=1.0, frame_len=60, dns_query_name=""),
            PacketMetadata(frame_number=2, time_epoch=2.0, frame_len=60, dns_query_name="   "),
        ]
        self.assertEqual(extract_dns_query_names(packets), [])


if __name__ == "__main__":
    unittest.main()
