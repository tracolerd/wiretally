"""Report helpers for defensive packet metadata analysis."""

from .models import PacketMetadata


def extract_dns_query_names(packets: list[PacketMetadata]) -> list[str]:
    """Return a deterministic, de-duplicated list of DNS query names.

    DNS names are case-insensitive. Trailing root dots and surrounding
    whitespace are normalized; no packet payload is retained by this helper.
    """
    names = {
        name.strip().rstrip(".").lower()
        for packet in packets
        if isinstance((name := packet.dns_query_name), str) and name.strip().rstrip(".")
    }
    return sorted(names)
